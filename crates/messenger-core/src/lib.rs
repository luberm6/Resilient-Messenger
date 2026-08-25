#![forbid(unsafe_code)]
//! Encrypted, offline-first local source of truth shared by both mobile clients.

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand_core::{OsRng, RngCore};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::{
    path::Path,
    sync::{Mutex, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use zeroize::Zeroizing;

const SCHEMA_VERSION: i64 = 2;
const MESSAGE_AAD: &[u8] = b"resilient/local-message/v1";

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("database operation failed")]
    Database(#[from] rusqlite::Error),
    #[error("local ciphertext failed authentication")]
    Authentication,
    #[error("invalid state transition")]
    InvalidTransition,
    #[error("message was not found")]
    NotFound,
    #[error("master key must contain exactly 32 bytes")]
    InvalidMasterKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i64)]
pub enum MessageStatus {
    Draft = 0,
    Queued = 1,
    Encrypting = 2,
    ReadyToUpload = 3,
    Uploading = 4,
    ServerAccepted = 5,
    Delivered = 6,
    Read = 7,
    RetryScheduled = 8,
    FailedPermanent = 9,
    Cancelled = 10,
}

impl TryFrom<i64> for MessageStatus {
    type Error = CoreError;
    fn try_from(value: i64) -> Result<Self, Self::Error> {
        Ok(match value {
            0 => Self::Draft,
            1 => Self::Queued,
            2 => Self::Encrypting,
            3 => Self::ReadyToUpload,
            4 => Self::Uploading,
            5 => Self::ServerAccepted,
            6 => Self::Delivered,
            7 => Self::Read,
            8 => Self::RetryScheduled,
            9 => Self::FailedPermanent,
            10 => Self::Cancelled,
            _ => return Err(CoreError::InvalidTransition),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalMessage {
    pub client_message_id: [u8; 16],
    pub conversation_id: [u8; 16],
    pub plaintext: String,
    pub status: MessageStatus,
    pub created_at_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingUpload {
    pub client_message_id: [u8; 16],
    pub conversation_id: [u8; 16],
    pub encrypted_payload: Vec<u8>,
    pub attempts: u32,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversationSummary {
    pub conversation_id: [u8; 16],
    pub updated_at_ms: i64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IncomingEvent {
    pub event_id: [u8; 16],
    pub conversation_id: [u8; 16],
    pub encrypted_event: Vec<u8>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachedRelayDirectory {
    pub version: u64,
    pub signed_directory: Vec<u8>,
    pub expires_at_ms: i64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkMode {
    Normal,
    Limited,
    Survival,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkDiagnostics {
    pub mode: NetworkMode,
    pub pending_uploads: u64,
    pub last_cursor: u64,
}

/// The native shell supplies a platform-protected key. The key is zeroized when dropped.
pub struct MessengerCore {
    db: Mutex<Connection>,
    master_key: RwLock<Zeroizing<[u8; 32]>>,
}

impl MessengerCore {
    pub fn open(path: impl AsRef<Path>, master_key: &[u8]) -> Result<Self, CoreError> {
        let key: [u8; 32] = master_key
            .try_into()
            .map_err(|_| CoreError::InvalidMasterKey)?;
        let db = Connection::open(path)?;
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.pragma_update(None, "foreign_keys", "ON")?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        migrate(&db)?;
        Ok(Self {
            db: Mutex::new(db),
            master_key: RwLock::new(Zeroizing::new(key)),
        })
    }

    pub fn open_in_memory(master_key: &[u8]) -> Result<Self, CoreError> {
        let key: [u8; 32] = master_key
            .try_into()
            .map_err(|_| CoreError::InvalidMasterKey)?;
        let db = Connection::open_in_memory()?;
        db.pragma_update(None, "foreign_keys", "ON")?;
        migrate(&db)?;
        Ok(Self {
            db: Mutex::new(db),
            master_key: RwLock::new(Zeroizing::new(key)),
        })
    }

    /// Atomically persists encrypted content and its outbox entry before returning success.
    pub fn create_message(
        &self,
        conversation_id: [u8; 16],
        plaintext: &str,
    ) -> Result<[u8; 16], CoreError> {
        let client_message_id = random_id();
        let encrypted = encrypt(
            &self.master_key.read().expect("key lock poisoned"),
            plaintext.as_bytes(),
        )?;
        let now = now_ms();
        let mut db = self.db.lock().expect("database mutex poisoned");
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT OR IGNORE INTO conversations(conversation_id, updated_at_ms) VALUES (?1, ?2)",
            params![conversation_id.as_slice(), now],
        )?;
        tx.execute(
            "INSERT INTO messages(client_message_id, conversation_id, body_ciphertext, status, created_at_ms) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![client_message_id.as_slice(), conversation_id.as_slice(), encrypted, MessageStatus::ReadyToUpload as i64, now],
        )?;
        tx.execute(
            "INSERT INTO outbox(client_message_id, next_attempt_at_ms, attempts) VALUES (?1, ?2, 0)",
            params![client_message_id.as_slice(), now],
        )?;
        tx.execute(
            "UPDATE conversations SET updated_at_ms=?2 WHERE conversation_id=?1",
            params![conversation_id.as_slice(), now],
        )?;
        tx.commit()?;
        Ok(client_message_id)
    }

    pub fn list_messages(&self, conversation_id: [u8; 16]) -> Result<Vec<LocalMessage>, CoreError> {
        let db = self.db.lock().expect("database mutex poisoned");
        let mut stmt = db.prepare(
            "SELECT client_message_id, body_ciphertext, status, created_at_ms FROM messages WHERE conversation_id=?1 ORDER BY created_at_ms, rowid",
        )?;
        let rows = stmt.query_map([conversation_id.as_slice()], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;
        rows.map(|row| {
            let (id, ciphertext, status, created_at_ms) = row?;
            let plaintext = String::from_utf8(decrypt(
                &self.master_key.read().expect("key lock poisoned"),
                &ciphertext,
            )?)
            .map_err(|_| CoreError::Authentication)?;
            Ok(LocalMessage {
                client_message_id: fixed_id(&id)?,
                conversation_id,
                plaintext,
                status: status.try_into()?,
                created_at_ms,
            })
        })
        .collect()
    }

    pub fn list_conversations(&self) -> Result<Vec<ConversationSummary>, CoreError> {
        let db = self.db.lock().expect("database mutex poisoned");
        let mut statement = db.prepare(
            "SELECT conversation_id,updated_at_ms FROM conversations ORDER BY updated_at_ms DESC,conversation_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
        })?;
        rows.map(|row| {
            let (id, updated_at_ms) = row?;
            Ok(ConversationSummary {
                conversation_id: fixed_id(&id)?,
                updated_at_ms,
            })
        })
        .collect()
    }

    pub fn observe_conversation_changes(&self, after_revision: u64) -> Result<u64, CoreError> {
        let db = self.db.lock().expect("database mutex poisoned");
        let revision: i64 = db.query_row(
            "SELECT revision FROM change_counter WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        Ok((revision as u64).max(after_revision))
    }

    pub fn create_group(&self, group_id: [u8; 16]) -> Result<(), CoreError> {
        let db = self.db.lock().expect("database mutex poisoned");
        db.execute(
            "INSERT INTO conversations(conversation_id,updated_at_ms) VALUES(?1,?2) ON CONFLICT(conversation_id) DO NOTHING",
            params![group_id.as_slice(), now_ms()],
        )?;
        Ok(())
    }

    pub fn add_member(
        &self,
        group_id: [u8; 16],
        device_id: [u8; 16],
        account_id: [u8; 32],
    ) -> Result<(), CoreError> {
        let db = self.db.lock().expect("database mutex poisoned");
        db.execute(
            "INSERT INTO conversation_members(conversation_id,device_id,account_id,removed_at_ms) VALUES(?1,?2,?3,NULL) ON CONFLICT(conversation_id,device_id) DO UPDATE SET account_id=excluded.account_id,removed_at_ms=NULL",
            params![group_id.as_slice(), device_id.as_slice(), account_id.as_slice()],
        )?;
        Ok(())
    }

    pub fn remove_member(&self, group_id: [u8; 16], device_id: [u8; 16]) -> Result<(), CoreError> {
        let db = self.db.lock().expect("database mutex poisoned");
        let changed = db.execute(
            "UPDATE conversation_members SET removed_at_ms=?3 WHERE conversation_id=?1 AND device_id=?2 AND removed_at_ms IS NULL",
            params![group_id.as_slice(), device_id.as_slice(), now_ms()],
        )?;
        if changed == 1 {
            Ok(())
        } else {
            Err(CoreError::NotFound)
        }
    }

    pub fn get_pending_uploads(&self, limit: usize) -> Result<Vec<PendingUpload>, CoreError> {
        let db = self.db.lock().expect("database mutex poisoned");
        let mut stmt = db.prepare(
            "SELECT m.client_message_id,m.conversation_id,m.body_ciphertext,o.attempts FROM outbox o JOIN messages m USING(client_message_id) WHERE o.next_attempt_at_ms<=?1 ORDER BY o.next_attempt_at_ms LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![now_ms(), limit.min(50) as i64], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, u32>(3)?,
            ))
        })?;
        rows.map(|row| {
            let (message, conversation, encrypted_payload, attempts) = row?;
            Ok(PendingUpload {
                client_message_id: fixed_id(&message)?,
                conversation_id: fixed_id(&conversation)?,
                encrypted_payload,
                attempts,
            })
        })
        .collect()
    }

    pub fn mark_upload_accepted(&self, id: [u8; 16]) -> Result<(), CoreError> {
        let mut db = self.db.lock().expect("database mutex poisoned");
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "UPDATE messages SET status=?2 WHERE client_message_id=?1 AND status IN (?3,?4,?5)",
            params![
                id.as_slice(),
                MessageStatus::ServerAccepted as i64,
                MessageStatus::ReadyToUpload as i64,
                MessageStatus::Uploading as i64,
                MessageStatus::RetryScheduled as i64
            ],
        )?;
        let already = tx
            .query_row(
                "SELECT status FROM messages WHERE client_message_id=?1",
                [id.as_slice()],
                |r| r.get::<_, i64>(0),
            )
            .optional()?;
        if changed == 0 && already != Some(MessageStatus::ServerAccepted as i64) {
            return Err(if already.is_some() {
                CoreError::InvalidTransition
            } else {
                CoreError::NotFound
            });
        }
        tx.execute(
            "DELETE FROM outbox WHERE client_message_id=?1",
            [id.as_slice()],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn retry_message(&self, id: [u8; 16]) -> Result<(), CoreError> {
        let db = self.db.lock().expect("database mutex poisoned");
        let attempts: u32 = db
            .query_row(
                "SELECT attempts FROM outbox WHERE client_message_id=?1",
                [id.as_slice()],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(CoreError::NotFound)?;
        let delay_ms = 1_000_i64.saturating_mul(1_i64 << attempts.min(10));
        db.execute("UPDATE outbox SET attempts=attempts+1,next_attempt_at_ms=?2 WHERE client_message_id=?1", params![id.as_slice(), now_ms() + delay_ms])?;
        db.execute(
            "UPDATE messages SET status=?2 WHERE client_message_id=?1",
            params![id.as_slice(), MessageStatus::RetryScheduled as i64],
        )?;
        Ok(())
    }

    pub fn cancel_pending_message(&self, id: [u8; 16]) -> Result<(), CoreError> {
        let mut db = self.db.lock().expect("database mutex poisoned");
        let tx = db.transaction()?;
        let changed = tx.execute(
            "UPDATE messages SET status=?2 WHERE client_message_id=?1 AND status IN (?3,?4,?5)",
            params![
                id.as_slice(),
                MessageStatus::Cancelled as i64,
                MessageStatus::Queued as i64,
                MessageStatus::ReadyToUpload as i64,
                MessageStatus::RetryScheduled as i64
            ],
        )?;
        if changed == 0 {
            return Err(CoreError::InvalidTransition);
        }
        tx.execute(
            "DELETE FROM outbox WHERE client_message_id=?1",
            [id.as_slice()],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn ingest_server_event(
        &self,
        event_id: [u8; 16],
        conversation_id: [u8; 16],
        encrypted_event: &[u8],
    ) -> Result<bool, CoreError> {
        let db = self.db.lock().expect("database mutex poisoned");
        let changed = db.execute(
            "INSERT OR IGNORE INTO inbox(event_id,conversation_id,event_ciphertext,received_at_ms) VALUES(?1,?2,?3,?4)",
            params![event_id.as_slice(), conversation_id.as_slice(), encrypted_event, now_ms()],
        )?;
        Ok(changed == 1)
    }

    pub fn ingest_server_batch(&self, events: &[IncomingEvent]) -> Result<usize, CoreError> {
        if events.len() > 50 {
            return Err(CoreError::InvalidTransition);
        }
        let mut db = self.db.lock().expect("database mutex poisoned");
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut inserted = 0;
        for event in events {
            inserted += tx.execute(
                "INSERT OR IGNORE INTO inbox(event_id,conversation_id,event_ciphertext,received_at_ms) VALUES(?1,?2,?3,?4)",
                params![event.event_id.as_slice(), event.conversation_id.as_slice(), &event.encrypted_event, now_ms()],
            )?;
        }
        tx.commit()?;
        Ok(inserted)
    }

    pub fn set_sync_cursor(&self, scope: [u8; 16], cursor: u64) -> Result<(), CoreError> {
        let db = self.db.lock().expect("database mutex poisoned");
        let current: Option<i64> = db
            .query_row(
                "SELECT cursor FROM sync_cursors WHERE scope=?1",
                [scope.as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        if current.is_some_and(|v| cursor < v as u64) {
            return Err(CoreError::InvalidTransition);
        }
        db.execute("INSERT INTO sync_cursors(scope,cursor) VALUES(?1,?2) ON CONFLICT(scope) DO UPDATE SET cursor=excluded.cursor", params![scope.as_slice(), cursor as i64])?;
        Ok(())
    }

    pub fn apply_delivery_receipt(&self, id: [u8; 16]) -> Result<(), CoreError> {
        self.advance_message_status(id, MessageStatus::Delivered)
    }
    pub fn apply_read_receipt(&self, id: [u8; 16]) -> Result<(), CoreError> {
        self.advance_message_status(id, MessageStatus::Read)
    }
    fn advance_message_status(&self, id: [u8; 16], status: MessageStatus) -> Result<(), CoreError> {
        let db = self.db.lock().expect("database mutex poisoned");
        let changed = db.execute(
            "UPDATE messages SET status=?2 WHERE client_message_id=?1 AND status<?2",
            params![id.as_slice(), status as i64],
        )?;
        if changed == 0 {
            let exists: bool = db.query_row(
                "SELECT EXISTS(SELECT 1 FROM messages WHERE client_message_id=?1)",
                [id.as_slice()],
                |row| row.get(0),
            )?;
            if !exists {
                return Err(CoreError::NotFound);
            }
        }
        Ok(())
    }

    pub fn block_account(&self, account_id: [u8; 32]) -> Result<(), CoreError> {
        self.db.lock().expect("database mutex poisoned").execute(
            "INSERT OR IGNORE INTO blocked_accounts(account_id,blocked_at_ms) VALUES(?1,?2)",
            params![account_id.as_slice(), now_ms()],
        )?;
        Ok(())
    }
    pub fn unblock_account(&self, account_id: [u8; 32]) -> Result<(), CoreError> {
        self.db.lock().expect("database mutex poisoned").execute(
            "DELETE FROM blocked_accounts WHERE account_id=?1",
            [account_id.as_slice()],
        )?;
        Ok(())
    }
    pub fn set_network_mode(&self, mode: NetworkMode) -> Result<(), CoreError> {
        self.db.lock().expect("database mutex poisoned").execute(
            "UPDATE network_state SET mode=?1 WHERE singleton=1",
            [match mode {
                NetworkMode::Normal => 0,
                NetworkMode::Limited => 1,
                NetworkMode::Survival => 2,
            }],
        )?;
        Ok(())
    }
    pub fn get_network_diagnostics(&self) -> Result<NetworkDiagnostics, CoreError> {
        let db = self.db.lock().expect("database mutex poisoned");
        let mode: i64 = db.query_row(
            "SELECT mode FROM network_state WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        let pending_uploads: i64 = db.query_row("SELECT count(*) FROM outbox", [], |r| r.get(0))?;
        let last_cursor: i64 = db.query_row(
            "SELECT COALESCE(MAX(cursor),0) FROM sync_cursors",
            [],
            |r| r.get(0),
        )?;
        Ok(NetworkDiagnostics {
            mode: match mode {
                0 => NetworkMode::Normal,
                1 => NetworkMode::Limited,
                2 => NetworkMode::Survival,
                _ => return Err(CoreError::Authentication),
            },
            pending_uploads: pending_uploads as u64,
            last_cursor: last_cursor as u64,
        })
    }

    pub fn cache_relay_directory(&self, directory: &CachedRelayDirectory) -> Result<(), CoreError> {
        let db = self.db.lock().expect("database mutex poisoned");
        let current: Option<i64> = db
            .query_row(
                "SELECT MAX(version) FROM relay_directory_cache",
                [],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        if current.is_some_and(|value| directory.version < value as u64) {
            return Err(CoreError::InvalidTransition);
        }
        db.execute(
            "INSERT INTO relay_directory_cache(version,signed_directory,expires_at_ms) VALUES(?1,?2,?3) ON CONFLICT(version) DO UPDATE SET signed_directory=excluded.signed_directory,expires_at_ms=excluded.expires_at_ms",
            params![directory.version as i64, &directory.signed_directory, directory.expires_at_ms],
        )?;
        Ok(())
    }

    pub fn last_relay_directory(&self) -> Result<Option<CachedRelayDirectory>, CoreError> {
        let db = self.db.lock().expect("database mutex poisoned");
        db.query_row(
            "SELECT version,signed_directory,expires_at_ms FROM relay_directory_cache ORDER BY version DESC LIMIT 1",
            [],
            |row| {
                Ok(CachedRelayDirectory {
                    version: row.get::<_, i64>(0)? as u64,
                    signed_directory: row.get(1)?,
                    expires_at_ms: row.get(2)?,
                })
            },
        )
        .optional()
        .map_err(CoreError::from)
    }

    pub fn local_search(&self, query: &str) -> Result<Vec<LocalMessage>, CoreError> {
        if query.is_empty() {
            return Ok(Vec::new());
        }
        let db = self.db.lock().expect("database mutex poisoned");
        let mut stmt = db.prepare("SELECT client_message_id,conversation_id,body_ciphertext,status,created_at_ms FROM messages ORDER BY created_at_ms DESC")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })?;
        let mut found = Vec::new();
        for row in rows {
            let (id, conversation, ciphertext, status, created_at_ms) = row?;
            let plaintext = String::from_utf8(decrypt(
                &self.master_key.read().expect("key lock poisoned"),
                &ciphertext,
            )?)
            .map_err(|_| CoreError::Authentication)?;
            if plaintext.to_lowercase().contains(&query.to_lowercase()) {
                found.push(LocalMessage {
                    client_message_id: fixed_id(&id)?,
                    conversation_id: fixed_id(&conversation)?,
                    plaintext,
                    status: status.try_into()?,
                    created_at_ms,
                });
            }
        }
        Ok(found)
    }

    pub fn rotate_master_key(&self, new_key: &[u8], new_version: u32) -> Result<(), CoreError> {
        let replacement: [u8; 32] = new_key
            .try_into()
            .map_err(|_| CoreError::InvalidMasterKey)?;
        let mut active = self.master_key.write().expect("key lock poisoned");
        let mut db = self.db.lock().expect("database mutex poisoned");
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: i64 = tx.query_row(
            "SELECT key_version FROM key_metadata WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        if new_version as i64 != current + 1 {
            return Err(CoreError::InvalidTransition);
        }
        let rows = {
            let mut stmt = tx.prepare("SELECT client_message_id,body_ciphertext FROM messages")?;
            stmt.query_map([], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?
        };
        for (id, ciphertext) in rows {
            let plaintext = decrypt(&active, &ciphertext)?;
            let reencrypted = encrypt(&replacement, &plaintext)?;
            tx.execute(
                "UPDATE messages SET body_ciphertext=?2 WHERE client_message_id=?1",
                params![id, reencrypted],
            )?;
        }
        tx.execute(
            "UPDATE key_metadata SET key_version=?1 WHERE singleton=1",
            [new_version as i64],
        )?;
        tx.commit()?;
        *active = Zeroizing::new(replacement);
        Ok(())
    }

    pub fn wipe_local_account(&self) -> Result<(), CoreError> {
        let db = self.db.lock().expect("database mutex poisoned");
        db.execute_batch("BEGIN; DELETE FROM outbox; DELETE FROM inbox; DELETE FROM messages; DELETE FROM conversation_members; DELETE FROM conversations; DELETE FROM sync_cursors; DELETE FROM receipts; DELETE FROM contact_requests; DELETE FROM blocked_accounts; DELETE FROM relay_directory_cache; DELETE FROM crypto_state; UPDATE change_counter SET revision=revision+1 WHERE singleton=1; COMMIT;")?;
        Ok(())
    }

    pub fn schema_version(&self) -> Result<i64, CoreError> {
        let db = self.db.lock().expect("database mutex poisoned");
        Ok(db.pragma_query_value(None, "user_version", |row| row.get(0))?)
    }
}

fn migrate(db: &Connection) -> Result<(), rusqlite::Error> {
    let version: i64 = db.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version > SCHEMA_VERSION {
        return Err(rusqlite::Error::InvalidQuery);
    }
    db.execute_batch(
        "BEGIN;
         CREATE TABLE IF NOT EXISTS conversations(conversation_id BLOB PRIMARY KEY CHECK(length(conversation_id)=16), updated_at_ms INTEGER NOT NULL);
         CREATE TABLE IF NOT EXISTS messages(client_message_id BLOB PRIMARY KEY CHECK(length(client_message_id)=16), conversation_id BLOB NOT NULL REFERENCES conversations(conversation_id), body_ciphertext BLOB NOT NULL, status INTEGER NOT NULL, created_at_ms INTEGER NOT NULL);
         CREATE INDEX IF NOT EXISTS messages_conversation_idx ON messages(conversation_id,created_at_ms);
         CREATE TABLE IF NOT EXISTS outbox(client_message_id BLOB PRIMARY KEY REFERENCES messages(client_message_id) ON DELETE CASCADE, next_attempt_at_ms INTEGER NOT NULL, attempts INTEGER NOT NULL CHECK(attempts>=0));
         CREATE INDEX IF NOT EXISTS outbox_due_idx ON outbox(next_attempt_at_ms);
         CREATE TABLE IF NOT EXISTS inbox(event_id BLOB PRIMARY KEY CHECK(length(event_id)=16), conversation_id BLOB NOT NULL, event_ciphertext BLOB NOT NULL, received_at_ms INTEGER NOT NULL);
         CREATE TABLE IF NOT EXISTS sync_cursors(scope BLOB PRIMARY KEY CHECK(length(scope)=16), cursor INTEGER NOT NULL CHECK(cursor>=0));
         CREATE TABLE IF NOT EXISTS account_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1), encrypted_blob BLOB NOT NULL);
         CREATE TABLE IF NOT EXISTS device_state(device_id BLOB PRIMARY KEY CHECK(length(device_id)=16), encrypted_blob BLOB NOT NULL);
         CREATE TABLE IF NOT EXISTS crypto_state(conversation_id BLOB PRIMARY KEY CHECK(length(conversation_id)=16), encrypted_snapshot BLOB NOT NULL, key_version INTEGER NOT NULL);
         CREATE TABLE IF NOT EXISTS receipts(event_id BLOB NOT NULL CHECK(length(event_id)=16), receipt_type INTEGER NOT NULL, received_at_ms INTEGER NOT NULL, PRIMARY KEY(event_id,receipt_type));
         CREATE TABLE IF NOT EXISTS contact_requests(event_id BLOB PRIMARY KEY CHECK(length(event_id)=16), encrypted_blob BLOB NOT NULL, status INTEGER NOT NULL);
         CREATE TABLE IF NOT EXISTS blocked_accounts(account_id BLOB PRIMARY KEY CHECK(length(account_id)=32), blocked_at_ms INTEGER NOT NULL);
         CREATE TABLE IF NOT EXISTS network_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1), mode INTEGER NOT NULL CHECK(mode BETWEEN 0 AND 2));
         INSERT OR IGNORE INTO network_state(singleton,mode) VALUES(1,0);
         CREATE TABLE IF NOT EXISTS key_metadata(singleton INTEGER PRIMARY KEY CHECK(singleton=1), key_version INTEGER NOT NULL CHECK(key_version>0));
         INSERT OR IGNORE INTO key_metadata(singleton,key_version) VALUES(1,1);
         CREATE TABLE IF NOT EXISTS relay_directory_cache(version INTEGER PRIMARY KEY CHECK(version>=0), signed_directory BLOB NOT NULL, expires_at_ms INTEGER NOT NULL);
         CREATE TABLE IF NOT EXISTS tombstones(object_id BLOB PRIMARY KEY, object_kind INTEGER NOT NULL, expires_at_ms INTEGER NOT NULL);
         CREATE TABLE IF NOT EXISTS conversation_members(conversation_id BLOB NOT NULL REFERENCES conversations(conversation_id) ON DELETE CASCADE,device_id BLOB NOT NULL CHECK(length(device_id)=16),account_id BLOB NOT NULL CHECK(length(account_id)=32),removed_at_ms INTEGER,PRIMARY KEY(conversation_id,device_id));
         CREATE TABLE IF NOT EXISTS change_counter(singleton INTEGER PRIMARY KEY CHECK(singleton=1),revision INTEGER NOT NULL CHECK(revision>=0));
         INSERT OR IGNORE INTO change_counter(singleton,revision) VALUES(1,0);
         CREATE TRIGGER IF NOT EXISTS messages_change_insert AFTER INSERT ON messages BEGIN UPDATE change_counter SET revision=revision+1 WHERE singleton=1; END;
         CREATE TRIGGER IF NOT EXISTS messages_change_update AFTER UPDATE ON messages BEGIN UPDATE change_counter SET revision=revision+1 WHERE singleton=1; END;
         CREATE TRIGGER IF NOT EXISTS inbox_change_insert AFTER INSERT ON inbox BEGIN UPDATE change_counter SET revision=revision+1 WHERE singleton=1; END;
         CREATE TRIGGER IF NOT EXISTS conversations_change_insert AFTER INSERT ON conversations BEGIN UPDATE change_counter SET revision=revision+1 WHERE singleton=1; END;
         CREATE TRIGGER IF NOT EXISTS members_change_insert AFTER INSERT ON conversation_members BEGIN UPDATE change_counter SET revision=revision+1 WHERE singleton=1; END;
         CREATE TRIGGER IF NOT EXISTS members_change_update AFTER UPDATE ON conversation_members BEGIN UPDATE change_counter SET revision=revision+1 WHERE singleton=1; END;
         PRAGMA user_version=2;
         COMMIT;",
    )?;
    let version: i64 = db.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version != SCHEMA_VERSION {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(())
}

fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, CoreError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| CoreError::Authentication)?;
    let mut nonce = [0_u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let mut out = nonce.to_vec();
    out.extend(
        cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: MESSAGE_AAD,
                },
            )
            .map_err(|_| CoreError::Authentication)?,
    );
    Ok(out)
}

fn decrypt(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, CoreError> {
    if blob.len() < 40 {
        return Err(CoreError::Authentication);
    }
    XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CoreError::Authentication)?
        .decrypt(
            XNonce::from_slice(&blob[..24]),
            Payload {
                msg: &blob[24..],
                aad: MESSAGE_AAD,
            },
        )
        .map_err(|_| CoreError::Authentication)
}

fn random_id() -> [u8; 16] {
    let mut id = [0; 16];
    OsRng.fill_bytes(&mut id);
    id
}
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}
fn fixed_id(value: &[u8]) -> Result<[u8; 16], CoreError> {
    value.try_into().map_err(|_| CoreError::Authentication)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_is_durable_before_network_and_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("messages.sqlite");
        let key = [7_u8; 32];
        let conversation = [3_u8; 16];
        let id = MessengerCore::open(&path, &key)
            .unwrap()
            .create_message(conversation, "Я дома")
            .unwrap();
        let reopened = MessengerCore::open(&path, &key).unwrap();
        assert_eq!(
            reopened.get_pending_uploads(50).unwrap()[0].client_message_id,
            id
        );
        assert_eq!(
            reopened.list_messages(conversation).unwrap()[0].plaintext,
            "Я дома"
        );
    }

    #[test]
    fn database_never_contains_plaintext_and_wrong_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("messages.sqlite");
        let core = MessengerCore::open(&path, &[1; 32]).unwrap();
        core.create_message([2; 16], "unique-private-needle")
            .unwrap();
        drop(core);
        assert!(
            !std::fs::read(&path)
                .unwrap()
                .windows(21)
                .any(|w| w == b"unique-private-needle")
        );
        let wrong = MessengerCore::open(&path, &[9; 32]).unwrap();
        assert!(matches!(
            wrong.list_messages([2; 16]),
            Err(CoreError::Authentication)
        ));
    }

    #[test]
    fn incoming_and_acceptance_are_idempotent_and_cursors_monotonic() {
        let core = MessengerCore::open_in_memory(&[4; 32]).unwrap();
        let id = core.create_message([5; 16], "OK").unwrap();
        core.mark_upload_accepted(id).unwrap();
        core.mark_upload_accepted(id).unwrap();
        assert!(
            core.ingest_server_event([6; 16], [5; 16], b"ciphertext")
                .unwrap()
        );
        assert!(
            !core
                .ingest_server_event([6; 16], [5; 16], b"ciphertext")
                .unwrap()
        );
        core.set_sync_cursor([5; 16], 42).unwrap();
        assert!(matches!(
            core.set_sync_cursor([5; 16], 41),
            Err(CoreError::InvalidTransition)
        ));
    }

    #[test]
    fn migration_and_cancel_are_safe() {
        let core = MessengerCore::open_in_memory(&[8; 32]).unwrap();
        assert_eq!(core.schema_version().unwrap(), SCHEMA_VERSION);
        let id = core.create_message([1; 16], "cancel me").unwrap();
        core.cancel_pending_message(id).unwrap();
        assert!(core.get_pending_uploads(50).unwrap().is_empty());
    }
    #[test]
    fn locked_database_and_write_failure_do_not_report_send_success() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("locked.sqlite");
        let core = MessengerCore::open(&path, &[7; 32]).unwrap();
        core.db
            .lock()
            .unwrap()
            .busy_timeout(std::time::Duration::from_millis(20))
            .unwrap();
        let locker = Connection::open(&path).unwrap();
        locker.execute_batch("BEGIN IMMEDIATE;").unwrap();
        assert!(matches!(
            core.create_message([2; 16], "must not be acknowledged"),
            Err(CoreError::Database(_))
        ));
        locker.execute_batch("ROLLBACK;").unwrap();
        assert!(core.get_pending_uploads(50).unwrap().is_empty());

        core.db
            .lock()
            .unwrap()
            .pragma_update(None, "query_only", true)
            .unwrap();
        assert!(matches!(
            core.create_message([2; 16], "disk write failure"),
            Err(CoreError::Database(_))
        ));
        assert!(core.get_pending_uploads(50).unwrap().is_empty());
    }
    #[test]
    fn v1_database_migrates_forward_and_group_state_is_observable() {
        let database = Connection::open_in_memory().unwrap();
        database.pragma_update(None, "user_version", 1).unwrap();
        migrate(&database).unwrap();
        assert_eq!(
            database
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            SCHEMA_VERSION
        );

        let core = MessengerCore::open_in_memory(&[5; 32]).unwrap();
        let revision = core.observe_conversation_changes(0).unwrap();
        core.create_group([20; 16]).unwrap();
        core.add_member([20; 16], [21; 16], [22; 32]).unwrap();
        assert!(core.observe_conversation_changes(revision).unwrap() > revision);
        assert_eq!(core.list_conversations().unwrap().len(), 1);
        core.remove_member([20; 16], [21; 16]).unwrap();
    }
    #[test]
    fn server_batches_and_relay_cache_are_idempotent_and_monotonic() {
        let core = MessengerCore::open_in_memory(&[6; 32]).unwrap();
        let events = vec![
            IncomingEvent {
                event_id: [1; 16],
                conversation_id: [2; 16],
                encrypted_event: vec![3; 32],
            },
            IncomingEvent {
                event_id: [4; 16],
                conversation_id: [2; 16],
                encrypted_event: vec![5; 32],
            },
        ];
        assert_eq!(core.ingest_server_batch(&events).unwrap(), 2);
        assert_eq!(core.ingest_server_batch(&events).unwrap(), 0);
        core.cache_relay_directory(&CachedRelayDirectory {
            version: 7,
            signed_directory: vec![8; 128],
            expires_at_ms: now_ms() + 60_000,
        })
        .unwrap();
        assert_eq!(core.last_relay_directory().unwrap().unwrap().version, 7);
        assert!(matches!(
            core.cache_relay_directory(&CachedRelayDirectory {
                version: 6,
                signed_directory: vec![9; 128],
                expires_at_ms: now_ms() + 60_000,
            }),
            Err(CoreError::InvalidTransition)
        ));
    }
    #[test]
    fn key_rotation_reencrypts_rows_and_corruption_is_detected() {
        let core = MessengerCore::open_in_memory(&[1; 32]).unwrap();
        let conversation = [8; 16];
        let id = core.create_message(conversation, "rotate safely").unwrap();
        core.rotate_master_key(&[2; 32], 2).unwrap();
        assert_eq!(
            core.list_messages(conversation).unwrap()[0].plaintext,
            "rotate safely"
        );
        core.db
            .lock()
            .unwrap()
            .execute(
                "UPDATE messages SET body_ciphertext=X'00' WHERE client_message_id=?1",
                [id.as_slice()],
            )
            .unwrap();
        assert!(matches!(
            core.list_messages(conversation),
            Err(CoreError::Authentication)
        ));
    }
    #[test]
    fn ten_thousand_messages_and_concurrent_access() {
        use std::sync::Arc;
        let core = Arc::new(MessengerCore::open_in_memory(&[3; 32]).unwrap());
        let conversation = [9; 16];
        for index in 0..10_000 {
            core.create_message(conversation, &format!("offline message {index}"))
                .unwrap();
        }
        assert_eq!(core.list_messages(conversation).unwrap().len(), 10_000);
        let threads = (0..4)
            .map(|worker| {
                let core = Arc::clone(&core);
                std::thread::spawn(move || {
                    for index in 0..25 {
                        core.create_message([worker; 16], &format!("concurrent {index}"))
                            .unwrap();
                    }
                })
            })
            .collect::<Vec<_>>();
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(
            core.get_network_diagnostics().unwrap().pending_uploads,
            10_100
        );
    }
}
