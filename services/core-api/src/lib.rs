#![forbid(unsafe_code)]
//! PostgreSQL-backed ciphertext delivery and device-bound authentication.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use messenger_identity::{
    DeviceCertificate, account_id_from_root_public, auth_challenge_payload, canonical_username,
    refresh_proof_payload, verify_device_certificate,
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use thiserror::Error;

pub const ACCESS_TTL_SECONDS: i64 = 15 * 60;
pub const REFRESH_TTL_SECONDS: i64 = 30 * 24 * 60 * 60;
pub const CHALLENGE_TTL_SECONDS: i64 = 120;
pub const EVENT_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;
pub const MAX_SYNC_BATCH: i64 = 50;
pub const MAX_KEY_PACKAGE_SIZE: usize = 64 * 1024;
pub const MAX_RECOVERY_BLOB_SIZE: usize = 256 * 1024;
pub const EVENT_KIND_MLS_COMMIT: i16 = 2;
pub const EVENT_NOTIFY_CHANNEL: &str = "device_events";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ApiError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("request expired")]
    Expired,
    #[error("request was already consumed")]
    Replay,
    #[error("refresh token reuse detected")]
    TokenReuse,
    #[error("resource already exists")]
    Conflict,
    #[error("request is not authorized")]
    Unauthorized,
    #[error("cursor cannot move backwards")]
    CursorRegression,
    #[error("input is invalid")]
    InvalidInput,
    #[error("database operation failed")]
    Database,
}

impl From<sqlx::Error> for ApiError {
    fn from(_: sqlx::Error) -> Self {
        Self::Database
    }
}

#[derive(Clone)]
pub struct Backend {
    pool: PgPool,
}

#[derive(Clone, Debug)]
pub struct Challenge {
    pub challenge_id: [u8; 16],
    pub challenge: [u8; 32],
}
#[derive(Clone, Debug)]
pub struct SessionTokens {
    pub access_token: [u8; 32],
    pub refresh_token: [u8; 32],
}
#[derive(Clone, Debug)]
pub struct UploadedEvent {
    pub event_id: [u8; 16],
    pub group_id: [u8; 16],
    pub author_device_id: [u8; 16],
    pub client_message_id: [u8; 16],
    pub event_kind: i16,
    pub ciphertext: Vec<u8>,
    pub correlation_id: Option<[u8; 16]>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadAccepted {
    pub cursor: i64,
    pub duplicate: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncEvent {
    pub cursor: i64,
    pub event_id: [u8; 16],
    pub event_kind: i16,
    pub ciphertext: Vec<u8>,
}
#[derive(Clone, Debug)]
pub struct MembershipOperation {
    pub correlation_id: [u8; 16],
    pub group_id: [u8; 16],
    pub author_device_id: [u8; 16],
    pub target_device_id: [u8; 16],
    pub role: i16,
    pub remove: bool,
    pub signature: [u8; 64],
}

type ChallengeRow = (Vec<u8>, Vec<u8>, Vec<u8>, bool, bool);
type RefreshRow = (Vec<u8>, Vec<u8>, bool, bool, bool);

impl Backend {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
    pub async fn migrate(&self) -> Result<(), ApiError> {
        const VERSION: i64 = 1;
        const MIGRATION: &str = include_str!("../migrations/0001_foundation.sql");
        let checksum = Sha256::digest(MIGRATION.as_bytes());
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(7319451201)")
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS resilient_schema_migrations(version BIGINT PRIMARY KEY, checksum BYTEA NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())",
        )
        .execute(&mut *tx)
        .await?;
        let applied: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT checksum FROM resilient_schema_migrations WHERE version=$1")
                .bind(VERSION)
                .fetch_optional(&mut *tx)
                .await?;
        match applied {
            Some(applied) if applied == checksum.as_slice() => {}
            Some(_) => return Err(ApiError::Conflict),
            None => {
                sqlx::raw_sql(MIGRATION).execute(&mut *tx).await?;
                sqlx::query(
                    "INSERT INTO resilient_schema_migrations(version,checksum) VALUES($1,$2)",
                )
                .bind(VERSION)
                .bind(checksum.as_slice())
                .execute(&mut *tx)
                .await?;
            }
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn authenticate_access(&self, access_token: [u8; 32]) -> Result<[u8; 16], ApiError> {
        let hash = token_hash(b"access", &access_token);
        let device: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT a.device_id FROM access_sessions a JOIN devices d USING(device_id) WHERE a.token_hash=$1 AND a.expires_at>now() AND d.revoked_at IS NULL",
        )
        .bind(hash.as_slice())
        .fetch_optional(&self.pool)
        .await?;
        device
            .ok_or(ApiError::InvalidCredentials)?
            .try_into()
            .map_err(|_| ApiError::Database)
    }

    pub async fn device_account_id(&self, device_id: [u8; 16]) -> Result<[u8; 32], ApiError> {
        let account_id: Vec<u8> = sqlx::query_scalar(
            "SELECT account_id FROM devices WHERE device_id=$1 AND revoked_at IS NULL",
        )
        .bind(device_id.as_slice())
        .fetch_optional(&self.pool)
        .await?
        .ok_or(ApiError::Unauthorized)?;
        account_id.try_into().map_err(|_| ApiError::Database)
    }

    pub async fn check_rate_limit(
        &self,
        scope: &[u8],
        maximum: i32,
        window_seconds: i64,
    ) -> Result<(), ApiError> {
        if scope.is_empty() || scope.len() > 96 || maximum < 1 || window_seconds < 1 {
            return Err(ApiError::InvalidInput);
        }
        let count: i32 = sqlx::query_scalar(
            "INSERT INTO abuse_counters(scope,window_start,count) VALUES($1,now(),1) ON CONFLICT(scope) DO UPDATE SET window_start=CASE WHEN abuse_counters.window_start<=now()-make_interval(secs=>$3) THEN now() ELSE abuse_counters.window_start END,count=CASE WHEN abuse_counters.window_start<=now()-make_interval(secs=>$3) THEN 1 ELSE abuse_counters.count+1 END RETURNING count",
        )
        .bind(scope)
        .bind(maximum)
        .bind(window_seconds as f64)
        .fetch_one(&self.pool)
        .await?;
        if count > maximum {
            Err(ApiError::Unauthorized)
        } else {
            Ok(())
        }
    }

    pub async fn register_account_device(
        &self,
        account_id: [u8; 32],
        root_public_key: [u8; 32],
        cert: &DeviceCertificate,
    ) -> Result<(), ApiError> {
        if account_id_from_root_public(&root_public_key) != account_id
            || !verify_device_certificate(&root_public_key, cert)
        {
            return Err(ApiError::InvalidCredentials);
        }
        let mut tx = self.pool.begin().await?;
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM devices WHERE device_id=$1)")
                .bind(cert.device_id.as_slice())
                .fetch_one(&mut *tx)
                .await?;
        if exists {
            return Err(ApiError::Replay);
        }
        sqlx::query("INSERT INTO accounts(account_id,root_public_key) VALUES($1,$2) ON CONFLICT(account_id) DO NOTHING")
            .bind(account_id.as_slice()).bind(root_public_key.as_slice()).execute(&mut *tx).await?;
        let valid: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM accounts WHERE account_id=$1 AND root_public_key=$2)",
        )
        .bind(account_id.as_slice())
        .bind(root_public_key.as_slice())
        .fetch_one(&mut *tx)
        .await?;
        if !valid {
            return Err(ApiError::Conflict);
        }
        sqlx::query("INSERT INTO devices(device_id,account_id,device_public_key) VALUES($1,$2,$3)")
            .bind(cert.device_id.as_slice())
            .bind(account_id.as_slice())
            .bind(cert.device_public_key.as_slice())
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO device_certificates(device_id,certificate_signature,issued_at) VALUES($1,$2,$3)")
            .bind(cert.device_id.as_slice()).bind(cert.signature.as_slice()).bind(cert.issued_at as i64).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn begin_challenge(&self, device_id: [u8; 16]) -> Result<Challenge, ApiError> {
        let active: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM devices WHERE device_id=$1 AND revoked_at IS NULL)",
        )
        .bind(device_id.as_slice())
        .fetch_one(&self.pool)
        .await?;
        if !active {
            return Err(ApiError::InvalidCredentials);
        }
        let challenge_id = random();
        let challenge = random();
        sqlx::query("INSERT INTO auth_challenges(challenge_id,device_id,challenge,expires_at) VALUES($1,$2,$3,now()+make_interval(secs=>$4))")
            .bind(challenge_id.as_slice()).bind(device_id.as_slice()).bind(challenge.as_slice()).bind(CHALLENGE_TTL_SECONDS as f64).execute(&self.pool).await?;
        Ok(Challenge {
            challenge_id,
            challenge,
        })
    }

    pub async fn complete_challenge(
        &self,
        challenge_id: [u8; 16],
        signature: [u8; 64],
    ) -> Result<SessionTokens, ApiError> {
        let mut tx = self.pool.begin().await?;
        let row: Option<ChallengeRow> = sqlx::query_as(
            "SELECT c.device_id,c.challenge,d.device_public_key,c.expires_at<=now(),c.consumed_at IS NOT NULL FROM auth_challenges c JOIN devices d USING(device_id) WHERE challenge_id=$1 FOR UPDATE"
        ).bind(challenge_id.as_slice()).fetch_optional(&mut *tx).await?;
        let (device_id, challenge, public, expired, consumed) =
            row.ok_or(ApiError::InvalidCredentials)?;
        if consumed {
            return Err(ApiError::Replay);
        }
        if expired {
            return Err(ApiError::Expired);
        }
        let public: [u8; 32] = public
            .try_into()
            .map_err(|_| ApiError::InvalidCredentials)?;
        let challenge: [u8; 32] = challenge
            .try_into()
            .map_err(|_| ApiError::InvalidCredentials)?;
        VerifyingKey::from_bytes(&public)
            .map_err(|_| ApiError::InvalidCredentials)?
            .verify(
                &auth_challenge_payload(&challenge_id, &challenge),
                &Signature::from_bytes(&signature),
            )
            .map_err(|_| ApiError::InvalidCredentials)?;
        sqlx::query("UPDATE auth_challenges SET consumed_at=now() WHERE challenge_id=$1")
            .bind(challenge_id.as_slice())
            .execute(&mut *tx)
            .await?;
        let tokens = issue_tokens(&mut tx, &device_id, None).await?;
        tx.commit().await?;
        Ok(tokens)
    }

    pub async fn rotate_refresh(
        &self,
        device_id: [u8; 16],
        refresh_token: [u8; 32],
        device_signature: [u8; 64],
    ) -> Result<SessionTokens, ApiError> {
        let hash = token_hash(b"refresh", &refresh_token);
        let mut tx = self.pool.begin().await?;
        let row: Option<RefreshRow> = sqlx::query_as(
            "SELECT r.family_id,d.device_public_key,r.used_at IS NOT NULL,r.revoked_at IS NOT NULL,r.expires_at<=now() FROM refresh_sessions r JOIN devices d USING(device_id) WHERE r.token_hash=$1 AND r.device_id=$2 FOR UPDATE"
        ).bind(hash.as_slice()).bind(device_id.as_slice()).fetch_optional(&mut *tx).await?;
        let (family, public, used, revoked, expired) = row.ok_or(ApiError::InvalidCredentials)?;
        if used || revoked {
            sqlx::query("UPDATE refresh_sessions SET revoked_at=COALESCE(revoked_at,now()) WHERE family_id=$1").bind(&family).execute(&mut *tx).await?;
            tx.commit().await?;
            return Err(ApiError::TokenReuse);
        }
        if expired {
            return Err(ApiError::Expired);
        }
        let public: [u8; 32] = public
            .try_into()
            .map_err(|_| ApiError::InvalidCredentials)?;
        VerifyingKey::from_bytes(&public)
            .map_err(|_| ApiError::InvalidCredentials)?
            .verify(
                &refresh_proof_payload(&refresh_token),
                &Signature::from_bytes(&device_signature),
            )
            .map_err(|_| ApiError::InvalidCredentials)?;
        let tokens = issue_tokens(&mut tx, &device_id, Some(&family)).await?;
        let new_hash = token_hash(b"refresh", &tokens.refresh_token);
        sqlx::query(
            "UPDATE refresh_sessions SET used_at=now(),replaced_by_hash=$2 WHERE token_hash=$1",
        )
        .bind(hash.as_slice())
        .bind(new_hash.as_slice())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(tokens)
    }

    pub async fn claim_username(
        &self,
        account_id: [u8; 32],
        requested: &str,
    ) -> Result<String, ApiError> {
        let canonical = canonical_username(requested).map_err(|_| ApiError::InvalidInput)?;
        if matches!(
            canonical.as_str(),
            "admin" | "support" | "security" | "resilient" | "system"
        ) {
            return Err(ApiError::InvalidInput);
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM usernames WHERE canonical_username=$1 AND released_at IS NOT NULL AND NOT EXISTS(SELECT 1 FROM username_cooldowns WHERE canonical_username=$1 AND release_after>now())")
            .bind(&canonical).execute(&mut *tx).await?;
        let changed = sqlx::query("INSERT INTO usernames(canonical_username,account_id) VALUES($1,$2) ON CONFLICT DO NOTHING")
            .bind(&canonical).bind(account_id.as_slice()).execute(&mut *tx).await?.rows_affected();
        if changed != 1 {
            return Err(ApiError::Conflict);
        }
        tx.commit().await?;
        Ok(canonical)
    }

    pub async fn change_username(
        &self,
        account_id: [u8; 32],
        requested: &str,
    ) -> Result<String, ApiError> {
        let next = canonical_username(requested).map_err(|_| ApiError::InvalidInput)?;
        if matches!(
            next.as_str(),
            "admin" | "support" | "security" | "resilient" | "system"
        ) {
            return Err(ApiError::InvalidInput);
        }
        let mut tx = self.pool.begin().await?;
        let current: Option<String> = sqlx::query_scalar("SELECT canonical_username FROM usernames WHERE account_id=$1 AND released_at IS NULL FOR UPDATE")
            .bind(account_id.as_slice()).fetch_optional(&mut *tx).await?;
        if current.as_deref() == Some(next.as_str()) {
            return Ok(next);
        }
        let available: bool = sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM usernames WHERE canonical_username=$1 AND (released_at IS NULL OR EXISTS(SELECT 1 FROM username_cooldowns WHERE canonical_username=$1 AND release_after>now())))")
            .bind(&next).fetch_one(&mut *tx).await?;
        if !available {
            return Err(ApiError::Conflict);
        }
        sqlx::query(
            "DELETE FROM usernames WHERE canonical_username=$1 AND released_at IS NOT NULL",
        )
        .bind(&next)
        .execute(&mut *tx)
        .await?;
        if let Some(old) = current {
            sqlx::query("UPDATE usernames SET released_at=now() WHERE canonical_username=$1")
                .bind(&old)
                .execute(&mut *tx)
                .await?;
            sqlx::query("INSERT INTO username_cooldowns(canonical_username,previous_account_id,release_after) VALUES($1,$2,now()+interval '30 days') ON CONFLICT(canonical_username) DO UPDATE SET previous_account_id=EXCLUDED.previous_account_id,release_after=EXCLUDED.release_after")
                .bind(&old).bind(account_id.as_slice()).execute(&mut *tx).await?;
        }
        sqlx::query("INSERT INTO usernames(canonical_username,account_id) VALUES($1,$2)")
            .bind(&next)
            .bind(account_id.as_slice())
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(next)
    }

    pub async fn release_username(&self, account_id: [u8; 32]) -> Result<(), ApiError> {
        let mut tx = self.pool.begin().await?;
        let current: String = sqlx::query_scalar("SELECT canonical_username FROM usernames WHERE account_id=$1 AND released_at IS NULL FOR UPDATE")
            .bind(account_id.as_slice()).fetch_optional(&mut *tx).await?.ok_or(ApiError::InvalidInput)?;
        sqlx::query("UPDATE usernames SET released_at=now() WHERE canonical_username=$1")
            .bind(&current)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO username_cooldowns(canonical_username,previous_account_id,release_after) VALUES($1,$2,now()+interval '30 days') ON CONFLICT(canonical_username) DO UPDATE SET previous_account_id=EXCLUDED.previous_account_id,release_after=EXCLUDED.release_after")
            .bind(&current).bind(account_id.as_slice()).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn exact_username_lookup(
        &self,
        requested: &str,
    ) -> Result<Option<[u8; 32]>, ApiError> {
        let canonical = canonical_username(requested).map_err(|_| ApiError::InvalidInput)?;
        let value: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT account_id FROM usernames WHERE canonical_username=$1 AND released_at IS NULL",
        )
        .bind(canonical)
        .fetch_optional(&self.pool)
        .await?;
        value
            .map(|bytes| bytes.try_into().map_err(|_| ApiError::Database))
            .transpose()
    }

    pub async fn store_recovery_package(
        &self,
        account_id: [u8; 32],
        recovery_identifier: [u8; 32],
        encrypted_blob: &[u8],
    ) -> Result<(), ApiError> {
        if encrypted_blob.is_empty() || encrypted_blob.len() > MAX_RECOVERY_BLOB_SIZE {
            return Err(ApiError::InvalidInput);
        }
        let changed = sqlx::query(
            "UPDATE accounts SET recovery_identifier=$2,recovery_blob=$3 WHERE account_id=$1 AND (recovery_identifier IS NULL OR recovery_identifier=$2)",
        )
        .bind(account_id.as_slice())
        .bind(recovery_identifier.as_slice())
        .bind(encrypted_blob)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if changed == 1 {
            Ok(())
        } else {
            Err(ApiError::Conflict)
        }
    }

    pub async fn fetch_recovery_package(
        &self,
        recovery_identifier: [u8; 32],
    ) -> Result<Option<Vec<u8>>, ApiError> {
        sqlx::query_scalar(
            "SELECT recovery_blob FROM accounts WHERE recovery_identifier=$1 AND recovery_blob IS NOT NULL",
        )
        .bind(recovery_identifier.as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(ApiError::from)
    }

    pub async fn publish_key_package(
        &self,
        device_id: [u8; 16],
        package_id: [u8; 16],
        package: &[u8],
    ) -> Result<(), ApiError> {
        if package.is_empty() || package.len() > MAX_KEY_PACKAGE_SIZE {
            return Err(ApiError::InvalidInput);
        }
        let changed = sqlx::query(
            "INSERT INTO key_packages(package_id,device_id,package) SELECT $1,$2,$3 WHERE EXISTS(SELECT 1 FROM devices WHERE device_id=$2 AND revoked_at IS NULL) ON CONFLICT(package_id) DO NOTHING",
        )
        .bind(package_id.as_slice())
        .bind(device_id.as_slice())
        .bind(package)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if changed == 1 {
            Ok(())
        } else {
            Err(ApiError::Conflict)
        }
    }

    pub async fn fetch_key_package(
        &self,
        target_device_id: [u8; 16],
    ) -> Result<Option<([u8; 16], Vec<u8>)>, ApiError> {
        let mut tx = self.pool.begin().await?;
        let row: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT package_id,package FROM key_packages WHERE device_id=$1 AND consumed_at IS NULL ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1",
        )
        .bind(target_device_id.as_slice())
        .fetch_optional(&mut *tx)
        .await?;
        let Some((id, package)) = row else {
            tx.commit().await?;
            return Ok(None);
        };
        sqlx::query("UPDATE key_packages SET consumed_at=now() WHERE package_id=$1")
            .bind(&id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Some((
            id.try_into().map_err(|_| ApiError::Database)?,
            package,
        )))
    }

    pub async fn create_group(
        &self,
        group_id: [u8; 16],
        creator_device: [u8; 16],
        account_id: [u8; 32],
    ) -> Result<(), ApiError> {
        let mut tx = self.pool.begin().await?;
        let owns_device: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM devices WHERE device_id=$1 AND account_id=$2 AND revoked_at IS NULL)",
        )
        .bind(creator_device.as_slice())
        .bind(account_id.as_slice())
        .fetch_one(&mut *tx)
        .await?;
        if !owns_device {
            return Err(ApiError::Unauthorized);
        }
        sqlx::query("INSERT INTO groups(group_id,created_by_device_id) VALUES($1,$2)")
            .bind(group_id.as_slice())
            .bind(creator_device.as_slice())
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO group_members(group_id,device_id,account_id,role) VALUES($1,$2,$3,2)",
        )
        .bind(group_id.as_slice())
        .bind(creator_device.as_slice())
        .bind(account_id.as_slice())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn add_group_member(
        &self,
        group_id: [u8; 16],
        device_id: [u8; 16],
        account_id: [u8; 32],
        role: i16,
    ) -> Result<(), ApiError> {
        sqlx::query(
            "INSERT INTO group_members(group_id,device_id,account_id,role) VALUES($1,$2,$3,$4)",
        )
        .bind(group_id.as_slice())
        .bind(device_id.as_slice())
        .bind(account_id.as_slice())
        .bind(role)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn apply_membership_operation(
        &self,
        request: &MembershipOperation,
    ) -> Result<bool, ApiError> {
        if !(0..=2).contains(&request.role) {
            return Err(ApiError::InvalidInput);
        }
        let operation = membership_operation_payload(
            &request.correlation_id,
            &request.group_id,
            &request.author_device_id,
            &request.target_device_id,
            request.role,
            request.remove,
        );
        let mut tx = self.pool.begin().await?;
        let author: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT d.device_public_key FROM group_members m JOIN devices d USING(device_id) WHERE m.group_id=$1 AND m.device_id=$2 AND m.role=2 AND m.removed_at IS NULL FOR UPDATE",
        )
        .bind(request.group_id.as_slice())
        .bind(request.author_device_id.as_slice())
        .fetch_optional(&mut *tx)
        .await?;
        let public: [u8; 32] = author
            .ok_or(ApiError::Unauthorized)?
            .try_into()
            .map_err(|_| ApiError::Database)?;
        VerifyingKey::from_bytes(&public)
            .map_err(|_| ApiError::InvalidCredentials)?
            .verify(&operation, &Signature::from_bytes(&request.signature))
            .map_err(|_| ApiError::InvalidCredentials)?;

        if let Some((stored_operation, stored_signature)) = sqlx::query_as::<_, (Vec<u8>, Vec<u8>)>(
            "SELECT operation,signature FROM membership_operations WHERE correlation_id=$1",
        )
        .bind(request.correlation_id.as_slice())
        .fetch_optional(&mut *tx)
        .await?
        {
            if stored_operation == operation && stored_signature == request.signature {
                tx.commit().await?;
                return Ok(true);
            }
            return Err(ApiError::Conflict);
        }
        sqlx::query("INSERT INTO membership_operations(correlation_id,group_id,author_device_id,operation,signature) VALUES($1,$2,$3,$4,$5)")
            .bind(request.correlation_id.as_slice()).bind(request.group_id.as_slice()).bind(request.author_device_id.as_slice()).bind(&operation).bind(request.signature.as_slice()).execute(&mut *tx).await?;
        if request.remove {
            let changed = sqlx::query("UPDATE group_members SET removed_at=now() WHERE group_id=$1 AND device_id=$2 AND removed_at IS NULL")
                .bind(request.group_id.as_slice()).bind(request.target_device_id.as_slice()).execute(&mut *tx).await?.rows_affected();
            if changed != 1 {
                return Err(ApiError::InvalidInput);
            }
        } else {
            let account: Vec<u8> = sqlx::query_scalar(
                "SELECT account_id FROM devices WHERE device_id=$1 AND revoked_at IS NULL",
            )
            .bind(request.target_device_id.as_slice())
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(ApiError::InvalidInput)?;
            sqlx::query("INSERT INTO group_members(group_id,device_id,account_id,role,removed_at) VALUES($1,$2,$3,$4,NULL) ON CONFLICT(group_id,device_id) DO UPDATE SET account_id=EXCLUDED.account_id,role=EXCLUDED.role,removed_at=NULL")
                .bind(request.group_id.as_slice()).bind(request.target_device_id.as_slice()).bind(account).bind(request.role).execute(&mut *tx).await?;
        }
        sqlx::query("UPDATE membership_operations SET applied_at=now() WHERE correlation_id=$1")
            .bind(request.correlation_id.as_slice())
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(false)
    }

    pub async fn upload_welcome(
        &self,
        author_device_id: [u8; 16],
        target_device_id: [u8; 16],
        group_id: [u8; 16],
        welcome_id: [u8; 16],
        welcome: &[u8],
    ) -> Result<(), ApiError> {
        if welcome.is_empty() || welcome.len() > 65_536 {
            return Err(ApiError::InvalidInput);
        }
        let mut tx = self.pool.begin().await?;
        assert_active_member(&mut tx, &group_id, &author_device_id).await?;
        let target_known: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM group_members WHERE group_id=$1 AND device_id=$2)",
        )
        .bind(group_id.as_slice())
        .bind(target_device_id.as_slice())
        .fetch_one(&mut *tx)
        .await?;
        if !target_known {
            return Err(ApiError::Unauthorized);
        }
        sqlx::query("INSERT INTO welcome_mailbox(welcome_id,target_device_id,group_id,welcome,expires_at) VALUES($1,$2,$3,$4,now()+make_interval(secs=>$5)) ON CONFLICT(welcome_id) DO NOTHING")
            .bind(welcome_id.as_slice()).bind(target_device_id.as_slice()).bind(group_id.as_slice()).bind(welcome).bind(EVENT_TTL_SECONDS as f64).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn fetch_welcomes(
        &self,
        target_device_id: [u8; 16],
        limit: i64,
    ) -> Result<Vec<([u8; 16], [u8; 16], Vec<u8>)>, ApiError> {
        let mut tx = self.pool.begin().await?;
        let rows = sqlx::query_as::<_, (Vec<u8>, Vec<u8>, Vec<u8>)>(
            "SELECT welcome_id,group_id,welcome FROM welcome_mailbox WHERE target_device_id=$1 AND consumed_at IS NULL AND expires_at>now() ORDER BY expires_at LIMIT $2 FOR UPDATE SKIP LOCKED",
        )
        .bind(target_device_id.as_slice())
        .bind(limit.clamp(1, MAX_SYNC_BATCH))
        .fetch_all(&mut *tx)
        .await?;
        for (id, _, _) in &rows {
            sqlx::query("UPDATE welcome_mailbox SET consumed_at=now() WHERE welcome_id=$1")
                .bind(id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        rows.into_iter()
            .map(|(welcome_id, group_id, welcome)| {
                Ok((
                    welcome_id.try_into().map_err(|_| ApiError::Database)?,
                    group_id.try_into().map_err(|_| ApiError::Database)?,
                    welcome,
                ))
            })
            .collect()
    }

    pub async fn upload_event(&self, event: &UploadedEvent) -> Result<UploadAccepted, ApiError> {
        if event.ciphertext.is_empty() || event.ciphertext.len() > 65_536 {
            return Err(ApiError::InvalidInput);
        }
        let mut tx = self.pool.begin().await?;
        assert_active_member(&mut tx, &event.group_id, &event.author_device_id).await?;
        if event.event_kind == EVENT_KIND_MLS_COMMIT && event.correlation_id.is_none() {
            return Err(ApiError::InvalidInput);
        }
        if let Some(correlation_id) = event.correlation_id {
            let operation_exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM membership_operations WHERE correlation_id=$1 AND group_id=$2 AND applied_at IS NOT NULL)")
                .bind(correlation_id.as_slice()).bind(event.group_id.as_slice()).fetch_one(&mut *tx).await?;
            if !operation_exists {
                return Err(ApiError::Conflict);
            }
        }
        if let Some((cursor, event_id, ciphertext)) = sqlx::query_as::<_, (i64, Vec<u8>, Vec<u8>)>(
            "SELECT event_cursor,event_id,ciphertext FROM group_events WHERE author_device_id=$1 AND client_message_id=$2"
        ).bind(event.author_device_id.as_slice()).bind(event.client_message_id.as_slice()).fetch_optional(&mut *tx).await? {
            if event_id == event.event_id && ciphertext == event.ciphertext { tx.commit().await?; return Ok(UploadAccepted { cursor, duplicate: true }); }
            return Err(ApiError::Conflict);
        }
        let cursor: i64 = sqlx::query_scalar(
            "INSERT INTO group_events(event_id,group_id,author_device_id,client_message_id,event_kind,ciphertext,correlation_id,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,now()+make_interval(secs=>$8)) RETURNING event_cursor"
        ).bind(event.event_id.as_slice()).bind(event.group_id.as_slice()).bind(event.author_device_id.as_slice()).bind(event.client_message_id.as_slice())
            .bind(event.event_kind).bind(&event.ciphertext).bind(event.correlation_id.as_ref().map(|value| value.as_slice())).bind(EVENT_TTL_SECONDS as f64).fetch_one(&mut *tx).await?;
        sqlx::query("SELECT pg_notify($1, encode($2::bytea,'hex'))")
            .bind(EVENT_NOTIFY_CHANNEL)
            .bind(event.group_id.as_slice())
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(UploadAccepted {
            cursor,
            duplicate: false,
        })
    }

    pub async fn sync_group(
        &self,
        device_id: [u8; 16],
        group_id: [u8; 16],
        after: i64,
        limit: i64,
    ) -> Result<Vec<SyncEvent>, ApiError> {
        let mut tx = self.pool.begin().await?;
        assert_active_member(&mut tx, &group_id, &device_id).await?;
        let rows = sqlx::query_as::<_, (i64, Vec<u8>, i16, Vec<u8>)>(
            "SELECT event_cursor,event_id,event_kind,ciphertext FROM group_events WHERE group_id=$1 AND event_cursor>$2 AND expires_at>now() ORDER BY event_cursor LIMIT $3"
        ).bind(group_id.as_slice()).bind(after.max(0)).bind(limit.clamp(1, MAX_SYNC_BATCH)).fetch_all(&mut *tx).await?;
        tx.commit().await?;
        rows.into_iter()
            .map(|(cursor, id, event_kind, ciphertext)| {
                Ok(SyncEvent {
                    cursor,
                    event_id: id.try_into().map_err(|_| ApiError::Database)?,
                    event_kind,
                    ciphertext,
                })
            })
            .collect()
    }

    pub async fn sync_global(
        &self,
        device_id: [u8; 16],
        after: i64,
        limit: i64,
    ) -> Result<Vec<SyncEvent>, ApiError> {
        let rows = sqlx::query_as::<_, (i64, Vec<u8>, i16, Vec<u8>)>(
            "SELECT e.event_cursor,e.event_id,e.event_kind,e.ciphertext FROM group_events e JOIN group_members m ON m.group_id=e.group_id AND m.device_id=$1 AND m.removed_at IS NULL WHERE e.event_cursor>$2 AND e.expires_at>now() ORDER BY e.event_cursor LIMIT $3",
        )
        .bind(device_id.as_slice())
        .bind(after.max(0))
        .bind(limit.clamp(1, MAX_SYNC_BATCH))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|(cursor, id, event_kind, ciphertext)| {
                Ok(SyncEvent {
                    cursor,
                    event_id: id.try_into().map_err(|_| ApiError::Database)?,
                    event_kind,
                    ciphertext,
                })
            })
            .collect()
    }

    pub async fn record_receipts(
        &self,
        device_id: [u8; 16],
        event_ids: &[[u8; 16]],
        receipt_type: i16,
    ) -> Result<u64, ApiError> {
        if !matches!(receipt_type, 1 | 2) || event_ids.len() > MAX_SYNC_BATCH as usize {
            return Err(ApiError::InvalidInput);
        }
        let mut tx = self.pool.begin().await?;
        let mut inserted = 0;
        for event_id in event_ids {
            inserted += sqlx::query("INSERT INTO message_receipts(event_id,device_id,receipt_type) SELECT e.event_id,$2,$3 FROM group_events e JOIN group_members m ON m.group_id=e.group_id AND m.device_id=$2 AND m.removed_at IS NULL WHERE e.event_id=$1 ON CONFLICT DO NOTHING")
                .bind(event_id.as_slice()).bind(device_id.as_slice()).bind(receipt_type).execute(&mut *tx).await?.rows_affected();
        }
        tx.commit().await?;
        Ok(inserted)
    }

    pub async fn advance_group_cursor(
        &self,
        device_id: [u8; 16],
        group_id: [u8; 16],
        cursor: i64,
    ) -> Result<(), ApiError> {
        let mut tx = self.pool.begin().await?;
        assert_active_member(&mut tx, &group_id, &device_id).await?;
        let current: Option<i64> = sqlx::query_scalar(
            "SELECT cursor FROM device_group_cursors WHERE device_id=$1 AND group_id=$2 FOR UPDATE",
        )
        .bind(device_id.as_slice())
        .bind(group_id.as_slice())
        .fetch_optional(&mut *tx)
        .await?;
        if current.is_some_and(|value| cursor < value) {
            return Err(ApiError::CursorRegression);
        }
        let available: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(event_cursor),0) FROM group_events WHERE group_id=$1",
        )
        .bind(group_id.as_slice())
        .fetch_one(&mut *tx)
        .await?;
        if cursor > available {
            return Err(ApiError::InvalidInput);
        }
        sqlx::query("INSERT INTO device_group_cursors(device_id,group_id,cursor) VALUES($1,$2,$3) ON CONFLICT(device_id,group_id) DO UPDATE SET cursor=EXCLUDED.cursor,updated_at=now()")
            .bind(device_id.as_slice()).bind(group_id.as_slice()).bind(cursor).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn cleanup_expired_events(&self, batch: i64) -> Result<u64, ApiError> {
        Ok(sqlx::query("DELETE FROM group_events WHERE event_id IN (SELECT event_id FROM group_events WHERE expires_at<=now() LIMIT $1)")
            .bind(batch.clamp(1, 10_000)).execute(&self.pool).await?.rows_affected())
    }
}

pub fn membership_operation_payload(
    correlation_id: &[u8; 16],
    group_id: &[u8; 16],
    author_device_id: &[u8; 16],
    target_device_id: &[u8; 16],
    role: i16,
    remove: bool,
) -> Vec<u8> {
    let mut value = b"resilient/membership-operation/v1".to_vec();
    value.extend_from_slice(correlation_id);
    value.extend_from_slice(group_id);
    value.extend_from_slice(author_device_id);
    value.extend_from_slice(target_device_id);
    value.extend_from_slice(&role.to_be_bytes());
    value.push(u8::from(remove));
    value
}

async fn assert_active_member(
    tx: &mut Transaction<'_, Postgres>,
    group: &[u8; 16],
    device: &[u8; 16],
) -> Result<(), ApiError> {
    let allowed: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM group_members WHERE group_id=$1 AND device_id=$2 AND removed_at IS NULL)")
        .bind(group.as_slice()).bind(device.as_slice()).fetch_one(&mut **tx).await?;
    if allowed {
        Ok(())
    } else {
        Err(ApiError::Unauthorized)
    }
}

async fn issue_tokens(
    tx: &mut Transaction<'_, Postgres>,
    device_id: &[u8],
    family: Option<&[u8]>,
) -> Result<SessionTokens, ApiError> {
    let access_token: [u8; 32] = random();
    let refresh_token: [u8; 32] = random();
    let access_hash = token_hash(b"access", &access_token);
    let refresh_hash = token_hash(b"refresh", &refresh_token);
    let family_id: Vec<u8> = family
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| random::<16>().to_vec());
    sqlx::query("INSERT INTO access_sessions(token_hash,device_id,expires_at) VALUES($1,$2,now()+make_interval(secs=>$3))")
        .bind(access_hash.as_slice()).bind(device_id).bind(ACCESS_TTL_SECONDS as f64).execute(&mut **tx).await?;
    sqlx::query("INSERT INTO refresh_sessions(token_hash,family_id,device_id,expires_at) VALUES($1,$2,$3,now()+make_interval(secs=>$4))")
        .bind(refresh_hash.as_slice()).bind(&family_id).bind(device_id).bind(REFRESH_TTL_SECONDS as f64).execute(&mut **tx).await?;
    Ok(SessionTokens {
        access_token,
        refresh_token,
    })
}
fn token_hash(domain: &[u8], token: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"resilient/session/v1");
    hash.update(domain);
    hash.update(token);
    hash.finalize().into()
}
fn random<const N: usize>() -> [u8; N] {
    let mut value = [0; N];
    OsRng.fill_bytes(&mut value);
    value
}
