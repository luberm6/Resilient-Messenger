CREATE TABLE accounts (
  account_id BYTEA PRIMARY KEY CHECK (octet_length(account_id)=32), root_public_key BYTEA NOT NULL UNIQUE CHECK (octet_length(root_public_key)=32),
  recovery_identifier BYTEA UNIQUE CHECK (recovery_identifier IS NULL OR octet_length(recovery_identifier)=32), recovery_blob BYTEA, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE devices (
  device_id BYTEA PRIMARY KEY CHECK (octet_length(device_id)=16), account_id BYTEA NOT NULL REFERENCES accounts ON DELETE CASCADE,
  device_public_key BYTEA NOT NULL CHECK (octet_length(device_public_key)=32), created_at TIMESTAMPTZ NOT NULL DEFAULT now(), revoked_at TIMESTAMPTZ, UNIQUE(account_id, device_public_key)
);
CREATE INDEX devices_account_active_idx ON devices(account_id) WHERE revoked_at IS NULL;
CREATE TABLE device_certificates (
  device_id BYTEA PRIMARY KEY REFERENCES devices ON DELETE CASCADE, certificate_signature BYTEA NOT NULL CHECK (octet_length(certificate_signature)=64), issued_at BIGINT NOT NULL CHECK (issued_at>=0)
);
CREATE TABLE usernames (
  canonical_username TEXT PRIMARY KEY CHECK (char_length(canonical_username) BETWEEN 3 AND 32), account_id BYTEA NOT NULL REFERENCES accounts ON DELETE CASCADE,
  claimed_at TIMESTAMPTZ NOT NULL DEFAULT now(), released_at TIMESTAMPTZ
);
CREATE INDEX usernames_active_exact_idx ON usernames(canonical_username) WHERE released_at IS NULL;
CREATE UNIQUE INDEX usernames_account_active_idx ON usernames(account_id) WHERE released_at IS NULL;
CREATE TABLE username_cooldowns (canonical_username TEXT PRIMARY KEY, previous_account_id BYTEA NOT NULL REFERENCES accounts, release_after TIMESTAMPTZ NOT NULL);
CREATE TABLE auth_challenges (
  challenge_id BYTEA PRIMARY KEY CHECK (octet_length(challenge_id)=16), device_id BYTEA NOT NULL REFERENCES devices ON DELETE CASCADE,
  challenge BYTEA NOT NULL UNIQUE CHECK (octet_length(challenge)=32), expires_at TIMESTAMPTZ NOT NULL, consumed_at TIMESTAMPTZ
);
CREATE INDEX auth_challenges_live_idx ON auth_challenges(device_id,expires_at) WHERE consumed_at IS NULL;
CREATE TABLE access_sessions (token_hash BYTEA PRIMARY KEY CHECK (octet_length(token_hash)=32), device_id BYTEA NOT NULL REFERENCES devices ON DELETE CASCADE, expires_at TIMESTAMPTZ NOT NULL);
CREATE INDEX access_sessions_device_idx ON access_sessions(device_id,expires_at);
CREATE TABLE refresh_sessions (
  token_hash BYTEA PRIMARY KEY CHECK (octet_length(token_hash)=32), family_id BYTEA NOT NULL CHECK (octet_length(family_id)=16), device_id BYTEA NOT NULL REFERENCES devices ON DELETE CASCADE,
  replaced_by_hash BYTEA REFERENCES refresh_sessions(token_hash), expires_at TIMESTAMPTZ NOT NULL, used_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ
);
CREATE INDEX refresh_sessions_device_live_idx ON refresh_sessions(device_id,expires_at) WHERE revoked_at IS NULL;
CREATE TABLE key_packages (
  package_id BYTEA PRIMARY KEY CHECK (octet_length(package_id)=16), device_id BYTEA NOT NULL REFERENCES devices ON DELETE CASCADE,
  package BYTEA NOT NULL CHECK (octet_length(package)<=65536), consumed_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX key_packages_available_idx ON key_packages(device_id,created_at) WHERE consumed_at IS NULL;
CREATE TABLE groups (group_id BYTEA PRIMARY KEY CHECK (octet_length(group_id)=16), created_by_device_id BYTEA NOT NULL REFERENCES devices, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE group_members (
  group_id BYTEA NOT NULL REFERENCES groups ON DELETE CASCADE, device_id BYTEA NOT NULL REFERENCES devices ON DELETE CASCADE, account_id BYTEA NOT NULL REFERENCES accounts ON DELETE CASCADE,
  role SMALLINT NOT NULL CHECK(role BETWEEN 0 AND 2), removed_at TIMESTAMPTZ, PRIMARY KEY(group_id,device_id)
);
CREATE INDEX group_members_device_active_idx ON group_members(device_id,group_id) WHERE removed_at IS NULL;
CREATE TABLE membership_operations (
  correlation_id BYTEA PRIMARY KEY CHECK(octet_length(correlation_id)=16), group_id BYTEA NOT NULL REFERENCES groups ON DELETE CASCADE, author_device_id BYTEA NOT NULL REFERENCES devices,
  operation BYTEA NOT NULL, signature BYTEA NOT NULL, applied_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE group_events (
  event_cursor BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE, event_id BYTEA PRIMARY KEY CHECK (octet_length(event_id)=16), group_id BYTEA NOT NULL REFERENCES groups ON DELETE CASCADE,
  author_device_id BYTEA NOT NULL REFERENCES devices, client_message_id BYTEA NOT NULL CHECK (octet_length(client_message_id)=16), correlation_id BYTEA CHECK(correlation_id IS NULL OR octet_length(correlation_id)=16),
  event_kind SMALLINT NOT NULL, ciphertext BYTEA NOT NULL CHECK (octet_length(ciphertext)<=65536), expires_at TIMESTAMPTZ NOT NULL, received_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE(author_device_id,client_message_id)
);
CREATE INDEX group_events_sync_idx ON group_events(group_id,event_cursor);
CREATE INDEX group_events_retention_idx ON group_events(expires_at);
CREATE TABLE welcome_mailbox (
  welcome_id BYTEA PRIMARY KEY CHECK(octet_length(welcome_id)=16), target_device_id BYTEA NOT NULL REFERENCES devices ON DELETE CASCADE, group_id BYTEA NOT NULL REFERENCES groups ON DELETE CASCADE,
  welcome BYTEA NOT NULL CHECK(octet_length(welcome)<=65536), expires_at TIMESTAMPTZ NOT NULL, consumed_at TIMESTAMPTZ
);
CREATE INDEX welcome_mailbox_pending_idx ON welcome_mailbox(target_device_id,expires_at) WHERE consumed_at IS NULL;
CREATE TABLE device_group_cursors (
  device_id BYTEA NOT NULL REFERENCES devices ON DELETE CASCADE, group_id BYTEA NOT NULL REFERENCES groups ON DELETE CASCADE, cursor BIGINT NOT NULL DEFAULT 0 CHECK(cursor>=0),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY(device_id,group_id)
);
CREATE TABLE device_global_cursors (device_id BYTEA PRIMARY KEY REFERENCES devices ON DELETE CASCADE, cursor BIGINT NOT NULL DEFAULT 0 CHECK(cursor>=0), updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE message_receipts (
  event_id BYTEA NOT NULL REFERENCES group_events ON DELETE CASCADE, device_id BYTEA NOT NULL REFERENCES devices ON DELETE CASCADE, receipt_type SMALLINT NOT NULL CHECK(receipt_type IN (1,2)),
  received_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY(event_id,device_id,receipt_type)
);
CREATE TABLE relay_directory_versions (version BIGINT PRIMARY KEY CHECK(version>=0), directory BYTEA NOT NULL, signature BYTEA NOT NULL, expires_at TIMESTAMPTZ NOT NULL, published_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE relay_endpoints (endpoint_id BYTEA PRIMARY KEY CHECK(octet_length(endpoint_id)=16), directory_version BIGINT NOT NULL REFERENCES relay_directory_versions ON DELETE CASCADE, endpoint BYTEA NOT NULL, enabled BOOLEAN NOT NULL DEFAULT true);
CREATE TABLE push_tokens (device_id BYTEA PRIMARY KEY REFERENCES devices ON DELETE CASCADE, token_hash BYTEA NOT NULL UNIQUE CHECK(octet_length(token_hash)=32), platform SMALLINT NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE blocked_accounts (account_id BYTEA NOT NULL REFERENCES accounts ON DELETE CASCADE, blocked_account_id BYTEA NOT NULL REFERENCES accounts ON DELETE CASCADE, PRIMARY KEY(account_id,blocked_account_id));
CREATE TABLE abuse_counters (scope BYTEA PRIMARY KEY, window_start TIMESTAMPTZ NOT NULL, count INTEGER NOT NULL CHECK(count>=0));
