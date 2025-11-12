-- Initial DB schema for ephemeral-vault

CREATE TABLE vaults (
    id TEXT PRIMARY KEY,
    owner TEXT NOT NULL,
    balance INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE delegations (
    id TEXT PRIMARY KEY,
    vault_id TEXT NOT NULL,
    delegate TEXT NOT NULL,
    expires_at INTEGER
);
