
CREATE TABLE IF NOT EXISTS metadata (
	driver_name TEXT NOT NULL,
	driver_version INT NOT NULL,
	wallet_id TEXT NOT NULL UNIQUE,
	wallet_name TEXT NOT NULL,
	mep_encrypted BLOB NOT NULL,
	mdk_encrypted BLOB NOT NULL,
	max_key_idx_encrypted BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS keys (
	address BLOB PRIMARY KEY,
	secret_key_encrypted BLOB NOT NULL,
	key_idx INT
);

CREATE TABLE IF NOT EXISTS msig_addrs (
	address BLOB PRIMARY KEY,
	version INT NOT NULL,
	threshold INT NOT NULL,
	pks BLOB NOT NULL
);
