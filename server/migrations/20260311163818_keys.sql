CREATE TABLE IF NOT EXISTS keys
(
    id              INTEGER PRIMARY KEY NOT NULL,
    keyid           TEXT    NOT NULL UNIQUE,
    verifying_key   BLOB    NOT NULL UNIQUE
);
