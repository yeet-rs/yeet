-- keyid - hostname - verifying_key
CREATE TABLE IF NOT EXISTS hosts
(
    keyid           TEXT    NOT NULL UNIQUE,
    verifying_key   BLOB    NOT NULL UNIQUE,
    hostname        TEXT    NOT NULL UNIQUE,
    last_ping       TEXT    NOT NULL
);
