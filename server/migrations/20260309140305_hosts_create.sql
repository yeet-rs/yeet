-- keyid - hostname - verifying_key
CREATE TABLE IF NOT EXISTS hosts
(
    id              INTEGER PRIMARY KEY NOT NULL,
    key_id          INTEGER NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
    hostname        TEXT    NOT NULL UNIQUE,
    last_ping       TEXT    NOT NULL
);
