-- keyid - hostname - verifying_key
CREATE TABLE IF NOT EXISTS secrets
(
    id              INTEGER PRIMARY KEY NOT NULL,
    name            TEXT    NOT NULL UNIQUE,
    secret          BLOB    NOT NULL
);

CREATE TABLE IF NOT EXISTS secrets_acl
(
    secret_id   INTEGER NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    host_id     INTEGER NOT NULL REFERENCES hosts(id)   ON DELETE CASCADE,
    PRIMARY KEY (secret_id, host_id)
);
