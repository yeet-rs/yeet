CREATE TABLE IF NOT EXISTS users
(
    id              INTEGER PRIMARY KEY NOT NULL,
    key_id          INTEGER NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
    level           TEXT    NOT NULL
);
