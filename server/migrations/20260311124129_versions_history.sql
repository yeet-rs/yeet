CREATE TABLE IF NOT EXISTS version_history
(
    id          INTEGER PRIMARY KEY NOT NULL,
    host_id     INTEGER NOT NULL REFERENCES hosts(id)   ON DELETE CASCADE,
    store_path  TEXT    NOT NULL,
    update_time TEXT    NOT NULL,
    UNIQUE (host_id, store_path, update_time)
);
