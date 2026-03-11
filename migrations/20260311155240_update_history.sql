-- TODO: add user who requested the update
CREATE TABLE IF NOT EXISTS update_request_history
(
    id          INTEGER PRIMARY KEY NOT NULL,
    host_id     INTEGER NOT NULL REFERENCES hosts(id)   ON DELETE CASCADE,
    store_path  TEXT    NOT NULL,
    public_key  TEXT    NOT NULL,
    substitutor TEXT    NOT NULL,
    update_time TEXT    NOT NULL
);
