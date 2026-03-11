CREATE TABLE IF NOT EXISTS state_history
(
    id          INTEGER PRIMARY KEY NOT NULL,
    host_id     INTEGER NOT NULL REFERENCES hosts(id)  ON DELETE CASCADE,
    state       TEXT    NOT NULL,
    changed_at  TEXT    NOT NULL
);
