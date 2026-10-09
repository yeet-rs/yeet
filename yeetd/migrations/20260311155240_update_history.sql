-- TODO: add user who requested the update
CREATE TABLE IF NOT EXISTS update_request_history
(
    id          INTEGER PRIMARY KEY NOT NULL,
    host_id     INTEGER NOT NULL REFERENCES hosts(id)   ON DELETE CASCADE,
    store_path  TEXT    NOT NULL,
    remote      INTEGER NOT NULL REFERENCES nix_remotes(id)   ON DELETE RESTRICT,
    update_time TEXT    NOT NULL
);

-- TODO: api to list / create remotes
CREATE TABLE IF NOT EXISTS nix_remotes
(
    id          INTEGER PRIMARY KEY NOT NULL,
    public_key  TEXT    NOT NULL UNIQUE,
    substitutor TEXT    NOT NULL UNIQUE
);
