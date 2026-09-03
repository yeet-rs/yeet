PRAGMA foreign_keys=OFF;

CREATE TABLE IF NOT EXISTS update_request_history_new
(
    id          INTEGER PRIMARY KEY NOT NULL,
    host_id     INTEGER NOT NULL REFERENCES hosts(id)   ON DELETE CASCADE,
    store_path  TEXT    NOT NULL,
    remote      INTEGER NOT NULL REFERENCES nix_remotes(id)   ON DELETE RESTRICT,
    update_time TEXT    NOT NULL,
    priority    TEXT    NOT NULL
);

INSERT INTO update_request_history_new (
id, host_id, store_path, remote, update_time, priority
)
SELECT
    id, host_id, store_path, remote, update_time, "Normal"
FROM update_request_history;

DROP TABLE update_request_history;

ALTER TABLE update_request_history_new RENAME TO update_request_history;

PRAGMA foreign_keys=ON;
