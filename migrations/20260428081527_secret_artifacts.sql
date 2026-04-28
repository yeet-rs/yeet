CREATE TABLE IF NOT EXISTS artifacts
(
    id              INTEGER PRIMARY KEY NOT NULL,
    -- host supplied name - can be duplicated (e.g. superceeding)
    name            TEXT    NOT NULL,
    -- host that registered the artifact
    host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    artifact        BLOB    NOT NULL,
    creation_time   TEXT    NOT NULL
);
