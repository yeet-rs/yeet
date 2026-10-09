CREATE TABLE IF NOT EXISTS tags
(
    id              INTEGER PRIMARY KEY NOT NULL,
    name            TEXT    NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS policies
(
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tag_id          INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    -- action          TEXT    NOT NULL,
    PRIMARY KEY (user_id, tag_id) -- action
);

CREATE TABLE IF NOT EXISTS resource_tags
(
    resource_id     INTEGER NOT NULL,
    resource_type   TEXT NOT NULL,
    tag_id          INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (resource_id, resource_type, tag_id)
);

ALTER TABLE users ADD COLUMN username TEXT NOT NULL DEFAULT 'name not set';
ALTER TABLE users ADD COLUMN all_tag INTEGER NOT NULL DEFAULT 0;
