PRAGMA foreign_keys=OFF;

CREATE TABLE users_new
(
    id              INTEGER PRIMARY KEY NOT NULL,
    key_id          INTEGER REFERENCES keys(id) ON DELETE CASCADE,
    oidc_id         TEXT UNIQUE,
    username        TEXT    NOT NULL,
    all_tag         INTEGER NOT NULL,
    level           TEXT    NOT NULL
);

INSERT INTO users_new (
id,
key_id,
oidc_id,
username,
all_tag,
level
)
SELECT
    id,
    key_id,
    NULL,
    username,
    all_tag,
    level
FROM users;

PRAGMA legacy_alter_table=ON;
DROP TABLE users;

ALTER TABLE users_new RENAME TO users;
PRAGMA legacy_alter_table=OFF;


PRAGMA foreign_keys=ON;
