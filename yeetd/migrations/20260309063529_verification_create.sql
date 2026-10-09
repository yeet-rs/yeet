-- 6 digit number -> unverified pub key
CREATE TABLE IF NOT EXISTS verification_attempts
(
    id              INTEGER     PRIMARY KEY NOT NULL,
    verifying_key   BLOB        NOT NULL,
    timestamp       TEXT        NOT NULL,
    nixos_facter    TEXT
);
