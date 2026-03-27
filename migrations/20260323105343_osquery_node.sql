CREATE TABLE IF NOT EXISTS osquery_nodes
(
    id              INTEGER PRIMARY KEY NOT NULL,
    node_key        BINARY  UNIQUE NOT NULL,
    host_identifier TEXT    UNIQUE NOT NULL,
    platform_type   TEXT    NOT NULL,
    host_details    TEXT    NOT NULL
);
