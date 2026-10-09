PRAGMA foreign_keys=OFF;

CREATE TABLE osquery_nodes_new
(
    id              INTEGER PRIMARY KEY NOT NULL,
    node_key        BINARY  UNIQUE NOT NULL,
    host_identifier TEXT    UNIQUE NOT NULL,
    platform_type   TEXT    NOT NULL,
    platform_name   TEXT,
    osquery_version TEXT,
    os_version      TEXT,
    cpu_arch        TEXT,
    platform        TEXT,
    hardware_serial TEXT,
    last_ping       TEXT    NOT NULL
);

INSERT INTO osquery_nodes_new (
    id, node_key, host_identifier, platform_type,
    platform_name, osquery_version, os_version, cpu_arch, platform,
    hardware_serial, last_ping
)
SELECT
    id, node_key, host_identifier, platform_type,
    platform_name, osquery_version, os_version, cpu_arch, platform,
    hardware_serial, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
FROM osquery_nodes;

DROP TABLE osquery_nodes;

ALTER TABLE osquery_nodes_new RENAME TO osquery_nodes;

PRAGMA foreign_keys=ON;
