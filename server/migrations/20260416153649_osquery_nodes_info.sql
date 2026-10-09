
ALTER TABLE osquery_nodes DROP COLUMN host_details;
ALTER TABLE osquery_nodes ADD COLUMN platform_name      TEXT NOT NULL DEFAULT 'Unknown';
ALTER TABLE osquery_nodes ADD COLUMN osquery_version    TEXT NOT NULL DEFAULT 'Unknown';
ALTER TABLE osquery_nodes ADD COLUMN os_version         TEXT NOT NULL DEFAULT 'Unknown';
ALTER TABLE osquery_nodes ADD COLUMN cpu_arch           TEXT NOT NULL DEFAULT 'Unknown';
ALTER TABLE osquery_nodes ADD COLUMN platform           TEXT NOT NULL DEFAULT 'Unknown';
ALTER TABLE osquery_nodes ADD COLUMN hardware_serial    TEXT NOT NULL DEFAULT 'Unknown';
