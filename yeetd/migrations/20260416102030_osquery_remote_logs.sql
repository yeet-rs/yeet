CREATE TABLE osquery_status_log
(
    id              INTEGER PRIMARY KEY NOT NULL,
    node_id         INTEGER NOT NULL REFERENCES osquery_nodes(id) ON DELETE RESTRICT,
    splunk_status   TEXT    NOT NULL, -- if the query sent event has been sent to splunk
    calendar_time   TEXT    NOT NULL, -- time when the client logged
    received_time   TEXT    NOT NULL, -- timestamp when the log was received by yeet
    unix_time       INTEGER NOT NULL, -- unix timestamp when the log was sent. TODO: windows?
    filename        TEXT    NOT NULL, -- file where the error came from
    line            INTEGER NOT NULL, -- line where on the file the error occured
    message         TEXT    NOT NULL, -- log message
    severity        INTEGER NOT NULL, -- severity of the log
    version         TEXT    NOT NULL  -- osquery version
);

CREATE TABLE osquery_result_log
(
    id              INTEGER PRIMARY KEY NOT NULL,
    node_id         INTEGER NOT NULL REFERENCES osquery_nodes(id) ON DELETE RESTRICT,
    splunk_status   TEXT    NOT NULL, -- if the query sent event has been sent to splunk
    calendar_time   TEXT    NOT NULL, -- time when the client logged
    received_time   TEXT    NOT NULL, -- timestamp when the log was received by yeet
    unix_time       INTEGER NOT NULL, -- unix timestamp when the log was sent. TODO: windows?
    numerics        INTEGER NOT NULL, -- This is an indicator for all results, true if osquery attempted to log numerics as numbers, otherwise false indicates they were logged as strings.
    epoch           INTEGER NOT NULL, -- used with event format. if the epoch changes the node will send the full table again
    pack_name       TEXT    NOT NULL, -- which pack the log originated from
    log             TEXT    NOT NULL  -- one of removed, added, snapshot
);
