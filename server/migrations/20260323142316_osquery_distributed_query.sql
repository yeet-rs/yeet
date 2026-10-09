
DROP TABLE IF EXISTS osquery_dq_responses;
DROP TABLE IF EXISTS osquery_dq_requests;
DROP TABLE IF EXISTS osquery_dq_queries;
CREATE TABLE osquery_dq_queries
(
    id              INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    splunk_status   TEXT    NOT NULL, -- if the query sent event has been sent to splunk
    persistent      INTEGER NOT NULL DEFAULT 0, -- if 0 the query will be deleted once the data has been sent to splunk
    creation_time   TEXT    NOT NULL, -- Time when the user create the query
    query           TEXT    NOT NULL
);

CREATE TABLE osquery_dq_requests
(
    query_id        INTEGER NOT NULL REFERENCES osquery_dq_queries(id) ON DELETE RESTRICT,
    node_id         INTEGER NOT NULL REFERENCES osquery_nodes(id) ON DELETE RESTRICT,
    PRIMARY KEY (query_id, node_id)
);
CREATE TABLE osquery_dq_responses
(
    id              INTEGER PRIMARY KEY NOT NULL,
    query_id        INTEGER NOT NULL REFERENCES osquery_dq_queries(id) ON DELETE RESTRICT,
    node_id         INTEGER NOT NULL REFERENCES osquery_nodes(id) ON DELETE RESTRICT,
    response        TEXT    NOT NULL,
    splunk_status   TEXT    NOT NULL, -- if the query sent event has been sent to splunk
    response_time   TEXT    NOT NULL, -- Time when the client responded
    status          INTEGER NOT NULL -- sqlite status code (sent from client)
);
