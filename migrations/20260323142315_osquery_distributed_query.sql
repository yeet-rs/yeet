
CREATE TABLE IF NOT EXISTS osquery_dq_queries
(
    id              INTEGER PRIMARY KEY NOT NULL,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    query           TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS osquery_dq_requests
(
    query_id        INTEGER NOT NULL REFERENCES osquery_dq_queries(id) ON DELETE RESTRICT,
    node_id         INTEGER NOT NULL REFERENCES osquery_nodes(id) ON DELETE RESTRICT,
    PRIMARY KEY (query_id, node_id)
);

CREATE TABLE IF NOT EXISTS osquery_dq_responses
(
    id              INTEGER PRIMARY KEY NOT NULL,
    query_id        INTEGER NOT NULL REFERENCES osquery_dq_queries(id) ON DELETE RESTRICT,
    node_id         INTEGER NOT NULL REFERENCES osquery_nodes(id) ON DELETE RESTRICT,
    response        TEXT    NOT NULL,
    status          INTEGER NOT NULL
);
