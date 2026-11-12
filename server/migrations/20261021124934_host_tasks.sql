-- one-shot tasks the agent of a host runs. rows never change after the insert
CREATE TABLE IF NOT EXISTS host_tasks
(
    id              INTEGER PRIMARY KEY NOT NULL,
    host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    -- admin that created the task. becomes NULL when the user gets deleted so we keep the rest of the audit trail
    created_by      INTEGER          REFERENCES users(id) ON DELETE SET NULL,
    -- the task as json, age encrypted to the server key
    payload         BLOB    NOT NULL,
    creation_time   TEXT    NOT NULL,
    expires_at      TEXT    NOT NULL
);

-- append only status history, the current state is the newest row
CREATE TABLE IF NOT EXISTS host_task_history
(
    id              INTEGER PRIMARY KEY NOT NULL,
    task_id         INTEGER NOT NULL REFERENCES host_tasks(id) ON DELETE CASCADE,
    -- 'Expired' is computed on the fly and never stored
    state           TEXT    NOT NULL CHECK (state IN ('Pending', 'Done', 'Failed')),
    message         TEXT,
    update_time     TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS host_tasks_host ON host_tasks (host_id);
CREATE INDEX IF NOT EXISTS host_task_history_task ON host_task_history (task_id, update_time);
