//! One-shot tasks for hosts, like setting a password.
//!
//! Payloads are the task as json, age encrypted to the server identity and stored like that.
//! When a host fetches its tasks every payload gets decrypted and encrypted again for the
//! ephemeral recipient the host sent along. Same dance as with the secrets

use jiff_sqlx::ToSqlx as _;
use sqlx::Acquire as _;

error_set::error_set! {
    CreateTaskError := {
        #[display("Task is not encrypted for the server: {0}")]
        Decrypt(age::DecryptError),
        #[display("Task is not a valid HostTask: {0}")]
        Json(serde_json::Error),
        #[display("Unsupported task type")]
        UnsupportedTask,
        #[display("Could not compute expiry: {0}")]
        Time(jiff::Error),
        SQLX(sqlx::Error),
    }
    GetTasksError := {
        #[display("Could not encrypt the task for the target: {0}")]
        Encrypt(age::EncryptError),
        Decrypt(age::DecryptError),
        SQLX(sqlx::Error),
    }
    ReportTaskError := {
        #[display("Task does not exist")]
        NotFound,
        #[display("Hosts may only report Done or Failed")]
        InvalidState,
        SQLX(sqlx::Error),
    }
}

/// Tasks that nobody picked up within a week are expired
const TASK_TTL: jiff::SignedDuration = jiff::SignedDuration::from_hours(24 * 7);
/// Max length of a message a host can report. nobody needs to read a novel
const MAX_MESSAGE_CHARS: usize = 1000;

pub async fn create_task<I: age::Identity>(
    conn: &mut sqlx::SqliteConnection,
    host: api::HostID,
    created_by: api::UserID,
    payload: Vec<u8>,
    store_key: &I,
) -> Result<api::TaskID, CreateTaskError> {
    // make sure it is encrypted for us and something we actually understand
    let decrypted = age::decrypt(store_key, &payload)?;
    let task: api::HostTask = serde_json::from_slice(&decrypted)?;
    if task == api::HostTask::Unknown {
        return Err(CreateTaskError::UnsupportedTask);
    }
    let now = jiff::Timestamp::now();
    let expires_at = now.checked_add(TASK_TTL)?.to_sqlx();
    let now = now.to_sqlx();

    let mut tx = conn.begin().await?;

    let id = sqlx::query_scalar!(
        r#"
        INSERT INTO host_tasks (host_id, created_by, payload, creation_time, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id AS "id!: api::TaskID""#,
        host,
        created_by,
        payload,
        now,
        expires_at
    )
    .fetch_one(&mut *tx)
    .await?;

    let pending = api::TaskState::Pending;
    sqlx::query!(
        r#"
        INSERT INTO host_task_history (task_id, state, message, update_time)
        VALUES ($1, $2, NULL, $3)"#,
        id,
        pending,
        now
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(id)
}

/// Pending tasks of a host that are not expired yet, encrypted again for the recipient.
/// Filtering by host is the access control here, a host only ever sees its own tasks
pub async fn pending_tasks_for<I: age::Identity, R: age::Recipient>(
    conn: &mut sqlx::SqliteConnection,
    host: api::HostID,
    store_key: &I,
    recipient: &R,
) -> Result<Vec<api::PendingTask>, GetTasksError> {
    let pending = api::TaskState::Pending;
    let rows = sqlx::query!(
        r#"
        SELECT
            t.id AS "id: api::TaskID",
            t.payload,
            t.expires_at AS "expires_at: jiff_sqlx::Timestamp"
        FROM host_tasks t
        WHERE t.host_id = $1
          AND (SELECT h.state FROM host_task_history h
               WHERE h.task_id = t.id
               ORDER BY h.update_time DESC, h.id DESC
               LIMIT 1) = $2
        ORDER BY t.creation_time"#,
        host,
        pending
    )
    .fetch_all(conn)
    .await?;

    // compare as timestamps and not as text, the fractional digits vary
    let now = jiff::Timestamp::now();
    let mut tasks = Vec::new();
    for row in rows {
        if row.expires_at.to_jiff() <= now {
            continue;
        }
        let decrypted = age::decrypt(store_key, &row.payload)?;
        let task = age::encrypt(recipient, &decrypted)?;
        tasks.push(api::PendingTask { id: row.id, task });
    }
    Ok(tasks)
}

pub async fn report_task(
    conn: &mut sqlx::SqliteConnection,
    host: api::HostID,
    task: api::TaskID,
    report: api::TaskReport,
) -> Result<(), ReportTaskError> {
    if !matches!(report.state, api::TaskState::Done | api::TaskState::Failed) {
        return Err(ReportTaskError::InvalidState);
    }

    let mut tx = conn.begin().await?;

    let row = sqlx::query!(
        r#"
        SELECT
            t.host_id AS "host_id: api::HostID",
            (SELECT h.state FROM host_task_history h
             WHERE h.task_id = t.id
             ORDER BY h.update_time DESC, h.id DESC
             LIMIT 1) AS "state!: api::TaskState"
        FROM host_tasks t
        WHERE t.id = $1"#,
        task
    )
    .fetch_optional(&mut *tx)
    .await?;

    // same error for "does not exist" and "belongs to another host" so nobody can probe for ids
    let Some(row) = row.filter(|row| row.host_id == host) else {
        return Err(ReportTaskError::NotFound);
    };

    // reporting a finished task again is fine but we don't store it
    if row.state != api::TaskState::Pending {
        return Ok(());
    }

    let message = report
        .message
        .map(|message| message.chars().take(MAX_MESSAGE_CHARS).collect::<String>());
    let now = jiff::Timestamp::now().to_sqlx();
    sqlx::query!(
        r#"
        INSERT INTO host_task_history (task_id, state, message, update_time)
        VALUES ($1, $2, $3, $4)"#,
        task,
        report.state,
        message,
        now
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(())
}

/// Host a task belongs to, needed for the tag check
pub async fn task_host(
    conn: &mut sqlx::SqliteConnection,
    task: api::TaskID,
) -> Result<Option<api::HostID>, sqlx::Error> {
    sqlx::query_scalar!(
        r#"
        SELECT host_id AS "host_id: api::HostID" FROM host_tasks
        WHERE id = $1"#,
        task
    )
    .fetch_optional(conn)
    .await
}

pub async fn task_status(
    conn: &mut sqlx::SqliteConnection,
    task: api::TaskID,
) -> Result<Option<api::TaskStatus>, sqlx::Error> {
    let row = sqlx::query!(
        r#"
        SELECT
            t.id AS "id: api::TaskID",
            t.host_id AS "host_id: api::HostID",
            t.creation_time AS "creation_time: jiff_sqlx::Timestamp",
            t.expires_at AS "expires_at: jiff_sqlx::Timestamp",
            h.state AS "state: api::TaskState",
            h.message,
            h.update_time AS "update_time: jiff_sqlx::Timestamp"
        FROM host_tasks t
        JOIN host_task_history h ON h.id = (
            SELECT id FROM host_task_history
            WHERE task_id = t.id
            ORDER BY update_time DESC, id DESC
            LIMIT 1
        )
        WHERE t.id = $1"#,
        task
    )
    .fetch_optional(conn)
    .await?;

    Ok(row.map(|row| {
        let expires_at = row.expires_at.to_jiff();
        // Expired is never stored, it's just a pending task past its deadline
        let state = if row.state == api::TaskState::Pending && expires_at <= jiff::Timestamp::now()
        {
            api::TaskState::Expired
        } else {
            row.state
        };
        api::TaskStatus {
            id: row.id,
            host: row.host_id,
            state,
            message: row.message,
            creation_time: row.creation_time.to_jiff(),
            update_time: row.update_time.to_jiff(),
            expires_at,
        }
    }))
}

#[cfg(test)]
mod test_task {
    use ed25519_dalek::{SigningKey, VerifyingKey};

    use crate::db::{
        self,
        task::{CreateTaskError, ReportTaskError},
    };

    struct Setup {
        conn: sqlx::pool::PoolConnection<sqlx::Sqlite>,
        /// pretends to be the age key of the server
        identity: age::x25519::Identity,
        host: api::HostID,
        user: api::UserID,
    }

    async fn setup(pool: sqlx::SqlitePool) -> Setup {
        let mut conn = crate::sql_conn(pool).await;
        let host = db::hosts::add_host(&mut conn, VerifyingKey::default(), "host".into())
            .await
            .unwrap();
        let user = db::user::create_user(
            &mut conn,
            "admin".into(),
            SigningKey::from_bytes(&[1; 32]).verifying_key(),
            "admin".into(),
            api::AuthLevel::Admin,
            true,
        )
        .await
        .unwrap();
        Setup {
            conn,
            identity: age::x25519::Identity::generate(),
            host,
            user,
        }
    }

    fn password_task() -> api::HostTask {
        api::HostTask::SetPassword {
            username: "alice".into(),
            hashed_password: "$6$salt$hash".into(),
        }
    }

    fn encrypt(identity: &age::x25519::Identity, task: &api::HostTask) -> Vec<u8> {
        age::encrypt(&identity.to_public(), &serde_json::to_vec(task).unwrap()).unwrap()
    }

    fn done() -> api::TaskReport {
        api::TaskReport {
            state: api::TaskState::Done,
            message: None,
        }
    }

    /// Number of rows in the status history of a task
    async fn history_rows(conn: &mut sqlx::SqliteConnection, task: api::TaskID) -> i64 {
        sqlx::query_scalar!(
            r#"SELECT COUNT(*) AS "count!: i64" FROM host_task_history WHERE task_id = $1"#,
            task
        )
        .fetch_one(conn)
        .await
        .unwrap()
    }

    /// Create, fetch, report and check the encryption round trip on the way
    #[sqlx::test]
    async fn lifecycle(pool: sqlx::SqlitePool) {
        let Setup {
            mut conn,
            identity,
            host,
            user,
        } = setup(pool).await;
        let task = db::task::create_task(
            &mut conn,
            host,
            user,
            encrypt(&identity, &password_task()),
            &identity,
        )
        .await
        .unwrap();

        let status = db::task::task_status(&mut conn, task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status.state, api::TaskState::Pending);
        assert_eq!(status.host, host);

        // ephemeral key of the agent
        let agent = age::x25519::Identity::generate();
        let pending = db::task::pending_tasks_for(&mut conn, host, &identity, &agent.to_public())
            .await
            .unwrap();
        assert_eq!(pending.len(), 1);
        let fetched = pending.first().unwrap();
        assert_eq!(fetched.id, task);
        let decrypted = age::decrypt(&agent, &fetched.task).unwrap();
        assert_eq!(
            serde_json::from_slice::<api::HostTask>(&decrypted).unwrap(),
            password_task()
        );
        // the server key can not read what was sent to the agent
        age::decrypt(&identity, &fetched.task).unwrap_err();

        db::task::report_task(&mut conn, host, task, done())
            .await
            .unwrap();

        let pending = db::task::pending_tasks_for(&mut conn, host, &identity, &agent.to_public())
            .await
            .unwrap();
        assert_eq!(pending, []);
        let status = db::task::task_status(&mut conn, task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status.state, api::TaskState::Done);
    }

    /// Garbage in, error out
    #[sqlx::test]
    async fn rejects_garbage(pool: sqlx::SqlitePool) {
        let Setup {
            mut conn,
            identity,
            host,
            user,
        } = setup(pool).await;

        let wrong_key = age::x25519::Identity::generate();
        let result = db::task::create_task(
            &mut conn,
            host,
            user,
            encrypt(&wrong_key, &password_task()),
            &identity,
        )
        .await;
        assert!(matches!(result, Err(CreateTaskError::Decrypt(_))));

        let not_json = age::encrypt(&identity.to_public(), b"not json").unwrap();
        let result = db::task::create_task(&mut conn, host, user, not_json, &identity).await;
        assert!(matches!(result, Err(CreateTaskError::Json(_))));

        let unknown = age::encrypt(&identity.to_public(), br#"{"type":"Reboot"}"#).unwrap();
        let result = db::task::create_task(&mut conn, host, user, unknown, &identity).await;
        assert!(matches!(result, Err(CreateTaskError::UnsupportedTask)));

        // nothing was stored
        let tasks = sqlx::query_scalar!(r#"SELECT COUNT(*) AS "count!: i64" FROM host_tasks"#)
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        assert_eq!(tasks, 0);
    }

    /// Hosts can't see or report tasks of other hosts
    #[sqlx::test]
    async fn host_isolation(pool: sqlx::SqlitePool) {
        let Setup {
            mut conn,
            identity,
            host,
            user,
        } = setup(pool).await;
        let other = db::hosts::add_host(
            &mut conn,
            SigningKey::from_bytes(&[2; 32]).verifying_key(),
            "other".into(),
        )
        .await
        .unwrap();
        let task = db::task::create_task(
            &mut conn,
            host,
            user,
            encrypt(&identity, &password_task()),
            &identity,
        )
        .await
        .unwrap();

        let agent = age::x25519::Identity::generate();
        let pending = db::task::pending_tasks_for(&mut conn, other, &identity, &agent.to_public())
            .await
            .unwrap();
        assert_eq!(pending, []);

        let result = db::task::report_task(&mut conn, other, task, done()).await;
        assert!(matches!(result, Err(ReportTaskError::NotFound)));
        // same error as for a task that does not exist at all
        let missing = api::TaskID::new(9999);
        let result = db::task::report_task(&mut conn, host, missing, done()).await;
        assert!(matches!(result, Err(ReportTaskError::NotFound)));

        // the foreign report changed nothing
        let status = db::task::task_status(&mut conn, task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status.state, api::TaskState::Pending);
    }

    /// Reporting twice doesn't change anything
    #[sqlx::test]
    async fn idempotent_report(pool: sqlx::SqlitePool) {
        let Setup {
            mut conn,
            identity,
            host,
            user,
        } = setup(pool).await;
        let task = db::task::create_task(
            &mut conn,
            host,
            user,
            encrypt(&identity, &password_task()),
            &identity,
        )
        .await
        .unwrap();

        db::task::report_task(&mut conn, host, task, done())
            .await
            .unwrap();
        db::task::report_task(&mut conn, host, task, done())
            .await
            .unwrap();
        // a late, different report does not overwrite the first one either
        let failed = api::TaskReport {
            state: api::TaskState::Failed,
            message: Some("too late".into()),
        };
        db::task::report_task(&mut conn, host, task, failed)
            .await
            .unwrap();

        assert_eq!(history_rows(&mut conn, task).await, 2); // Pending + one Done
        let status = db::task::task_status(&mut conn, task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status.state, api::TaskState::Done);
    }

    /// Hosts may only report a final state, and long messages are truncated
    #[sqlx::test]
    async fn report_validation(pool: sqlx::SqlitePool) {
        let Setup {
            mut conn,
            identity,
            host,
            user,
        } = setup(pool).await;
        let task = db::task::create_task(
            &mut conn,
            host,
            user,
            encrypt(&identity, &password_task()),
            &identity,
        )
        .await
        .unwrap();

        for state in [api::TaskState::Pending, api::TaskState::Expired] {
            let report = api::TaskReport {
                state,
                message: None,
            };
            let result = db::task::report_task(&mut conn, host, task, report).await;
            assert!(matches!(result, Err(ReportTaskError::InvalidState)));
        }
        assert_eq!(history_rows(&mut conn, task).await, 1);

        let failed = api::TaskReport {
            state: api::TaskState::Failed,
            message: Some("x".repeat(5000)),
        };
        db::task::report_task(&mut conn, host, task, failed)
            .await
            .unwrap();
        let status = db::task::task_status(&mut conn, task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status.state, api::TaskState::Failed);
        assert_eq!(
            status.message.map(|message| message.chars().count()),
            Some(super::MAX_MESSAGE_CHARS)
        );
    }

    /// Old tasks expire and are not handed out anymore
    #[sqlx::test]
    async fn expiry(pool: sqlx::SqlitePool) {
        let Setup {
            mut conn,
            identity,
            host,
            user,
        } = setup(pool).await;
        let task = db::task::create_task(
            &mut conn,
            host,
            user,
            encrypt(&identity, &password_task()),
            &identity,
        )
        .await
        .unwrap();

        let expired = jiff::Timestamp::UNIX_EPOCH.to_string();
        sqlx::query!(
            "UPDATE host_tasks SET expires_at = $1 WHERE id = $2",
            expired,
            task
        )
        .execute(&mut *conn)
        .await
        .unwrap();

        let status = db::task::task_status(&mut conn, task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status.state, api::TaskState::Expired);
        let agent = age::x25519::Identity::generate();
        let pending = db::task::pending_tasks_for(&mut conn, host, &identity, &agent.to_public())
            .await
            .unwrap();
        assert_eq!(pending, []);
    }
}
