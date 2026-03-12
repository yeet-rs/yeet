use axum::http::StatusCode;
use ed25519_dalek::VerifyingKey;
use jiff_sqlx::ToSqlx;
use serde::Deserialize;
use sqlx::Acquire;

#[derive(thiserror::Error, Debug, axum_thiserror::ErrorStatus)]
pub enum HostError {
    #[error(transparent)]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    SQLXError(#[from] sqlx::Error),
}
type Result<T> = core::result::Result<T, HostError>;

#[derive(Clone, Copy, Debug, sqlx::Type, Deserialize)]
#[sqlx(transparent)]
pub struct HostID(pub(super) i64);
pub async fn host_by_verify_key(
    conn: &mut sqlx::SqliteConnection,
    key: VerifyingKey,
) -> Result<Option<String>> {
    let key = &key.as_bytes()[..];
    Ok(sqlx::query_scalar!(
        r#"
        SELECT hostname FROM hosts
        LEFT JOIN keys on hosts.key_id = keys.id
        WHERE verifying_key = $1"#,
        key
    )
    .fetch_optional(conn)
    .await?)
}

pub async fn add_host(
    conn: &mut sqlx::SqliteConnection,
    keyid: String,
    key: VerifyingKey,
    hostname: String,
) -> Result<HostID> {
    let mut tx = conn.begin().await?;
    let now = jiff::Timestamp::now().to_sqlx();
    let key = &key.as_bytes()[..];
    let key = sqlx::query!(
        r#"
        INSERT INTO keys (keyid, verifying_key)
        VALUES ($1, $2)"#,
        keyid,
        key
    )
    .execute(&mut *tx)
    .await?
    .last_insert_rowid();

    let host = sqlx::query!(
        r#"
        INSERT INTO hosts (hostname, last_ping, key_id)
        VALUES ($1, $2, $3)"#,
        hostname,
        now,
        key
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(HostID(host.last_insert_rowid()))
}

pub async fn remove_host(conn: &mut sqlx::SqliteConnection, host: HostID) -> Result<()> {
    sqlx::query!(r#"DELETE FROM hosts WHERE id = $1"#, host)
        .execute(conn)
        .await?;
    Ok(())
}

// pub async fn add_version(conn: &mut sqlx::SqliteConnection, host: HostID,store_path) -> Result<()> {
//     sqlx::query!(r#"DELETE FROM hosts WHERE id = $1"#, host)
//         .execute(conn)
//         .await?;
//     Ok(())
// }
