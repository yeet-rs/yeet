use axum::http::StatusCode;
use ed25519_dalek::VerifyingKey;
use jiff_sqlx::ToSqlx;
use serde::Deserialize;

#[derive(thiserror::Error, Debug, axum_thiserror::ErrorStatus)]
pub enum KeyError {
    #[error(transparent)]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    SQLXError(#[from] sqlx::Error),
}
type Result<T> = core::result::Result<T, KeyError>;

#[derive(Clone, Copy, Debug, sqlx::Type, Deserialize)]
#[sqlx(transparent)]
pub struct HostID(pub(super) i64);
pub async fn host_by_key(
    conn: &mut sqlx::SqliteConnection,
    key: VerifyingKey,
) -> Result<Option<String>> {
    let key = &key.as_bytes()[..];
    Ok(sqlx::query_scalar!(
        r#"SELECT hostname from hosts WHERE verifying_key = $1"#,
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
    let now = jiff::Timestamp::now().to_sqlx();
    let key = &key.as_bytes()[..];
    let host = sqlx::query!(
        r#"
        INSERT INTO hosts (keyid, verifying_key, hostname, last_ping)
        VALUES ($1, $2, $3, $4)"#,
        keyid,
        key,
        hostname,
        now
    )
    .execute(conn)
    .await?;
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
