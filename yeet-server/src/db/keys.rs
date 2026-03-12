use axum::http::StatusCode;
use ed25519_dalek::VerifyingKey;

#[derive(thiserror::Error, Debug, axum_thiserror::ErrorStatus)]
pub enum KeyError {
    #[error(transparent)]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    SQLXError(#[from] sqlx::Error),
}
type Result<T> = core::result::Result<T, KeyError>;

pub async fn fetch_by_keyid(
    conn: &mut sqlx::SqliteConnection,
    keyid: &String,
) -> Result<Option<VerifyingKey>> {
    let key = sqlx::query_scalar!(
        r#"
        SELECT verifying_key FROM keys
        WHERE keyid = $1"#,
        keyid
    )
    .fetch_optional(conn)
    .await?;
    match key {
        Some(key) => Ok(Some(
            VerifyingKey::from_bytes(
                &key.try_into()
                    .expect("We never store anything else than verifying keys"),
            )
            .expect("Verifying key already is validated"),
        )),
        None => Ok(None),
    }
}
