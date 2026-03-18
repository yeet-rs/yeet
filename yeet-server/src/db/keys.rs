use api::AuthLevel;
use axum::http::StatusCode;
use ed25519_dalek::VerifyingKey;
use sqlx::Acquire as _;

use crate::{db, error::InternalError};

pub async fn fetch_by_keyid(
    conn: &mut sqlx::SqliteConnection,
    keyid: &String,
) -> Result<Option<VerifyingKey>, sqlx::Error> {
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

pub async fn add_key(
    conn: &mut sqlx::SqliteConnection,
    keyid: String,
    key: VerifyingKey,
) -> Result<i64, sqlx::Error> {
    let key = &key.as_bytes()[..];
    Ok(sqlx::query!(
        r#"
        INSERT INTO keys (keyid, verifying_key)
        VALUES ($1, $2)"#,
        keyid,
        key
    )
    .execute(conn)
    .await?
    .last_insert_rowid())
}

pub async fn delete_key(
    conn: &mut sqlx::SqliteConnection,
    key: VerifyingKey,
) -> Result<(), sqlx::Error> {
    let key = &key.as_bytes()[..];
    sqlx::query!(r#"DELETE FROM keys WHERE verifying_key = $1"#, key)
        .execute(conn)
        .await?;
    Ok(())
}

pub async fn add_user_key(
    conn: &mut sqlx::SqliteConnection,
    keyid: String,
    key: VerifyingKey,
    level: AuthLevel,
) -> Result<(), sqlx::Error> {
    let mut tx = conn.begin().await?;

    let key = db::keys::add_key(&mut *tx, keyid, key).await?;

    // TODO: return userid
    let _user = sqlx::query!(
        r#"
        INSERT INTO users (key_id, level)
        VALUES ($1, $2)"#,
        key,
        level
    )
    .execute(&mut *tx)
    .await?
    .last_insert_rowid();
    tx.commit().await?;
    Ok(())
}

pub async fn auth_admin(
    conn: &mut sqlx::SqliteConnection,
    key: VerifyingKey,
) -> Result<(), (StatusCode, String)> {
    auth_level(conn, key, AuthLevel::Admin).await
}

pub async fn auth_build(
    conn: &mut sqlx::SqliteConnection,
    key: VerifyingKey,
) -> Result<(), (StatusCode, String)> {
    auth_level(conn, key, AuthLevel::Build).await
}

pub async fn auth_level(
    conn: &mut sqlx::SqliteConnection,
    key: VerifyingKey,
    level: AuthLevel,
) -> Result<(), (StatusCode, String)> {
    #[cfg(any(test, feature = "test-server"))]
    return Ok(());

    let key = &key.as_bytes()[..];

    let user_level = sqlx::query_scalar!(
        r#"
        SELECT level AS "level: api::AuthLevel" FROM users
        LEFT JOIN keys ON users.key_id = keys.id
        WHERE verifying_key = $1"#,
        key
    )
    .fetch_optional(conn)
    .await
    .internal_server()?;

    match user_level {
        Some(user_level) => {
            if user_level == level {
                Ok(())
            } else {
                Err((
                    StatusCode::FORBIDDEN,
                    "Key is registered but you have not the required permissions".to_owned(),
                ))
            }
        }
        None => Err((
            StatusCode::FORBIDDEN,
            "Key is registered but has no AuthLevel associated".to_owned(),
        )),
    }
}
