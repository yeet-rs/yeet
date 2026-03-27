use ed25519_dalek::VerifyingKey;

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

pub async fn has_any_admin(conn: &mut sqlx::SqliteConnection) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query!(r#"SELECT 1 AS "col" FROM users LIMIT 1"#)
        .fetch_optional(conn)
        .await?
        .is_some())
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
