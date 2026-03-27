use ed25519_dalek::VerifyingKey;
use sqlx::Acquire as _;
use sqlx::types::Json;

use crate::db;

pub async fn fetch_by_key(
    conn: &mut sqlx::SqliteConnection,
    key: VerifyingKey,
) -> Result<Option<api::UserID>, sqlx::Error> {
    let key = &key.as_bytes()[..];
    let user = sqlx::query_scalar!(
        r#"
        SELECT users.id from users
        JOIN keys on keys.id = users.key_id
        WHERE verifying_key = $1"#,
        key
    )
    .fetch_optional(conn)
    .await?;

    Ok(user.map(api::UserID::new))
}

// TODO
// pub async fn allow_all_tag(
//     conn: &mut sqlx::SqliteConnection,
//     user: api::UserID,
// ) -> Result<api::auth::TagID, sqlx::Error> {
//     let tag_id = sqlx::query!(r#"UPDATE users SET all_tag = 1 WHERE id = $1"#, user)
//         .execute(conn)
//         .await?
//         .last_insert_rowid();

//     Ok(api::auth::TagID::new(tag_id))
// }

pub async fn create_user(
    conn: &mut sqlx::SqliteConnection,
    keyid: String,
    key: VerifyingKey,
    name: String,
    level: api::AuthLevel,
    all_tag: bool,
) -> Result<api::UserID, sqlx::Error> {
    let mut tx = conn.begin().await?;

    let key = db::keys::add_key(&mut tx, keyid, key).await?;

    let user = sqlx::query!(
        r#"
        INSERT INTO users (key_id, level, username, all_tag)
        VALUES ($1, $2, $3, $4)"#,
        key,
        level,
        name,
        all_tag
    )
    .execute(&mut *tx)
    .await?
    .last_insert_rowid();
    tx.commit().await?;
    Ok(api::UserID::new(user))
}

pub async fn rename_user(
    conn: &mut sqlx::SqliteConnection,
    id: api::UserID,
    new: String,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        UPDATE users
        SET username = $1
        WHERE id = $2"#,
        new,
        id
    )
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn list_users(conn: &mut sqlx::SqliteConnection) -> Result<Vec<api::User>, sqlx::Error> {
    let users = sqlx::query!(
        r#"
        SELECT
            u.id as "id!: api::UserID",
            u.username as "username!",
            u.level as "level!: api::AuthLevel",
            json_group_array(json_object('id', t.id, 'name', t.name)) as "tags!: Json<Vec<api::tag::Tag>>"
        FROM users u
        LEFT JOIN policies p
            ON p.user_id = u.id
            AND u.all_tag != 1
        LEFT JOIN tags t
            ON (u.all_tag = 1 OR p.tag_id = t.id)
        GROUP BY u.id, u.username, u.level;
        "#
    )
    .map(|row| api::User {
        id: row.id,
        username: row.username,
        level: row.level,
        tags: row.tags.0,
    })
    .fetch_all(conn)
    .await?;

    Ok(users)
}
