use axum::http::StatusCode;

use crate::error::InternalError as _;

pub async fn create_tag(
    conn: &mut sqlx::SqliteConnection,
    name: String,
) -> Result<api::tag::TagID, sqlx::Error> {
    let tag_id = sqlx::query!(r#"INSERT INTO tags (name) VALUES ($1)"#, name)
        .execute(conn)
        .await?
        .last_insert_rowid();

    Ok(api::tag::TagID::new(tag_id))
}

pub async fn rename_tag(
    conn: &mut sqlx::SqliteConnection,
    id: api::tag::TagID,
    new: String,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        UPDATE tags
        SET name = $1
        WHERE id = $2"#,
        new,
        id
    )
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn delete_tag(
    conn: &mut sqlx::SqliteConnection,
    tag: api::tag::TagID,
) -> Result<(), sqlx::Error> {
    sqlx::query!(r#"DELETE FROM tags WHERE id = $1"#, tag)
        .execute(conn)
        .await?;
    Ok(())
}

pub async fn add_resource_to_tag(
    conn: &mut sqlx::SqliteConnection,
    resource: api::tag::Resource,
    tag: api::tag::TagID,
) -> Result<api::tag::TagID, sqlx::Error> {
    let resource_id = i64::from(resource);
    let resource_type = api::tag::ResourceType::from(resource);
    let tag_id = sqlx::query!(
        r#"INSERT INTO resource_tags (resource_id, resource_type, tag_id)
        VALUES ($1,$2,$3)"#,
        resource_id,
        resource_type,
        tag
    )
    .execute(conn)
    .await?
    .last_insert_rowid();

    Ok(api::tag::TagID::new(tag_id))
}

pub async fn delete_resource_from_tag(
    conn: &mut sqlx::SqliteConnection,
    resource: api::tag::Resource,
    tag: api::tag::TagID,
) -> Result<(), sqlx::Error> {
    let resource_id = i64::from(resource);
    let resource_type = api::tag::ResourceType::from(resource);
    sqlx::query!(
        r#"DELETE FROM resource_tags WHERE resource_id = $1 AND resource_type = $2 AND tag_id = $3"#,
        resource_id,
        resource_type,
        tag
    )
    .execute(conn)
    .await?;

    Ok(())
}

pub async fn allow_user_on_tag(
    conn: &mut sqlx::SqliteConnection,
    user: api::UserID,
    tag: api::tag::TagID,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"INSERT INTO policies (user_id, tag_id)
        VALUES ($1,$2)"#,
        user,
        tag
    )
    .execute(conn)
    .await?;

    Ok(())
}

pub async fn remove_user_from_tag(
    conn: &mut sqlx::SqliteConnection,
    user: api::UserID,
    tag: api::tag::TagID,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"DELETE FROM policies WHERE user_id = $1 AND tag_id = $2"#,
        user,
        tag
    )
    .execute(conn)
    .await?;

    Ok(())
}

pub async fn auth_tag(
    conn: &mut sqlx::SqliteConnection,
    user: api::UserID,
    resource: api::tag::Resource,
) -> Result<(), (StatusCode, String)> {
    let resource_id = i64::from(resource);
    let resource_type = api::tag::ResourceType::from(resource);
    let policy = sqlx::query_scalar!(
        r#"
        SELECT user_id FROM access
        WHERE user_id = $1 AND resource_type = $2 AND resource_id = $3"#,
        user,
        resource_type,
        resource_id
    )
    .fetch_optional(conn)
    .await
    .internal_server()?;
    if policy.is_none() {
        Err((
            StatusCode::FORBIDDEN,
            "You have no permission to access this resource".to_owned(),
        ))
    } else {
        Ok(())
    }
}

pub async fn auth_all_tag(
    conn: &mut sqlx::SqliteConnection,
    user: api::UserID,
) -> Result<(), (StatusCode, String)> {
    if is_all_tag(&mut *conn, user).await.internal_server()? {
        return Ok(());
    } else {
        Err((
            StatusCode::FORBIDDEN,
            "You have no permission to access this resource".to_owned(),
        ))
    }
}

pub async fn list_tags(
    conn: &mut sqlx::SqliteConnection,
) -> Result<Vec<api::tag::Tag>, sqlx::Error> {
    let tags = sqlx::query!(
        r#"
        SELECT
            tags.id as "id: api::tag::TagID",
            tags.name
        FROM tags
        "#
    )
    .map(|row| api::tag::Tag {
        id: row.id,
        name: row.name,
    })
    .fetch_all(conn)
    .await?;
    Ok(tags)
}

pub async fn is_all_tag(
    conn: &mut sqlx::SqliteConnection,
    user: api::UserID,
) -> Result<bool, sqlx::Error> {
    let all_tags = sqlx::query_scalar!(
        r#"
        SELECT id FROM users
        WHERE id = $1 AND all_tag = 1"#,
        user
    )
    .fetch_optional(conn)
    .await?;

    Ok(all_tags.is_some())
}

pub async fn auth_admin(
    conn: &mut sqlx::SqliteConnection,
    user: api::UserID,
) -> Result<(), (StatusCode, String)> {
    auth_level(conn, user, api::AuthLevel::Admin).await
}

pub async fn auth_build(
    conn: &mut sqlx::SqliteConnection,
    user: api::UserID,
) -> Result<(), (StatusCode, String)> {
    auth_level(conn, user, api::AuthLevel::Build).await
}

pub async fn auth_osquery(
    conn: &mut sqlx::SqliteConnection,
    user: api::UserID,
) -> Result<(), (StatusCode, String)> {
    auth_level(conn, user, api::AuthLevel::Osquery).await
}

pub async fn auth_level(
    conn: &mut sqlx::SqliteConnection,
    user: api::UserID,
    level: api::AuthLevel,
) -> Result<(), (StatusCode, String)> {
    // #[cfg(any(test, feature = "test-server"))]
    // return Ok(());

    let user_level = sqlx::query_scalar!(
        r#"
        SELECT level AS "level: api::AuthLevel" FROM users
        WHERE id = $1"#,
        user
    )
    .fetch_optional(conn)
    .await
    .internal_server()?;

    match user_level {
        Some(user_level) => {
            if user_level == level || user_level == api::AuthLevel::Admin {
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
