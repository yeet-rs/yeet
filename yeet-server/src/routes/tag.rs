use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};

use crate::{
    YeetState, db,
    error::{BadRequest as _, InternalError as _},
    httpsig::{User, VerifiedJson},
};

pub async fn create_tag(
    State(state): State<YeetState>,
    User(user): User,
    Path(name): Path<String>,
) -> Result<Json<api::tag::TagID>, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::tag::auth_admin(&mut conn, user).await?;
    db::tag::auth_all_tag(&mut conn, user).await?;

    Ok(Json(
        db::tag::create_tag(&mut conn, name).await.bad_request()?,
    ))
}

pub async fn rename_tag(
    State(state): State<YeetState>,
    User(user): User,
    Path((tag, name)): Path<(api::tag::TagID, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::tag::auth_admin(&mut conn, user).await?;
    db::tag::auth_all_tag(&mut conn, user).await?;
    db::tag::rename_tag(&mut conn, tag, name)
        .await
        .bad_request()?;

    Ok(StatusCode::OK)
}

pub async fn delete_tag(
    State(state): State<YeetState>,
    User(user): User,
    Path(tag): Path<api::tag::TagID>,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::tag::auth_admin(&mut conn, user).await?;
    db::tag::auth_all_tag(&mut conn, user).await?;
    db::tag::delete_tag(&mut conn, tag).await.bad_request()?;

    Ok(StatusCode::OK)
}

pub async fn allow_user(
    State(state): State<YeetState>,
    User(user): User,
    Path((tag, user_id)): Path<(api::tag::TagID, api::UserID)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::tag::auth_admin(&mut conn, user).await?;
    db::tag::auth_all_tag(&mut conn, user).await?;
    db::tag::allow_user_on_tag(&mut conn, user_id, tag)
        .await
        .bad_request()?;

    Ok(StatusCode::OK)
}

pub async fn remove_user(
    State(state): State<YeetState>,
    User(user): User,
    Path((tag, user_id)): Path<(api::tag::TagID, api::UserID)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::tag::auth_admin(&mut conn, user).await?;
    db::tag::auth_all_tag(&mut conn, user).await?;
    db::tag::remove_user_from_tag(&mut conn, user_id, tag)
        .await
        .bad_request()?;

    Ok(StatusCode::OK)
}

pub async fn add_resource_tag(
    State(state): State<YeetState>,
    User(user): User,
    VerifiedJson(api::tag::ResourceTag { tag, resource }): VerifiedJson<api::tag::ResourceTag>,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::tag::auth_admin(&mut conn, user).await?;
    db::tag::auth_all_tag(&mut conn, user).await?;
    db::tag::add_resource_to_tag(&mut conn, resource, tag)
        .await
        .bad_request()?;

    Ok(StatusCode::OK)
}

pub async fn delete_resource_tag(
    State(state): State<YeetState>,
    User(user): User,
    VerifiedJson(api::tag::ResourceTag { tag, resource }): VerifiedJson<api::tag::ResourceTag>,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::tag::auth_admin(&mut conn, user).await?;
    db::tag::auth_all_tag(&mut conn, user).await?;
    db::tag::delete_resource_from_tag(&mut conn, resource, tag)
        .await
        .bad_request()?;

    Ok(StatusCode::OK)
}

pub async fn list_tags(
    State(state): State<YeetState>,
    User(user): User,
) -> Result<Json<Vec<api::tag::Tag>>, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::tag::auth_admin(&mut conn, user).await?;
    db::tag::auth_all_tag(&mut conn, user).await?;
    Ok(Json(db::tag::list_tags(&mut conn).await.internal_server()?))
}
