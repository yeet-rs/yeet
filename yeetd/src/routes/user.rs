use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use httpsig_hyper::prelude::VerifyingKey as _;

use crate::{
    YeetState, db,
    error::{BadRequest as _, InternalError as _},
    httpsig::{HttpSig, User, VerifiedJson},
};

pub async fn create_user(
    State(state): State<YeetState>,
    HttpSig(http_key): HttpSig,
    VerifiedJson(api::CreateUser {
        key,
        level,
        username,
        all_tag: all_tags,
    }): VerifiedJson<api::CreateUser>,
) -> Result<Json<api::UserID>, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;

    // If we do not have any credentials yet we want to allow adding the first key
    if db::keys::has_any_admin(&mut conn).await.internal_server()? {
        let Some(user) = db::user::fetch_by_key(&mut conn, http_key)
            .await
            .internal_server()?
        else {
            return Err((
                StatusCode::FORBIDDEN,
                "Key is registered but caller is not an user".to_owned(),
            ));
        };
        db::tag::auth_admin(&mut conn, user).await?;
        db::tag::auth_all_tag(&mut conn, user).await?;
    }

    let httpsig_key = httpsig_hyper::prelude::PublicKey::from_bytes(
        &httpsig_hyper::prelude::AlgorithmName::Ed25519,
        key.as_bytes(),
    )
    .expect("Verifying key already is validated");

    Ok(Json(
        db::user::create_user(
            &mut conn,
            httpsig_key.key_id(),
            key,
            username,
            level,
            all_tags,
        )
        .await
        .bad_request()?,
    ))
}

pub async fn rename_user(
    State(state): State<YeetState>,
    User(user): User,
    Path((user_id, name)): Path<(api::UserID, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::tag::auth_admin(&mut conn, user).await?;
    db::tag::auth_all_tag(&mut conn, user).await?;
    db::user::rename_user(&mut conn, user_id, name)
        .await
        .bad_request()?;

    Ok(StatusCode::OK)
}

pub async fn list_users(
    State(state): State<YeetState>,
    User(user): User,
) -> Result<Json<Vec<api::User>>, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::tag::auth_admin(&mut conn, user).await?;
    db::tag::auth_all_tag(&mut conn, user).await?;
    Ok(Json(
        db::user::list_users(&mut conn).await.internal_server()?,
    ))
}
