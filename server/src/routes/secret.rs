use std::str::FromStr as _;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};

use crate::{
    YeetState,
    db::{self},
    error::{BadRequest as _, InternalError as _, WithStatusCode as _},
    httpsig::{HttpSig, User, VerifiedJson},
};

pub async fn add_secret(
    State(state): State<YeetState>,
    User(user): User,
    Path(name): Path<String>,
    VerifiedJson(secret): VerifiedJson<Vec<u8>>,
) -> Result<Json<api::SecretName>, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::tag::auth_admin(&mut conn, user).await?;
    db::tag::auth_all_tag(&mut conn, user).await?;

    let id = db::secrets::add_secret(&mut conn, name, secret, &*state.age_key)
        .await
        .bad_request()?;
    Ok(Json(id))
}

pub async fn rename_secret(
    State(state): State<YeetState>,
    User(user): User,
    Path((secret_id, name)): Path<(api::SecretID, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::tag::auth_admin(&mut conn, user).await?;
    db::tag::auth_tag(&mut conn, user, secret_id.into()).await?;
    db::secrets::rename_secret(&mut conn, secret_id, name)
        .await
        .bad_request()?;

    Ok(StatusCode::OK)
}

pub async fn delete_secret(
    State(state): State<YeetState>,
    Path(id): Path<api::SecretID>,
    User(user): User,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::tag::auth_admin(&mut conn, user).await?;
    db::tag::auth_tag(&mut conn, user, id.into()).await?;
    db::secrets::remove_secret(&mut conn, id)
        .await
        .bad_request()?;

    Ok(StatusCode::OK)
}

pub async fn allow_host(
    State(state): State<YeetState>,
    Path((secret_id, host_id)): Path<(api::SecretID, api::HostID)>,
    User(user): User,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::tag::auth_admin(&mut conn, user).await?;
    db::tag::auth_tag(&mut conn, user, secret_id.into()).await?;
    db::tag::auth_tag(&mut conn, user, host_id.into()).await?;

    db::secrets::add_access_for(&mut conn, secret_id, host_id)
        .await
        .bad_request()?;

    Ok(StatusCode::OK)
}

pub async fn block_host(
    State(state): State<YeetState>,
    Path((secret_id, host_id)): Path<(api::SecretID, api::HostID)>,
    User(user): User,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::tag::auth_admin(&mut conn, user).await?;
    db::tag::auth_tag(&mut conn, user, secret_id.into()).await?;
    db::tag::auth_tag(&mut conn, user, host_id.into()).await?;

    db::secrets::remove_access_for(&mut conn, secret_id, host_id)
        .await
        .bad_request()?;

    Ok(StatusCode::OK)
}

pub async fn list_secrets(
    State(state): State<YeetState>,
    User(user): User,
) -> Result<Json<Vec<api::SecretName>>, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::tag::auth_admin(&mut conn, user).await?;

    Ok(Json(
        db::secrets::list_secrets(&mut conn, user)
            .await
            .bad_request()?,
    ))
}

pub async fn get_server_age_key(
    State(state): State<YeetState>,
    HttpSig(_key): HttpSig,
) -> Json<String> {
    Json(state.age_key.to_public().to_string())
}

pub async fn get_secret(
    State(state): State<YeetState>,
    // can't use user because these are hosts TODO: maybe add a HOST extractor
    HttpSig(key): HttpSig,
    VerifiedJson(api::GetSecretRequest { secret, recipient }): VerifiedJson<api::GetSecretRequest>,
) -> Result<Json<Option<Vec<u8>>>, (StatusCode, String)> {
    let mut conn = state
        .pool
        .acquire()
        .await
        .with_code(StatusCode::INTERNAL_SERVER_ERROR)?;

    let Some(host) = db::hosts::host_by_verify_key(&mut conn, key)
        .await
        .internal_server()?
    else {
        return Err((
            StatusCode::FORBIDDEN,
            "Unknown keyid. You are not a registered host".to_owned(),
        ));
    };

    let recipient =
        age::x25519::Recipient::from_str(&recipient).with_code(StatusCode::BAD_REQUEST)?;

    let secret = db::secrets::get_secret_for(&mut conn, &secret, &*state.age_key, host, &recipient)
        .await
        .bad_request()?;

    Ok(Json(secret))
}
