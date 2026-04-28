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

pub async fn store(
    State(state): State<YeetState>,
    // can't use user because these are hosts TODO: maybe add a HOST extractor
    HttpSig(key): HttpSig,
    Path(name): Path<String>,
    VerifiedJson(secret): VerifiedJson<Vec<u8>>,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;

    let Some(host) = db::hosts::host_by_verify_key(&mut conn, key)
        .await
        .internal_server()?
    else {
        return Err((
            StatusCode::FORBIDDEN,
            "Unknown keyid. You are not a registered host".to_owned(),
        ));
    };

    db::artifact::store_artifact(&mut conn, name, host, secret, &*state.age_key)
        .await
        .bad_request()?;
    Ok(StatusCode::CREATED)
}

pub async fn list(
    State(state): State<YeetState>,
    User(user): User,
) -> Result<Json<Vec<api::Artifact>>, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::tag::auth_admin(&mut conn, user).await?;

    Ok(Json(
        db::artifact::list(&mut conn, user).await.bad_request()?,
    ))
}

pub async fn get_latest(
    State(state): State<YeetState>,
    // can't use user because these are hosts TODO: maybe add a HOST extractor
    HttpSig(key): HttpSig,
    Path(name): Path<String>,
    VerifiedJson(recipient): VerifiedJson<String>,
) -> Result<Json<Option<Vec<u8>>>, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;

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

    let artifact = db::artifact::get_latest(&mut conn, &name, &*state.age_key, host, &recipient)
        .await
        .bad_request()?;
    Ok(Json(artifact))
}

pub async fn get_artifact(
    State(state): State<YeetState>,

    User(user): User,
    Path(id): Path<api::ArtifactID>,
    VerifiedJson(recipient): VerifiedJson<String>,
) -> Result<Json<Vec<u8>>, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::tag::auth_admin(&mut conn, user).await?;

    // artifacts do not have tags themself but inherti the ones of the host
    let host = db::artifact::get_owner(&mut conn, id).await.bad_request()?;
    db::tag::auth_tag(&mut conn, user, host.into()).await?;

    let recipient =
        age::x25519::Recipient::from_str(&recipient).with_code(StatusCode::BAD_REQUEST)?;

    let artifact = db::artifact::get_artifact(&mut conn, id, &*state.age_key, &recipient)
        .await
        .bad_request()?;
    Ok(Json(artifact))
}
