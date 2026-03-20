use axum::{extract::State, http::StatusCode};
use ed25519_dalek::VerifyingKey;
use httpsig_hyper::prelude::VerifyingKey as _;

use crate::{
    YeetState, db,
    error::{BadRequest as _, InternalError as _},
    httpsig::{HttpSig, VerifiedJson},
};

pub async fn add_key(
    State(state): State<YeetState>,
    HttpSig(http_key): HttpSig,
    VerifiedJson(api::AddKey { key, level }): VerifiedJson<api::AddKey>,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;

    // If we do not have any credentials yet we want to allow adding the first key
    if db::keys::has_any_admin(&mut conn).await.internal_server()? {
        db::keys::auth_admin(&mut conn, http_key).await?;
    }

    let httpsig_key = httpsig_hyper::prelude::PublicKey::from_bytes(
        &httpsig_hyper::prelude::AlgorithmName::Ed25519,
        key.as_bytes(),
    )
    .expect("Verifying key already is validated");

    db::keys::add_user_key(&mut conn, httpsig_key.key_id(), key, level)
        .await
        .bad_request()?;

    Ok(StatusCode::CREATED)
}

pub async fn delete_key(
    State(state): State<YeetState>,
    HttpSig(http_key): HttpSig,
    VerifiedJson(key): VerifiedJson<VerifyingKey>,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;

    db::keys::auth_admin(&mut conn, http_key).await?;

    // deleting this propagates the user credentials deletion
    db::keys::delete_key(&mut conn, key)
        .await
        .internal_server()?;

    Ok(StatusCode::OK)
}
