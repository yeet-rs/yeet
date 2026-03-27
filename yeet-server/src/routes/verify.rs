/// The goal is to no longer require the pub key at registration of the host.
/// Rather any unauthenticated client can try an `verification_attempt` and supply his public key.
/// This then generates a six digit number which the admin has to retrieve from the client (not the server!)
/// This ensure that the identity of the host is verified.
/// However the identity model is now flipped. Instead of just identifying the host based on
/// the public key it is now tied to an arbitrary name.
/// We could make it so that the client saves its hostname either by looking at its hostname
/// or via config. An other solution would be that when you run `yeet approve` and input the clients
/// one time pin that you also have to input the hostname that it should be associated with.
///
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};

use crate::{
    YeetState, db,
    error::{BadRequest as _, InternalError as _},
    httpsig::{HttpSig, User, VerifiedJson},
};

/// That is literally it because the `HttpSig` extractor checks if the key is in the keyids
pub async fn is_host_verified(HttpSig(_http_key): HttpSig) -> StatusCode {
    StatusCode::OK
}

/// Adds a new key as an verification attempt
pub async fn add_verification_attempt(
    State(state): State<YeetState>,
    Json(attempt): Json<api::VerificationAttempt>,
) -> Result<Json<i64>, (StatusCode, String)> {
    // TODO: check if httsig is correct so that non key owners can not send verification attempts
    // Altough this is not a security risk because even if you create an foreign attempt still only the key holder get authorized
    let mut conn = state.pool.acquire().await.internal_server()?;

    let code =
        db::verification::add_verification_attempt(&mut conn, attempt.key, attempt.nixos_facter)
            .await
            .bad_request()?;

    Ok(Json(code))
}

/// Accept an verification attempt
pub async fn accept_attempt(
    State(state): State<YeetState>,
    User(user): User,
    Path(id): Path<u32>,
    VerifiedJson(hostname): VerifiedJson<String>,
) -> Result<Json<Option<String>>, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::tag::auth_admin(&mut conn, user).await?;
    db::tag::auth_all_tag(&mut conn, user).await?;

    // TODO: return Bad request if key does not exist
    let facter = db::verification::accept_attempt(&mut conn, i64::from(id), hostname)
        .await
        .bad_request()?;

    Ok(Json(facter))
}
