use axum::{
    extract::Query,
    http::StatusCode,
    response::{IntoResponse, Redirect},
};
use axum_login::tower_sessions::Session;
use serde::Deserialize;

use crate::{auth::UserSession, oauth::CSRF_STATE_KEY};

pub const NEXT_URL_KEY: &str = "auth.next-url";

// This allows us to extract the "next" field from the query string. We use this
// to redirect after log in.
#[derive(Debug, Deserialize)]
pub struct NextUrl {
    next: Option<String>,
}

use crate::oauth::{CODE_VERIFIER_KEY, NONCE_KEY};

pub async fn login(
    user_session: UserSession,
    session: Session,
    Query(NextUrl { next }): Query<NextUrl>,
) -> impl IntoResponse {
    let (auth_url, csrf_state, nonce, pkce_verifier) = user_session.backend.authorize_url().await;

    // associate the openid auth attempt with the user session

    session
        .insert(CSRF_STATE_KEY, csrf_state.secret())
        .await
        .expect("Serialization should not fail.");

    session
        .insert(NEXT_URL_KEY, next)
        .await
        .expect("Serialization should not fail.");

    session
        .insert(CODE_VERIFIER_KEY, pkce_verifier)
        .await
        .expect("Serialization should not fail.");

    session
        .insert(NONCE_KEY, nonce)
        .await
        .expect("Serialization should not fail.");

    Redirect::to(auth_url.as_str()).into_response()
}

pub async fn logout(mut user_session: UserSession) -> impl IntoResponse {
    match user_session.logout().await {
        Ok(_) => Redirect::to("/").into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
