use axum::{
    extract::Query,
    http::StatusCode,
    response::{IntoResponse, Redirect},
};
use axum_login::tower_sessions::Session;
use openidconnect::CsrfToken;
use serde::Deserialize;

use crate::{
    auth::{UserCredentials, UserSession},
    login::NEXT_URL_KEY,
};

pub const CSRF_STATE_KEY: &str = "oauth.csrf-state";
pub const NONCE_KEY: &str = "openid.nonce";
pub const CODE_VERIFIER_KEY: &str = "pkce.code_verifier";

#[derive(Debug, Clone, Deserialize)]
pub struct AuthzResp {
    code: String,
    state: CsrfToken,
}

pub async fn callback(
    mut user_session: UserSession,
    session: Session,
    Query(AuthzResp {
        code,
        state: new_state,
    }): Query<AuthzResp>,
) -> impl IntoResponse {
    let Ok(Some(old_state)) = session.get(CSRF_STATE_KEY).await else {
        return StatusCode::BAD_REQUEST.into_response();
    };

    let Ok(Some(nonce)) = session.get(NONCE_KEY).await else {
        return StatusCode::BAD_REQUEST.into_response();
    };

    let Ok(Some(pkce_verifier)) = session.get(CODE_VERIFIER_KEY).await else {
        return StatusCode::BAD_REQUEST.into_response();
    };

    let creds = UserCredentials {
        code,
        old_state,
        new_state,
        pkce_verifier,
        nonce,
    };

    let user = match user_session.authenticate(creds).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return (StatusCode::UNAUTHORIZED, "Invalid CSRF state.").into_response();
        }
        Err(err) => {
            log::debug!("could not authenticate oidc user: {err}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    if let Err(err) = user_session.login(&user).await {
        log::debug!("could not login user: {err}");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };

    if let Ok(Some(next)) = session.remove::<String>(NEXT_URL_KEY).await {
        Redirect::to(&next).into_response()
    } else {
        Redirect::to("/").into_response()
    }
}
