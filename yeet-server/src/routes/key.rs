use axum::{extract::State, http::StatusCode};
use ed25519_dalek::VerifyingKey;

use crate::{
    YeetState, db,
    error::InternalError as _,
    httpsig::{User, VerifiedJson},
};

pub async fn delete_key(
    State(state): State<YeetState>,
    User(user): User,
    VerifiedJson(key): VerifiedJson<VerifyingKey>,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;

    db::tag::auth_admin(&mut conn, user).await?;
    db::tag::auth_all_tag(&mut conn, user).await?;

    // deleting this propagates the user credentials deletion
    db::keys::delete_key(&mut conn, key)
        .await
        .internal_server()?;

    Ok(StatusCode::OK)
}
