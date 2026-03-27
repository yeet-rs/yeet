use axum::{
    Json,
    extract::{FromRequest, FromRequestParts, Request},
    http::{self, HeaderMap, StatusCode, header},
};
use ed25519_dalek::VerifyingKey;
use httpsig_hyper::{
    ContentDigest as _, MessageSignature as _, MessageSignatureReq as _, RequestContentDigest as _,
    prelude::{AlgorithmName, PublicKey},
};
use serde::de::DeserializeOwned;

use crate::{
    YeetState, db,
    error::{InternalError, WithStatusCode as _},
};

pub struct HttpSig(pub VerifyingKey);

impl FromRequestParts<YeetState> for HttpSig {
    type Rejection = (StatusCode, String);

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &YeetState,
    ) -> Result<Self, Self::Rejection> {
        Ok(HttpSig(extract_key(parts, state).await?))
    }
}

pub struct User(pub api::UserID);

impl FromRequestParts<YeetState> for User {
    type Rejection = (StatusCode, String);

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &YeetState,
    ) -> Result<Self, Self::Rejection> {
        let user_key = extract_key(parts, state).await?;
        // TODO maybe acquire a connection only once instead of here and in the handler

        let mut conn = state
            .pool
            .acquire()
            .await
            .with_code(StatusCode::INTERNAL_SERVER_ERROR)?;
        let Some(user_id) = db::user::fetch_by_key(&mut conn, user_key)
            .await
            .internal_server()?
        else {
            return Err((
                StatusCode::FORBIDDEN,
                "Key is registered but caller is not an user".to_owned(),
            ));
        };

        Ok(User(user_id))
    }
}

async fn extract_key(
    parts: &mut axum::http::request::Parts,
    state: &YeetState,
) -> Result<VerifyingKey, (StatusCode, String)> {
    // #[cfg(any(test, feature = "test-server"))]
    // {
    //     if let Some(header) = parts.headers.get("key") {
    //         let key = VerifyingKey::from_bytes(
    //             &serde_json::from_slice::<Vec<u8>>(header.as_bytes())
    //                 .unwrap()
    //                 .try_into()
    //                 .unwrap(),
    //         )
    //         .unwrap();
    //         return Ok(key);
    //     } else {
    //         return Ok(VerifyingKey::default());
    //     }
    // };

    let req = http::Request::from_parts(parts.clone(), String::new());

    let keyids = req.get_alg_key_ids().with_code(StatusCode::BAD_REQUEST)?;
    if keyids.len() != 1 {
        return Err((
            StatusCode::BAD_REQUEST,
            "KeyIDs must be exactly one".to_owned(),
        ));
    }

    #[expect(clippy::pattern_type_mismatch)] // I am to dumb for this one
    let (_signature, (alg, keyid)) = keyids
        .first()
        .expect("This is safe as long as we check the keyid length");

    if *alg != Some(AlgorithmName::Ed25519) {
        return Err((
            StatusCode::BAD_REQUEST,
            "Only Ed25519 is supported at the moment".to_owned(),
        ));
    }

    #[expect(clippy::pattern_type_mismatch)] // I am to dumb for this one
    let Some(keyid) = keyid else {
        return Err((
            StatusCode::BAD_REQUEST,
            "Key signature included but no keyid found".to_owned(),
        ));
    };
    // TODO maybe acquire a connection only once instead of here and in the handler

    let mut conn = state
        .pool
        .acquire()
        .await
        .with_code(StatusCode::INTERNAL_SERVER_ERROR)?;

    let Some(verifying_key) = db::keys::fetch_by_keyid(&mut conn, keyid)
        .await
        .with_code(StatusCode::INTERNAL_SERVER_ERROR)?
    else {
        // the db does not have any users so we allow to add the first admin
        if !db::keys::has_any_admin(&mut conn)
            .await
            .with_code(StatusCode::INTERNAL_SERVER_ERROR)?
        {
            return Ok(VerifyingKey::default());
        }

        return Err((
            StatusCode::BAD_REQUEST,
            "The KeyID is not registered".to_owned(),
        ));
    };

    let pub_key = PublicKey::from_bytes(&AlgorithmName::Ed25519, verifying_key.as_bytes())
        .with_code(StatusCode::BAD_REQUEST)?;

    req.verify_message_signature(&pub_key, Some(keyid))
        .await
        .with_code(StatusCode::BAD_REQUEST)?;
    Ok(verifying_key)
}

pub struct VerifiedJson<T>(pub T);

impl<T, S> FromRequest<S> for VerifiedJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request(req: Request, _state: &S) -> Result<Self, Self::Rejection> {
        // #[cfg(not(any(test, feature = "test-server")))]
        let req = req
            .verify_content_digest()
            .await
            .with_code(StatusCode::BAD_REQUEST)?;

        // #[cfg(not(any(test, feature = "test-server")))]
        if !json_content_type(req.headers()) {
            return Err((
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "Expected request with `Content-Type: application/json`".to_owned(),
            ));
        }

        Json::from_bytes(
            &req.into_bytes()
                .await
                .with_code(StatusCode::INTERNAL_SERVER_ERROR)?,
        )
        .with_code(StatusCode::INTERNAL_SERVER_ERROR)
        .map(|json| VerifiedJson(json.0))
    }
}

fn json_content_type(headers: &HeaderMap) -> bool {
    let Some(content_type) = headers.get(header::CONTENT_TYPE) else {
        return false;
    };

    let Ok(content_type) = content_type.to_str() else {
        return false;
    };

    let Ok(mime) = content_type.parse::<mime::Mime>() else {
        return false;
    };

    mime.type_() == "application"
        && (mime.subtype() == "json" || mime.suffix().is_some_and(|name| name == "json"))
}
