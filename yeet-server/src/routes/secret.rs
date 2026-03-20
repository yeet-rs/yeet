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
    httpsig::{HttpSig, VerifiedJson},
};

pub async fn add_secret(
    State(state): State<YeetState>,
    HttpSig(key): HttpSig,
    Path(name): Path<String>,
    VerifiedJson(secret): VerifiedJson<Vec<u8>>,
) -> Result<Json<api::SecretName>, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::keys::auth_admin(&mut conn, key).await?;

    let id = db::secrets::add_secret(&mut conn, name, secret, &*state.age_key)
        .await
        .bad_request()?;
    Ok(Json(id))
}

pub async fn rename_secret(
    State(state): State<YeetState>,
    HttpSig(key): HttpSig,
    Path((secret_id, name)): Path<(api::SecretID, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::keys::auth_admin(&mut conn, key).await?;
    db::secrets::rename_secret(&mut conn, secret_id, name)
        .await
        .bad_request()?;

    Ok(StatusCode::OK)
}

pub async fn delete_secret(
    State(state): State<YeetState>,
    Path(id): Path<api::SecretID>,
    HttpSig(key): HttpSig,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::keys::auth_admin(&mut conn, key).await?;
    db::secrets::remove_secret(&mut conn, id)
        .await
        .bad_request()?;

    Ok(StatusCode::OK)
}

pub async fn allow_host(
    State(state): State<YeetState>,
    Path((secret_id, host_id)): Path<(api::SecretID, api::HostID)>,
    HttpSig(key): HttpSig,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::keys::auth_admin(&mut conn, key).await?;
    db::secrets::add_access_for(&mut conn, secret_id, host_id)
        .await
        .bad_request()?;

    Ok(StatusCode::OK)
}

pub async fn block_host(
    State(state): State<YeetState>,
    Path((secret_id, host_id)): Path<(api::SecretID, api::HostID)>,
    HttpSig(key): HttpSig,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::keys::auth_admin(&mut conn, key).await?;
    db::secrets::remove_access_for(&mut conn, secret_id, host_id)
        .await
        .bad_request()?;

    Ok(StatusCode::OK)
}

pub async fn list_acl(
    State(state): State<YeetState>,
    HttpSig(key): HttpSig,
) -> Result<Json<Vec<(api::SecretName, Vec<api::HostID>)>>, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::keys::auth_admin(&mut conn, key).await?;
    Ok(Json(db::secrets::list_acl(&mut conn).await.bad_request()?))
}

pub async fn list(
    State(state): State<YeetState>,
    HttpSig(key): HttpSig,
) -> Result<Json<Vec<api::SecretName>>, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::keys::auth_admin(&mut conn, key).await?;
    Ok(Json(
        db::secrets::list_secrets(&mut conn).await.bad_request()?,
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
#[cfg(test)]
mod test_secret {
    use std::{collections::HashMap, str::FromStr};

    use sqlx::SqlitePool;

    #[sqlx::test]
    async fn add_and_get_secret(pool: SqlitePool) {
        let server = crate::test_server(pool.clone()).await;
        let mut conn = pool.acquire().await.unwrap();
        crate::add_default_host(&mut conn).await;
        let identity = age::x25519::Identity::generate();

        let recipient = {
            let recipient: String = server.get("/secret/server_key").await.json();
            age::x25519::Recipient::from_str(&recipient).unwrap()
        };

        let secret = age::encrypt(&recipient, b"plaintext").unwrap();

        let id: api::SecretName = server
            .post("/secret/add/secretstuff")
            .json(&secret)
            .await
            .json();

        server.put(&format!("/secret/{}/allow/1", id.id)).await;

        let secret: Option<Vec<u8>> = server
            .post("/secret")
            .json(&api::GetSecretRequest {
                secret: "secretstuff".to_owned(),
                recipient: identity.to_public().to_string(),
            })
            .await
            .json();
        let decrypted = age::decrypt(&identity, &secret.unwrap()).unwrap();
        assert_eq!(decrypted, b"plaintext")
    }

    #[sqlx::test]
    // secret retrieval is based on the name
    async fn add_rename_and_get_secret(pool: SqlitePool) {
        let server = crate::test_server(pool.clone()).await;
        let mut conn = pool.acquire().await.unwrap();
        crate::add_default_host(&mut conn).await;
        let identity = age::x25519::Identity::generate();

        let recipient = {
            let recipient: String = server.get("/secret/server_key").await.json();
            age::x25519::Recipient::from_str(&recipient).unwrap()
        };

        let secret = age::encrypt(&recipient, b"plaintext").unwrap();

        let id: api::SecretName = server
            .post("/secret/add/secretstuff")
            .json(&secret)
            .await
            .json();

        server.put(&format!("/secret/{}/allow/1", id.id)).await;

        server
            .put(&format!("/secret/{}/rename/mynewname", id.id))
            .await;

        let secret: Option<Vec<u8>> = server
            .post("/secret")
            .json(&api::GetSecretRequest {
                secret: "secretstuff".to_owned(),
                recipient: identity.to_public().to_string(),
            })
            .await
            .json();
        assert!(secret.is_none());

        let secret: Option<Vec<u8>> = server
            .post("/secret")
            .json(&api::GetSecretRequest {
                secret: "mynewname".to_owned(),
                recipient: identity.to_public().to_string(),
            })
            .await
            .json();
        let decrypted = age::decrypt(&identity, &secret.unwrap()).unwrap();
        assert_eq!(decrypted, b"plaintext")
    }

    #[sqlx::test]
    async fn secret_deletion(pool: SqlitePool) {
        let server = crate::test_server(pool.clone()).await;
        let mut conn = pool.acquire().await.unwrap();
        crate::add_default_host(&mut conn).await;
        let identity = age::x25519::Identity::generate();

        let recipient = {
            let recipient: String = server.get("/secret/server_key").await.json();
            age::x25519::Recipient::from_str(&recipient).unwrap()
        };

        let secret = age::encrypt(&recipient, b"plaintext").unwrap();

        let id: api::SecretName = server
            .post("/secret/add/secretstuff")
            .json(&secret)
            .await
            .json();

        server.delete(&format!("/secret/{}/delete", id.id)).await;

        let secret: Option<Vec<u8>> = server
            .post("/secret")
            .json(&api::GetSecretRequest {
                secret: "secretstuff".to_owned(),
                recipient: identity.to_public().to_string(),
            })
            .await
            .json();
        // Should be Ok(None) because the secret does not exist anymore
        assert!(secret.is_none());
    }

    #[sqlx::test]
    // host that has no acces tries to get a secret
    async fn unauthorized(pool: SqlitePool) {
        let server = crate::test_server(pool.clone()).await;
        let mut conn = pool.acquire().await.unwrap();
        crate::add_default_host(&mut conn).await;
        let identity = age::x25519::Identity::generate();

        let recipient = {
            let recipient: String = server.get("/secret/server_key").await.json();
            age::x25519::Recipient::from_str(&recipient).unwrap()
        };

        let secret = age::encrypt(&recipient, b"plaintext").unwrap();

        let _id: api::SecretName = server
            .post("/secret/add/secretstuff")
            .json(&secret)
            .await
            .json();

        let secret: Option<Vec<u8>> = server
            .post("/secret")
            .json(&api::GetSecretRequest {
                secret: "secretstuff".to_owned(),
                recipient: identity.to_public().to_string(),
            })
            .await
            .json();

        // None is expected because he has no access
        assert!(secret.is_none())
    }

    #[sqlx::test]
    async fn list_secrets(pool: SqlitePool) {
        let server = crate::test_server(pool.clone()).await;
        let mut conn = pool.acquire().await.unwrap();
        crate::add_default_host(&mut conn).await;

        let recipient = {
            let recipient: String = server.get("/secret/server_key").await.json();
            age::x25519::Recipient::from_str(&recipient).unwrap()
        };

        let secret = age::encrypt(&recipient, b"plaintext").unwrap();

        let id: api::SecretName = server
            .post("/secret/add/secretstuff")
            .json(&secret)
            .await
            .json();

        let secrets: Vec<api::SecretName> = server.get("/secret/list").await.json();

        assert_eq!(secrets, vec![id]);
    }

    #[sqlx::test]
    async fn get_secret_acl(pool: SqlitePool) {
        let server = crate::test_server(pool.clone()).await;
        let mut conn = pool.acquire().await.unwrap();
        crate::add_default_host(&mut conn).await;

        let recipient = {
            let recipient: String = server.get("/secret/server_key").await.json();
            age::x25519::Recipient::from_str(&recipient).unwrap()
        };

        let secret = age::encrypt(&recipient, b"plaintext").unwrap();

        let id: api::SecretName = server
            .post("/secret/add/secretstuff")
            .json(&secret)
            .await
            .json();

        server.put(&format!("/secret/{}/allow/1", id.id)).await;

        let acl: Vec<(api::SecretName, Vec<api::HostID>)> = server.get("/secret/acl").await.json();

        assert_eq!(acl.get(0).unwrap().1, vec![api::HostID::new(1)])
    }

    #[sqlx::test]
    async fn no_secret(pool: SqlitePool) {
        let server = crate::test_server(pool.clone()).await;
        let mut conn = pool.acquire().await.unwrap();
        crate::add_default_host(&mut conn).await;
        let identity = age::x25519::Identity::generate();

        let secret: Option<Vec<u8>> = server
            .post("/secret")
            .json(&api::GetSecretRequest {
                secret: "secretstuff".to_owned(),
                recipient: identity.to_public().to_string(),
            })
            .await
            .json();

        assert!(secret.is_none())
    }
}
