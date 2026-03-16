use std::{collections::HashMap, str::FromStr};

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};

use crate::{
    YeetState,
    db::{self},
    error::{BadRequest, InternalError, WithStatusCode},
    httpsig::{HttpSig, VerifiedJson},
};

pub async fn add_secret(
    State(state): State<YeetState>,
    HttpSig(_key): HttpSig,
    Path(name): Path<String>,
    VerifiedJson(api::AddSecretRequest { secret }): VerifiedJson<api::AddSecretRequest>,
) -> Result<Json<api::SecretID>, (StatusCode, String)> {
    // state.auth_admin(&key)?;
    let mut conn = state.pool.acquire().await.internal_server()?;

    let id = db::secrets::add_secret(&mut conn, name, secret, &*state.age_key)
        .await
        .bad_request()?;
    Ok(Json(id))
}

pub async fn rename_secret(
    State(state): State<YeetState>,
    HttpSig(_key): HttpSig,
    Path((secret_id, name)): Path<(api::SecretID, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    // state.auth_admin(&key)?;

    let mut conn = state.pool.acquire().await.internal_server()?;
    db::secrets::rename_secret(&mut conn, secret_id, name)
        .await
        .bad_request()?;

    Ok(StatusCode::OK)
}

pub async fn delete_secret(
    State(state): State<YeetState>,
    Path(id): Path<api::SecretID>,
    HttpSig(_key): HttpSig,
) -> Result<StatusCode, (StatusCode, String)> {
    // state.auth_admin(&key)?;
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::secrets::remove_secret(&mut conn, id)
        .await
        .bad_request()?;

    Ok(StatusCode::OK)
}

pub async fn allow_host(
    State(state): State<YeetState>,
    Path((secret_id, host_id)): Path<(api::SecretID, api::HostID)>,
    HttpSig(_key): HttpSig,
) -> Result<StatusCode, (StatusCode, String)> {
    // state.auth_admin(&key)?;
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::secrets::add_access_for(&mut conn, secret_id, host_id)
        .await
        .bad_request()?;

    Ok(StatusCode::OK)
}

pub async fn block_host(
    State(state): State<YeetState>,
    Path((secret_id, host_id)): Path<(api::SecretID, api::HostID)>,
    HttpSig(_key): HttpSig,
) -> Result<StatusCode, (StatusCode, String)> {
    // state.auth_admin(&key)?;
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::secrets::remove_access_for(&mut conn, secret_id, host_id)
        .await
        .bad_request()?;

    Ok(StatusCode::OK)
}

pub async fn get_all_acl(
    State(state): State<YeetState>,
    HttpSig(_key): HttpSig,
) -> Result<Json<HashMap<api::SecretID, Vec<api::HostID>>>, (StatusCode, String)> {
    // let state = state.read_arc();
    let mut conn = state.pool.acquire().await.internal_server()?;
    Ok(Json(db::secrets::list_acl(&mut conn).await.bad_request()?))
}

pub async fn list(
    State(state): State<YeetState>,
    HttpSig(_key): HttpSig,
) -> Result<Json<Vec<api::SecretName>>, (StatusCode, String)> {
    // state.auth_admin(&key)?;
    let mut conn = state.pool.acquire().await.internal_server()?;

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
mod test_verification {
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

        let id: api::SecretID = server
            .post("/secret/add/secretstuff")
            .json(&api::AddSecretRequest { secret })
            .await
            .json();

        server.put(&format!("/secret/{id}/allow/1")).await;

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

        let id: api::SecretID = server
            .post("/secret/add/secretstuff")
            .json(&api::AddSecretRequest { secret })
            .await
            .json();

        server.put(&format!("/secret/{id}/allow/1")).await;

        server.put(&format!("/secret/{id}/rename/mynewname")).await;

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

        let id: api::SecretID = server
            .post("/secret/add/secretstuff")
            .json(&api::AddSecretRequest { secret })
            .await
            .json();

        server.delete(&format!("/secret/{id}/delete")).await;

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

        let _id: api::SecretID = server
            .post("/secret/add/secretstuff")
            .json(&api::AddSecretRequest { secret })
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

        let id: api::SecretID = server
            .post("/secret/add/secretstuff")
            .json(&api::AddSecretRequest { secret })
            .await
            .json();

        let secrets: Vec<api::SecretName> = server.get("/secret/list").await.json();

        assert_eq!(
            secrets,
            vec![api::SecretName {
                id,
                name: "secretstuff".to_owned()
            }]
        );
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

        let id: api::SecretID = server
            .post("/secret/add/secretstuff")
            .json(&api::AddSecretRequest { secret })
            .await
            .json();

        server.put(&format!("/secret/{id}/allow/1")).await;

        let acl: HashMap<api::SecretID, Vec<api::HostID>> = server.get("/secret/acl").await.json();

        assert_eq!(acl.get(&id).unwrap(), &vec![api::HostID::new(1)])
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
