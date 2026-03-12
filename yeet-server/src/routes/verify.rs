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
    db,
    httpsig::{HttpSig, VerifiedJson},
};

/// That is literally it because the `HttpSig` extractor checks if the key is in the keyids
pub async fn is_host_verified(HttpSig(_http_key): HttpSig) -> StatusCode {
    StatusCode::OK
}

/// Adds a new key as an verification attempt
pub async fn add_verification_attempt(
    State(pool): State<sqlx::SqlitePool>,
    Json(attempt): Json<api::verify::VerificationAttempt>,
) -> Result<Json<i64>, db::verification::VerificationError> {
    // TODO: check if httsig is correct so that non key owners can not send verification attempts
    // Altough this is not a security risk because even if you create an foreign attempt still only the key holder get authorized
    let mut conn = pool.acquire().await?;

    let code =
        db::verification::add_verification_attempt(&mut conn, attempt.key, attempt.nixos_facter)
            .await?;

    Ok(Json(code))
}

/// Accept an verification attempt
pub async fn accept_attempt(
    State(pool): State<sqlx::SqlitePool>,
    HttpSig(_key): HttpSig,
    Path(id): Path<u32>,
    VerifiedJson(hostname): VerifiedJson<String>,
) -> Result<Json<Option<String>>, db::verification::VerificationError> {
    // todo admin auth

    let mut conn = pool.acquire().await?;

    let facter = db::verification::accept_attempt(&mut conn, id as i64, hostname).await?;
    Ok(Json(facter))
}

#[cfg(test)]
mod test_verification {
    use api::verify::VerificationAttempt;
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use rand::random;

    use crate::db;

    #[sqlx::test]
    async fn add_and_accept(pool: sqlx::SqlitePool) {
        let server = crate::test_server(pool.clone()).await;
        let mut conn = pool.acquire().await.unwrap();

        let code: i64 = server
            .post("/verification/add")
            .json(&VerificationAttempt {
                key: VerifyingKey::default(),
                nixos_facter: Some("hi".to_owned()),
            })
            .await
            .json();

        assert!(code >= 100_000 && code <= 999_999);

        let facter: Option<String> = server
            .put(&format!("/verification/{code}/accept"))
            .json(&"myhost".to_owned())
            .await
            .json();

        assert_eq!(facter, Some("hi".to_owned()));

        let host = db::hosts::host_by_verify_key(&mut conn, VerifyingKey::default())
            .await
            .unwrap();

        assert_eq!(host, Some("myhost".to_owned()));
    }

    #[sqlx::test]
    async fn add_verification(pool: sqlx::SqlitePool) {
        let server = crate::test_server(pool.clone()).await;

        let code: i64 = server
            .post("/verification/add")
            .json(&VerificationAttempt {
                key: VerifyingKey::default(),
                nixos_facter: None,
            })
            .await
            .json();
        assert!(code >= 100_000 && code <= 999_999)
    }

    #[sqlx::test]
    async fn key_pending(pool: sqlx::SqlitePool) {
        let mut server = crate::test_server(pool.clone()).await;

        let code: i64 = server
            .post("/verification/add")
            .json(&VerificationAttempt {
                key: VerifyingKey::default(),
                nixos_facter: None,
            })
            .await
            .json();
        assert!(code >= 100_000 && code <= 999_999);

        server.expect_failure();
        let response = server
            .post("/verification/add")
            .json(&VerificationAttempt {
                key: VerifyingKey::default(),
                nixos_facter: None,
            })
            .await;

        response.assert_status_failure();
    }

    #[sqlx::test]
    async fn too_much_verification(pool: sqlx::SqlitePool) {
        let mut server = crate::test_server(pool.clone()).await;

        for _ in 0..10 {
            let code: i64 = server
                .post("/verification/add")
                .json(&VerificationAttempt {
                    key: SigningKey::from_bytes(&random()).verifying_key(),
                    nixos_facter: None,
                })
                .await
                .json();
            assert!(code >= 100_000 && code <= 999_999)
        }
        server.expect_failure();
        server
            .post("/verification/add")
            .json(&VerificationAttempt {
                key: VerifyingKey::default(),
                nixos_facter: None,
            })
            .await;
    }
}
