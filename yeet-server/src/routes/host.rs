use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};

use crate::{
    YeetState, db,
    error::{BadRequest as _, InternalError as _},
    httpsig::{HttpSig, VerifiedJson},
};

pub async fn list(
    State(state): State<YeetState>,
    HttpSig(key): HttpSig,
) -> Result<Json<Vec<api::Host>>, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::keys::auth_admin(&mut conn, key).await?;
    Ok(Json(db::hosts::list(&mut conn).await.internal_server()?))
}

pub async fn rename_host(
    State(state): State<YeetState>,
    Path((id, name)): Path<(api::HostID, String)>,
    HttpSig(key): HttpSig,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::keys::auth_admin(&mut conn, key).await?;
    db::hosts::rename(&mut conn, id, name)
        .await
        .internal_server()?;
    Ok(StatusCode::OK)
}

/// Endpoint to set a new version for a host.
/// The whole request needs to be signed by a build machine.
/// The update consist of a simple `key` -> `version` and a `substitutor` which is where the agent should get its update
/// This means that for each origin e.g. cachix, you need to call update seperately
pub async fn update_hosts(
    State(state): State<YeetState>,
    HttpSig(key): HttpSig,

    VerifiedJson(api::HostUpdateRequest {
        hosts,
        public_key,
        substitutor,
    }): VerifiedJson<api::HostUpdateRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;

    db::keys::auth_build(&mut conn, key).await?;

    db::hosts::update(&mut conn, hosts.iter(), public_key, substitutor)
        .await
        .bad_request()?;

    Ok(StatusCode::CREATED)
}

#[cfg(test)]
mod test_host {

    use axum_test::TestServer;
    use ed25519_dalek::VerifyingKey;
    use sqlx::SqlitePool;

    async fn add_host(server: &TestServer) {
        let code: i64 = server
            .post("/verification/add")
            .json(&api::VerificationAttempt {
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
    }

    #[sqlx::test]
    async fn list(pool: SqlitePool) {
        let server = crate::test_server(pool.clone()).await;

        add_host(&server).await;

        let hosts: Vec<api::Host> = server.get("/host/list").await.json();

        assert_eq!(
            hosts,
            vec![api::Host {
                id: api::HostID::new(1),
                key: VerifyingKey::default(),
                hostname: "myhost".to_owned(),
                state: api::ProvisionState::NotSet,
                last_ping: jiff::Timestamp::now(),
                version: None,
                latest_update: None
            }]
        );
    }

    #[sqlx::test]
    async fn rename(pool: SqlitePool) {
        let server = crate::test_server(pool.clone()).await;

        add_host(&server).await;

        server.put("/host/1/rename/otherhost").await;

        let hosts: Vec<api::Host> = server.get("/host/list").await.json();

        assert_eq!(
            hosts,
            vec![api::Host {
                id: api::HostID::new(1),
                key: VerifyingKey::default(),
                hostname: "otherhost".to_owned(),
                state: api::ProvisionState::NotSet,
                last_ping: jiff::Timestamp::now(),
                version: None,
                latest_update: None
            }]
        );
    }

    #[sqlx::test]
    async fn delete(pool: SqlitePool) {
        let server = crate::test_server(pool.clone()).await;

        add_host(&server).await;

        server
            .delete("/key/delete")
            .json(&VerifyingKey::default())
            .await;

        let hosts: Vec<api::Host> = server.get("/host/list").await.json();

        assert_eq!(hosts, vec![]);
    }
}
