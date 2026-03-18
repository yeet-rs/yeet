use std::sync::Arc;

use axum::routing::{delete, get, post, put};

mod routes {
    pub mod host;
    pub mod key;
    pub mod secret;
    pub mod system;
    pub mod verify;
}
mod db {
    pub mod hosts;
    pub mod keys;
    pub mod secrets;
    pub mod verification;
}
mod error;
mod httpsig;
mod state;

#[cfg(any(test, feature = "test-server"))]
use ed25519_dalek::VerifyingKey;
pub(crate) use routes::*;

#[derive(Clone)]
pub struct YeetState {
    pub pool: sqlx::SqlitePool,
    pub age_key: Arc<age::x25519::Identity>,
}

pub fn routes(state: YeetState) -> axum::Router {
    axum::Router::new()
        .route("/verification/add", post(verify::add_verification_attempt))
        .route("/verification/{id}/accept", put(verify::accept_attempt))
        .route("/verification/check", get(verify::is_host_verified))
        // === Secrets
        .route("/secret/add/{name}", post(secret::add_secret))
        .route(
            "/secret/{secret_id}/allow/{host_id}",
            put(secret::allow_host),
        )
        .route(
            "/secret/{secret_id}/block/{host_id}",
            put(secret::block_host),
        )
        .route("/secret/{id}/rename/{name}", put(secret::rename_secret))
        .route("/secret/{id}/delete", delete(secret::delete_secret))
        .route("/secret/list", get(secret::list))
        .route("/secret/acl", get(secret::get_all_acl))
        .route("/secret/server_key", get(secret::get_server_age_key)) // locked
        .route("/secret", post(secret::get_secret)) // locked
        // === Keys
        .route("/key/add", post(key::add_key))
        .route("/key/delete", delete(key::delete_key))
        // === Hosts
        .route("/host/list", get(host::list))
        .route("/host/{id}/rename/{name}", put(host::rename_host))
        .route("/host/update", post(host::update_hosts)) // TODO: use put and make it non batch
        // === System
        .route("/system/self/detach", put(system::detach))
        .route("/system/self/attach", put(system::attach))
        .route("/system/check", post(system::system_check)) // locked
        .with_state(state)
}

#[cfg(any(test, feature = "test-server"))]
pub async fn test_server(pool: sqlx::SqlitePool) -> axum_test::TestServer {
    let age_key = std::sync::Arc::new(age::x25519::Identity::generate());
    let state = YeetState { pool, age_key };
    let mut conn = state.pool.acquire().await.unwrap();
    sqlx::migrate!("../migrations")
        .run(&mut conn)
        .await
        .unwrap();
    let app = routes(state);
    let server = axum_test::TestServer::builder()
        .expect_success_by_default()
        .http_transport()
        .build(app);

    server
}

#[cfg(any(test, feature = "test-server"))]
async fn add_default_host(conn: &mut sqlx::SqliteConnection) {
    use httpsig_hyper::prelude::VerifyingKey as _;

    let httpsig_key = httpsig_hyper::prelude::PublicKey::from_bytes(
        &httpsig_hyper::prelude::AlgorithmName::Ed25519,
        ed25519_dalek::VerifyingKey::default().as_bytes(),
    )
    .unwrap();

    db::hosts::add_host(
        conn,
        httpsig_key.key_id(),
        ed25519_dalek::VerifyingKey::default(),
        "default_host".to_owned(),
    )
    .await
    .unwrap();
}

#[cfg(any(test, feature = "test-server"))]
async fn sql_conn(pool: sqlx::SqlitePool) -> sqlx::pool::PoolConnection<sqlx::Sqlite> {
    let mut conn = pool.acquire().await.unwrap();
    sqlx::migrate!("../migrations")
        .run(&mut conn)
        .await
        .unwrap();
    conn
}
