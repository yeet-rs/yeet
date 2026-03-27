use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use axum::routing::{delete, get, post, put};

mod routes {
    pub mod host;
    pub mod key;
    pub mod osquery;
    pub mod secret;
    pub mod system;
    pub mod tag;
    pub mod user;
    pub mod verify;
}
mod db {
    pub mod hosts;
    pub mod keys;
    pub mod osquery;
    pub mod secrets;
    pub mod tag;
    pub mod user;
    pub mod verification;
}
mod error;
mod httpsig;

use axum_server::tls_rustls::RustlsConfig;
use ed25519_dalek::VerifyingKey;
pub(crate) use routes::{host, key, secret, system, verify};

#[derive(Clone)]
struct YeetState {
    pub pool: sqlx::SqlitePool,
    pub age_key: Arc<age::x25519::Identity>,
}

use serde::{Deserialize, Serialize};
use serde_json_any_key::any_key_map;

use crate::routes::{osquery, tag, user};

#[derive(Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AppState {
    #[serde(with = "any_key_map")]
    host_by_key: HashMap<VerifyingKey, String>,
    keyids: HashMap<String, VerifyingKey>,
}

#[expect(clippy::missing_panics_doc)]
pub async fn launch<I: Into<std::net::IpAddr>>(
    port: u16,
    host: I,
    pool: sqlx::SqlitePool,
    age_key: age::x25519::Identity,
    tls: Option<RustlsConfig>,
) -> tokio::task::JoinHandle<()> {
    #[expect(clippy::unwrap_used)]
    {
        let mut conn = pool.acquire().await.unwrap();
        sqlx::migrate!("../migrations")
            .run(&mut conn)
            .await
            .unwrap();
        // add hosts from state.json
        let state = std::fs::File::open("state.json");
        if let Ok(state) = state
            && !db::keys::has_any_admin(&mut conn).await.unwrap()
        {
            let state: AppState = serde_json::from_reader(state).unwrap();
            let valid_keys = state.keyids.values().collect::<Vec<_>>();
            for (key, hostname) in state.host_by_key {
                if valid_keys.contains(&&key) {
                    db::hosts::add_host(&mut conn, key, hostname).await.unwrap();
                }
            }
        }
    }

    let addr = SocketAddr::from((host, port));

    let age_key = Arc::new(age_key);

    let state = YeetState { pool, age_key };

    tokio::spawn(async move {
        if let Some(tls) = tls {
            axum_server::bind_rustls(addr, tls)
                .serve(routes(state).into_make_service())
                .await
                .expect("Could not start axum");
        } else {
            axum_server::bind(addr)
                .serve(routes(state).into_make_service())
                .await
                .expect("Could not start axum");
        }
    })
}

fn routes(state: YeetState) -> axum::Router {
    let _tracer = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .or_else(|_| tracing_subscriber::EnvFilter::try_new("yeetd=error,tower_http=warn"))
                .unwrap(),
        )
        .try_init();

    axum::Router::new()
        // Public
        .route("/verification/add", post(verify::add_verification_attempt))
        // `api::auth::Host::Accept`
        .route("/verification/{id}/accept", put(verify::accept_attempt))
        // Public
        .route("/verification/check", get(verify::is_host_verified))
        // Public / legacy path binding
        .route("/system/verify", get(verify::is_host_verified))
        // === Secrets
        // `api::auth::Secret::Create`
        .route("/secret/add/{name}", post(secret::add_secret))
        // `api::auth::Secret::Allow`
        .route(
            "/secret/{secret_id}/allow/{host_id}",
            put(secret::allow_host),
        )
        // `api::auth::Secret::Block`
        .route(
            "/secret/{secret_id}/block/{host_id}",
            put(secret::block_host),
        )
        // `api::auth::Secret::Rename`
        .route("/secret/{id}/rename/{name}", put(secret::rename_secret))
        // `api::auth::Secret::Delete`
        .route("/secret/{id}/delete", delete(secret::delete_secret))
        // `api::auth::Secret::View`
        .route("/secret/list", get(secret::list_secrets))
        // Public
        .route("/secret/server_key", get(secret::get_server_age_key)) // locked
        // Public
        .route("/secret", post(secret::get_secret)) // locked
        // === Keys
        .route("/key/delete", delete(key::delete_key))
        // === User
        .route("/user", get(user::list_users))
        .route("/user/create", post(user::create_user))
        .route("/user/{user_id}/rename/{name}", put(user::rename_user))
        // === Tags
        .route("/tag", get(tag::list_tags))
        .route("/tag/create/{name}", post(tag::create_tag))
        .route("/tag/{tag}/rename/{name}", put(tag::rename_tag))
        .route("/tag/{tag}/delete", delete(tag::delete_tag))
        .route("/tag/{tag}/allow/{user_id}", put(tag::allow_user))
        .route("/tag/{tag}/remove/{user_id}", delete(tag::remove_user))
        .route("/resource/add_tag", put(tag::add_resource_tag))
        .route("/resource/delete_tag", delete(tag::delete_resource_tag))
        // === Hosts
        // `api::auth::Host::View`
        .route("/host", get(host::list_hosts))
        // `api::auth::Host::Rename`
        .route("/host/{id}/rename/{name}", put(host::rename_host))
        // `api::auth::Host::Update`
        .route("/host/update", post(host::update_hosts)) // TODO: use put and make it non batch
        // === System - Public
        .route("/system/self/detach", put(system::detach))
        .route("/system/self/attach", put(system::attach))
        .route("/system/check", post(system::system_check)) // locked
        // === Osquery - Node
        .route("/osquery/enroll", post(osquery::enroll))
        .route("/osquery/query/read", post(osquery::query_read))
        .route("/osquery/query/write", post(osquery::query_write))
        // === TODO
        .route("/osquery/nodes", get(osquery::list_nodes))
        .route("/osquery/query/create", post(osquery::create_query))
        .route(
            "/osquery/query/response/{query}",
            get(osquery::query_response_all),
        )
        // .route(
        // "/osquery/query/response/{query_id}/{node_id}",
        // get(osquery::query_write),
        // )
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}

// #[cfg(any(test, feature = "test-server"))]
// pub async fn test_server(pool: sqlx::SqlitePool) -> axum_test::TestServer {
//     let age_key = std::sync::Arc::new(age::x25519::Identity::generate());
//     let state = YeetState { pool, age_key };
//     let mut conn = state.pool.acquire().await.unwrap();
//     sqlx::migrate!("../migrations")
//         .run(&mut conn)
//         .await
//         .unwrap();
//     let app = routes(state);
//     let server = axum_test::TestServer::builder()
//         .expect_success_by_default()
//         .http_transport()
//         .build(app);

//     server
// }

// #[cfg(any(test, feature = "test-server"))]
// async fn add_default_host(conn: &mut sqlx::SqliteConnection) {
//     use httpsig_hyper::prelude::VerifyingKey as _;

//     let httpsig_key = httpsig_hyper::prelude::PublicKey::from_bytes(
//         &httpsig_hyper::prelude::AlgorithmName::Ed25519,
//         ed25519_dalek::VerifyingKey::default().as_bytes(),
//     )
//     .unwrap();

//     db::hosts::add_host(
//         conn,
//         ed25519_dalek::VerifyingKey::default(),
//         "default_host".to_owned(),
//     )
//     .await
//     .unwrap();
// }

#[cfg(test)]
async fn sql_conn(pool: sqlx::SqlitePool) -> sqlx::pool::PoolConnection<sqlx::Sqlite> {
    let mut conn = pool.acquire().await.unwrap();
    sqlx::migrate!("../migrations")
        .run(&mut conn)
        .await
        .unwrap();
    conn
}
