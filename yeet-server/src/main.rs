//! Yeet that Config

use std::{env, fs::read_to_string, str::FromStr, sync::Arc};

use axum::{
    Router,
    routing::{delete, get, post, put},
};

use ed25519_dalek::VerifyingKey;
#[cfg(test)]
use sqlx::SqliteConnection;
// use routes::status;
use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};
use tokio::net::TcpListener;

// TODO: is this enough or do we need to use rand_chacha?

mod error;
mod httpsig;
mod state;
mod routes {
    //     pub mod detach;
    //     pub mod host;
    //     pub mod key;
    pub(crate) mod secret;
    //     pub mod status;
    //     pub mod system_check;
    //     pub mod update;
    pub(crate) mod verify;
}
pub use routes::*;

#[derive(Clone)]
pub(crate) struct YeetState {
    pool: sqlx::SqlitePool,
    age_key: Arc<age::x25519::Identity>,
}

mod db {
    pub mod hosts;
    pub mod keys;
    pub mod secrets;
    pub mod verification;
}
#[tokio::main]
#[expect(
    clippy::expect_used,
    clippy::print_stdout,
    reason = "allow in server main"
)]
async fn main() {
    // let mut state = File::open("state.json")
    //     .map(serde_json::from_reader)
    //     .unwrap_or(Ok(AppState::default()))
    //     .expect("Could not parse state.json - missing migration");

    // // TODO: make this interactive if interactive shell found
    // if !state.has_admin_credential() {
    //     // TODO: also accept the key directly
    //     let key_location = env::var("YEET_INIT_KEY")
    //         .expect("Cannot start without an init key. Set it via `YEET_INIT_KEY`");

    //     let key = get_verify_key(key_location).expect("Not a valid key {key_location}");
    //     state.add_key(key, api::AuthLevel::Admin);
    // }
    // state.purge_keyids();

    let listener = {
        let port = env::var("YEET_PORT").unwrap_or("4337".to_owned());
        let host = env::var("YEET_HOST").unwrap_or("localhost".to_owned());
        TcpListener::bind(format!("{host}:{port}"))
            .await
            .expect("Could not bind to port")
    };

    let age_key = {
        let path = env::var("YEET_AGE_KEY").expect("YEET_AGE_KEY was not set");
        let content = read_to_string(path).unwrap();
        Arc::new(age::x25519::Identity::from_str(&content).unwrap())
    };

    let pool = SqlitePoolOptions::new()
        .connect("sqlite:yeet.db")
        .await
        .expect("Can't connect to yeet.db");

    let state = YeetState { pool, age_key };

    axum::serve(listener, routes(state))
        .await
        .expect("Could not start axum");
}

fn routes(state: YeetState) -> Router {
    Router::new()
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
        // ===
        // .route("/system/check", post(system_check))
        // .route("/system/update", post(update_hosts))
        // .route("/key/add", post(add_key))
        // .route("/key/remove", post(remove_key))
        // .route("/status", get(status::status))
        // .route("/status/host_by_key", get(status::hosts_by_key))
        // .route("/host/remove", post(host::remove_host))
        // .route("/host/rename", post(host::rename_host))
        // .route("/system/detach", post(detach::detach_host))
        // .route("/system/detach/permission", get(detach::is_detach_allowed))
        // .route("/detach/permission", post(detach::set_detach_permission))
        // .route("/detach/permission", get(detach::is_detach_global_allowed))
        .with_state(state)
}

#[cfg(test)]
use axum_test::TestServer;

#[cfg(test)]
async fn test_server(pool: SqlitePool) -> TestServer {
    let age_key = Arc::new(age::x25519::Identity::generate());
    let state = YeetState { pool, age_key };
    let mut conn = state.pool.acquire().await.unwrap();
    sqlx::migrate!("../migrations")
        .run(&mut conn)
        .await
        .unwrap();
    let app = routes(state);
    let server = TestServer::builder()
        .expect_success_by_default()
        .http_transport()
        .build(app);

    server
}

#[cfg(test)]
async fn add_default_host(conn: &mut SqliteConnection) {
    use httpsig_hyper::prelude::VerifyingKey as _;

    let httpsig_key = httpsig_hyper::prelude::PublicKey::from_bytes(
        &httpsig_hyper::prelude::AlgorithmName::Ed25519,
        VerifyingKey::default().as_bytes(),
    )
    .unwrap();

    db::hosts::add_host(
        conn,
        httpsig_key.key_id(),
        VerifyingKey::default(),
        "default_host".to_owned(),
    )
    .await
    .unwrap();
}

#[cfg(test)]
async fn sql_conn(pool: SqlitePool) -> sqlx::pool::PoolConnection<sqlx::Sqlite> {
    let mut conn = pool.acquire().await.unwrap();
    sqlx::migrate!("../migrations")
        .run(&mut conn)
        .await
        .unwrap();
    conn
}
