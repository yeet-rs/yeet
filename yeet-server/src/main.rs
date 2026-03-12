//! Yeet that Config

use std::{
    env,
    fs::{File, OpenOptions},
    hash::{DefaultHasher, Hash as _, Hasher as _},
    os::unix::prelude::FileExt as _,
    sync::Arc,
    time::Duration,
};

use api::key::get_verify_key;
use axum::{
    Router,
    routing::{get, post, put},
};
use parking_lot::RwLock;
// use routes::status;
use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};
use tokio::{net::TcpListener, time::interval};

use crate::{
    // routes::{
    //     detach, host,
    //     key::{add_key, remove_key},
    //     secret,
    //     system_check::system_check,
    //     update::update_hosts,
    //     verify::{add_verification_attempt, is_host_verified, verify_attempt},
    // },
    state::AppState,
}; // TODO: is this enough or do we need to use rand_chacha?

mod error;
mod httpsig;
mod state;
mod routes {
    //     pub mod detach;
    //     pub mod host;
    //     pub mod key;
    //     pub mod secret;
    //     pub mod status;
    //     pub mod system_check;
    //     pub mod update;
    pub mod verify;
}
pub use routes::*;

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
    let pool = SqlitePoolOptions::new()
        .connect("sqlite:yeet.db")
        .await
        .expect("Can't connect to yeet.db");

    axum::serve(listener, routes(pool))
        .await
        .expect("Could not start axum");
}

fn routes(state: SqlitePool) -> Router {
    Router::new()
        .route("/verification/add", post(verify::add_verification_attempt))
        .route("/verification/{id}/accept", put(verify::accept_attempt))
        .route("/verification/check", get(verify::is_host_verified))
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
        // .route("/secret/add", post(secret::add_secret))
        // .route("/secret/rename", post(secret::rename_secret))
        // .route("/secret/remove", post(secret::remove_secret))
        // .route("/secret/acl", post(secret::set_acl))
        // .route("/secret/acl/all", get(secret::get_all_acl))
        // .route("/secret/list", get(secret::list))
        // .route("/secret/server_key", get(secret::get_server_recipient))
        // .route("/secret", post(secret::get_secret))
        .with_state(state)
}

#[cfg(test)]
use axum_test::TestServer;

#[cfg(test)]
async fn test_server(pool: SqlitePool) -> TestServer {
    let mut conn = pool.acquire().await.unwrap();
    sqlx::migrate!("../migrations")
        .run(&mut conn)
        .await
        .unwrap();
    let app = routes(pool.clone());
    let server = TestServer::builder()
        .expect_success_by_default()
        .http_transport()
        .build(app);
    server
}
