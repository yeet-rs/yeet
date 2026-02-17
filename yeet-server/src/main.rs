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
    routing::{get, post},
};
use parking_lot::RwLock;
use routes::status;
use tokio::{net::TcpListener, time::interval};

use crate::{
    routes::{
        detach, host,
        key::{add_key, remove_key},
        secret,
        system_check::system_check,
        update::update_hosts,
        verify::{add_verification_attempt, is_host_verified, verify_attempt},
    },
    state::AppState,
}; // TODO: is this enough or do we need to use rand_chacha?

mod error;
mod httpsig;
mod secret_store;
mod state;
mod routes {
    pub mod detach;
    pub mod host;
    pub mod key;
    pub mod secret;
    pub mod status;
    pub mod system_check;
    pub mod update;
    pub mod verify;
}

#[tokio::main]
#[expect(
    clippy::expect_used,
    clippy::print_stdout,
    reason = "allow in server main"
)]
async fn main() {
    let mut state = File::open("state.json")
        .map(serde_json::from_reader)
        .unwrap_or(Ok(AppState::default()))
        .expect("Could not parse state.json - missing migration");

    // TODO: make this interactive if interactive shell found
    if !state.has_admin_credential() {
        // TODO: also accept the key directly
        let key_location = env::var("YEET_INIT_KEY")
            .expect("Cannot start without an init key. Set it via `YEET_INIT_KEY`");

        let key = get_verify_key(key_location).expect("Not a valid key {key_location}");
        state.add_key(key, api::AuthLevel::Admin);
    }

    let state = Arc::new(RwLock::new(state));
    {
        let state = Arc::clone(&state);
        tokio::spawn(async move { save_state(&state).await });
    };

    let port = env::var("YEET_PORT").unwrap_or("4337".to_owned());
    let host = env::var("YEET_HOST").unwrap_or("localhost".to_owned());

    let listener = TcpListener::bind(format!("{host}:{port}"))
        .await
        .expect("Could not bind to port");
    axum::serve(listener, routes(state))
        .await
        .expect("Could not start axum");
}

fn routes(state: Arc<RwLock<AppState>>) -> Router {
    Router::new()
        .route("/system/check", post(system_check))
        .route("/system/update", post(update_hosts))
        .route("/system/verify/accept", post(verify_attempt))
        .route("/system/verify", get(is_host_verified))
        .route("/system/verify", post(add_verification_attempt))
        .route("/key/add", post(add_key))
        .route("/key/remove", post(remove_key))
        .route("/status", get(status::status))
        .route("/status/host_by_key", get(status::hosts_by_key))
        .route("/host/remove", post(host::remove_host))
        .route("/host/rename", post(host::rename_host))
        .route("/system/detach", post(detach::detach_host))
        .route("/system/detach/permission", get(detach::is_detach_allowed))
        .route("/detach/permission", post(detach::set_detach_permission))
        .route("/detach/permission", get(detach::is_detach_global_allowed))
        .route("/secret/add", post(secret::add_secret))
        .route("/secret/rename", post(secret::rename_secret))
        .route("/secret/remove", post(secret::remove_secret))
        .route("/secret/acl", post(secret::set_acl))
        .route("/secret/acl/all", get(secret::get_all_acl))
        .route("/secret/list", get(secret::list))
        .route("/secret/server_key", get(secret::get_server_recipient))
        .route("/secret", post(secret::get_secret))
        .with_state(state)
}

#[expect(
    clippy::expect_used,
    clippy::infinite_loop,
    reason = "Save state as long as the server is running"
)]
async fn save_state(state: &Arc<RwLock<AppState>>) {
    let state_location = env::var("YEET_STATE").unwrap_or("state.json".to_owned());

    let mut interval = interval(Duration::from_millis(500));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(state_location)
        .expect("Could not open state.json");

    let mut hash = 0;

    loop {
        interval.tick().await;
        let state = state.read();
        let data = serde_json::to_vec_pretty(&*state).expect("Could not serialize state");
        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);

        if hash != hasher.finish() {
            hash = hasher.finish();
            file.set_len(0).expect("Could not truncate file");
            file.write_all_at(&data, 0)
                .expect("Could not write to file");
        }
    }
}

// #[cfg(test)]
// use axum_test::TestServer;

// #[cfg(test)]
// fn test_server(state: AppState) -> (TestServer, Arc<RwLock<AppState>>) {
//     let app_state = Arc::new(RwLock::new(state));
//     let app_state_copy = Arc::clone(&app_state);
//     let app = routes(app_state);
//     let server = TestServer::builder()
//         .expect_success_by_default()
//         .http_transport()
//         .build(app)
//         .expect("Could not build TestServer");
//     (server, app_state_copy)
// }
