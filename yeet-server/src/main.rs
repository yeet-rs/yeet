//! Yeet that Config

use std::{env, fs::read_to_string, str::FromStr, sync::Arc};

// use routes::status;
use sqlx::sqlite::SqlitePoolOptions;
use tokio::net::TcpListener;

// TODO: is this enough or do we need to use rand_chacha?

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

    let state = yeetd::YeetState { pool, age_key };

    axum::serve(listener, yeetd::routes(state))
        .await
        .expect("Could not start axum");
}
