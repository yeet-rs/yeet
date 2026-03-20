//! Yeet that Config

use std::{env, fs::read_to_string, str::FromStr};

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

#[tokio::main]
#[expect(
    clippy::expect_used,
    clippy::print_stdout,
    reason = "allow in server main"
)]
async fn main() {
    let port = env::var("YEET_PORT").unwrap_or("4337".to_owned());
    let host = env::var("YEET_HOST").unwrap_or("localhost".to_owned());

    let age_key = {
        let path = env::var("YEET_AGE_KEY").expect("YEET_AGE_KEY was not set");
        let content = read_to_string(path).unwrap();
        age::x25519::Identity::from_str(&content).unwrap()
    };

    let options = SqliteConnectOptions::new()
        .filename("yeet.db")
        .create_if_missing(true);

    let pool = SqlitePoolOptions::new()
        .connect_with(options)
        .await
        .expect("Can't connect to yeet.db");

    let handle = yeetd::launch(&port, &host, pool, age_key).await;
    handle.await.expect("axum quit");
}
