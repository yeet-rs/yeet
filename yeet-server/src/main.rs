//! Yeet that Config

use std::{
    env,
    fs::{File, read_to_string},
    io::Write,
    str::FromStr,
};

use age::secrecy::ExposeSecret as _;
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
        match read_to_string("age.key") {
            Ok(content) => {
                age::x25519::Identity::from_str(serde_json::from_str(&content).unwrap()).unwrap()
            }
            Err(_) => {
                let identity = age::x25519::Identity::generate();
                File::create("age.key")
                    .unwrap()
                    .write_all(
                        &serde_json::to_vec(&identity.to_string().expose_secret().to_string())
                            .unwrap(),
                    )
                    .unwrap();
                identity
            }
        }
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
