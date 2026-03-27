//! Yeet that Config

use std::{
    env,
    fs::{File, read_to_string},
    io::Write as _,
    str::FromStr as _,
};

use age::secrecy::ExposeSecret as _;
use axum_server::tls_rustls::RustlsConfig;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

#[tokio::main]
#[expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "allow in server main"
)]
async fn main() {
    let port = env::var("YEET_PORT")
        .map(|port| port.parse().unwrap())
        .unwrap_or(4337);
    let host = env::var("YEET_HOST")
        .map(|host| host.parse().unwrap())
        .unwrap_or(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST));

    let age_key = {
        if let Ok(content) = read_to_string("age.key") {
            age::x25519::Identity::from_str(serde_json::from_str(&content).unwrap()).unwrap()
        } else {
            let identity = age::x25519::Identity::generate();
            File::create("age.key")
                .unwrap()
                .write_all(
                    &serde_json::to_vec(&identity.to_string().expose_secret().to_owned()).unwrap(),
                )
                .unwrap();
            identity
        }
    };

    let tls = RustlsConfig::from_pem_file("cert.pem", "key.pem")
        .await
        .unwrap();

    let options = SqliteConnectOptions::new()
        .filename("yeet.db")
        .create_if_missing(true);

    let pool = SqlitePoolOptions::new()
        .connect_with(options)
        .await
        .expect("Can't connect to yeet.db");

    let handle = yeetd::launch(port, host, pool, age_key, Some(tls)).await;
    handle.await.expect("axum quit");
}
