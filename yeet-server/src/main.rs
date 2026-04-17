//! Yeet that Config

use std::{
    env,
    fs::{File, read_to_string},
    io::Write as _,
    path::Path,
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
    let _tracer = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .or_else(|_| tracing_subscriber::EnvFilter::try_new("yeetd=error,tower_http=warn"))
                .expect("Could not init tracing logger"),
        )
        .try_init();

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

    let tls = {
        let cert = env::var("YEET_CERT").expect("`YEET_CERT` must be set");
        let key = env::var("YEET_CERT_KEY").expect("`YEET_CERT_KEY` must be set");
        RustlsConfig::from_pem_file(cert, key).await.unwrap()
    };

    let splunk = 'splunk: {
        let Ok(server) = env::var("YEET_SPLUNK_URL").map(|url| url.parse().unwrap()) else {
            log::error!("`YEET_SPLUNK_URL` not set. Not using splunk");
            break 'splunk None;
        };

        let index = env::var("YEET_SPLUNK_INDEX").expect("`YEET_SPLUNK_INDEX` must be set");
        let yeet_server = env::var("YEET_URL")
            .map(|url| url.parse().unwrap())
            .expect("`YEET_URL` must be set");
        let token = env::var("YEET_SPLUNK_TOKEN").expect("`YEET_SPLUNK_TOKEN` must be set");
        Some(splunk_hec::SplunkConfig::new(
            index,
            yeet_server,
            server,
            token,
        ))
    };

    let packs = {
        let env = env::var("YEET_OSQUERY_PACKS").ok();
        env.map(|env| Path::new(&env).to_path_buf())
    };

    let options = SqliteConnectOptions::new()
        .filename("yeet.db")
        .create_if_missing(true);

    let pool = SqlitePoolOptions::new()
        .connect_with(options)
        .await
        .expect("Can't connect to yeet.db");

    let handle = yeetd::launch(port, host, pool, age_key, Some(tls), splunk, packs).await;
    handle.await.expect("axum quit");
}
