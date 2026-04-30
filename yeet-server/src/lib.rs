use std::{
    collections::HashMap,
    env,
    fs::File,
    io::{self},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use axum::routing::{delete, get, post, put};

mod routes {
    pub mod health;
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
pub mod defectdojo;
mod error;
mod httpsig;
mod splunk_sender;

use axum_server::tls_rustls::RustlsConfig;
use ed25519_dalek::VerifyingKey;
use indexmap::IndexMap;
pub(crate) use routes::{health, host, key, secret, system, verify};

#[derive(Clone)]
struct YeetState {
    pub pool: sqlx::SqlitePool,
    pub age_key: Arc<age::x25519::Identity>,
    pub splunk_sender: Option<tokio::sync::mpsc::Sender<()>>,
    pub defectdojo_sender: Option<tokio::sync::mpsc::Sender<defectdojo::Action>>,
    pub osquery_packs: IndexMap<String, serde_json::Value>,
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
    splunk: Option<splunk_hec::SplunkConfig>,
    osquery_packs: Option<PathBuf>,
    defectdojo: Option<defectdojo::Config>,
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

    let splunk_sender = if let Some(splunk) = splunk {
        let (tx, rx) = tokio::sync::mpsc::channel(5);
        let pool = pool.clone();
        let _detached = tokio::spawn(async move { splunk_sender::run(splunk, rx, pool).await });
        Some(tx)
    } else {
        None
    };

    let defectdojo_sender = if let Some(defectdojo) = defectdojo {
        let (tx, rx) = tokio::sync::mpsc::channel(5);
        let pool = pool.clone();
        let _detached = tokio::spawn(async move { defectdojo::run(defectdojo, rx, pool).await });
        Some(tx)
    } else {
        None
    };

    let osquery_packs = osquery_packs
        .map(|path| get_osquery_packs(&path).expect("Could not retrive packs"))
        .unwrap_or_default();

    let state = YeetState {
        pool,
        age_key,
        splunk_sender,
        defectdojo_sender,
        osquery_packs,
    };

    // wake the splunk sender immediately so that he can send all logs
    wake_splunk(state.splunk_sender.as_ref()).await;

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
        .route("/osquery/config", post(osquery::config))
        .route("/osquery/log", post(osquery::log))
        // === Osquery
        .route("/osquery/nodes", get(osquery::list_nodes))
        .route("/osquery/query/create", post(osquery::create_query))
        // === health endpoint
        .route("/health", get(health::health))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}

pub(crate) async fn wake_splunk(sender: Option<&tokio::sync::mpsc::Sender<()>>) {
    if let Some(sender) = sender {
        // TODO: log if we could not notify
        let _ignore = sender.send_timeout((), Duration::from_secs(1)).await;
    }
}

pub(crate) async fn wake_defectdojo(
    sender: Option<&tokio::sync::mpsc::Sender<defectdojo::Action>>,
    action: defectdojo::Action,
) {
    if let Some(sender) = sender {
        // TODO: log if we could not notify
        let _ignore = sender.send_timeout(action, Duration::from_secs(1)).await;
    }
}

/// Read all files in a directory to json
#[expect(clippy::indexing_slicing)]
fn get_osquery_packs(path: &Path) -> Result<IndexMap<String, serde_json::Value>, io::Error> {
    let mut packs = IndexMap::new();
    for path in path.read_dir()? {
        let path = path?;
        log::info!("Scanning {} for packs", path.file_name().display());
        let Ok(pack) = serde_json::from_reader::<_, serde_json::Value>(File::open(path.path())?)
        else {
            log::warn!(
                "Pack `{}` not ingested - not valid json",
                path.path().display()
            );
            continue;
        };

        let file_name = path
            .file_name()
            .to_string_lossy()
            .split('.')
            .next()
            .map_or("unnamedPack".to_owned(), std::borrow::ToOwned::to_owned);

        log::info!("Loaded pack {file_name}:");
        log::info!("Queries:");
        if let Some(queries) = pack["queries"].as_object() {
            for query in queries.keys() {
                log::info!("- {query}");
            }
        } else {
            log::warn!("Pack {file_name} had no queries");
        }
        log::debug!("Pack content:\n{:?}", serde_json::to_string_pretty(&pack));
        packs.insert(file_name, pack);
    }

    if packs.is_empty() {
        log::warn!("Could not find any packs in {}", path.display());
    }

    let interval = env::var("YEET_INTERNAL_PACK_INTERVAL").unwrap_or("86400".to_owned());

    let yeet_nodes_information = serde_json::json!({
          "queries": {
            "node_info": {
              "query" : "SELECT os_version.name, os_version.version as os_version, os_version.arch, os_version.platform, system_info.computer_name, system_info.hardware_serial, osquery_info.version FROM osquery_info,os_version,system_info;",
              "interval" : interval,
              "snapshot": true,
              "description" : "Internal pack from yeet to gather information about nodes"
            }
          }
        }
    );

    packs.insert("yeet_internal".to_owned(), yeet_nodes_information);

    Ok(packs)
}

#[cfg(test)]
async fn sql_conn(pool: sqlx::SqlitePool) -> sqlx::pool::PoolConnection<sqlx::Sqlite> {
    let mut conn = pool.acquire().await.unwrap();
    sqlx::migrate!("../migrations")
        .run(&mut conn)
        .await
        .unwrap();
    conn
}
