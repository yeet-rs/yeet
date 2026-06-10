use std::{
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
    pub mod artifact;
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
    pub mod artifact;
    pub mod hosts;
    pub mod keys;
    pub mod osquery;
    pub mod secrets;
    pub mod tag;
    pub mod user;
    pub mod verification;
}
pub mod defectdojo_sender;
mod error;
mod httpsig;
mod splunk_sender;

use axum_server::tls_rustls::RustlsConfig;
use figment::Figment;
use indexmap::IndexMap;
pub(crate) use routes::{artifact, health, host, key, secret, system, verify};

#[derive(Clone)]
struct YeetState {
    pub pool: sqlx::SqlitePool,
    pub age_key: Arc<age::x25519::Identity>,
    pub splunk_sender: Option<tokio::sync::mpsc::Sender<()>>,
    pub defectdojo_sender: Option<tokio::sync::mpsc::Sender<defectdojo_sender::Action>>,
    pub osquery_packs: IndexMap<String, serde_json::Value>,
}

use serde::{Deserialize, Serialize};

use crate::routes::{osquery, tag, user};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Flags {
    /// Address to start the axum server
    pub addr: std::net::SocketAddr,
    /// Certificate required for tls
    pub cert: PathBuf,
    /// Certificate required for tls
    pub cert_key: PathBuf,
    #[serde(flatten)]
    pub defect_dojo_flags: Option<DefectDojoFlags>,
    #[serde(flatten)]
    pub osquery_flags: Option<OsqueryFlags>,
}

impl Default for Flags {
    fn default() -> Self {
        Self {
            addr: std::net::SocketAddrV6::new(std::net::Ipv6Addr::LOCALHOST, 4337, 0, 0).into(),
            cert: "cert.pem".into(),
            cert_key: "key.pem".into(),
            defect_dojo_flags: None,
            osquery_flags: None,
        }
    }
}

error_set::error_set! {
    ConfigError := {
        IO(std::io::Error),
        DefectDojo(defectdojo::Error),
        SQLX(sqlx::Error)
    }
}

impl Flags {
    #[must_use]
    pub fn figment() -> Figment {
        use figment::providers::Env;

        Figment::from(Self::default()).merge(Env::prefixed("YEET_"))
    }

    pub async fn build(self, identity: age::x25519::Identity) -> Result<Config, ConfigError> {
        let tls = RustlsConfig::from_pem_file(self.cert, self.cert_key).await?;
        let osquery_packs = self
            .osquery_flags
            .as_ref()
            .map(|flags| get_osquery_packs(&flags.osquery_packs))
            .transpose()?
            .unwrap_or_default();

        let splunk = self.osquery_flags.map(|flags| {
            splunk_hec::SplunkConfig::new(
                flags.splunk_index,
                flags.url,
                flags.splunk_url,
                flags.splunk_token,
            )
        });

        if splunk.is_none() {
            log::info!("Not using splunk");
        }

        let defectdojo = self
            .defect_dojo_flags
            .map(|flags| {
                let client =
                    defectdojo::Client::new(flags.defectdojo_url, &flags.defectdojo_token)?;
                Ok::<_, defectdojo::Error>(defectdojo_sender::Config {
                    client,
                    organization: flags.defectdojo_org.into(),
                })
            })
            .transpose()?;

        if defectdojo.is_none() {
            log::info!("Not using defectdojo");
        }
        let pool = {
            let options = sqlx::sqlite::SqliteConnectOptions::new()
                .filename("yeet.db")
                .create_if_missing(true);

            sqlx::sqlite::SqlitePoolOptions::new()
                .connect_with(options)
                .await?
        };

        Ok(Config {
            addr: self.addr,
            pool,
            age_key: identity,
            tls: Some(tls),
            splunk,
            osquery_packs,
            defectdojo,
        })
    }
}

impl figment::Provider for Flags {
    fn metadata(&self) -> figment::Metadata {
        figment::Metadata::named("Yeet Default Config")
    }

    fn data(
        &self,
    ) -> Result<figment::value::Map<figment::Profile, figment::value::Dict>, figment::Error> {
        figment::providers::Serialized::defaults(Self::default()).data()
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DefectDojoFlags {
    /// `DefectDojo` api url
    pub defectdojo_url: url::Url,
    /// `DefectDojo` auth token
    pub defectdojo_token: String,
    pub defectdojo_org: u32,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct OsqueryFlags {
    /// Splunk server used for osquery
    pub splunk_url: url::Url,
    /// Name of the index to send logs to
    pub splunk_index: String,
    /// URL of the yeet server (sent in splunk logs)
    pub url: url::Url,
    /// Splunk Auth token
    pub splunk_token: String,
    /// Path location of osquery packs to load
    pub osquery_packs: PathBuf,
}

pub struct Config {
    pub addr: SocketAddr,
    pub pool: sqlx::SqlitePool,
    pub age_key: age::x25519::Identity,
    pub tls: Option<RustlsConfig>,
    pub splunk: Option<splunk_hec::SplunkConfig>,
    pub osquery_packs: IndexMap<String, serde_json::Value>,
    pub defectdojo: Option<defectdojo_sender::Config>,
}

// TODO: too_many_arguments
#[expect(clippy::missing_panics_doc)]
pub async fn launch(config: Config) -> tokio::task::JoinHandle<()> {
    #[expect(clippy::unwrap_used)]
    {
        let mut conn = config.pool.acquire().await.unwrap();
        sqlx::migrate!("../migrations")
            .run(&mut conn)
            .await
            .unwrap();
    };

    let age_key = Arc::new(config.age_key);

    let splunk_sender = if let Some(splunk) = config.splunk {
        let (tx, rx) = tokio::sync::mpsc::channel(5);
        let pool = config.pool.clone();
        let _detached = tokio::spawn(async move { splunk_sender::run(splunk, rx, pool).await });
        Some(tx)
    } else {
        None
    };

    let defectdojo_sender = if let Some(defectdojo) = config.defectdojo {
        let (tx, rx) = tokio::sync::mpsc::channel(5);
        let pool = config.pool.clone();
        let _detached =
            tokio::spawn(async move { defectdojo_sender::run(defectdojo, rx, pool).await });
        Some(tx)
    } else {
        None
    };

    let state = YeetState {
        pool: config.pool,
        age_key,
        splunk_sender,
        defectdojo_sender,
        osquery_packs: config.osquery_packs,
    };

    // wake the splunk sender immediately so that he can send all logs
    wake_splunk(state.splunk_sender.as_ref()).await;

    tokio::spawn(async move {
        if let Some(tls) = config.tls {
            axum_server::bind_rustls(config.addr, tls)
                .serve(routes(state).into_make_service())
                .await
                .expect("Could not start axum");
        } else {
            axum_server::bind(config.addr)
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
        // === Artifacts
        .route("/artifact/store/{name}", post(artifact::store))
        .route("/artifact", get(artifact::list))
        // returns the latest artifact data
        .route("/artifact/name/{name}", post(artifact::get_latest))
        // retrieve any artifact
        .route("/artifact/id/{id}", post(artifact::get_artifact))
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
    sender: Option<&tokio::sync::mpsc::Sender<defectdojo_sender::Action>>,
    action: defectdojo_sender::Action,
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
