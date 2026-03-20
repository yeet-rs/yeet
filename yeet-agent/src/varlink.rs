#![expect(clippy::multiple_inherent_impl)]
use std::{
    os::unix::fs::{PermissionsExt as _, lchown},
    path::Path,
};

use api::AgentAction;
use httpsig_hyper::prelude::SecretKey;
use log::info;
use nix::unistd::Group;
use rootcause::{Report, compat::ReportAsError, prelude::ResultExt as _};
use serde::{Deserialize, Serialize};
use tokio::fs::{self, remove_file};
use url::Url;

use zlink::{Connection, ReplyError, connection::socket::FetchPeerCredentials, proxy, unix};

shadow_rs::shadow!(build);

use crate::{
    agent,
    cli_args::{self, AgentConfig},
    polkit::PolkitError,
    version,
};

const SOCKET_PATH: &str = "/run/yeet/agent.varlink";

#[proxy("ch.yeetme.yeet")]
pub trait YeetProxy {
    async fn status(&mut self) -> zlink::Result<Result<DaemonStatus, YeetDaemonError>>;
    async fn config(&mut self) -> zlink::Result<Result<AgentConfig, YeetDaemonError>>;
    async fn detach(
        &mut self,
        version: api::StorePath,
    ) -> zlink::Result<Result<(), YeetDaemonError>>;
    async fn attach(&mut self) -> zlink::Result<Result<(), YeetDaemonError>>;
}

pub async fn client() -> Result<Connection<zlink::unix::Stream>, VarlinkError> {
    log::debug!("Connecting to {SOCKET_PATH}");
    Ok(unix::connect(SOCKET_PATH)
        .await
        .context("Trying to set up the varlink connection\nMake sure you are in the `yeet` group and the daemon is running")
        .map_err(ReportAsError::from)?)
}

pub async fn status() -> Result<DaemonStatus, VarlinkError> {
    let mut client = client().await?;
    client
        .status()
        .await
        .context("Could not communicate with the varlink daemon. Are you running the same version?")
        .map_err(ReportAsError::from)?
        .map_err(VarlinkError::DaemonError)
}

pub async fn config() -> Result<AgentConfig, VarlinkError> {
    let mut client = client().await?;
    Ok(client
        .config()
        .await
        .context("Could not communicate with the varlink daemon. Are you running the same version?")
        .map_err(ReportAsError::from)?
        .expect("Config can never Error because it does not return a result"))
}

pub async fn detach(version: api::StorePath) -> Result<(), VarlinkError> {
    let mut client = client().await?;
    client
        .detach(version)
        .await
        .context("Could not communicate with the varlink daemon. Are you running the same version?")
        .map_err(ReportAsError::from)?
        .map_err(VarlinkError::DaemonError)
}

pub async fn attach() -> Result<(), VarlinkError> {
    let mut client = client().await?;
    client
        .attach()
        .await
        .context("Could not communicate with the varlink daemon. Are you running the same version?")
        .map_err(ReportAsError::from)?
        .map_err(VarlinkError::DaemonError)
}

#[derive(thiserror::Error, Debug)]
pub enum VarlinkError {
    #[error(transparent)]
    Report(#[from] ReportAsError<&'static str>),
    #[error("Defined error from Daemon:\n{0:?}")]
    DaemonError(YeetDaemonError),
}

#[derive(Debug, ReplyError, zlink::introspect::ReplyError)]
#[zlink(interface = "ch.yeetme.yeet")]
pub enum YeetDaemonError {
    NoCurrentSystem,
    /// Could not connect to the yeet-server in an operation where a server connection is required
    NoConnectionToServer {
        error: String,
    },
    CredentialError {
        error: String,
    },
    /// Polkit was not able to perform authentication
    PolkitError {
        error: String,
    },
}

impl From<std::io::Error> for YeetDaemonError {
    fn from(value: std::io::Error) -> Self {
        Self::CredentialError {
            error: value.to_string(),
        }
    }
}

impl From<PolkitError> for YeetDaemonError {
    fn from(value: PolkitError) -> Self {
        Self::PolkitError {
            error: value.to_string(),
        }
    }
}
impl From<api::ResponseError> for YeetDaemonError {
    fn from(value: api::ResponseError) -> Self {
        Self::NoConnectionToServer {
            error: value.to_string(),
        }
    }
}

struct YeetVarlinkService {
    pub config: cli_args::AgentConfig,
    pub key: SecretKey,
}

#[zlink::service]
impl<Sock> YeetVarlinkService
where
    Sock::ReadHalf: FetchPeerCredentials,
{
    #[zlink(interface = "ch.yeetme.yeet")]
    pub async fn status(&self) -> Result<DaemonStatus, YeetDaemonError> {
        log::debug!("Varlink: Daemon status requested");

        //TODO unwrap
        let verified = match api::is_host_verified(&self.config.server, &self.key).await {
            Ok(verified) => Some(verified.is_success()),
            Err(_) => None,
        };

        let system_check = {
            let Ok(store_path) = version::get_active_version() else {
                return Err(YeetDaemonError::NoCurrentSystem);
            };

            api::check_system(
                &self.config.server,
                &self.key,
                &api::VersionRequest { store_path },
            )
            .await
        };

        let up_to_date = match system_check {
            Ok(AgentAction::Nothing) => UpToDate::Yes,
            Ok(AgentAction::Detach) => UpToDate::Detached,
            Ok(AgentAction::SwitchTo(_)) | Err(_) => UpToDate::No,
        };

        let mode = 'b: {
            if let Some(verified) = verified
                && !verified
            {
                break 'b DaemonMode::Unverified;
            }

            match system_check {
                Ok(AgentAction::Nothing | AgentAction::SwitchTo(_)) => DaemonMode::Provisioned,
                Ok(AgentAction::Detach) => DaemonMode::Detached,
                Err(_) => DaemonMode::NetworkError,
            }
        };

        Ok(DaemonStatus {
            up_to_date,
            server: self.config.server.clone(),
            mode,
            version: String::from(build::PKG_VERSION),
        })
    }

    #[expect(clippy::unused_async)]
    pub async fn config(&self) -> AgentConfig {
        self.config.clone()
    }

    pub async fn detach(
        &self,
        version: api::StorePath,
        // #[zlink(connection)] conn: &mut zlink::Connection<Sock>,
    ) -> Result<(), YeetDaemonError> {
        // {
        //     let credentials = conn.peer_credentials().await?;
        //     let auth_result = polkit::detach(
        //         credentials.process_id().as_raw_pid() as u32,
        //         credentials.unix_user_id().as_raw(),
        //     )
        //     .await?;
        //     if !auth_result.is_authorized {
        //         return Err(YeetDaemonError::PolkitDetachNoPermission);
        //     }
        // }

        // Force switches to the revision without signaling the server
        // Meaning that once the agent gets the action to switch to the next revision this will be reverted
        // Only use force on offline clients

        // Signal detaching to server
        let _status = api::detach_self(&self.config.server, &self.key).await?;
        info!("System detached. Switching");

        // Switch to version
        let _err = agent::switch_to(&version);

        info!("Switched to detached version");

        Ok(())
    }

    pub async fn attach(&self) -> Result<(), YeetDaemonError> {
        let _status = api::attach_self(&self.config.server, &self.key).await?;
        info!("System attached");

        Ok(())
    }
}

pub async fn start_service(config: cli_args::AgentConfig, key: SecretKey) -> Result<(), Report> {
    YeetVarlinkService::start(config, key).await
}

impl YeetVarlinkService {
    pub async fn start(config: cli_args::AgentConfig, key: SecretKey) -> Result<(), Report> {
        let listener = {
            let _err = remove_file(SOCKET_PATH).await;
            #[expect(clippy::unwrap_used)]
            fs::create_dir_all(Path::new(SOCKET_PATH).parent().unwrap())
                .await
                .context("Ensuring the Socket dir is available")?;
            let listener =
                zlink::unix::bind(SOCKET_PATH).attach(format!("SOCKET_PATH: {SOCKET_PATH}"))?;

            setup_socket_permissions(SOCKET_PATH, "yeet").await?;

            listener
        };

        log::debug!("Socket created at {SOCKET_PATH}");
        let server = zlink::Server::new(listener, Self { config, key });
        log::info!("Listening for varlink connections");
        server.run().await.map_err(std::convert::Into::into)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub up_to_date: UpToDate,
    pub server: Url,
    pub mode: DaemonMode,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum UpToDate {
    Yes,
    No,
    Detached,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum DaemonMode {
    Provisioned,
    Unverified,
    Detached,
    NetworkError,
}

async fn setup_socket_permissions(path: &str, group_name: &str) -> Result<(), Report> {
    let group = Group::from_name(group_name)
        .context("Error while trying to look up `yeet` group on the system")?
        .ok_or(rootcause::report!("`yeet` Group does not exist on system"))?;

    lchown(path, None, Some(group.gid.as_raw()))
        .context("Trying to set varlink socket connection")?;

    let mut perms = fs::metadata(path)
        .await
        .context("Trying to fetch existing file permissions")?
        .permissions();
    perms.set_mode(0o660);
    fs::set_permissions(path, perms)
        .await
        .context("Trying to set file permission")?;

    log::debug!("Socket permissions set: Group '{group_name}' can now access {path}");
    Ok(())
}
