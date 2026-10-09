#![expect(clippy::multiple_inherent_impl)]
use std::os::fd::OwnedFd;

use color_eyre::eyre::{Context as _, Result};

use serde::{Deserialize, Serialize};

use url::Url;
use zlink::{Connection, ReplyError, proxy, unix};

shadow_rs::shadow!(build);

use crate::cli_args::AgentConfig;

const SOCKET_PATH: &str = "/run/yeet/agent.varlink";

#[proxy("ch.yeetme.yeet")]
pub trait YeetProxy {
    async fn status(&mut self) -> zlink::Result<Result<DaemonStatus, YeetDaemonError>>;
    async fn config(&mut self) -> zlink::Result<Result<AgentConfig, YeetDaemonError>>;

    async fn download_update(
        &mut self,
        dry_run: bool,
        #[zlink(fds)] fds: Vec<OwnedFd>,
    ) -> zlink::Result<Result<DownloadUpdateResult, YeetDaemonError>>;

    async fn activate_update(
        &mut self,
        dry_run: bool,
        #[zlink(fds)] fds: Vec<OwnedFd>,
    ) -> zlink::Result<Result<ActivateUpdateResult, YeetDaemonError>>;
    async fn detach(
        &mut self,
        version: api::StorePath,
    ) -> zlink::Result<Result<(), YeetDaemonError>>;
    async fn attach(&mut self) -> zlink::Result<Result<(), YeetDaemonError>>;
}

#[tracing::instrument(err, ret)]
pub async fn client() -> Result<Connection<zlink::unix::Stream>, VarlinkError> {
    log::debug!("Connecting to {SOCKET_PATH}");
    Ok(unix::connect(SOCKET_PATH)
        .await
        .context("Trying to set up the varlink connection\nMake sure you are in the `yeet` group and the daemon is running")
        ?)
}

varlink_method!(status() -> DaemonStatus);
varlink_method!(config() -> AgentConfig);
varlink_method!(detach(version: api::StorePath) -> ());
varlink_method!(attach() -> ());
varlink_method!(download_update(dry_run: bool, fds: Vec<OwnedFd>) -> DownloadUpdateResult);
varlink_method!(activate_update(dry_run: bool, fds: Vec<OwnedFd>) -> ActivateUpdateResult);

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

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum DownloadUpdateResult {
    DryRun,
    Downloaded,
    UpToDate,
    Detached,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ActivateUpdateResult {
    DryRun,
    NotDownloaded,
    Activated,
    AlreadySwitched,
    Detached,
}

#[derive(thiserror::Error, Debug)]
pub enum VarlinkError {
    #[error(transparent)]
    Report(#[from] color_eyre::Report),
    #[error("Defined error from Daemon:\n{0:?}")]
    DaemonError(YeetDaemonError),
}

#[derive(Debug, ReplyError, zlink::introspect::ReplyError)]
#[zlink(interface = "ch.yeetme.yeet")]
pub enum YeetDaemonError {
    EyreError {
        error: String,
    },
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
    /// Update actions only available only on attended systems
    UnattendedSystem,
}

impl From<std::io::Error> for YeetDaemonError {
    fn from(value: std::io::Error) -> Self {
        Self::CredentialError {
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
impl From<color_eyre::eyre::ErrReport> for YeetDaemonError {
    fn from(value: color_eyre::eyre::ErrReport) -> Self {
        Self::EyreError {
            error: value.to_string(),
        }
    }
}

macro_rules! varlink_method {
    ($fn_name:ident($($param:ident: $param_ty:ty),* $(,)?) -> $ret:ty) => {
        #[tracing::instrument(err)]
        pub async fn $fn_name($($param: $param_ty),*) -> Result<$ret, VarlinkError> {
            let mut client = client().await?;
            client
                .$fn_name($($param),*)
                .await
                .context(
                    "Could not communicate with the varlink daemon. Are you running the same version?",
                )?
                .map_err(VarlinkError::DaemonError)
        }
    };
}
pub(crate) use varlink_method;
