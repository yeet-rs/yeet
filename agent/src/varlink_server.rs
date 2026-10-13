#![expect(clippy::multiple_inherent_impl)]
use std::{
    os::{
        fd::OwnedFd,
        unix::fs::{PermissionsExt as _, lchown},
    },
    path::Path,
    process::Stdio,
};

use api::AgentAction;
use color_eyre::{
    Section as _,
    eyre::{Context as _, OptionExt as _, Result, eyre},
};
use httpsig_hyper::prelude::SecretKey;

use nix::unistd::Group;
use tokio::fs::{self, remove_file};
use tracing::{debug, info};

use yeet_agent::varlink::*;
use zlink::connection::socket::FetchPeerCredentials;

shadow_rs::shadow!(build);

use crate::{AgentConfig, agent};

struct YeetVarlinkService {
    pub config: AgentConfig,
    pub key: SecretKey,
}

#[zlink::service]
impl<Sock> YeetVarlinkService
where
    Sock::ReadHalf: FetchPeerCredentials,
{
    #[zlink(interface = "ch.yeetme.yeet")]
    pub async fn status(&self) -> Result<DaemonStatus, YeetDaemonError> {
        debug!("Varlink: Daemon status requested");

        //TODO unwrap
        let verified = match api::is_host_verified(&self.config.server, &self.key).await {
            Ok(verified) => Some(verified.is_success()),
            Err(_) => None,
        };

        let system_check = {
            let Ok(store_path) = crate::nix::get_active_version() else {
                return Err(YeetDaemonError::NoCurrentSystem);
            };

            api::check_system(
                &self.config.server,
                &self.key,
                api::VersionRequest { store_path },
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

    #[expect(
        clippy::unused_async,
        clippy::unused_async_trait_impl,
        reason = "varlink proxy methods need async"
    )]
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
        let _err = crate::nix::detach(&version);

        info!("Switched to detached version");

        Ok(())
    }

    pub async fn attach(&self) -> Result<(), YeetDaemonError> {
        let _status = api::attach_self(&self.config.server, &self.key).await?;
        info!("System attached");

        Ok(())
    }

    pub async fn download_update(
        &self,
        dry_run: bool,
        #[zlink(fds)] mut fds: Vec<OwnedFd>,
    ) -> Result<DownloadUpdateResult, YeetDaemonError> {
        if !self.config.attended {
            return Err(YeetDaemonError::UnattendedSystem);
        }

        let Ok(store_path) = crate::nix::get_active_version() else {
            return Err(YeetDaemonError::NoCurrentSystem);
        };

        let agent_action = api::check_system(
            &self.config.server,
            &self.key,
            api::VersionRequest { store_path },
        )
        .await?;
        let store_path = match agent_action {
            AgentAction::Nothing => return Ok(DownloadUpdateResult::UpToDate),
            AgentAction::Detach => return Ok(DownloadUpdateResult::Detached),
            AgentAction::SwitchTo(remote_store_path) => remote_store_path,
        };

        let stdout = fds.pop().ok_or_eyre("Not fd for stderr sent")?;
        let stderr = fds.pop().ok_or_eyre("Not fd for stdout sent")?;

        crate::nix::realise_store_path(
            &store_path,
            &self.config.server,
            &self.key,
            Stdio::from(stderr),
            Stdio::from(stdout),
            dry_run,
        )
        .await?;

        if std::fs::exists(store_path.store_path)? {
            Ok(DownloadUpdateResult::Downloaded)
        } else {
            Ok(DownloadUpdateResult::DryRun)
        }
    }

    pub async fn activate_update(
        &self,
        dry_run: bool,
        #[zlink(fds)] mut fds: Vec<OwnedFd>,
    ) -> Result<ActivateUpdateResult, YeetDaemonError> {
        if !self.config.attended {
            return Err(YeetDaemonError::UnattendedSystem);
        }

        let Ok(store_path) = crate::nix::get_active_version() else {
            return Err(YeetDaemonError::NoCurrentSystem);
        };

        let agent_action = api::check_system(
            &self.config.server,
            &self.key,
            api::VersionRequest { store_path },
        )
        .await?;
        let store_path = match agent_action {
            AgentAction::Nothing => return Ok(ActivateUpdateResult::AlreadySwitched),
            AgentAction::Detach => return Ok(ActivateUpdateResult::Detached),
            AgentAction::SwitchTo(remote_store_path) => remote_store_path,
        };

        // User first needs to download -> does not happen normally with `yeet update`
        if !std::fs::exists(&store_path.store_path)? {
            return Ok(ActivateUpdateResult::NotDownloaded);
        }

        let stdout = fds.pop().ok_or_eyre("Not fd for stderr sent")?;
        let stderr = fds.pop().ok_or_eyre("Not fd for stdout sent")?;

        if dry_run {
            crate::nix::activate_system(&store_path.store_path, stderr, stdout, dry_run)?;
            Ok(ActivateUpdateResult::DryRun)
        } else {
            agent::activate_system_with_secrets(
                &store_path,
                &self.config.server,
                &self.key,
                stderr,
                stdout,
            )
            .await?;
            Ok(ActivateUpdateResult::Activated)
        }
    }
}

#[tracing::instrument(err, skip(key))]
pub(crate) async fn start_service(config: AgentConfig, key: SecretKey) -> Result<()> {
    YeetVarlinkService::start(config, key).await
}

impl YeetVarlinkService {
    #[tracing::instrument(err, skip(key))]
    pub async fn start(config: AgentConfig, key: SecretKey) -> Result<()> {
        let listener = {
            let _err = remove_file(SOCKET_PATH).await;
            #[expect(clippy::unwrap_used)]
            fs::create_dir_all(Path::new(SOCKET_PATH).parent().unwrap())
                .await
                .context("Ensuring the Socket dir is available")?;
            let listener =
                zlink::unix::bind(SOCKET_PATH).note(format!("SOCKET_PATH: {SOCKET_PATH}"))?;

            setup_socket_permissions(SOCKET_PATH, "yeet").await?;

            listener
        };

        debug!("Socket created at {SOCKET_PATH}");
        let server = zlink::Server::new(listener, Self { config, key });
        info!("Listening for varlink connections");
        server.run().await.map_err(std::convert::Into::into)
    }
}

async fn setup_socket_permissions(path: &str, group_name: &str) -> Result<()> {
    let group = Group::from_name(group_name)
        .context("Error while trying to look up `yeet` group on the system")?
        .ok_or(eyre!("`yeet` Group does not exist on system"))?;

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

    debug!("Socket permissions set: Group '{group_name}' can now access {path}");
    Ok(())
}
