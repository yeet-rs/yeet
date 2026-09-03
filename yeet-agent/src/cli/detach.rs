use std::path::PathBuf;

use color_eyre::{Result, Section as _, eyre::eyre};
use log::info;
use yeet::nix;

use crate::{varlink, varlink::YeetDaemonError};

#[tracing::instrument(err)]
pub async fn detach(version: Option<api::StorePath>, path: PathBuf, darwin: bool) -> Result<()> {
    let confirm = inquire::Confirm::new(
        "Are you sure you want to detach? This will leave your system in a detached state until you re-attach your system",
    )
    .with_default(true)
    .prompt()?;
    if !confirm {
        info!("Aborting...");
        return Ok(());
    }

    let revision = if let Some(version) = version {
        version
    } else {
        let host = nix::get_host(&path.to_string_lossy(), darwin)?;

        let mut hosts = nix::build_hosts(
            &path.to_string_lossy(),
            vec![host.clone()],
            darwin,
            Some("Detached".to_owned()),
        )?;
        #[expect(
            clippy::unwrap_used,
            reason = "because we source nix::get_host from the same nix file source"
        )]
        hosts.remove(&host).unwrap()
    };

    info!("Build done. Connecting to yeet agent");

    // The rest is error handling
    match varlink::detach(revision).await {
        Ok(()) => {
            info!("Detached successfully");
        }
        Err(varlink::VarlinkError::Report(report)) => {
            return Err(report);
        }
        Err(varlink::VarlinkError::DaemonError(err)) => match err {
            YeetDaemonError::NoConnectionToServer { error } => {
                return Err(eyre!("Could not connect to yeet server").note(error));
            }
            YeetDaemonError::CredentialError { error } => {
                return Err(eyre!("There was an error retrieving process permissions").note(error));
            }
            YeetDaemonError::PolkitError { error } => {
                return Err(eyre!("There was an error during polikit auth").note(error));
            }
            #[expect(clippy::unreachable, reason = "Can only happen on varlink status")]
            YeetDaemonError::NoCurrentSystem
            | YeetDaemonError::EyreError { .. }
            | YeetDaemonError::UnattendedSystem => unreachable!(),
        },
    }
    Ok(())
}

#[tracing::instrument(err)]
pub async fn attach() -> Result<()> {
    let confirm = inquire::Confirm::new("Are you sure you want to attach to the server? This will switch to the server specified version").with_default(false).prompt()?;
    if !confirm {
        info!("Aborting...");
        return Ok(());
    }
    varlink::attach().await?;
    info!("Done, system is attached. Will switch to the server version in the next cycle");
    Ok(())
}
