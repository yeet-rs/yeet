use crate::{nix, varlink::YeetDaemonError};
use std::path::PathBuf;

use log::info;
use rootcause::{Report, bail, report};

use crate::varlink;

pub async fn detach(
    version: Option<api::StorePath>,
    force: bool,
    path: PathBuf,
    darwin: bool,
) -> Result<(), Report> {
    let confirm = inquire::Confirm::new(
        "Are you sure you want to detach? This will leave your system in a detached state until you re-attach your system",
    )
    .with_default(true)
    .prompt()?;
    if !confirm {
        info!("Aborting...");
        return Ok(());
    }

    let revision = match version {
        Some(version) => version,
        None => {
            let host = nix::get_host(&path.to_string_lossy(), darwin)?;

            let mut hosts = nix::build_hosts(
                &path.to_string_lossy(),
                vec![host.clone()],
                darwin,
                Some("Detached".to_owned()),
            )?;
            hosts.remove(&host).unwrap()
        }
    };

    info!("Build done. Connecting to yeet agent");

    // The rest is error handling
    match varlink::detach(revision, force).await {
        Ok(_) => {
            info!("Detached successfully")
        }
        Err(varlink::Error::Report(report)) => {
            return Err(report.into());
        }
        Err(varlink::Error::DaemonError(err)) => match err {
            YeetDaemonError::NoConnectionToServer { report } => {
                return Err(report!("Could not connect to yeet server")
                    .context(report)
                    .into_dynamic());
            }
            YeetDaemonError::CredentialError { error } => {
                return Err(report!("There was an error retrieving process permissions")
                    .context(error)
                    .into_dynamic());
            }
            YeetDaemonError::PolkitError { error } => {
                return Err(report!("There was an error during polikit auth")
                    .context(error)
                    .into_dynamic());
            }
            YeetDaemonError::PolkitDetachNoPermission => {
                bail!("Polkit did not authenticate successfully")
            }
            YeetDaemonError::ServerDetachNoPermission => bail!(
                "You have no permission to detach. If you want to ignore this you can use `--force`
                Make sure you understand the consequences before doing so."
            ),
            YeetDaemonError::NoCurrentSystem => unreachable!(),
        },
    }
    Ok(())
}

pub async fn attach() -> Result<(), Report> {
    let confirm = inquire::Confirm::new("Are you sure you want to attach to the server? This will switch to the server specified version").with_default(false).prompt()?;
    if !confirm {
        info!("Aborting...");
        return Ok(());
    }
    varlink::attach().await?;
    info!("Done, system is attached. Will switch to the server version in the next cycle");
    Ok(())
}
