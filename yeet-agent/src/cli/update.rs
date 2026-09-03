use clap::Args;
use color_eyre::{Result, eyre::bail};
use log::info;
use std::io::{self};

use crate::varlink;

#[derive(Args, Debug)]
pub struct UpdateArgs {
    /// Say yes to every prompt
    #[arg(long)]
    yes: bool,
    // #[command(subcommand)]
    // pub command: UpdateCommands,
}

#[tracing::instrument(err)]
pub async fn update(args: UpdateArgs) -> Result<()> {
    // get a dry run to ask the user
    let dry_run_result = varlink::download_update(
        !args.yes,
        vec![
            nix::unistd::dup(&io::stdout())?,
            nix::unistd::dup(&io::stderr())?,
        ],
    )
    .await?;

    match dry_run_result {
        varlink::DownloadUpdateResult::Downloaded => {
            info!("File is already downloaded")
        }
        varlink::DownloadUpdateResult::UpToDate => {
            info!("You are Up To Date");
            return Ok(());
        }
        varlink::DownloadUpdateResult::Detached => {
            info!("You are currently detached");
            return Ok(());
        }
        varlink::DownloadUpdateResult::DryRun => {}
    }

    if !args.yes && matches!(dry_run_result, varlink::DownloadUpdateResult::DryRun) {
        if !inquire::Confirm::new("Do you want to download this update (without installing)?")
            .with_default(true)
            .prompt()?
        {
            // User does not want to update yet
            return Ok(());
        }
    }

    // we do not need to run it a second time if it is already downloaded
    if matches!(dry_run_result, varlink::DownloadUpdateResult::DryRun) {
        varlink::download_update(
            false,
            vec![
                nix::unistd::dup(&io::stdout())?,
                nix::unistd::dup(&io::stderr())?,
            ],
        )
        .await?;
    }

    let dry_run_result = varlink::activate_update(
        !args.yes,
        vec![
            nix::unistd::dup(&io::stdout())?,
            nix::unistd::dup(&io::stderr())?,
        ],
    )
    .await?;
    match dry_run_result {
        varlink::ActivateUpdateResult::DryRun => {}
        varlink::ActivateUpdateResult::NotDownloaded => {
            bail!("Downloading the update was not succesfull")
        }
        varlink::ActivateUpdateResult::Activated
        | varlink::ActivateUpdateResult::AlreadySwitched => {
            info!("You are already running on the newest version");
            return Ok(());
        }

        varlink::ActivateUpdateResult::Detached => {
            info!("You are currently detached");
            return Ok(());
        }
    }

    if !args.yes && matches!(dry_run_result, varlink::ActivateUpdateResult::DryRun) {
        if !inquire::Confirm::new("Do you want to install this update (might cause a logout)?")
            .with_default(true)
            .prompt()?
        {
            // User does not want to update yet
            return Ok(());
        }
    }

    varlink::activate_update(
        false,
        vec![
            nix::unistd::dup(&io::stdout())?,
            nix::unistd::dup(&io::stderr())?,
        ],
    )
    .await?;
    let version = crate::nix::nixos_version()?;
    info!(
        "Updated to {}: {}",
        version.nixos_version,
        crate::nix::nixos_variant_name()?
    );

    Ok(())
}
