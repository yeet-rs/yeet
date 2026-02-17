use console::style;
use log::info;
use rootcause::Report;
use yeet::server;

use crate::{cli::common, cli_args::Config, sig::ssh};

pub async fn remove(config: &Config, hostname: Option<String>) -> Result<(), Report> {
    let url = common::get_server_url(config).await?;
    let secret_key = &ssh::key_by_url(&url)?;

    let hostname = if let Some(hostname) = hostname {
        hostname
    } else {
        let hostnames = {
            let hosts = server::status(&url, secret_key).await?;
            let mut hostnames: Vec<_> = hosts.iter().map(|h| h.name.clone()).collect();
            hostnames.sort();
            hostnames
        };
        let selected =
            inquire::Select::new("Which host do you want to delete>", hostnames).prompt()?;
        selected
    };

    // The user has to confirm the action
    let confirm = inquire::Confirm::new(
        &style(format!(
            "Are you sure you want to delete {hostname}. This action is not reversable"
        ))
        .red()
        .to_string(),
    )
    .with_default(false)
    .prompt()?;

    if !confirm {
        info!("Aborting...");
        return Ok(());
    }

    info!("Deleting {hostname}...");

    // no takies backsies past this point

    server::host::remove_host(&url, secret_key, &api::HostRemoveRequest { hostname }).await?;

    info!("Deleted!");

    Ok(())
}

pub async fn rename(
    config: &Config,
    current_name: Option<String>,
    new_name: Option<String>,
) -> Result<(), Report> {
    let url = common::get_server_url(config).await?;
    let secret_key = &ssh::key_by_url(&url)?;

    let current_name = if let Some(current_name) = current_name {
        current_name
    } else {
        let hostnames = {
            let hosts = server::status(&url, secret_key).await?;
            let mut hostnames: Vec<_> = hosts.into_iter().map(|h| h.name).collect();
            hostnames.sort();
            hostnames
        };

        let selected =
            inquire::Select::new("Which host do you want to rename>", hostnames).prompt()?;
        selected
    };

    let new_name = if let Some(new_name) = new_name {
        new_name
    } else {
        inquire::Text::new("What should the new name be?").prompt()?
    };

    // The user has to confirm the action
    let confirm = inquire::Confirm::new(&format!(
        "Are you sure you want to rename {current_name} to {new_name}."
    ))
    .with_default(false)
    .prompt()?;

    if !confirm {
        info!("Aborting...");
        return Ok(());
    }

    info!("Renaming {current_name} to {new_name}...");

    server::host::rename_host(
        &url,
        secret_key,
        &api::HostRenameRequest {
            new_name,
            current_name,
        },
    )
    .await?;

    info!("Done!");

    Ok(())
}
