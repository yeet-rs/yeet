use console::style;
use log::info;
use rootcause::Report;

use crate::{cli::common, cli_args::Config, sig::ssh};

pub async fn remove(config: &Config) -> Result<(), Report> {
    let url = common::get_server_url(config).await?;
    let secret_key = &ssh::key_by_url(&url)?;

    let hosts = api::list_hosts(&url, secret_key).await?;
    let selected_host = {
        let hostnames = {
            let mut hostnames: Vec<_> = hosts.iter().map(|host| host.hostname.clone()).collect();
            hostnames.sort();
            hostnames
        };

        inquire::Select::new("Which host do you want to delete>", hostnames).prompt()?
    };
    #[expect(
        clippy::unwrap_used,
        reason = "we fed the hosts into the select. inquire ensure a selection"
    )]
    let selected_host = hosts
        .into_iter()
        .find(|host| host.hostname == selected_host)
        .unwrap();

    // The user has to confirm the action
    let confirm = inquire::Confirm::new(
        &style(format!(
            "Are you sure you want to delete {}. It will delete every trace of this host.
            This action is not reversable",
            selected_host.hostname
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

    info!("Deleting {}...", selected_host.hostname);

    // no takies backsies past this point

    api::delete_key(&url, secret_key, &selected_host.key).await?;

    info!("Deleted!");

    Ok(())
}

pub async fn rename(config: &Config) -> Result<(), Report> {
    let url = common::get_server_url(config).await?;
    let secret_key = &ssh::key_by_url(&url)?;

    let hosts = api::list_hosts(&url, secret_key).await?;
    let selected_host = {
        let hostnames = {
            let mut hostnames: Vec<_> = hosts.iter().map(|host| host.hostname.clone()).collect();
            hostnames.sort();
            hostnames
        };

        inquire::Select::new("Which host do you want to rename>", hostnames).prompt()?
    };
    #[expect(
        clippy::unwrap_used,
        reason = "we fed the hosts into the select. inquire ensure a selection"
    )]
    let selected_host = hosts
        .into_iter()
        .find(|host| host.hostname == selected_host)
        .unwrap();

    let new_name = inquire::Text::new("What should the new name be?").prompt()?;

    // The user has to confirm the action
    let confirm = inquire::Confirm::new(&format!(
        "Are you sure you want to rename {} to {new_name}.",
        selected_host.hostname
    ))
    .with_default(false)
    .prompt()?;

    if !confirm {
        info!("Aborting...");
        return Ok(());
    }

    info!("Renaming {} to {new_name}...", selected_host.hostname);

    api::rename_host(&url, secret_key, selected_host.id, &new_name).await?;

    info!("Done!");

    Ok(())
}
