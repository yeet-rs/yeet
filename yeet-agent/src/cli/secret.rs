use std::{collections::HashMap, fs::File, io::Read as _, path::Path};

use clap::{Args, Subcommand};
use console::style;
use inquire::validator::Validation;
use rootcause::Report;

use crate::{cli::common, cli_args::Config, section, sig::ssh};

#[derive(Args)]
pub struct SecretArgs {
    #[command(subcommand)]
    pub command: SecretCommands,
}

#[derive(Subcommand)]
pub enum SecretCommands {
    /// Add or Update a secret
    Add,
    /// Rename an existing secret
    Rename,
    /// Delete a secret
    Remove,
    /// Allow a `host` to access a `secret`
    Allow,
    /// Deny a `host` to access a `secret`
    Block,
    /// Show secrets and the associated hosts
    Show,
}

pub async fn handle_secret_command(
    args: SecretArgs,
    config: &Config,
) -> Result<(), rootcause::Report> {
    match args.command {
        SecretCommands::Add => add(config).await?,
        SecretCommands::Rename => rename(config).await?,
        SecretCommands::Remove => remove(config).await?,
        SecretCommands::Allow => allow(config).await?,
        SecretCommands::Block => deny(config).await?,
        SecretCommands::Show => show(config).await?,
    }
    Ok(())
}

async fn add(config: &Config) -> Result<(), Report> {
    let url = common::get_server_url(config).await?;
    let secret_key = &ssh::key_by_url(&url)?;

    let recipient: age::x25519::Recipient = {
        let recipient = api::server_age_key(&url, secret_key).await?;
        recipient
            .parse()
            .map_err(|err| rootcause::report!("Could not parse the server recipient key: {err}"))?
    };

    let name = inquire::Text::new("What should the name of the secret be?").prompt()?;

    let secret = {
        let path = inquire::Text::new("Secret File:")
            .with_validator(|path: &str| {
                Ok(match File::open(path) {
                    Ok(_) => Validation::Valid,
                    Err(err) => Validation::Invalid(format!("Not a valid file: {err}").into()),
                })
            })
            .prompt()?;
        let bytes = read_to_bytes(path)?;
        age::encrypt(&recipient, &bytes)
    }?;

    api::create_secret(&url, secret_key, &name, &secret).await?;
    log::info!("Secret {name} created!");

    allow(config).await?;

    Ok(())
}

async fn rename(config: &Config) -> Result<(), Report> {
    let url = common::get_server_url(config).await?;
    let secret_key = &ssh::key_by_url(&url)?;

    let secret_list = api::list_secrets(&url, secret_key).await?;

    let secret =
        inquire::Select::new("Which secret do you want to rename?", secret_list).prompt()?;

    let new = inquire::Text::new("What should the new name be?").prompt()?;

    log::info!("Renaming {} to {new}...", secret.name);

    api::rename_secret(&url, secret_key, secret.id, &new).await?;
    log::info!("Done!");

    Ok(())
}

async fn remove(config: &Config) -> Result<(), Report> {
    let url = common::get_server_url(config).await?;
    let secret_key = &ssh::key_by_url(&url)?;

    let secret_list = api::list_secrets(&url, secret_key).await?;

    let secret =
        inquire::Select::new("Which secret do you want to delete?", secret_list).prompt()?;

    // The user has to confirm the action
    let confirm = inquire::Confirm::new(
        &style(format!(
            "Are you sure you want to delete {secret}. This action is not reversable"
        ))
        .red()
        .to_string(),
    )
    .with_default(false)
    .prompt()?;

    if !confirm {
        log::info!("Aborting...");
        return Ok(());
    }

    log::info!("Deleting...");

    api::delete_secret(&url, secret_key, secret.id).await?;
    log::info!("Done!");

    Ok(())
}

pub async fn allow(config: &Config) -> Result<(), Report> {
    let url = common::get_server_url(config).await?;
    let secret_key = &ssh::key_by_url(&url)?;

    let secret_list = api::list_secrets(&url, secret_key).await?;

    let secrets =
        inquire::MultiSelect::new("Which secret do you want to modify?", secret_list.clone())
            .prompt()?;

    let mut hosts = api::list_hosts(&url, secret_key).await?;
    let hostnames = {
        let mut hostnames: Vec<_> = hosts.iter().map(|host| host.hostname.clone()).collect();
        hostnames.sort();
        hostnames
    };
    let selected = inquire::MultiSelect::new(
        "Which Hosts should be able to access this secret>",
        hostnames,
    )
    .prompt()?;

    hosts.retain(|host| selected.contains(&host.hostname));

    log::info!("Allowing {hosts:?} to access {secrets:?}...");

    for host in hosts {
        for secret in &secrets {
            let response = api::allow_host(&url, secret_key, secret.id, host.id).await;
            if let Err(err) = response {
                log::error!(
                    "Error adding access for {} from {secret}:\n{err}",
                    host.hostname
                );
            }
        }
    }
    log::info!("Done!");

    Ok(())
}

async fn deny(config: &Config) -> Result<(), Report> {
    let url = common::get_server_url(config).await?;
    let secret_key = &ssh::key_by_url(&url)?;

    let selected_secrets = {
        let secret_list = api::list_secrets(&url, secret_key).await?;
        inquire::MultiSelect::new("Which secret do you want to modify?", secret_list).prompt()?
    };

    // get acl of all the secrets and then collect all the hosts that are allowed

    let mut hosts = {
        // collect acl
        let mut acl = api::list_secret_acl(&url, secret_key).await?;

        // only want the acl that are selected
        acl.retain(|(secret, _v)| selected_secrets.contains(secret));

        let host_ids: Vec<api::HostID> = acl.into_iter().flat_map(|(_k, hosts)| hosts).collect();
        let mut hosts = api::list_hosts(&url, secret_key).await?;
        // only want hosts in the acl
        hosts.retain(|host| host_ids.contains(&host.id));
        hosts
    };
    let selected_hosts = {
        let hostnames = {
            let mut hostnames: Vec<_> = hosts.iter().map(|host| host.hostname.clone()).collect();
            hostnames.sort();
            hostnames
        };

        inquire::MultiSelect::new("Which Hosts should be removed>", hostnames).prompt()?
    };

    hosts.retain(|host| selected_hosts.contains(&host.hostname));

    log::info!("Denying {hosts:?} to access {selected_secrets:?}...");

    for host in hosts {
        for secret in &selected_secrets {
            let response = api::block_host(&url, secret_key, secret.id, host.id).await;
            if let Err(err) = response {
                log::error!(
                    "Error removing access for {} from {secret}:\n{err}",
                    host.id
                );
            }
        }
    }
    log::info!("Done!");

    Ok(())
}

async fn show(config: &Config) -> Result<(), Report> {
    let url = common::get_server_url(config).await?;
    let secret_key = &ssh::key_by_url(&url)?;

    let acl = api::list_secret_acl(&url, secret_key).await?;

    if acl.is_empty() {
        log::info!("No secrets yet!");
        return Ok(());
    }

    let all_hosts: HashMap<api::HostID, String> = {
        let hosts = api::list_hosts(&url, secret_key).await?;
        hosts
            .into_iter()
            .map(|host| (host.id, host.hostname))
            .collect()
    };

    let mut sections = Vec::new();
    for (secret, hosts) in acl {
        // map the host ids to hostnames
        let mut hosts: Vec<String> = hosts
            .iter()
            .map(|host| {
                all_hosts
                    .get(host)
                    .cloned()
                    .unwrap_or("Unknown Host".to_owned())
            })
            .collect();
        hosts.sort();

        sections.push((
            style(format!("{secret}:")).bold().underlined().to_string(),
            vec![("Hosts".to_owned(), hosts.join("\n"))],
        ));
    }

    section::print_sections(&sections);

    Ok(())
}

fn read_to_bytes<P: AsRef<Path>>(path: P) -> std::io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(buf)
}
