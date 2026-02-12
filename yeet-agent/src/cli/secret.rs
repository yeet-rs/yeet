use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

use clap::{Args, Subcommand};
use console::style;
use inquire::validator::Validation;
use rootcause::{Report, bail};
use yeet::server;

use crate::{cli::common, cli_args::Config, section, sig::ssh};

#[derive(Args)]
pub struct SecretArgs {
    #[command(subcommand)]
    pub command: SecretCommands,
}

#[derive(Subcommand)]
pub enum SecretCommands {
    /// Add or Update a secret
    Add {
        /// The name of the secret
        #[arg(long)]
        name: Option<String>,
        /// The content
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Rename an existing secret
    Rename {
        /// The current name of the host
        #[arg(long)]
        name: Option<String>,
        /// The new name for the host
        #[arg(long)]
        new: Option<String>,
    },
    /// Delete a secret
    Remove {
        /// The name of the secret
        #[arg(long)]
        name: Option<String>,
    },
    /// Allow a `host` to access a `secret`
    Allow {
        /// The name of the host
        #[arg(long)]
        host: Option<String>,
        /// The name of the secret
        #[arg(long)]
        secret: Option<String>,
    },
    /// Deny a `host` to access a `secret`
    Deny {
        /// The name of the host
        #[arg(long)]
        host: Option<String>,
        /// The name of the secret
        #[arg(long)]
        secret: Option<String>,
    },
    /// Show secrets and the associated hosts
    Show {
        /// Filter by secret
        #[arg(long)]
        secret: Vec<String>,
        /// Filter by host
        #[arg(long)]
        host: Vec<String>,
    },
}

pub async fn handle_secret_command(
    args: SecretArgs,
    config: &Config,
) -> Result<(), rootcause::Report> {
    match args.command {
        SecretCommands::Add { name, file } => add(config, name, file).await?,
        SecretCommands::Rename { name, new } => rename(config, name, new).await?,
        SecretCommands::Remove { name } => remove(config, name).await?,
        SecretCommands::Allow { host, secret } => allow(config, secret, host).await?,
        SecretCommands::Deny { host, secret } => deny(config, secret, host).await?,
        SecretCommands::Show { secret, host } => show(config, secret, host).await?,
    }
    Ok(())
}

async fn add(config: &Config, name: Option<String>, file: Option<PathBuf>) -> Result<(), Report> {
    let url = common::get_server_url(config).await?;
    let secret_key = &ssh::key_by_url(&url)?;

    let recipient: age::x25519::Recipient = {
        let recipient = server::secret::get_server_recipient(&url, secret_key).await?;
        recipient
            .parse()
            .map_err(|err| rootcause::report!("Could not parse the server recipient key: {err}"))?
    };

    let name = if let Some(name) = name {
        name
    } else {
        inquire::Text::new("What should the name of the secret be?").prompt()?
    };

    let secret = if let Some(file) = file {
        let bytes = read_to_bytes(file)?;
        age::encrypt(&recipient, &bytes)
    } else {
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

    server::secret::add_secret(
        &url,
        secret_key,
        &api::AddSecretRequest {
            name: name.clone(),
            secret,
        },
    )
    .await?;
    log::info!("Secret {name} created!");

    Ok(())
}

async fn rename(config: &Config, name: Option<String>, new: Option<String>) -> Result<(), Report> {
    let url = common::get_server_url(config).await?;
    let secret_key = &ssh::key_by_url(&url)?;

    let secret_list = server::secret::list(&url, secret_key).await?;

    let name = if let Some(name) = name {
        if !secret_list.contains(&name) {
            bail!("Secret {name} does not exist!")
        }
        name
    } else {
        inquire::Select::new("Which secret do you want to rename?", secret_list.clone()).prompt()?
    };

    let new = if let Some(new) = new {
        new
    } else {
        inquire::Text::new("What should the new name be?").prompt()?
    };

    log::info!("Renaming {name} to {new}...");

    server::secret::rename_secret(
        &url,
        secret_key,
        &api::RenameSecretRequest {
            current_name: name,
            new_name: new,
        },
    )
    .await?;
    log::info!("Done!");

    Ok(())
}

async fn remove(config: &Config, secret: Option<String>) -> Result<(), Report> {
    let url = common::get_server_url(config).await?;
    let secret_key = &ssh::key_by_url(&url)?;

    let secret_list = server::secret::list(&url, secret_key).await?;

    let secret = if let Some(secret) = secret {
        if !secret_list.contains(&secret) {
            bail!("Secret {secret} does not exist!")
        }
        secret
    } else {
        inquire::Select::new("Which secret do you want to delete?", secret_list.clone()).prompt()?
    };

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

    server::secret::remove_secret(
        &url,
        secret_key,
        &api::RemoveSecretRequest {
            secret_name: secret,
        },
    )
    .await?;
    log::info!("Done!");

    Ok(())
}

async fn allow(
    config: &Config,
    secret: Option<String>,
    host: Option<String>,
) -> Result<(), Report> {
    let url = common::get_server_url(config).await?;
    let secret_key = &ssh::key_by_url(&url)?;

    let secret_list = server::secret::list(&url, secret_key).await?;

    let secret = if let Some(secret) = secret {
        if !secret_list.contains(&secret) {
            bail!("Secret {secret} does not exist!")
        }
        secret
    } else {
        inquire::Select::new("Which secret do you want to modify?", secret_list.clone()).prompt()?
    };

    let hostnames = {
        let hosts = server::status(&url, secret_key).await?;
        let mut hostnames: Vec<_> = hosts.iter().map(|h| h.name.clone()).collect();
        hostnames.sort();
        hostnames
    };
    let host = if let Some(host) = host {
        if !hostnames.contains(&host) {
            bail!("Host {host} does not exist!")
        }
        host
    } else {
        inquire::Select::new(
            "Which Host should be able to access this secret?",
            hostnames,
        )
        .prompt()?
    };

    log::info!("Allowing {host} to access {secret}...");

    server::secret::acl(
        &url,
        secret_key,
        &api::AclSecretRequest::AllowHost { secret, host },
    )
    .await?;
    log::info!("Done!");

    Ok(())
}

async fn deny(config: &Config, secret: Option<String>, host: Option<String>) -> Result<(), Report> {
    let url = common::get_server_url(config).await?;
    let secret_key = &ssh::key_by_url(&url)?;

    let secret_list = server::secret::list(&url, secret_key).await?;

    let secret = if let Some(secret) = secret {
        if !secret_list.contains(&secret) {
            bail!("Secret {secret} does not exist!")
        }
        secret
    } else {
        inquire::Select::new("Which secret do you want to modify?", secret_list.clone()).prompt()?
    };

    let hostnames = {
        let hosts = server::status(&url, secret_key).await?;
        let mut hostnames: Vec<_> = hosts.iter().map(|h| h.name.clone()).collect();
        hostnames.sort();
        hostnames
    };
    let host = if let Some(host) = host {
        if !hostnames.contains(&host) {
            bail!("Host {host} does not exist!")
        }
        host
    } else {
        inquire::Select::new("Which Host should be removed?", hostnames).prompt()?
    };

    log::info!("Denying {host} to access {secret}...");

    server::secret::acl(
        &url,
        secret_key,
        &api::AclSecretRequest::RemoveHost { secret, host },
    )
    .await?;
    log::info!("Done!");

    Ok(())
}

async fn show(config: &Config, secret: Vec<String>, host: Vec<String>) -> Result<(), Report> {
    let url = common::get_server_url(config).await?;
    let secret_key = &ssh::key_by_url(&url)?;

    let mut acl = server::secret::get_all_acl(&url, secret_key).await?;

    // Only show the specified secrets if some are set
    if !secret.is_empty() {
        acl.retain(|k, _v| secret.contains(k));
    }

    // Only show the specified hosts if some are set
    if !host.is_empty() {
        acl.values_mut()
            .map(|hosts| hosts.retain(|h| host.contains(h)));
    }

    let mut sections = Vec::new();
    for (secret, hosts) in acl {
        sections.push((
            style(secret).underlined().to_string(),
            vec![("Hosts".to_owned(), hosts.join("\n"))],
        ));
    }

    section::print_sections(&sections);

    Ok(())
}

fn read_to_bytes<P: AsRef<Path>>(path: P) -> std::io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf);
    Ok(buf)
}
