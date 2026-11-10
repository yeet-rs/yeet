use clap::{Args, Subcommand};
use color_eyre::Result;
use owo_colors::OwoColorize as _;
use tracing::info;

use crate::{
    cli::common,
    cli_args::Config,
    section::{self, DisplaySection as _, DisplaySectionItem as _},
    sig::ssh,
};

#[derive(Args)]
pub struct HostArgs {
    #[command(subcommand)]
    pub command: HostCommands,
}

#[derive(Subcommand)]
pub enum HostCommands {
    /// Rename an existing yeet host
    Rename,
    /// Delete an host including all authentication info
    Remove,
    /// Add a tag to this host
    Tag,
    /// Remove a tag from this host
    RemoveTag,
    /// Change the password of a local user on a host. Applied on the next agent poll
    SetPassword,
}

pub async fn handle_command(args: HostArgs, config: &Config) -> Result<()> {
    match args.command {
        HostCommands::Remove => remove(config).await,
        HostCommands::Rename => rename(config).await,
        HostCommands::Tag => tag(config).await,
        HostCommands::RemoveTag => remove_tag(config).await,
        HostCommands::SetPassword => set_password(config).await,
    }
}

#[tracing::instrument(skip(config))]
pub async fn remove(config: &Config) -> Result<()> {
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
    let confirm = inquire::Confirm::new(&format!(
        "Are you sure you want to delete {}. It will delete every trace of this host.
            This action is not reversable",
        selected_host.hostname.red()
    ))
    .with_default(false)
    .prompt()?;

    if !confirm {
        info!("Aborting...");
        return Ok(());
    }

    info!("Deleting {}...", selected_host.hostname);

    // no takies backsies past this point

    api::delete_key(&url, secret_key, selected_host.key).await?;

    info!("Deleted!");

    Ok(())
}

#[tracing::instrument(skip(config))]
pub async fn rename(config: &Config) -> Result<()> {
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

#[tracing::instrument(skip(config))]
pub async fn hosts(config: &Config, full: bool) -> Result<()> {
    let url = common::get_server_url(config).await?;
    let secret_key = &ssh::key_by_url(&url)?;

    let hosts_section: Vec<(String, Vec<(String, String)>)> = {
        let mut hosts = api::list_hosts(&url, secret_key).await?;
        hosts.sort_by_key(|host| host.hostname.clone());

        if full {
            let hostnames = hosts.iter().map(|host| host.hostname.clone()).collect();
            let selected =
                inquire::MultiSelect::new("Which hosts do you want to display>", hostnames)
                    .prompt()?;
            hosts.retain(|host| selected.contains(&host.hostname));
            hosts.into_iter().map(|host| host.as_section()).collect()
        } else {
            vec![(
                "Hosts:".underline().to_string(),
                hosts
                    .into_iter()
                    .map(|host| host.as_section_item())
                    .collect(),
            )]
        }
    };

    section::print_sections(&hosts_section);

    Ok(())
}

#[tracing::instrument(skip(config))]
async fn tag(config: &Config) -> Result<()> {
    let url = common::get_server_url(config).await?;
    let key = &ssh::key_by_url(&url)?;

    let hosts = api::list_hosts(&url, key).await?;

    let hosts = inquire::MultiSelect::new("Which hosts do you want to tag?", hosts)
        .with_validator(|list: &[inquire::list_option::ListOption<&api::Host>]| {
            if list.is_empty() {
                return Ok(inquire::validator::Validation::Invalid(
                    "You must select a host!".into(),
                ));
            }
            Ok(inquire::validator::Validation::Valid)
        })
        .prompt()?;

    let tags = api::tag::list_tags(&url, key).await?;
    let tags = inquire::MultiSelect::new("Which tags should be assigned?", tags)
        .with_validator(
            |list: &[inquire::list_option::ListOption<&api::tag::Tag>]| {
                if list.is_empty() {
                    return Ok(inquire::validator::Validation::Invalid(
                        "You must select a tag!".into(),
                    ));
                }
                Ok(inquire::validator::Validation::Valid)
            },
        )
        .prompt()?;

    for tag in tags {
        for host in &hosts {
            api::tag::tag_resource(
                &url,
                key,
                api::tag::ResourceTag {
                    resource: api::tag::Resource::Host(host.id),
                    tag: tag.id,
                },
            )
            .await?;
            info!("Tagging {} with {}", host.hostname, tag.name);
        }
    }

    Ok(())
}

#[tracing::instrument(skip(config))]
async fn remove_tag(config: &Config) -> Result<()> {
    let url = common::get_server_url(config).await?;
    let key = &ssh::key_by_url(&url)?;

    let hosts = api::list_hosts(&url, key).await?;

    let hosts = inquire::MultiSelect::new("Which hosts do you want to modify?", hosts)
        .with_validator(|list: &[inquire::list_option::ListOption<&api::Host>]| {
            if list.is_empty() {
                return Ok(inquire::validator::Validation::Invalid(
                    "You must select a host!".into(),
                ));
            }
            Ok(inquire::validator::Validation::Valid)
        })
        .prompt()?;

    let tags = {
        let mut tags = hosts
            .iter()
            .flat_map(|host| host.tags.clone())
            .collect::<Vec<_>>();
        tags.dedup();
        tags
    };
    let tags = inquire::MultiSelect::new("Which tags should be removed?", tags)
        .with_validator(
            |list: &[inquire::list_option::ListOption<&api::tag::Tag>]| {
                if list.is_empty() {
                    return Ok(inquire::validator::Validation::Invalid(
                        "You must select a tag!".into(),
                    ));
                }
                Ok(inquire::validator::Validation::Valid)
            },
        )
        .prompt()?;

    for tag in tags {
        for host in &hosts {
            api::tag::delete_resource_from_tag(
                &url,
                key,
                api::tag::ResourceTag {
                    resource: api::tag::Resource::Host(host.id),
                    tag: tag.id,
                },
            )
            .await?;
            info!("Removing {} from {}", tag.name, host.hostname);
        }
    }

    Ok(())
}

/// How long to wait for the agent before reporting the task as queued
const SET_PASSWORD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);
/// How often to ask the server whether the agent has reported back
const SET_PASSWORD_POLL: std::time::Duration = std::time::Duration::from_secs(3);

#[tracing::instrument(skip(config))]
async fn set_password(config: &Config) -> Result<()> {
    use color_eyre::eyre::eyre;
    use sha_crypt::{PasswordHasher as _, ShaCrypt};

    let url = common::get_server_url(config).await?;
    let secret_key = &ssh::key_by_url(&url)?;

    let hosts = api::list_hosts(&url, secret_key).await?;
    let host = inquire::Select::new("On which host?", hosts).prompt()?;

    let username = inquire::Text::new("Which user?").prompt()?;
    if username.is_empty() {
        return Err(eyre!("Username cannot be empty"));
    }
    if username == "root" {
        return Err(eyre!("Changing the password of root is not permitted"));
    }

    let hashed_password = {
        let password = inquire::Password::new("New password:").prompt()?;
        if password.is_empty() {
            return Err(eyre!("Password cannot be empty"));
        }
        ShaCrypt::default()
            .hash_password(password.as_bytes())
            .map_err(|err| eyre!("Could not hash the password: {err}"))?
            .as_str()
            .to_owned()
    }; // plaintext password is dropped here, only the hash leaves this block

    let confirm = inquire::Confirm::new(&format!(
        "Change the password of {} on {}?",
        username.bold(),
        host.hostname.bold()
    ))
    .with_default(false)
    .prompt()?;

    if !confirm {
        info!("Aborting...");
        return Ok(());
    }

    let task = api::HostTask::SetPassword {
        username,
        hashed_password,
    };
    let id = api::create_task(&url, secret_key, host.id, &task).await?;
    info!("Queued, waiting for {} to pick it up...", host.hostname);

    let start = tokio::time::Instant::now();
    loop {
        let status = api::task_status(&url, secret_key, id).await?;
        match status.state {
            api::TaskState::Pending if start.elapsed() >= SET_PASSWORD_TIMEOUT => {
                info!(
                    "{} has not picked up the task yet (last seen {}). It will be applied when the host next polls, until {}",
                    host.hostname,
                    api::time_diff(host.last_ping, jiff::Unit::Minute, 5.0, jiff::Unit::Second),
                    status.expires_at
                );
                return Ok(());
            }
            api::TaskState::Pending => tokio::time::sleep(SET_PASSWORD_POLL).await,
            api::TaskState::Done => {
                info!("Password changed on {}", host.hostname.green());
                return Ok(());
            }
            api::TaskState::Failed => {
                return Err(eyre!(
                    "{} refused: {}",
                    host.hostname,
                    status.message.unwrap_or_default()
                ));
            }
            api::TaskState::Expired => {
                return Err(eyre!(
                    "The task expired before {} picked it up",
                    host.hostname
                ));
            }
        }
    }
}
