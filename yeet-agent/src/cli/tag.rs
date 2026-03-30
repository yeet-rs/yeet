use clap::{Args, Subcommand};

use colored::Colorize as _;
use log::info;
use rootcause::Report;

use crate::{
    cli::common,
    cli_args::Config,
    section::{self},
    sig::ssh,
};

#[derive(Args)]
pub struct TagArgs {
    #[command(subcommand)]
    pub command: TagCommands,
}

#[derive(Subcommand)]
pub enum TagCommands {
    /// Create a new tag (requires `all_tag`)
    Create,
    /// Delete an existing tag (requires `all_tag`)
    Delete,
    /// Rename an existing tag (requires `all_tag`)
    Rename,
}

pub async fn handle_command(args: TagArgs, config: &Config) -> Result<(), rootcause::Report> {
    match args.command {
        TagCommands::Create => create_tag(config).await,
        TagCommands::Delete => delete_tag(config).await,
        TagCommands::Rename => rename_tag(config).await,
    }
}

async fn create_tag(config: &Config) -> Result<(), Report> {
    let url = common::get_server_url(config).await?;
    let key = &ssh::key_by_url(&url)?;

    let tagname = inquire::Text::new("What should the tag be called?").prompt()?;

    api::tag::create_tag(&url, key, &tagname).await?;
    info!("tag {tagname} created");

    Ok(())
}

async fn delete_tag(config: &Config) -> Result<(), Report> {
    let url = common::get_server_url(config).await?;
    let key = &ssh::key_by_url(&url)?;

    let tag = inquire::Select::new(
        "Which tag do you want to delete?",
        api::tag::list_tags(&url, key).await?,
    )
    .prompt()?;

    let confirm = inquire::Confirm::new(
        &format!(
            "Are you sure you want to delete {}. It will delete every trace of this tag.
This action is not reversable",
            tag.name
        )
        .red(),
    )
    .with_default(false)
    .prompt()?;

    if !confirm {
        info!("Aborting");
        return Ok(());
    }

    api::tag::delete_tag(&url, key, tag.id).await?;
    info!("Deleted {tag}");

    Ok(())
}

async fn rename_tag(config: &Config) -> Result<(), Report> {
    let url = common::get_server_url(config).await?;
    let key = &ssh::key_by_url(&url)?;

    let tag = inquire::Select::new(
        "Which tag do you want to rename?",
        api::tag::list_tags(&url, key).await?,
    )
    .prompt()?;

    let new = inquire::Text::new(&format!("How should {} be called?", tag.name)).prompt()?;

    api::tag::rename_tag(&url, key, tag.id, &new).await?;

    info!("Renamed {} to {new}", tag.name);

    Ok(())
}

pub async fn list_tags(config: &Config) -> Result<(), Report> {
    let url = common::get_server_url(config).await?;
    let key = &ssh::key_by_url(&url)?;

    let tags = {
        let tags = api::tag::list_tags(&url, key).await?;
        tags.into_iter()
            .map(|tag| (tag.to_string(), "".to_owned()))
            .collect()
    };

    let section = vec![("Tags:".underline().to_string(), tags)];
    section::print_sections(&section);

    Ok(())
}
