use clap::{Args, Subcommand};
use color_eyre::Result;
use colored::Colorize as _;

use crate::{
    cli::common,
    cli_args::Config,
    section::{self, DisplaySectionItem as _},
    sig::ssh,
};

#[derive(Args)]
pub struct ArtifactArgs {
    #[command(subcommand)]
    pub command: ArtifactCommands,
}

#[derive(Subcommand)]
pub enum ArtifactCommands {
    /// Show the content of an artifact
    Show,
    /// Delete an artifact
    Delete,
}

pub async fn handle_command(args: ArtifactArgs, config: &Config) -> Result<()> {
    match args.command {
        ArtifactCommands::Show => show(config).await,
        ArtifactCommands::Delete => delete(config).await,
    }
}
#[tracing::instrument(skip(config), err)]
async fn show(config: &Config) -> Result<()> {
    let url = common::get_server_url(config).await?;
    let secret_key = &ssh::key_by_url(&url)?;

    let artifact = {
        let mut artifacts = api::list_artifacts(&url, secret_key).await?;
        artifacts.sort_by_key(|artifact| artifact.id);
        inquire::Select::new("message", artifacts).prompt()?
    };

    let artifact_content = api::get_artifact_by_id(&url, secret_key, artifact.id).await?;
    let artifact_content = String::from_utf8(artifact_content)?;

    println!("{}:", artifact.to_string().bold().underline());
    println!("{artifact_content}");
    Ok(())
}

#[tracing::instrument(skip(config), err)]
async fn delete(config: &Config) -> Result<()> {
    let url = common::get_server_url(config).await?;
    let secret_key = &ssh::key_by_url(&url)?;

    let artifacts = api::list_artifacts(&url, secret_key).await?;

    let artifact =
        inquire::Select::new("Which artifact do you want to delete?", artifacts).prompt()?;

    // The user has to confirm the action
    let confirm = inquire::Confirm::new(
        &format!("Are you sure you want to delete {artifact}. This action is not reversable").red(),
    )
    .with_default(false)
    .prompt()?;

    if !confirm {
        log::info!("Aborting...");
        return Ok(());
    }

    log::info!("Deleting...");

    api::delete_artifact(&url, secret_key, artifact.id).await?;
    log::info!("Done!");

    Ok(())
}
#[tracing::instrument(skip(config), err)]
pub async fn artifacts(config: &Config) -> Result<()> {
    let url = common::get_server_url(config).await?;
    let secret_key = &ssh::key_by_url(&url)?;

    let artifacts: Vec<(String, Vec<(String, String)>)> = {
        let mut artifacts = api::list_artifacts(&url, secret_key).await?;
        artifacts.sort_by_key(|artifact| artifact.id);

        vec![(
            "Artifacts:".underline().to_string(),
            artifacts
                .into_iter()
                .map(|artifact| artifact.as_section_item())
                .collect(),
        )]
    };

    section::print_sections(&artifacts);

    Ok(())
}
