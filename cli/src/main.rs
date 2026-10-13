//! # Yeet Agent

use clap::Parser as _;
use color_eyre::Section as _;
use figment::{
    Figment,
    providers::{Env, Format as _, Serialized, Toml},
};
use owo_colors::OwoColorize as _;

use crate::cli_args::{Commands, Config, Yeet};

mod cli_args;

mod section;
mod server_cli;
mod sig {
    pub mod ssh;
}
mod cli {
    pub mod approve;
    pub mod artifact;
    pub mod common;
    pub mod detach;
    pub mod host;
    pub mod osquery;
    pub mod publish;
    pub mod secret;
    pub mod tag;
    pub mod update;
    pub mod user;
}
mod cachix;
mod nix;
mod section_impls;
mod status;
mod systemd;

fn install_tracing() {
    use std::io::IsTerminal as _;

    use tracing::Level;
    use tracing_error::ErrorLayer;
    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::fmt::{self, FmtContext, FormatEvent, FormatFields, format::Writer};
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::registry::LookupSpan;

    struct LevelPrefixFormat;

    impl<S, N> FormatEvent<S, N> for LevelPrefixFormat
    where
        S: tracing::Subscriber + for<'a> LookupSpan<'a>,
        N: for<'a> FormatFields<'a> + 'static,
    {
        fn format_event(
            &self,
            ctx: &FmtContext<'_, S, N>,
            mut writer: Writer<'_>,
            event: &tracing::Event<'_>,
        ) -> std::fmt::Result {
            let level = *event.metadata().level();
            if writer.has_ansi_escapes() {
                let styled = match level {
                    Level::ERROR => "ERROR".red().to_string(),
                    Level::WARN => "WARN".yellow().to_string(),
                    Level::INFO => "INFO".green().to_string(),
                    Level::DEBUG => "DEBUG".blue().to_string(),
                    Level::TRACE => "TRACE".cyan().to_string(),
                };
                write!(writer, "{styled}: ")?;
            } else {
                write!(writer, "{level}: ")?;
            }
            ctx.field_format().format_fields(writer.by_ref(), event)?;
            writeln!(writer)
        }
    }

    let fmt_layer = fmt::layer()
        .event_format(LevelPrefixFormat)
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal());

    let filter_layer =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn,yeet=info"));

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .with(ErrorLayer::default())
        .init();
}

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    install_tracing();
    let args = Yeet::try_parse()?; // above color_eyre so it does not get formatted weird
    color_eyre::install()?;

    let xdg_dirs = xdg::BaseDirectories::with_prefix("yeet");

    let config: Config = Figment::new()
        .merge(Toml::file(
            xdg_dirs.find_config_file("agent.toml").unwrap_or_default(),
        ))
        .merge(Serialized::defaults(args.config))
        .merge(Env::prefixed("YEET_"))
        .extract()?;

    let command = match args.command {
        Commands::Artifact(args) => cli::artifact::handle_command(args, &config).await,
        Commands::Update(args) => cli::update::update(args).await,
        Commands::Artifacts => cli::artifact::artifacts(&config).await,
        Commands::Nodes => cli::osquery::show_nodes(&config).await,
        Commands::Query { query } => cli::osquery::query(&config, query).await,
        Commands::Secret(args) => cli::secret::handle_command(args, &config).await,
        Commands::Secrets => cli::secret::list(&config).await,
        Commands::User(args) => cli::user::handle_command(args, &config).await,
        Commands::Users => cli::user::list_users(&config).await,
        Commands::Tag(args) => cli::tag::handle_command(args, &config).await,
        Commands::Host(args) => cli::host::handle_command(args, &config).await,
        Commands::Hosts { full } => cli::host::hosts(&config, full).await,
        Commands::Tags => cli::tag::list_tags(&config).await,
        Commands::Detach {
            version,
            darwin,
            path,
        } => cli::detach::detach(version, path, darwin).await,
        Commands::Attach => cli::detach::attach().await,
        Commands::Approve => cli::approve::approve(&config).await,
        Commands::Status { json } => status::status(json).await,
        Commands::Publish {
            path,
            host,
            darwin,
            variant,
            priority,
        } => cli::publish::publish(&config, path, host, variant, darwin, priority.into()).await,
        Commands::Server(args) => server_cli::handle_server_commands(args, &config).await,
    };

    match command {
        Ok(()) => Ok(()),
        Err(err) => {
            let url = cli::common::get_server_url(&config).await?;

            let server_health = if api::is_healthy(&url).await {
                format!(
                    "{} {}",
                    url.domain().unwrap_or_default().bold().underline(),
                    "is up".green().bold()
                )
            } else {
                format!(
                    "{} {}",
                    url.domain().unwrap_or_default().bold().underline(),
                    "is not reachable".red().bold()
                )
            };

            Err(err).note(server_health)
        }
    }
}
