//! # Yeet Agent

use clap::Parser as _;
use color_eyre::Section;
use colored::Colorize as _;
use figment::{
    Figment,
    providers::{Env, Format as _, Serialized, Toml},
};

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::cli_args::{AgentConfig, Commands, Config, Yeet};

mod agent;
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
    pub mod user;
}
mod notification;
mod polkit;
mod section_impls;
mod status;
mod systemd;
mod varlink;
mod version;

#[tokio::main(flavor = "local")]
async fn main() -> color_eyre::Result<()> {
    let provider = init_tracer();
    let result = run().await;
    // this is required because `color_eyre` holds a ref to the current span
    if let Err(e) = result {
        tracing::error!(error = ?e);
    }
    tokio::task::yield_now().await;
    provider.force_flush()?;
    provider.shutdown()?;
    Ok(())
}

#[tracing::instrument(err)]
async fn run() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let xdg_dirs = xdg::BaseDirectories::with_prefix("yeet");
    let args = Yeet::try_parse()?;

    let config: Config = Figment::new()
        .merge(Toml::file(
            xdg_dirs.find_config_file("agent.toml").unwrap_or_default(),
        ))
        .merge(Serialized::defaults(args.config))
        .merge(Env::prefixed("YEET_"))
        .extract()?;

    let command = match args.command {
        Commands::Artifact(args) => cli::artifact::handle_command(args, &config).await,
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
        Commands::Notify => notification::notify(),
        Commands::Agent {
            server,
            sleep,
            facter,
            key,
        } => {
            let config = AgentConfig {
                server,
                sleep,
                facter,
                key,
            };
            agent::agent(&config, sleep, facter).await
        }
        Commands::Status { json } => status::status(json).await,
        Commands::Publish {
            path,
            host,
            darwin,
            variant,
        } => cli::publish::publish(&config, path, host, variant, darwin).await,
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

fn init_tracer() -> SdkTracerProvider {
    let exporter = opentelemetry_otlp::SpanExporter::builder().build().unwrap();

    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        // .with_resource(resource())
        .with_batch_exporter(exporter)
        .build();

    let tracer = provider.tracer("yeet");

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_error::ErrorLayer::default())
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .with(tracing_opentelemetry::OpenTelemetryLayer::new(tracer))
        .init();
    provider
}
