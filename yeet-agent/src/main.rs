//! # Yeet Agent

use std::io::{IsTerminal as _, Write as _};

use clap::Parser as _;
use figment::{
    Figment,
    providers::{Env, Format as _, Serialized, Toml},
};
use rootcause::{Report, hooks::Hooks};

use crate::cli_args::{AgentConfig, Commands, Config, HostArgs, Yeet};

mod agent;
mod cli_args;
mod section;
mod server_cli;
mod sig {
    pub mod ssh;
}
mod cli {
    pub mod approve;
    pub mod detach;
    pub mod host;
    pub mod hosts;
    pub mod publish;
}
mod notification;
mod polkit;
mod section_impls;
mod status;
mod systemd;
mod varlink;
mod version;

#[expect(unexpected_cfgs)]
#[tokio::main(flavor = "local")]
#[expect(clippy::too_many_lines)]
#[expect(clippy::unwrap_in_result)]
async fn main() -> Result<(), Report> {
    Hooks::new()
                .report_formatter(rootcause::hooks::builtin_hooks::report_formatter::DefaultReportFormatter::UNICODE_COLORS)
                .install()
                .expect("failed to install hooks");

    let mut log_builder =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"));

    if std::io::stderr().is_terminal() {
        log_builder.format(|buf, record| {
            write!(buf, "{}", buf.default_level_style(record.level()))?;
            write!(buf, "{}", record.level())?;
            write!(buf, "{:#}", buf.default_level_style(record.level()))?;
            writeln!(buf, ": {}", record.args())
        });
    }
    log_builder.init();

    let xdg_dirs = xdg::BaseDirectories::with_prefix("yeet");
    let args = Yeet::try_parse()?;

    let config: Config = Figment::new()
        .merge(Toml::file(
            xdg_dirs.find_config_file("agent.toml").unwrap_or_default(),
        ))
        .merge(Serialized::defaults(args.config))
        .merge(Env::prefixed("YEET_"))
        .extract()?;

    match args.command {
        Commands::Detach {
            version,
            force,
            darwin,
            path,
        } => cli::detach::detach(version, force, path, darwin).await?,
        Commands::Attach => cli::detach::attach().await?,
        Commands::Approve { name, code, facter } => {
            cli::approve::approve(&config, facter, code, name).await?
        }
        Commands::Host(HostArgs { command }) => match command {
            cli_args::HostCommands::Rename { name, new } => {
                cli::host::rename(&config, name, new).await?
            }
            cli_args::HostCommands::Remove { name } => cli::host::remove(&config, name).await?,
        },
        Commands::Hosts { full } => cli::hosts::hosts(&config, full).await?,
        Commands::Notify => notification::notify()?,
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
            agent::agent(&config, sleep, facter).await?;
        }
        Commands::Status { json } => status::status(json).await?,
        Commands::Publish {
            path,
            host,
            darwin,
            variant,
        } => {
            cli::publish::publish(&config, path, host, variant, darwin).await?;
        }
        Commands::Server(args) => server_cli::handle_server_commands(args, &config).await?,
    }
    Ok(())
}
