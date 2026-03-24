//! # Yeet Agent

use std::io::{IsTerminal as _, Write as _};

use clap::Parser as _;
use figment::{
    Figment,
    providers::{Env, Format as _, Serialized, Toml},
};
use rootcause::{
    Report, ReportRef,
    handlers::{ContextFormattingStyle, FormattingFunction},
    hooks::{Hooks, context_formatter::ContextFormatterHook},
    markers::{Dynamic, Local, Uncloneable},
};

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
    pub mod common;
    pub mod detach;
    pub mod host;
    pub mod hosts;
    pub mod osquery;
    pub mod publish;
    pub mod secret;
}
mod notification;
mod polkit;
mod section_impls;
mod status;
mod systemd;
mod varlink;
mod version;

struct ClapDisplayHook;

impl ContextFormatterHook<clap::Error> for ClapDisplayHook {
    fn preferred_context_formatting_style(
        &self,
        _report: ReportRef<'_, Dynamic, Uncloneable, Local>,
        _report_formatting_function: FormattingFunction,
    ) -> ContextFormattingStyle {
        ContextFormattingStyle {
            function: FormattingFunction::Display,
            follow_source: false,
            follow_source_depth: None,
        }
    }
}

#[expect(unexpected_cfgs)]
#[tokio::main(flavor = "local")]
async fn main() -> Result<(), Report> {
    Hooks::new()
        .context_formatter::<clap::Error, _>(ClapDisplayHook)
        .report_formatter(
            rootcause::hooks::builtin_hooks::report_formatter::DefaultReportFormatter::ASCII,
        )
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
        Commands::Nodes => cli::osquery::show_nodes(&config).await?,
        Commands::Query { query } => cli::osquery::query(&config, query).await?,
        Commands::Secret(args) => cli::secret::handle_secret_command(args, &config).await?,
        Commands::Detach {
            version,
            darwin,
            path,
        } => cli::detach::detach(version, path, darwin).await?,
        Commands::Attach => cli::detach::attach().await?,
        Commands::Approve => cli::approve::approve(&config).await?,
        Commands::Host(HostArgs { command }) => match command {
            cli_args::HostCommands::Rename => cli::host::rename(&config).await?,
            cli_args::HostCommands::Remove => cli::host::remove(&config).await?,
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
