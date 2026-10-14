//! # Yeet Agent

use std::{
    env::{self, args},
    time::Duration,
};

use api::{get_secret_key, get_verify_key};
use backon::{ConstantBuilder, Retryable as _};
use color_eyre::{Result, eyre::OptionExt, owo_colors::OwoColorize as _};
use tracing::{error, info};
use yeet_agent::AgentConfig;

use crate::agent::agent_loop;

mod agent;
mod nix;
mod notification;
mod varlink_server;

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

/// When running the agent should do these things in order:
/// 1. Check if agent is active aka if the key is enrolled with `/system/verify`
///    if not:
///    create a new verification request
///    pull the verify endpoint in a time intervall
/// 2. Continuosly pull the system endpoint and execute based on the provided
#[tokio::main(flavor = "local")]
async fn main() -> Result<()> {
    install_tracing();
    let mut args = args();
    args.next(); // ignore arg0
    if let Some(arg1) = args.next()
        && arg1 == "notify"
    {
        let body = args.next().ok_or_eyre("No notification body provided")?;
        let summary = args.next().ok_or_eyre("No notification summary provided")?;
        notification::notify(&body, &summary)?;
        return Ok(());
    }
    color_eyre::install()?;

    let config = get_agent_config()?;

    let key = get_secret_key(&config.key)?;
    let pub_key = get_verify_key(&config.key)?;

    info!("Spawning varlink daemon");
    {
        let key = key.clone();
        let config = config.clone();
        tokio::task::spawn_local(async move {
            if let Err(err) = varlink_server::start_service(config, key).await {
                error!("Varlink failure:\n{err}");
            }
        })
    };

    (|| async { agent_loop(&config, &key, pub_key).await })
        .retry(
            ConstantBuilder::new()
                .without_max_times()
                .with_delay(Duration::from_secs(config.sleep)),
        )
        .notify(|err: &color_eyre::Report, dur: Duration| {
            error!("{err} - retrying in {dur:?}");
        })
        .await?;

    Ok(())
}

fn get_agent_config() -> Result<AgentConfig> {
    Ok(AgentConfig {
        server: env::var("YEET_SERVER")?.parse()?,
        key: env::var("YEET_KEY")?.parse()?,
        sleep: env::var("YEET_SLEEP")?.parse()?,
        facter: env::var("YEET_FACTER")?.parse()?,
        attended: env::var("YEET_ATTENDED")?.parse()?,
    })
}
