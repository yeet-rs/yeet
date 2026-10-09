//! # Yeet Agent

use std::{
    env::args,
    io::{IsTerminal as _, Write as _},
};

use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_subscriber::{layer::SubscriberExt as _, util::SubscriberInitExt as _};

use crate::cli_args::Commands;

mod agent;
mod cli_args;

mod nix;
mod notification;

mod varlink;
mod version;

#[tokio::main(flavor = "local")]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let (provider, _guard) = init_tracer();
    let result = run().await;
    // this is required because `color_eyre` holds a ref to the current span
    if let Err(ref err) = result {
        tracing::error!(error = ?err);
    }
    tokio::task::yield_now().await;
    provider.force_flush()?;
    provider.shutdown()?;

    result?;
    Ok(())
}

#[tracing::instrument(err)]
async fn run() -> color_eyre::Result<()> {
    let args = Yeet::try_parse()?;

    let command = match args.command {
        Commands::Notify { body, summary } => notification::notify(&body, &summary),
        Commands::Agent {
            server,
            sleep,
            facter,
            key,
            attended,
        } => {
            let config = AgentConfig {
                server,
                sleep,
                facter,
                key,
                attended,
            };
            agent::agent(&config, sleep, facter).await
        }
    };
    Ok(())
}

fn init_tracer() -> (
    SdkTracerProvider,
    tracing_appender::non_blocking::WorkerGuard,
) {
    // let exporter = opentelemetry_otlp::SpanExporter::builder()
    //     .build()
    //     .expect("Could not build SpanExporter");

    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        // .with_resource(resource())
        // .with_batch_exporter(exporter)
        .build();

    // let tracer = provider.tracer("yeet");

    let (non_blocking, guard) = tracing_appender::non_blocking(std::io::stdout());

    if std::io::stderr().is_terminal() && args().nth(1) != Some("agent".to_owned()) {
        let mut log_builder =
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"));
        log_builder.format(|buf, record| {
            write!(buf, "{}", buf.default_level_style(record.level()))?;
            write!(buf, "{}", record.level())?;
            write!(buf, "{:#}", buf.default_level_style(record.level()))?;
            writeln!(buf, ": {}", record.args())
        });
        log_builder.init();
    } else {
        let format = tracing_subscriber::fmt::format().pretty();
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::EnvFilter::builder()
                    .with_default_directive(tracing::level_filters::LevelFilter::INFO.into())
                    .from_env_lossy(),
            )
            .with(tracing_error::ErrorLayer::default())
            .with(
                tracing_subscriber::fmt::layer()
                    .with_target(false)
                    .event_format(format)
                    .with_writer(non_blocking),
            )
            // .with(tracing_opentelemetry::OpenTelemetryLayer::new(tracer))
            .init();
    }

    (provider, guard)
}
