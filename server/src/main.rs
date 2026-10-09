//! Yeet that Config

use std::{fs::File, io::Write as _, str::FromStr as _};

use age::secrecy::ExposeSecret as _;
use color_eyre::eyre::eyre;

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    let provider = init_tracer();
    color_eyre::install()?;

    let flags: yeetd::Flags = yeetd::Flags::figment().extract()?;

    let age_key = {
        if let Ok(content) = std::fs::read_to_string("age.key") {
            age::x25519::Identity::from_str(serde_json::from_str(&content)?)
                .map_err(|err| eyre!("age.key does not contain a valid identity {err}"))?
        } else {
            let identity = age::x25519::Identity::generate();
            File::create("age.key")?.write_all(&serde_json::to_vec(
                &identity.to_string().expose_secret().to_owned(),
            )?)?;
            identity
        }
    };

    let handle = yeetd::launch(flags.build(age_key).await?).await;
    handle.await.expect("axum quit");
    provider.force_flush()?;
    provider.shutdown()?;
    Ok(())
}

fn init_tracer() -> opentelemetry_sdk::trace::SdkTracerProvider {
    use opentelemetry::trace::TracerProvider as _;
    use tracing_subscriber::{layer::SubscriberExt as _, util::SubscriberInitExt as _};

    // let exporter = opentelemetry_otlp::SpanExporter::builder()
    //     .build()
    //     .expect("Could not build SpanExporter");

    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        // .with_resource(resource())
        // .with_batch_exporter(exporter)
        .build();

    let tracer = provider.tracer("yeetd");

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_error::ErrorLayer::default())
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .with(tracing_opentelemetry::OpenTelemetryLayer::new(tracer))
        .init();
    provider
}
