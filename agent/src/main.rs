//! # Yeet Agent

use std::{
    env::{self, args},
    path::PathBuf,
    time::Duration,
};

use api::{get_secret_key, get_verify_key};
use backon::{ConstantBuilder, Retryable as _};
use color_eyre::{Result, eyre::OptionExt};
use serde::{Deserialize, Serialize};
use tracing::{error, info};

use crate::agent::agent_loop;

mod agent;

mod nix;
mod notification;

mod varlink;
mod version;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// URL of the Yeet Server
    server: url::Url,
    /// Path to ed25519 key which is used for authentication
    key: PathBuf,
    /// Seconds to wait between updates.
    /// Lower bound, may be higher between switching versions
    sleep: u64,
    /// Collect facter with nixos-facter
    facter: bool,
    /// In unattended mode all updates are installed immediately
    attended: bool,
}

/// When running the agent should do these things in order:
/// 1. Check if agent is active aka if the key is enrolled with `/system/verify`
///    if not:
///    create a new verification request
///    pull the verify endpoint in a time intervall
/// 2. Continuosly pull the system endpoint and execute based on the provided
#[tokio::main(flavor = "local")]
async fn main() -> Result<()> {
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
            if let Err(err) = varlink::start_service(config, key).await {
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
