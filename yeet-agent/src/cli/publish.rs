use std::path::PathBuf;

use color_eyre::{
    Result,
    eyre::{Context as _, bail, eyre},
};
use log::info;
use yeet::{cachix, nix};

use crate::{cli::common, cli_args::Config, sig::ssh};

#[tracing::instrument(skip(config), err)]
pub async fn publish(
    config: &Config,
    path: PathBuf,
    host: Vec<String>,
    variant: Option<String>,
    darwin: bool,
    priority: api::UpdatePriority,
) -> Result<()> {
    let url = common::get_server_url(config).await?;
    let secret_key = &ssh::key_by_url(&url)?;

    let cachix = config.cachix.clone().ok_or(eyre!(
        "Cachix cache name required. Set it in config or via the --cachix flag"
    ))?;

    let public_key = if let Some(key) = &config.cachix_key {
        key.clone()
    } else {
        let cache_info = cachix::get_cachix_info(&cachix)
            .await
            .context("Could not get cache information. For private caches use `--cachix-key`")?;
        cache_info
            .public_signing_keys
            .first()
            .cloned()
            .ok_or(eyre!("Cachix cache has no public signing keys"))?
    };

    let host = if host.is_empty() {
        nix::get_hosts(&path.to_string_lossy(), darwin)?
    } else {
        host
    };

    info!("Building {host:?}");

    let hosts = nix::build_hosts(&path.to_string_lossy(), host, darwin, variant)?;

    if hosts.is_empty() {
        bail!("No hosts found - did you commit your files?")
    }

    info!("Pushing {hosts:?}");

    cachix::push_paths(hosts.values(), &cachix).await?;

    api::update_hosts(
        &url,
        secret_key,
        api::HostUpdateRequest {
            hosts,
            public_key,
            substitutor: format!("https://{cachix}.cachix.org"),
            priority,
        },
    )
    .await?;
    Ok(())
}
