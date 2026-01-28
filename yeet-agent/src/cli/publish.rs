use std::path::PathBuf;

use log::info;
use rootcause::{Report, bail, prelude::ResultExt as _, report};
use yeet::{cachix, nix, server};

use crate::{cli_args::Config, sig::ssh, varlink};

pub async fn publish(
    config: &Config,
    path: PathBuf,
    host: Vec<String>,
    variant: Option<String>,
    darwin: bool,
) -> Result<(), Report> {
    let agent_url = {
        let agent_config = varlink::config().await;
        if let Err(e) = &agent_config {
            log::error!("Could not get agent config: {e}")
        }
        agent_config.ok().map(|config| config.server)
    };

    let url = &config
        .url
        .clone()
        .or(agent_url)
        .ok_or(rootcause::report!("`--url` required for publish"))?;
    let secret_key = {
        let domain = url
            .domain()
            .ok_or(rootcause::report!("Provided URL has no domain part"))?;
        &ssh::key_by_url(domain)?
    };

    let cachix = config.cachix.clone().ok_or(report!(
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
            .ok_or(report!("Cachix cache has no public signing keys"))?
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

    server::system::update(
        &url,
        secret_key,
        &api::HostUpdateRequest {
            hosts,
            public_key,
            substitutor: format!("https://{cachix}.cachix.org"),
        },
    )
    .await?;
    Ok(())
}
