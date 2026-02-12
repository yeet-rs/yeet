use std::{collections::HashMap, fs::read_to_string};

use api::key::{get_secret_key, get_verify_key};
use log::info;
use rootcause::{Report, prelude::ResultExt as _};
use yeet::server;

use crate::cli_args::{AuthLevel, Config, ServerArgs, ServerCommands};

pub async fn handle_server_commands(args: ServerArgs, config: &Config) -> Result<(), Report> {
    let url = &config
        .url
        .clone()
        .ok_or(rootcause::report!("`--url` required for server commands"))?;

    let httpsig_key = &args.httpsig_key.clone().ok_or(rootcause::report!(
        "`--httpsig_key` required for server commands"
    ))?;
    match args.command {
        ServerCommands::Update {
            host,
            store_path,
            public_key,
            substitutor,
            netrc,
        } => {
            let netrc = match netrc {
                Some(netrc) => Some(
                    read_to_string(&netrc)
                        .context("Could not read netrc file")
                        .attach(format!("File: {}", &netrc.to_string_lossy()))?,
                ),
                None => None,
            };
            server::system::update(
                &url,
                &get_secret_key(&httpsig_key)?,
                &api::HostUpdateRequest {
                    hosts: HashMap::from([(host, store_path)]),
                    public_key,
                    substitutor,
                    netrc,
                },
            )
            .await?;
        }
        ServerCommands::VerifyStatus => {
            let status =
                server::system::is_host_verified(&url, &get_secret_key(&httpsig_key)?).await?;
            info!("{status}");
        }
        ServerCommands::AddVerification {
            store_path,
            public_key,
            facter,
        } => {
            let nixos_facter = if let Some(facter) = facter {
                Some(read_to_string(facter)?)
            } else {
                None
            };

            let code = server::system::add_verification_attempt(
                &url,
                &api::VerificationAttempt {
                    store_path,
                    key: get_verify_key(&public_key)?,
                    artifacts: api::VerificationArtifacts { nixos_facter },
                },
            )
            .await?;
            info!("{code}");
        }
        ServerCommands::AddKey { key, admin } => {
            let level = if admin == AuthLevel::Admin {
                api::AuthLevel::Admin
            } else {
                api::AuthLevel::Build
            };
            let status = server::key::add_key(
                &url,
                &get_secret_key(&httpsig_key)?,
                &api::AddKey {
                    key: get_verify_key(&key)?,
                    level,
                },
            )
            .await?;
            info!("{status}");
        }
        ServerCommands::RemoveKey { key } => {
            let status = server::key::remove_key(
                &url,
                &get_secret_key(&httpsig_key)?,
                &get_verify_key(&key)?,
            )
            .await?;
            info!("{status}");
        }
    }
    Ok(())
}
