use std::collections::HashMap;

use api::{get_secret_key, get_verify_key};
use log::info;
use rootcause::Report;

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
        } => {
            api::update_hosts(
                url,
                &get_secret_key(httpsig_key)?,
                &api::HostUpdateRequest {
                    hosts: HashMap::from([(host, store_path)]),
                    public_key,
                    substitutor,
                },
            )
            .await?;
        }
        ServerCommands::AddKey { key, admin } => {
            let level = if admin == AuthLevel::Admin {
                api::AuthLevel::Admin
            } else {
                api::AuthLevel::Build
            };
            let status = api::add_key(
                url,
                &get_secret_key(httpsig_key)?,
                &api::AddKey {
                    key: get_verify_key(&key)?,
                    level,
                },
            )
            .await?;
            info!("{status}");
        }
        ServerCommands::DeleteKey { key } => {
            let status =
                api::delete_key(url, &get_secret_key(httpsig_key)?, &get_verify_key(&key)?)
                    .await?;
            info!("{status}");
        }
    }
    Ok(())
}
