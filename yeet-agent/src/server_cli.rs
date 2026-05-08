use std::collections::HashMap;

use api::get_secret_key;
use color_eyre::eyre::{Result, eyre};

use crate::cli_args::{Config, ServerArgs, ServerCommands};

pub async fn handle_server_commands(args: ServerArgs, config: &Config) -> Result<()> {
    let url = &config
        .url
        .clone()
        .ok_or(eyre!("`--url` required for server commands"))?;

    let httpsig_key = &args
        .httpsig_key
        .clone()
        .ok_or(eyre!("`--httpsig_key` required for server commands"))?;
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
                api::HostUpdateRequest {
                    hosts: HashMap::from([(host, store_path)]),
                    public_key,
                    substitutor,
                },
            )
            .await?;
        }
    }
    Ok(())
}
