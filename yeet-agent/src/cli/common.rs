use color_eyre::{Result, eyre::eyre};

use crate::{cli_args::Config, varlink};

#[tracing::instrument(skip(config), err)]
pub async fn get_server_url(config: &Config) -> Result<url::Url> {
    let agent_url = {
        let agent_config = varlink::config().await;
        if let Err(err) = &agent_config {
            log::error!("Could not get agent config: {err}");
        }
        agent_config.ok().map(|config| config.server)
    };

    config
        .url
        .clone()
        .or(agent_url)
        .ok_or(eyre!("`--url` required for publish"))
}
