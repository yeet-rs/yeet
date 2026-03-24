use std::time::Duration;

use rootcause::Report;
use tokio::time::sleep;

use crate::{
    cli::common,
    cli_args::Config,
    section::{self, DisplaySection},
    sig::ssh,
};

pub async fn show_nodes(config: &Config) -> Result<(), Report> {
    let url = common::get_server_url(config).await?;
    let key = &ssh::key_by_url(&url)?;

    let nodes = api::list_nodes(&url, key).await?;

    let nodes_section = nodes
        .into_iter()
        .map(|n| n.as_section())
        .collect::<Vec<_>>();

    section::print_sections(&nodes_section);
    Ok(())
}

pub async fn query(config: &Config, sql: String) -> Result<(), Report> {
    let url = common::get_server_url(config).await?;
    let key = &ssh::key_by_url(&url)?;

    let query = api::create_query(&url, key, &api::CreateQuery { sql }).await?;

    let mut response = api::query_response_all(&url, key, query).await?;
    while !response.missing.is_empty() {
        log::info!("{:#?} has not yet responded to the query", response.missing);
        sleep(Duration::from_secs(1)).await; // TODO: async model
        response = api::query_response_all(&url, key, query).await?;
    }
    println!("{:#?}", response.responses);

    Ok(())
}
