use color_eyre::Result;
use colored::Colorize as _;

use crate::{
    cli::common,
    cli_args::Config,
    section::{self, DisplaySectionItem as _},
    sig::ssh,
};

#[tracing::instrument(skip(config), err)]
pub async fn show_nodes(config: &Config) -> Result<()> {
    let url = common::get_server_url(config).await?;
    let key = &ssh::key_by_url(&url)?;

    let nodes = {
        let mut nodes = api::list_nodes(&url, key).await?;
        nodes.sort();
        nodes
    };

    let nodes_section = nodes
        .into_iter()
        .map(|n| n.as_section_item())
        .collect::<Vec<_>>();

    let section = vec![("Nodes:".underline().to_string(), nodes_section)];
    section::print_sections(&section);
    Ok(())
}

#[tracing::instrument(skip(config), err)]
pub async fn query(config: &Config, sql: String) -> Result<()> {
    let url = common::get_server_url(config).await?;
    let key = &ssh::key_by_url(&url)?;
    let mut nodes = api::list_nodes(&url, key).await?;
    nodes.sort();

    let nodes = inquire::MultiSelect::new("Which nodes should execute this query?", nodes)
        .with_validator(
            inquire::validator::MinLengthValidator::new(1).with_message("Select at least one node"),
        )
        .prompt()?;

    let nodes = nodes.into_iter().map(|node| node.id).collect();

    let query = api::create_query(&url, key, api::CreateQuery { sql, nodes }).await?;

    // TODO: maybe server streaming
    // for node in response.responses {
    //     let mut builder = tabled::builder::Builder::new();

    //     for (header, column) in node.response {
    //         let mut header = vec![header];
    //         header.extend(column);
    //         builder.push_column(header);
    //     }
    //     let mut table = builder.build();
    //     table.with(tabled::settings::Style::modern_rounded());

    //     println!("{table}");
    // }

    log::info!("You can search for your query with `sid: {query}`");
    Ok(())
}
