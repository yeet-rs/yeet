use rootcause::Report;

use crate::{
    cli::common,
    cli_args::Config,
    section::{self, DisplaySection as _},
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
    let mut nodes = api::list_nodes(&url, key).await?;
    nodes.sort();

    let nodes =
        inquire::MultiSelect::new("Which nodes should execute this query?", nodes).prompt()?;

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
