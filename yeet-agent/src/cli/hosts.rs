use console::style;
use rootcause::Report;

use crate::{
    cli::common,
    cli_args::Config,
    section::{self, DisplaySection as _, DisplaySectionItem as _},
    sig::ssh,
};

pub async fn hosts(config: &Config, full: bool) -> Result<(), Report> {
    let url = common::get_server_url(config).await?;
    let secret_key = &ssh::key_by_url(&url)?;

    let hosts_section: Vec<(String, Vec<(String, String)>)> = {
        let mut hosts = api::list_hosts(&url, secret_key).await?;
        hosts.sort_by_key(|host| host.hostname.clone());

        if full {
            let hostnames = hosts.iter().map(|host| host.hostname.clone()).collect();
            let selected =
                inquire::MultiSelect::new("Which hosts do you want to display>", hostnames)
                    .prompt()?;
            hosts.retain(|host| selected.contains(&host.hostname));
        }

        if full {
            hosts.into_iter().map(|host| host.as_section()).collect()
        } else {
            vec![(
                style("Hosts:").underlined().to_string(),
                hosts
                    .into_iter()
                    .map(|host| host.as_section_item())
                    .collect(),
            )]
        }
    };

    section::print_sections(&hosts_section);

    Ok(())
}
