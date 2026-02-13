use std::{
    fs::File,
    io::Write as _,
    path::{Path, PathBuf},
};

use inquire::validator::Validation;
use log::info;
use rootcause::Report;
use yeet::server;

use crate::{
    cli::{self, common},
    cli_args::Config,
    sig::ssh,
};

pub async fn approve(
    config: &Config,
    facter_output: Option<PathBuf>,
    code: Option<u32>,
    hostname: Option<String>,
) -> Result<(), Report> {
    let url = common::get_server_url(config).await?;
    let secret_key = &ssh::key_by_url(&url)?;

    let hostname = if let Some(hostname) = hostname {
        hostname
    } else {
        // TODO nix select
        inquire::Text::new("Hostname:").prompt()?
    };

    let code = if let Some(code) = code {
        code
    } else {
        inquire::CustomType::<u32>::new("Approval code:").prompt()?
    };

    info!("Approving {hostname} with code {code}...");

    let artifacts = server::system::verify_attempt(
        &url,
        secret_key,
        &api::VerificationAcceptance { code, hostname },
    )
    .await?;

    info!("Approved");

    if artifacts.nixos_facter.is_none() {
        return Ok(());
    }
    let nixos_facter = artifacts.nixos_facter.unwrap();

    // Get file to write facter data
    let facter_output = if let Some(facter_output) = facter_output {
        facter_output
    } else {
        let output = inquire::Text::new("Facter Output:")
            .with_validator(|path: &str| {
                let Some(parent_dir) = Path::new(path).parent() else {
                    return Ok(Validation::Invalid("Not a directory".into()));
                };

                if !parent_dir.exists() {
                    return Ok(Validation::Invalid("Directory does not exist".into()));
                }

                if Path::new(path).exists() {
                    return Ok(Validation::Invalid(
                        format!("{path} already exists!").into(),
                    ));
                }

                Ok(Validation::Valid)
            })
            .prompt()?;
        PathBuf::from(output)
    };

    File::create_new(&facter_output)?.write_all(nixos_facter.as_bytes())?;
    info!("File {} written", facter_output.as_os_str().display());

    cli::secret::allow(config, None, None).await?;
    Ok(())
}
