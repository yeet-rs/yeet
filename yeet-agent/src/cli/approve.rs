use std::{
    fs::File,
    io::Write as _,
    path::{Path, PathBuf},
};

use inquire::validator::Validation;
use log::info;
use rootcause::Report;

use crate::{
    cli::{self, common},
    cli_args::Config,
    sig::ssh,
};

pub async fn approve(config: &Config) -> Result<(), Report> {
    let url = common::get_server_url(config).await?;
    let secret_key = &ssh::key_by_url(&url)?;

    let hostname =
        // TODO nix select
        inquire::Text::new("Hostname:").prompt()?;

    let code = inquire::CustomType::<u32>::new("Approval code:").prompt()?;

    info!("Approving {hostname} with code {code}...");

    let nixos_facter = api::accept_attempt(&url, secret_key, code, &hostname).await?;

    info!("Approved");

    if nixos_facter.is_none() {
        return Ok(());
    }
    #[expect(clippy::unwrap_used)] // we checked
    let nixos_facter = nixos_facter.unwrap();

    // Get file to write facter data
    let facter_output = {
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

    // TODO: allow to limit the host
    cli::secret::allow(config).await?;
    Ok(())
}
