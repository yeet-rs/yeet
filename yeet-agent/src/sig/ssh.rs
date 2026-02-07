use std::{env, fs::File, io::BufReader};

use httpsig_hyper::prelude::SecretKey;
use inquire::validator::Validation;
use rootcause::{Report, bail, prelude::ResultExt};
use ssh2_config::{ParseRule, SshConfig};

pub fn key_by_url(url: impl AsRef<str>) -> Result<SecretKey, Report> {
    Ok(key_from_ssh_config(url).or_else(|err| get_key_manual().context(err))?)
}

fn key_from_ssh_config(url: impl AsRef<str>) -> Result<SecretKey, Report> {
    // read the ~/.ssh/config
    let config = {
        let mut reader = BufReader::new(
            File::open(
                env::home_dir()
                    .expect("Platform should have a home dir")
                    .join(".ssh/config"),
            )
            .context("Could not open `~/.ssh/config`")?,
        );

        let config = SshConfig::default()
            .parse(&mut reader, ParseRule::STRICT)
            .context("Failed to parse ssh config to get yeet httpsig key")?;
        config
    };

    // Try to match the yeet server in the ssh config
    let host = {
        let mut hosts = config
            .intersecting_hosts(url.as_ref())
            .filter(|host| host.params.identity_file.is_some())
            .collect::<Vec<_>>();

        // TODO: inquire select
        if hosts.len() == 0 {
            bail!(
                "No match blocks found in `~/.ssh/config` for {}",
                url.as_ref()
            )
        } else if hosts.len() > 1 {
            bail!(
                "Multiple match blocks found in `~/.ssh/config` for {}",
                url.as_ref()
            )
        }
        hosts.pop().unwrap().clone()
    };

    // filter the indentity file attribute from the ssh host section
    let identity_file = {
        let mut identity_files = host
            .params
            .identity_file
            .expect("We filter for identity_files");

        if identity_files.len() != 1 {
            bail!(
                "Multiple identities found in `~/.ssh/config` for {}",
                url.as_ref()
            )
        }
        identity_files.pop().unwrap()
    };

    Ok(api::key::get_secret_key(identity_file)?)
}

pub fn get_key_manual() -> Result<SecretKey, Report> {
    let key = inquire::Text::new("Yeet Admin Key:")
        .with_validator(|path: &str| {
            Ok(match api::key::get_secret_key(path) {
                Ok(_) => Validation::Valid,
                Err(err) => Validation::Invalid(format!("Not a valid secret key: {err}").into()),
            })
        })
        .prompt()?;
    Ok(api::key::get_secret_key(key)?)
}
