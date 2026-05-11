use std::{env, fs::File, io::BufReader};

use color_eyre::{
    Result,
    eyre::{Context as _, bail, eyre},
};
use ed25519_dalek::VerifyingKey;
use httpsig_hyper::prelude::SecretKey;
use inquire::validator::Validation;
use ssh2_config::{ParseRule, SshConfig};

/// Get key from `~/.ssh/config` or ask the user which key should be used
#[tracing::instrument(fields(%url = url))]
pub fn key_by_url(url: &url::Url) -> Result<SecretKey> {
    let url = url
        .domain()
        .ok_or(eyre!("Provided URL has no domain part"))?;
    Ok(key_from_ssh_config(url).or_else(|err| get_key_manual().context(err))?)
}

#[tracing::instrument(fields(%url = url.as_ref()))]
fn key_from_ssh_config(url: impl AsRef<str>) -> Result<SecretKey> {
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

        SshConfig::default()
            .parse(&mut reader, ParseRule::STRICT)
            .context("Failed to parse ssh config to get yeet httpsig key")?
    };

    // Try to match the yeet server in the ssh config
    let host = {
        let mut hosts = config
            .intersecting_hosts(url.as_ref())
            .filter(|host| host.params.identity_file.is_some())
            .collect::<Vec<_>>();

        // TODO: inquire select
        if hosts.is_empty() {
            bail!(
                "No match blocks found in `~/.ssh/config` for {}",
                url.as_ref()
            )
        }
        if hosts.len() > 1 {
            bail!(
                "Multiple match blocks found in `~/.ssh/config` for {}",
                url.as_ref()
            )
        }
        #[expect(clippy::unwrap_used)] // we checked with hosts.is_empty
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
        #[expect(clippy::unwrap_used)] // we checked
        identity_files.pop().unwrap()
    };

    tracing::debug!(key_path = %identity_file.display());

    Ok(api::get_secret_key(identity_file)?)
}

#[tracing::instrument]
pub fn get_key_manual() -> Result<SecretKey> {
    let key = inquire::Text::new("Yeet Admin Key:")
        .with_validator(|path: &str| {
            Ok(match api::get_secret_key(path) {
                Ok(_) => Validation::Valid,
                Err(err) => Validation::Invalid(format!("Not a valid secret key: {err}").into()),
            })
        })
        .prompt()?;
    tracing::debug!(key_path = key);
    Ok(api::get_secret_key(key)?)
}

#[tracing::instrument]
pub fn get_pub_key_manual() -> Result<VerifyingKey> {
    let key = inquire::Text::new("Yeet Admin Key:")
        .with_validator(|path: &str| {
            Ok(match api::get_verify_key(path) {
                Ok(_) => Validation::Valid,
                Err(err) => Validation::Invalid(format!("Not a valid public key: {err}").into()),
            })
        })
        .prompt()?;
    tracing::debug!(key_path = key);
    Ok(api::get_verify_key(key)?)
}
