use std::{
    ffi::OsStr,
    fs::{
        self, File, Permissions, read_dir, read_link, read_to_string, remove_dir_all, remove_file,
    },
    io::{self, BufRead as _, BufReader, Write as _},
    os::unix::fs::{PermissionsExt as _, chown, symlink},
    path::{Path, PathBuf},
    process::Command,
    sync::OnceLock,
    time::Duration,
};

use api::{get_secret_key, get_verify_key};
use backon::{ConstantBuilder, Retryable as _};
use color_eyre::{
    Result, Section as _,
    eyre::{Context as _, bail, eyre},
};
use ed25519_dalek::VerifyingKey;
use httpsig_hyper::prelude::SecretKey;
use log::{error, info};
use tempfile::NamedTempFile;
use tokio::time;
use url::Url;
use yeet::nix;

use crate::{cli_args::AgentConfig, notification, varlink, version::get_active_version};

static VERIFICATION_CODE: OnceLock<u32> = OnceLock::new();

/// When running the agent should do these things in order:
/// 1. Check if agent is active aka if the key is enrolled with `/system/verify`
///    if not:
///    create a new verification request
///    pull the verify endpoint in a time intervall
/// 2. Continuosly pull the system endpoint and execute based on the provided
#[tracing::instrument(err)]
pub async fn agent(config: &AgentConfig, sleep: u64, facter: bool) -> Result<()> {
    let key = get_secret_key(&config.key)?;
    let pub_key = get_verify_key(&config.key)?;

    log::info!("Spawning varlink daemon");
    {
        let config = config.clone();
        let key = key.clone();
        tokio::task::spawn_local(async move {
            if let Err(err) = varlink::start_service(config, key).await {
                log::error!("Varlink failure:\n{err}");
            }
        })
    };

    (|| async { agent_loop(config, &key, pub_key, sleep, facter).await })
        .retry(
            ConstantBuilder::new()
                .without_max_times()
                .with_delay(Duration::from_secs(sleep)),
        )
        .notify(|err: &color_eyre::Report, dur: Duration| {
            error!("{err} - retrying in {dur:?}");
        })
        .await?;

    Ok(())
}

#[tracing::instrument(err)]
async fn agent_loop(
    config: &AgentConfig,
    key: &SecretKey,
    pub_key: VerifyingKey,
    sleep: u64,
    facter: bool,
) -> Result<()> {
    let verified = api::is_host_verified(&config.server, key) //TODO unwrap
        .await?
        .is_success();

    if !verified {
        if let Some(code) = VERIFICATION_CODE.get() {
            bail!("Verification requested but not yet approved. Code: {code}");
        }

        let nixos_facter = if facter {
            info!("Collecting nixos-facter information");
            let facts = Some(nix::facter()?);
            info!("Done collecting facts");
            facts
        } else {
            None
        };

        let code = api::add_verification_attempt(
            &config.server,
            key,
            api::VerificationAttempt {
                key: pub_key,
                nixos_facter,
            },
        )
        .await?;
        let _code = VERIFICATION_CODE.set(code as u32); // Bad so sad if we can't set it
        info!("Your verification code is: {code}");
        bail!("Waiting for verification");
    }
    info!("Verified!");

    loop {
        let action = api::check_system(
            &config.server,
            key,
            api::VersionRequest {
                store_path: get_active_version()?,
            },
        )
        .await?;

        info!("{action:#?}");

        agent_action(action, &config.server, key).await?;
        time::sleep(Duration::from_secs(sleep)).await;
    }
}

#[tracing::instrument(err, skip(key))]
async fn agent_action(action: api::AgentAction, url: &Url, key: &SecretKey) -> Result<()> {
    match action {
        api::AgentAction::Nothing | api::AgentAction::Detach => {}
        api::AgentAction::SwitchTo(remote_store_path) => {
            update(&remote_store_path, url, key).await?;
        }
    }
    Ok(())
}

#[tracing::instrument(err, ret)]
fn trusted_public_keys() -> Result<Vec<String>> {
    let file = File::open("/etc/nix/nix.conf")?;
    Ok(BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .find(|line| line.starts_with("trusted-public-keys"))
        .unwrap_or(String::from(
            "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=",
        ))
        .split_whitespace()
        .skip(2)
        .map(str::to_owned)
        .collect())
}

#[tracing::instrument(err, skip(key))]
async fn update(version: &api::RemoteStorePath, url: &Url, key: &SecretKey) -> Result<()> {
    download(version, url, key).await?;
    let current_gen = read_link("/etc/yeet/secret");
    activate_secrets(version, url, key).await?;
    let next_gen = read_link("/etc/yeet/secret");

    let activation_err = activate(&version.store_path);
    // switch did not go correct
    if get_active_version()? == version.store_path {
        if let Ok(next_gen) = next_gen {
            let _err = remove_all_dirs_unless(
                next_gen.parent().unwrap_or(Path::new("/etc/yeet/secret.d")),
                next_gen.file_name().unwrap_or_default(),
            );
        }
    } else {
        // Restore last gen if there was one
        if let Ok(current_gen) = current_gen {
            let _err = remove_file("/etc/yeet/secret");
            symlink(current_gen, "/etc/yeet/secret")?;
        }
        // Delete the generation that was just created
        if let Ok(next_gen) = next_gen {
            remove_dir_all(&next_gen)?;
        }
        activation_err?;
    }
    notification::notify_all()?;
    Ok(())
}

#[tracing::instrument(err, fields(base = %base.as_ref().display()))]
fn remove_all_dirs_unless<P: AsRef<Path>>(base: P, dirname: &OsStr) -> Result<()> {
    for dir in read_dir(base)? {
        if let Ok(dir) = dir
            && dir.file_name() != dirname
        {
            let _err = remove_dir_all(dir.path());
        }
    }

    Ok(())
}
#[tracing::instrument(err)]
pub fn switch_to(store_path: &api::StorePath) -> Result<()> {
    activate(store_path)?;
    notification::notify_all()?;
    Ok(())
}

#[tracing::instrument(err, skip(key))]
async fn download(version: &api::RemoteStorePath, url: &Url, key: &SecretKey) -> Result<()> {
    info!("Downloading {}", version.store_path);
    let mut keys = trusted_public_keys()?;
    keys.push(version.public_key.clone());
    keys.sort();
    keys.dedup();

    let mut command = Command::new("nix-store");
    command.stderr(io::stderr()).stdout(io::stdout());
    command.args(vec![
        "--realise",
        &version.store_path,
        "--option",
        "extra-substituters",
        &version.substitutor,
        "--option",
        "trusted-public-keys",
        &keys.join(" "),
        "--option",
        "narinfo-cache-negative-ttl",
        "0",
    ]);

    // Even if we do not end up using the temp file we create it outside of the if scope.
    // Else it would get dropped before nix-store can use it
    let mut netrc_file = NamedTempFile::new().context("Could not create netrc temp file")?;
    let netrc = match api::get_secret(url, key, "netrc".into()).await {
        Ok(secret) => secret,
        Err(err) => {
            log::error!("could not get netrc secret: {err}");
            None
        }
    };
    if let Some(netrc) = netrc {
        netrc_file
            .write_all(&netrc)
            .context("Could not write to the temp netrc file")?;
        netrc_file.flush()?;
        command.args([
            "--option",
            "netrc-file",
            &netrc_file.path().to_string_lossy(),
        ]);
    }

    let download = command.output()?;

    if !download.status.success() {
        return Err(eyre!("{}", String::from_utf8(download.stderr)?)
            .note("Could not realize new version")
            .note(format!(
                "Command: {}",
                command
                    .get_args()
                    .map(|ostr| ostr.to_string_lossy())
                    .collect::<Vec<_>>()
                    .join(" ")
            )));
    }
    Ok(())
}

#[tracing::instrument(err, skip(key))]
async fn activate_secrets(
    version: &api::RemoteStorePath,
    url: &Url,
    key: &SecretKey,
) -> Result<()> {
    // find out which secrets are required for this derivation
    let nix_secrets: api::Secrets = {
        let path = Path::new(&version.store_path).join("yeet-secrets.json");
        if !path.exists() {
            log::info!(
                "No yeet-secrets.json file found at {}",
                path.to_string_lossy()
            );
            return Ok(());
        }
        serde_json::from_str(&read_to_string(path)?)?
    };

    // try to fetch all secrets
    let mut secrets = Vec::new();
    for (name, secret) in nix_secrets {
        if secret.is_generated() {
            // short circuit if the artifact exists on the server
            if let Some(data) = api::get_artifact_by_name(url, key, name.clone()).await? {
                log::info!("Retrieved generated secret {name}");
                secrets.push((secret, data));
                continue;
            }

            // else create a new secret and store it on the server as an artifact
            let Some(data) = secret.generate() else {
                bail!("Secret {name} not found! Unable to switch to derivation");
            };
            log::info!("Generated secret {name}");
            api::store_artifact(url, key, &name, data.as_slice()).await?;
            secrets.push((secret, data));
        } else {
            log::info!("Fetching secret {name}");
            let Some(data) = api::get_secret(url, key, name.clone()).await? else {
                bail!("Secret {name} not found! Unable to switch to derivation");
            };
            secrets.push((secret, data));
        }
    }

    // get next generation number
    // This basically reads `/etc/yeet/secret` as u32 and if it fails it returns 0 (first gen)
    let generation = {
        let link = read_link("/etc/yeet/secret"); // this will return a path like `/etc/yeet/secret.d/1`
        let gen_str = link.ok().and_then(|path| {
            path.file_name()
                .map(|path| path.to_string_lossy().to_string())
        });
        log::info!("Current Generation: {gen_str:?}");
        let gen_num = gen_str
            .and_then(|str| str.parse::<u32>().ok().map(|i| i.wrapping_add(1)))
            .unwrap_or(0);
        log::info!("Creating new Generation {gen_num}");
        PathBuf::from(format!("/etc/yeet/secret.d/{gen_num}"))
    };

    // create new generation
    let genration_result = create_secret_generation(&generation, secrets);
    if genration_result.is_err() {
        if let Err(result) =
            remove_dir_all(&generation).note(generation.to_string_lossy().to_string())
        {
            log::error!("could not remove generation: {result:?}");
        }
        genration_result?;
    }

    // switch to new generation
    let _err = remove_file("/etc/yeet/secret");
    symlink(&generation, "/etc/yeet/secret")?;

    Ok(())
}

#[tracing::instrument(err, skip(secrets))]
/// At this point all secret content is known.
/// Create the secrets on disk
fn create_secret_generation(generation: &Path, secrets: Vec<(api::Secret, Vec<u8>)>) -> Result<()> {
    fs::create_dir_all(generation)?;
    fs::set_permissions(generation, fs::Permissions::from_mode(0o751))?;

    for (secret, content) in secrets {
        let file_name = {
            let file_name = Path::new(&secret.name)
                .file_name()
                .ok_or(eyre!("Invalid secret name: {}", secret.name))?;
            generation.join(file_name)
        };
        let mut secret_file = File::create_new(&file_name)?;

        secret_file.set_permissions(Permissions::from_mode(u32::from_str_radix(
            &secret.mode,
            8,
        )?))?;

        secret_file.write_all(&content)?;
        secret_file.flush()?;

        chown(
            &file_name,
            Some(secret.owner.parse()?),
            Some(secret.owner.parse()?),
        )
        .note(format!("File to chown: {}", file_name.to_string_lossy()))?;
    }

    Ok(())
}

#[tracing::instrument(err)]
fn set_system_profile(store_path: &api::StorePath) -> Result<()> {
    info!("Setting system profile to {store_path}");
    let profile = Command::new("nix-env")
        .args([
            "--profile",
            "/nix/var/nix/profiles/system",
            "--set",
            store_path,
        ])
        .output()?;
    if !profile.status.success() {
        bail!("{}", String::from_utf8(profile.stderr)?);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
#[tracing::instrument(err)]
fn activate(store_path: &api::StorePath) -> Result<()> {
    set_system_profile(store_path)?;
    info!("Activating {}", store_path);
    Command::new(Path::new(&store_path).join("activate"))
        .spawn()?
        .wait()?;
    Ok(())
}

#[cfg(target_os = "linux")]
#[tracing::instrument(err)]
fn activate(store_path: &api::StorePath) -> Result<()> {
    info!("Activating {store_path}");
    set_system_profile(store_path)?;
    Command::new(Path::new(&store_path).join("bin/switch-to-configuration"))
        .arg("switch")
        .spawn()?
        .wait()?;
    Ok(())
}
