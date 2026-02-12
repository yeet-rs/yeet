use std::{
    ffi::OsStr,
    fs::{
        self, File, Permissions, read_dir, read_link, read_to_string, remove_dir_all, remove_file,
    },
    io::{self, BufRead as _, BufReader, Write as _},
    os::unix::fs::{PermissionsExt, chown, symlink},
    path::{Path, PathBuf},
    process::Command,
    sync::OnceLock,
    time::Duration,
};

use api::key::{get_secret_key, get_verify_key};
use backon::{ConstantBuilder, Retryable as _};
use ed25519_dalek::VerifyingKey;
use httpsig_hyper::prelude::SecretKey;
use log::{error, info};
use rootcause::{Report, bail, prelude::ResultExt as _, report};
use tempfile::NamedTempFile;
use tokio::time;
use url::Url;
use yeet::{nix, server};

use crate::{cli_args::AgentConfig, notification, varlink, version::get_active_version};

static VERIFICATION_CODE: OnceLock<u32> = OnceLock::new();

/// When running the agent should do these things in order:
/// 1. Check if agent is active aka if the key is enrolled with `/system/verify`
///     if not:
///         create a new verification request
///         pull the verify endpoint in a time intervall
/// 2. Continuosly pull the system endpoint and execute based on the provided
pub async fn agent(config: &AgentConfig, sleep: u64, facter: bool) -> Result<(), Report> {
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
        });
    }

    (|| async { agent_loop(config, &key, pub_key, sleep, facter).await })
        .retry(
            ConstantBuilder::new()
                .without_max_times()
                .with_delay(Duration::from_secs(sleep)),
        )
        .notify(|err: &Report, dur: Duration| {
            error!("{err} - retrying in {dur:?}");
        })
        .await?;

    Ok(())
}

async fn agent_loop(
    config: &AgentConfig,
    key: &SecretKey,
    pub_key: VerifyingKey,
    sleep: u64,
    facter: bool,
) -> Result<(), Report> {
    let verified = server::system::is_host_verified(&config.server, key) //TODO unwrap
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

        let code = server::system::add_verification_attempt(
            &config.server,
            &api::VerificationAttempt {
                key: pub_key,
                store_path: get_active_version()?,
                artifacts: api::VerificationArtifacts { nixos_facter },
            },
        )
        .await?;
        let _ = VERIFICATION_CODE.set(code);
        info!("Your verification code is: {code}");
        bail!("Waiting for verification");
    }
    info!("Verified!");

    loop {
        let action = server::system::check(
            &config.server,
            key,
            &api::VersionRequest {
                store_path: get_active_version()?,
            },
        )
        .await?;

        info!("{action:#?}");

        agent_action(action, &config.server, key).await?;
        time::sleep(Duration::from_secs(sleep)).await;
    }
}

async fn agent_action(action: api::AgentAction, url: &Url, key: &SecretKey) -> Result<(), Report> {
    match action {
        api::AgentAction::Nothing => {}
        api::AgentAction::Detach => {}
        api::AgentAction::SwitchTo(remote_store_path) => {
            update(&remote_store_path, url, key).await?
        }
    }
    Ok(())
}

fn trusted_public_keys() -> Result<Vec<String>, Report> {
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

async fn update(version: &api::RemoteStorePath, url: &Url, key: &SecretKey) -> Result<(), Report> {
    download(version, url, key).await?;
    let current_gen = read_link("/etc/yeet/secret");
    get_secrets(version, url, key).await?;
    let next_gen = read_link("/etc/yeet/secret");

    let activation_err = activate(&version.store_path);
    // switch did not go correct
    if get_active_version()? != version.store_path {
        // Restore last gen if there was one
        if let Ok(current_gen) = current_gen {
            let _ = remove_file("/etc/yeet/secret");
            symlink(current_gen, "/etc/yeet/secret")?;
        }
        // Delete the generation that was just created
        if let Ok(next_gen) = next_gen {
            remove_dir_all(&next_gen)?;
        }
        activation_err?;
    } else {
        if let Ok(next_gen) = next_gen {
            let _ = remove_all_dirs_unless(
                next_gen.parent().unwrap_or(Path::new("/etc/yeet/secret.d")),
                next_gen.file_name().unwrap_or_default(),
            );
        }
    }
    notification::notify_all()?;
    Ok(())
}

fn remove_all_dirs_unless<P: AsRef<Path>>(
    base: P,
    dirname: &OsStr,
) -> Result<(), rootcause::Report> {
    for dir in read_dir(base)? {
        if let Ok(dir) = dir
            && &dir.file_name() != dirname
        {
            let _ = remove_dir_all(dir.path());
        }
    }

    Ok(())
}

pub fn switch_to(store_path: &api::StorePath) -> Result<(), Report> {
    activate(store_path)?;
    notification::notify_all()?;
    Ok(())
}

async fn download(
    version: &api::RemoteStorePath,
    url: &Url,
    key: &SecretKey,
) -> Result<(), Report> {
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
    let netrc = match server::secret::get_secret(url, key, "netrc").await {
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
        return Err(report!("{}", String::from_utf8(download.stderr)?)
            .context("Could not realize new version")
            .attach(format!(
                "Command: {}",
                command
                    .get_args()
                    .map(|ostr| ostr.to_string_lossy())
                    .collect::<Vec<_>>()
                    .join(" ")
            ))
            .into_dynamic());
    }
    Ok(())
}

async fn get_secrets(
    version: &api::RemoteStorePath,
    url: &Url,
    key: &SecretKey,
) -> Result<(), Report> {
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
    for (secret, definition) in nix_secrets {
        log::info!("Fetching secret {secret}");
        let Some(secret) = server::secret::get_secret(url, key, &secret).await? else {
            rootcause::bail!("Secret {secret} not found! Unable to switch to derivation");
        };
        secrets.push((definition, secret));
    }

    // get next generation number
    // This basically reads `/etc/yeet/secret` as u32 and if it fails it returns 0 (first gen)
    let generation = {
        let link = read_link("/etc/yeet/secret"); // this will return a path like `/etc/yeet/secret.d/1`
        let gen_str = link
            .ok()
            .and_then(|p| p.file_name().map(|p| p.to_string_lossy().to_string()));
        log::info!("Current Generation: {:?}", gen_str);
        let gen_num = gen_str
            .and_then(|str| str.parse::<u32>().ok().map(|i| i + 1))
            .unwrap_or(0);
        log::info!("Creating new Generation {gen_num}");
        PathBuf::from(format!("/etc/yeet/secret.d/{gen_num}"))
    };

    // create new generation
    let genration_result = create_generation(&generation, secrets);
    if genration_result.is_err() {
        if let Err(result) =
            remove_dir_all(&generation).attach(generation.to_string_lossy().to_string())
        {
            log::error!("could not remove generation: {result:?}");
        }
        genration_result?;
    }

    // switch to new generation
    let _ = remove_file("/etc/yeet/secret");
    symlink(&generation, "/etc/yeet/secret")?;

    Ok(())
}

fn create_generation(
    generation: &Path,
    secrets: Vec<(api::Secret, Vec<u8>)>,
) -> Result<(), rootcause::Report> {
    fs::create_dir_all(&generation)?;
    fs::set_permissions(&generation, fs::Permissions::from_mode(0o751));

    for (secret, content) in secrets {
        let file_name = {
            let file_name = Path::new(&secret.name)
                .file_name()
                .ok_or(rootcause::report!("Invalid secret name: {}", secret.name))?;
            generation.join(file_name)
        };
        let mut secret_file = File::create_new(&file_name)?;

        secret_file.set_permissions(Permissions::from_mode(u32::from_str_radix(
            &secret.mode,
            8,
        )?));

        secret_file.write_all(&content)?;
        secret_file.flush()?;

        chown(
            &file_name,
            Some(secret.owner.parse()?),
            Some(secret.owner.parse()?),
        )
        .attach(format!("File to chown: {}", file_name.to_string_lossy()))?;
    }

    Ok(())
}

fn set_system_profile(store_path: &api::StorePath) -> Result<(), Report> {
    info!("Setting system profile to {}", store_path);
    let profile = Command::new("nix-env")
        .args([
            "--profile",
            "/nix/var/nix/profiles/system",
            "--set",
            &store_path,
        ])
        .output()?;
    if !profile.status.success() {
        bail!("{}", String::from_utf8(profile.stderr)?);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn activate(store_path: &api::StorePath) -> Result<(), Report> {
    set_system_profile(store_path)?;
    info!("Activating {}", store_path);
    Command::new(Path::new(&store_path).join("activate"))
        .spawn()?
        .wait()?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn activate(store_path: &api::StorePath) -> Result<(), Report> {
    info!("Activating {}", store_path);
    set_system_profile(store_path)?;
    Command::new(Path::new(&store_path).join("bin/switch-to-configuration"))
        .arg("switch")
        .spawn()?
        .wait()?;
    Ok(())
}
