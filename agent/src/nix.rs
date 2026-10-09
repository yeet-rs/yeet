use std::{
    fs::{read_to_string, remove_file},
    io::{self, BufRead as _, Write as _},
    path::Path,
    process::{Command, Stdio},
};

use color_eyre::{
    Section as _,
    eyre::{Context as _, Result, bail, eyre},
};

use tempfile::NamedTempFile;
use tracing::{error, info};

use crate::notification;

#[tracing::instrument(err, ret)]
pub fn facter() -> Result<String> {
    let exit = Command::new("nixos-facter")
        .args(["-o", "facter.json"])
        .spawn()
        .context("Could not spawn `nixos-facter`")?
        .wait()
        .context("Could not wait for `nixos-facter`")?;
    if !exit.success() {
        bail!("nixos-facter did not exist successfully")
    }
    let facter = read_to_string("facter.json")
        .context("Facter did collect the data but `facter.json` does not exist")?;
    remove_file("facter.json").context("`facter.json` read but could not clean up")?;
    Ok(facter)
}

#[tracing::instrument(err, ret)]
pub fn nixos_variant_name() -> Result<String> {
    let output = Command::new("grep")
        .arg("^VARIANT=")
        .arg("/etc/os-release")
        .stdout(Stdio::piped())
        .spawn()
        .context("Could not spawn `grep`")?
        .wait_with_output()?;

    let output = String::from_utf8_lossy(&output.stdout).to_string();
    let output = output
        .trim()
        .trim_start_matches("VARIANT=")
        .trim_matches('"')
        .to_owned();
    Ok(output)
}

#[tracing::instrument(err, ret)]
fn trusted_public_keys() -> Result<Vec<String>> {
    let file = std::fs::File::open("/etc/nix/nix.conf")?;
    Ok(io::BufReader::new(file)
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

#[tracing::instrument(err, skip(key, stderr, stdout))]
pub async fn realise_store_path(
    version: &api::RemoteStorePath,
    url: &url::Url,
    key: &httpsig_hyper::prelude::SecretKey,
    stderr: impl Into<Stdio>,
    stdout: impl Into<Stdio>,
    dry_run: bool,
) -> Result<()> {
    info!("Downloading {}", version.store_path);
    let mut keys = trusted_public_keys()?;
    keys.push(version.public_key.clone());
    keys.sort();
    keys.dedup();

    let mut command = Command::new("nix-store");
    command.stderr(stderr).stdout(stdout);
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
            error!("could not get netrc secret: {err}");
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
    if dry_run {
        command.arg("--dry-run");
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

#[tracing::instrument(err, skip(stderr, stdout))]
pub fn activate_system(
    store_path: &api::StorePath,
    stderr: impl Into<Stdio>,
    stdout: impl Into<Stdio>,
    dry_run: bool,
) -> Result<()> {
    info!("Activating {store_path}");
    let cmd = if dry_run {
        "dry-activate"
    } else {
        set_system_profile(store_path)?;
        "switch"
    };
    Command::new(Path::new(&store_path).join("bin/switch-to-configuration"))
        .arg(cmd)
        .stderr(stderr)
        .stdout(stdout)
        .spawn()?
        .wait()?;
    Ok(())
}

/// Used for detaching
#[tracing::instrument(err)]
pub fn detach(store_path: &api::StorePath) -> Result<()> {
    activate_system(store_path, io::stderr(), io::stdout(), false)?;
    let variant = nixos_variant_name()?;
    notification::notify_all(
        &format!("System has been updated to `{variant}`"),
        "System Update",
    )?;
    Ok(())
}
