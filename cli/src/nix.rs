use std::{
    collections::HashMap,
    io::{self},
    process::{Command, Stdio},
};

use color_eyre::eyre::{Context as _, Result, bail, eyre};
use inquire::{list_option::ListOption, validator::Validation};

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[tracing::instrument( fields(program = %program.as_ref()))]
pub fn cmd_exists<T: AsRef<str>>(program: T) -> io::Result<()> {
    let mut cmd = Command::new("sh");

    let arg = {
        cmd.arg("-c"); // invocation flag
        format!("command -v {}", program.as_ref())
    };

    if cmd
        .arg(arg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?
        .success()
    {
        Ok(())
    } else {
        Err(io::ErrorKind::NotFound.into())
    }
}

fn nom_or_nix() -> String {
    if cmd_exists("nom").is_ok() {
        "nom"
    } else {
        "nix"
    }
    .to_owned()
}

// TODO: build multiple hosts at once
// TODO: limit output
#[tracing::instrument]
pub fn build_hosts(
    flake_path: &str,
    hosts: Vec<String>,
    darwin: bool,
    variant: Option<String>,
) -> Result<HashMap<String, String>> {
    let mut closures = HashMap::with_capacity(hosts.len());

    let env = {
        let mut env = HashMap::new();
        if let Some(variant) = variant {
            env.insert("NIXOS_VARIANT", variant);
        }
        env
    };

    for ref host in hosts {
        let system = if darwin {
            format!("darwinConfigurations.{host}.system")
        } else {
            format!("nixosConfigurations.{host}.config.system.build.toplevel")
        };
        let output = Command::new(nom_or_nix())
            .args(["build", "--json", "--no-link", "-f", flake_path, &system])
            .envs(&env)
            .stdout(Stdio::piped())
            .spawn()?
            .wait_with_output()?;
        let build = serde_json::from_slice::<Value>(&output.stdout)?;
        #[expect(clippy::indexing_slicing)] // yeah ik
        let closure = build[0]["outputs"]["out"]
            .as_str()
            .ok_or(eyre!("Build output did not contain a valid closure"))?;

        closures.insert(host.clone(), closure.to_owned());
    }
    Ok(closures)
}

#[tracing::instrument]
pub fn list_hosts(flake_path: &str, darwin: bool) -> Result<Vec<String>> {
    let flavor = if darwin {
        "darwinConfigurations"
    } else {
        "nixosConfigurations"
    };
    let output = Command::new("nix")
        .arg("eval")
        .args([
            "-f",
            flake_path,
            flavor,
            "--apply",
            "builtins.attrNames",
            "--json",
        ])
        .stdout(Stdio::piped())
        .spawn()?
        .wait_with_output()
        .context("Could not find nix systems in the current dir")?;

    if !output.status.success() {
        bail!("Could not find nix systems in the current dir");
    }

    Ok(serde_json::from_slice(&output.stdout)?)
}

#[tracing::instrument]
pub fn get_hosts(flake_path: &str, darwin: bool) -> Result<Vec<String>> {
    let detected_hosts = list_hosts(flake_path, darwin)?;
    Ok(
        inquire::MultiSelect::new("Which host(s) would you like to publish>", detected_hosts)
            .with_validator(|list: &[ListOption<&String>]| {
                if list.is_empty() {
                    return Ok(Validation::Invalid("You must select a host!".into()));
                }
                Ok(Validation::Valid)
            })
            .prompt()?,
    )
}

#[tracing::instrument]
pub fn get_host(flake_path: &str, darwin: bool) -> Result<String> {
    let detected_hosts = list_hosts(flake_path, darwin)?;
    Ok(inquire::Select::new("Which host would you like to build>", detected_hosts).prompt()?)
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct NixOSVersion {
    pub configuration_revision: String,
    pub nixos_version: String,
    pub nixpkgs_revision: Option<String>,
}

#[tracing::instrument]
pub fn nixos_version() -> Result<NixOSVersion> {
    let output = Command::new("nixos-version")
        .arg("--json")
        .stdout(Stdio::piped())
        .spawn()
        .context("Could not spawn `nixos-version`")?
        .wait_with_output()?;

    Ok(serde_json::from_slice(&output.stdout)?)
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct NixOSGeneration {
    pub generation: u32,
    pub date: jiff::civil::DateTime,
    pub nixos_version: String,
    pub kernel_version: String,
    pub configuration_revision: String,
    pub specialisations: Vec<String>,
    pub current: bool,
}

impl Default for NixOSGeneration {
    fn default() -> Self {
        Self {
            generation: 0,
            date: Default::default(),
            nixos_version: "unknown".to_owned(),
            kernel_version: "unknown".to_owned(),
            configuration_revision: "unknown".to_owned(),
            specialisations: Default::default(),
            current: Default::default(),
        }
    }
}

#[tracing::instrument]
pub fn nixos_generations() -> Result<Vec<NixOSGeneration>> {
    let output = Command::new("nixos-rebuild")
        .arg("list-generations")
        .arg("--json")
        .stdout(Stdio::piped())
        .spawn()
        .context("Could not spawn `nixos-rebuild`")?
        .wait_with_output()?;

    Ok(serde_json::from_slice(&output.stdout)?)
}

#[tracing::instrument]
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
