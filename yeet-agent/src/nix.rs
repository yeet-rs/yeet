use std::{
    collections::HashMap,
    fs::{read_to_string, remove_file},
    io,
    path::Path,
    process::{Command, Stdio},
};

use inquire::{list_option::ListOption, validator::Validation};
use rootcause::{Report, bail, prelude::ResultExt as _, report};
use serde::{Deserialize, Serialize};
use serde_json::Value;

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

// This command is used to run the virtual machine of a particular system
// WARNING: currently is just shelling out. In future we need to valide if
// the system is in the flake or not
// TODO: split build and run into different parts
pub fn run_vm(flake_path: &Path, system: &str) -> Result<(), Report> {
    let flake_path = flake_path.canonicalize()?; // Maybe check if its a dir and if it contains a flake.nix
    let flake_path = flake_path.to_string_lossy();
    #[cfg(target_arch = "x86_64")]
    let flake_target = format!("nixosConfigurations.{system}.config.formats.vm");
    #[cfg(target_arch = "aarch64")]
    let flake_target = format!("darwinConfigurations.{system}.config.formats.vm");
    let build_output = Command::new(nom_or_nix())
        .args(["build", "-f", &flake_path, &flake_target])
        .stderr(io::stderr())
        .stdout(io::stdout())
        .spawn()?
        .wait()?;
    if !build_output.success() {
        bail!("Could not build the Virtual Machine");
    }
    Command::new(format!("{flake_path}/result/run-nixos-vm"))
        .stderr(io::stderr())
        .stdout(io::stdout())
        .spawn()?
        .wait()?;
    Ok(())
}

// TODO: build multiple hosts at once
// TODO: limit output
pub fn build_hosts(
    flake_path: &str,
    hosts: Vec<String>,
    darwin: bool,
    variant: Option<String>,
) -> Result<HashMap<String, String>, Report> {
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
            .ok_or(report!("Build output did not contain a valid closure"))?;
        closures.insert(host.clone(), closure.to_owned());
    }
    Ok(closures)
}

pub fn facter() -> Result<String, Report> {
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

pub fn list_hosts(flake_path: &str, darwin: bool) -> Result<Vec<String>, Report> {
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

pub fn get_hosts(flake_path: &str, darwin: bool) -> Result<Vec<String>, Report> {
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

pub fn get_host(flake_path: &str, darwin: bool) -> Result<String, Report> {
    let detected_hosts = list_hosts(flake_path, darwin)?;
    Ok(inquire::Select::new("Which host would you like to build>", detected_hosts).prompt()?)
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NixOSVersion {
    pub configuration_revision: String,
    pub nixos_version: String,
    pub nixpkgs_revision: String,
}

pub fn nixos_version() -> Result<NixOSVersion, Report> {
    let output = Command::new("nixos-version")
        .arg("--json")
        .stdout(Stdio::piped())
        .spawn()
        .context("Could not spawn `nixos-version`")?
        .wait_with_output()?;

    Ok(serde_json::from_slice(&output.stdout)?)
}

#[derive(Serialize, Deserialize)]
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

pub fn nixos_generations() -> Result<Vec<NixOSGeneration>, Report> {
    let output = Command::new("nixos-rebuild")
        .arg("list-generations")
        .arg("--json")
        .stdout(Stdio::piped())
        .spawn()
        .context("Could not spawn `nixos-rebuild`")?
        .wait_with_output()?;

    Ok(serde_json::from_slice(&output.stdout)?)
}

pub fn nixos_variant_name() -> Result<String, Report> {
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
