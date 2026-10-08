use color_eyre::{
    Result,
    eyre::{OptionExt as _, bail},
};
use log::info;
use std::{fmt::Debug, path::PathBuf, process::Command};

use tracing::instrument;

#[instrument(err, ret)]
pub fn build(modules: &[String], attr: &str) -> Result<PathBuf> {
    info!("Building {attr} with {modules:?}");
    // --expr resolves relative paths against CWD. pin it down

    let expr = format!(
        "import <nixpkgs/nixos/lib/eval-config.nix> {{ system = null; modules = [ {} ]; }}",
        modules
            .into_iter()
            .map(|module| format!("{}.nix", module))
            .collect::<Vec<_>>()
            .join(" ")
    );
    let output = Command::new("nom")
        .current_dir("/etc/yeet")
        .arg("build")
        .arg("--impure")
        .arg("--expr")
        .arg(&expr)
        .arg(attr)
        .arg("--no-link")
        .arg("--json")
        .stderr(std::io::stderr())
        .output()?;
    if !output.status.success() {
        bail!("Could not build the attr {attr}")
    }
    let nixout =
        serde_json::from_str::<serde_json::Value>(&String::from_utf8_lossy(&output.stdout))?;
    let path = nixout
        .pointer("/0/outputs/out")
        .ok_or_eyre("Disko script built but did not contain output")?
        .as_str()
        .ok_or_eyre("Nix build output was of unexpected type")?;

    Ok(PathBuf::from(path))
}

#[instrument(err, ret)]
pub fn nixos_install<P: AsRef<std::ffi::OsStr> + Debug>(system: P) -> Result<()> {
    let output = Command::new("nixos-install")
        .arg("--system")
        .arg(system)
        .arg("--no-root-passwd")
        .arg("--cores")
        .arg("0")
        .stderr(std::io::stderr())
        .output()?;
    if !output.status.success() {
        bail!("Could not install the NixOS system")
    }
    Ok(())
}
