use color_eyre::{
    Result,
    eyre::{OptionExt as _, bail},
};
use log::info;
use std::{
    fmt::Debug,
    path::{Path, PathBuf},
    process::Command,
};

use tracing::instrument;

#[instrument(err, ret)]
pub fn build<P: AsRef<Path> + Debug>(nix_file: P, attr: &str) -> Result<PathBuf> {
    info!("Building {attr}");
    let output = Command::new("nom")
        .arg("build")
        .arg("-f")
        .arg(nix_file.as_ref())
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
