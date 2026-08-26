use std::{
    collections::{HashMap, HashSet},
    env::args,
    fs::{self, read_to_string},
    io::stderr,
    process::Command,
};

use color_eyre::{
    Result,
    eyre::{OptionExt, bail},
};
use serde::Deserialize;
use tracing::instrument;
use tracing_subscriber::{layer::SubscriberExt as _, util::SubscriberInitExt as _};

#[derive(Debug, Deserialize)]
pub struct Config {
    pub nix_system: Option<String>,
    #[serde(default = "nix_disko_attr")]
    pub nix_disko_attr: String,
}
fn nix_disko_attr() -> String {
    "config.system.build.diskoScript".to_owned()
}

#[instrument(err)]
fn main() -> Result<()> {
    init_tracer();
    color_eyre::install()?;
    // 1. Get a list of disko configurations
    // 1.2 build disko configuration
    // 2. query all devices in this disko configuration
    // 3. query all disks and assign the disko devices
    // 3.2 prompt for luks password
    // 4. run disko
    // 5. select system to build
    // 6. build
    // 7. ?? myabe install luks key in distro
    //
    // inquire::Select::new("What is your favourite color?", vec!["red", "blue"]).prompt()?;

    let mut args = args();
    args.next(); // ignore arg0
    let toml = args
        .next()
        .ok_or_eyre("No `installer.toml` specified. exiting")?;

    let config: Config = toml::from_str(&read_to_string(toml)?)?;

    let disko = nix_eval_disko(config.nix_system.unwrap(), config.nix_disko_attr)?;

    let disks = list_devices()?;
    let anchors = get_disko_anchors(&disko)?;
    let map = map_disko_anchors(anchors, disks)?;
    let disko = replace_disko_devices(disko, map);
    println!("{}", disko);
    Ok(())
}

#[instrument(err, ret)]
fn nix_eval_disko(nix_system: String, disko_attr: String) -> Result<String> {
    let output = Command::new("nom")
        .arg("build")
        .arg("-f")
        .arg(nix_system)
        .arg(disko_attr)
        .arg("--no-link")
        .arg("--json")
        .stderr(stderr())
        .output()?;
    if !output.status.success() {
        bail!("Could not build the disko script")
    }
    let nixout =
        serde_json::from_str::<serde_json::Value>(&String::from_utf8_lossy(&output.stdout))?;
    let path = nixout
        .pointer("/0/outputs/out")
        .ok_or_eyre("Disko script built but did not contain output")?
        .as_str()
        .ok_or_eyre("Nix build output was of unexpected type")?;

    Ok(read_to_string(path)?)
}

/// creates a mapping between available disks and the disko anchors
#[instrument(err, ret)]
fn map_disko_anchors(
    anchors: HashSet<String>,
    mut disks: Vec<String>,
) -> Result<HashMap<String, String>> {
    if anchors.len() != disks.len() {
        bail!(
            "You have {} disk but {} anchors defined in your disko config",
            disks.len(),
            anchors.len()
        );
    }
    // if we only have one anchor and one disk it is easy because we can just return the mapping
    if anchors.len() == 1 {
        let mut anchors = anchors;
        return Ok(HashMap::from([(
            anchors.drain().next().unwrap(),
            disks.pop().unwrap(),
        )]));
    }
    let mut map = HashMap::new();
    for anchor in anchors {
        let disk = inquire::Select::new(&format!("Select the disk for `{anchor}`"), disks.clone())
            .prompt()?;
        map.insert(anchor, disk.clone());
        disks.retain(|x| *x != disk);
    }
    Ok(map)
}

/// replaces every `INSTALLER_DISK` with the corresponding disk
#[instrument(ret)]
fn replace_disko_devices(mut disko: String, map: HashMap<String, String>) -> String {
    for (anchor, disk) in map {
        disko = disko.replace(&format!("INSTALLER_DISK_{anchor}"), &disk);
    }
    disko
}

/// returns all anchors marked with `INSTALLER_DISK`
#[instrument(err, ret)]
fn get_disko_anchors(disko: &str) -> Result<HashSet<String>> {
    let mut anchors = HashSet::new();
    let mut remainder = disko;
    while let Some((_rest, rest)) = remainder.split_once("INSTALLER_DISK_") {
        let anchor = rest
            .chars()
            .take_while(|char| {
                char.is_ascii_lowercase() || char.is_ascii_uppercase() || *char == '_'
            })
            .collect::<String>();

        remainder = rest;
        anchors.insert(anchor.to_owned());
    }
    Ok(anchors)
}

#[instrument(err, ret)]
fn list_devices() -> Result<Vec<String>> {
    let mut out = Vec::new();
    for entry in fs::read_dir("/sys/block")? {
        let entry = entry?;
        let path = entry.path();

        // virtual devices (loop, dm-*, md, zram) have no `device` link
        if !path.join("device").exists() {
            continue;
        }

        // skip hidden gendisks
        if fs::read_to_string(path.join("hidden")).is_ok_and(|gendisk| gendisk.trim() == "1") {
            continue;
        }

        out.push(entry.file_name().to_string_lossy().into_owned());
    }
    Ok(out)
}

fn init_tracer() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_error::ErrorLayer::default())
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .init();
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use crate::{get_disko_anchors, replace_disko_devices};

    #[test]
    fn disko_anchor_replace() {
        let after = replace_disko_devices(r#"{disko.devices = {disk = {main = {device = "/dev/INSTALLER_DISK_main";};two = {device = "/dev/INSTALLER_DISK_two";};};};}"#.into(),
            HashMap::from([("main".into(),"sda".into()),("two".into(),"sdb".into())]));
        assert_eq!(after,r#"{disko.devices = {disk = {main = {device = "/dev/sda";};two = {device = "/dev/sdb";};};};}"#.to_owned());
    }

    #[test]
    fn disko_anchor_extract() {
        let anchors = get_disko_anchors(
            r#"{disko.devices = {disk = {main = {device = "/dev/INSTALLER_DISK_main";};two = {device = "/dev/INSTALLER_DISK_two";};};};}"#,
        ).unwrap();
        assert_eq!(anchors, vec!["main".to_owned(), "two".to_owned()]);
    }
}
