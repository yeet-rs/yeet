use std::{
    collections::{HashMap, HashSet},
    env::args,
    fs::{self, read_to_string},
    io::{BufRead, BufReader, Write},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{self, Command, Stdio},
};

use color_eyre::{Result, eyre::bail};

use serde::Deserialize;
use tempfile::NamedTempFile;
use tracing::instrument;
use tracing_subscriber::{layer::SubscriberExt as _, util::SubscriberInitExt as _};

use crate::cache::Cache;

mod cache;
mod nix;

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct Preset {
    pub modules: Vec<String>,
    pub description: String,
    #[serde(default)]
    pub default: bool,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    /// List of user-configured presets
    #[serde(default = "Vec::new")]
    pub presets: Vec<Preset>,
    /// nix attr that should get build to get the disko script
    #[serde(default = "nix_disko_attr")]
    pub nix_disko_attr: String,
    /// directories that empty cache if they get modified
    #[serde(default = "default_cache")]
    pub cache: Vec<String>,
}
fn nix_disko_attr() -> String {
    "config.system.build.diskoScript".to_owned()
}

fn default_cache() -> Vec<String> {
    vec!["/etc/yeet/disko".to_owned(), "/etc/yeet/modules".to_owned()]
}

fn init_tracing() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing::level_filters::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        // .with(tracing_subscriber::fmt::layer().with_target(false))
        .with(tracing_error::ErrorLayer::default())
        .init();

    let mut log_builder =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"));
    log_builder.format(|buf, record| {
        write!(buf, "{}", buf.default_level_style(record.level()))?;
        write!(buf, "{}", record.level())?;
        write!(buf, "{:#}", buf.default_level_style(record.level()))?;
        writeln!(buf, ": {}", record.args())
    });

    log_builder.init();
}

#[instrument(err)]
fn main() -> Result<()> {
    init_tracing();
    color_eyre::install()?;
    cliclack::clear_screen()?;
    cliclack::intro("Yeet Installer")?;
    // 1. Get a list of system configurations
    // 1.2 build disko configuration
    // 2. query all devices in this disko configuration
    // 3. query all disks and assign the disko devices
    // 3.2 prompt for luks password
    // 4. run disko
    // 6. build system
    // 7. ?? myabe install luks key in distro
    //

    let mut args = args();
    args.next(); // ignore arg0

    let toml = args.next().unwrap_or("/etc/yeet/installer.toml".to_owned());

    let config: Config = toml::from_str(&read_to_string(toml)?)?;
    let mut cache = Cache::from_file(config.cache, PathBuf::from("/etc/yeet/cache.toml"))?;

    let modules = get_modules(config.presets)?;

    let disko = read_to_string(cache.nix_build(&modules, &config.nix_disko_attr)?)?;

    let disks = list_devices()?;
    let anchors = get_disko_anchors(&disko)?;
    let map = map_disko_anchors(anchors, disks)?;
    let disko = replace_disko_devices(disko, map);
    run_disko(disko)?;

    // now after partitioning we need to build the system
    let system = cache.nix_build(&modules, "config.system.build.toplevel")?;
    nix::nixos_install(system)?;
    process::Command::new("systemctl").arg("reboot").status()?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PresetOption {
    Preset(Preset),
    ManualSelect,
}

#[instrument(err)]
fn get_modules(presets: Vec<Preset>) -> Result<Vec<String>> {
    // if default is set use it
    for preset in presets.iter() {
        if preset.default {
            return Ok(preset.modules.clone());
        }
    }
    let preset_options = presets
        .into_iter()
        .map(|preset| {
            (
                PresetOption::Preset(preset.clone()),
                preset.description,
                preset.modules.join(" "),
            )
        })
        .collect::<Vec<_>>();

    let preset = cliclack::select("Select a preset")
        .item(
            PresetOption::ManualSelect,
            "<Select modules manually>".to_owned(),
            "".to_owned(),
        )
        .items(&preset_options)
        .interact()?;

    match preset {
        PresetOption::Preset(preset) => Ok(preset.modules),
        PresetOption::ManualSelect => manual_preset(),
    }
}

fn manual_preset() -> Result<Vec<String>> {
    let modules = fs::read_dir("/etc/yeet/modules")?
        .chain(fs::read_dir("/etc/yeet/disko")?)
        .flat_map(|dir| dir.ok())
        .map(|p| p.path().to_string_lossy().into_owned())
        .map(|path| path.trim_start_matches("/etc/yeet/").to_owned())
        .map(|path| path.trim_end_matches(".nix").to_owned())
        .map(|path| (path.clone(), path, ""))
        .collect::<Vec<_>>();
    Ok(
        cliclack::multiselect("Select the modules you want to install")
            .items(&modules)
            .interact()?,
    )
}

#[instrument(err)]
fn run_disko(disko: String) -> Result<()> {
    let spinner = cliclack::spinner();
    spinner.start("Formatting...");

    let path = {
        let mut tmp = NamedTempFile::new()?;
        tmp.write_all(disko.as_bytes())?;

        let (file, path) = tmp.keep()?;
        let mut permissions = file.metadata()?.permissions();
        permissions.set_mode(0o700);
        file.set_permissions(permissions)?;
        path
    };

    let (stdout_read, stdout_write) = std::io::pipe()?;
    let child = Command::new(path)
        .stderr(Stdio::piped())
        .stdout(stdout_write)
        .spawn()?;

    // start reading the output continously
    let mut stdout = BufReader::new(stdout_read);
    // at the end print the whole report
    let mut message = String::new();
    loop {
        let mut line = String::new();
        if stdout.read_line(&mut line)? == 0 {
            break;
        }
        if line.starts_with("The operation has completed") {
            continue;
        }
        message.push_str(&line);
        // show what it is currently doing
        spinner.set_message(&line);
    }
    let output = child.wait_with_output()?;

    if !output.status.success() {
        spinner.error("Formatting failed");
        cliclack::log::error(String::from_utf8_lossy(&output.stderr))?;

        bail!("Disko script did not execute correctly. Aborting");
    }
    spinner.stop("Formatting successful");
    cliclack::log::remark(message)?;

    Ok(())
}

/// creates a mapping between available disks and the disko anchors
#[instrument(err, ret)]
fn map_disko_anchors(
    anchors: HashSet<String>,
    mut disks: Vec<String>,
) -> Result<HashMap<String, String>> {
    if anchors.len() > disks.len() {
        bail!(
            "You have {} disk but {} anchors defined in your disko config",
            disks.len(),
            anchors.len()
        );
    }
    // if we only have one anchor and one disk it is easy because we can just return the mapping
    if anchors.len() == 1 && disks.len() == 1 {
        let mut anchors = anchors;
        return Ok(HashMap::from([(
            anchors.drain().next().unwrap(),
            disks.pop().unwrap(),
        )]));
    }
    let mut map = HashMap::new();
    for anchor in anchors {
        let disk = cliclack::select(&format!("Select the disk for `{anchor}`"))
            .items(
                &disks
                    .iter()
                    .map(|disk| (disk.clone(), disk, ""))
                    .collect::<Vec<_>>(),
            )
            .interact()?;
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
    let usb_partition = fs::canonicalize("/dev/disk/by-partlabel/YEET_ROOTFS")?;

    cliclack::log::remark(format!(
        "Detected Installer running on {}",
        usb_partition.display()
    ))?;
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

        // skip the usb device
        // use string starts_with instead of path starts_with because else it would not match because of the partition
        if usb_partition
            .to_string_lossy()
            .to_string()
            .starts_with(&format!(
                "/dev/{}",
                entry.file_name().to_string_lossy().to_string()
            ))
        {
            continue;
        }

        out.push(entry.file_name().to_string_lossy().into_owned());
    }
    Ok(out)
}

// #[cfg(test)]
// mod test {
//     use std::collections::HashMap;

//     use crate::{get_disko_anchors, replace_disko_devices};

//     #[test]
//     fn disko_anchor_replace() {
//         let after = replace_disko_devices(r#"{disko.devices = {disk = {main = {device = "/dev/INSTALLER_DISK_main";};two = {device = "/dev/INSTALLER_DISK_two";};};};}"#.into(),
//             HashMap::from([("main".into(),"sda".into()),("two".into(),"sdb".into())]));
//         assert_eq!(after,r#"{disko.devices = {disk = {main = {device = "/dev/sda";};two = {device = "/dev/sdb";};};};}"#.to_owned());
//     }

//     #[test]
//     fn disko_anchor_extract() {
//         let anchors = get_disko_anchors(
//             r#"{disko.devices = {disk = {main = {device = "/dev/INSTALLER_DISK_main";};two = {device = "/dev/INSTALLER_DISK_two";};};};}"#,
//         ).unwrap();
//         assert_eq!(anchors, vec!["main".to_owned(), "two".to_owned()]);
//     }
// }
