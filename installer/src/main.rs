use std::{collections::HashMap, fs, hash::Hash};

use color_eyre::{
    Result,
    eyre::{Ok, OptionExt},
};

fn main() -> Result<()> {
    // 1. Get a list of disko configurations
    // 2. query all devices in this disko configuration
    // 3. query all disks and assign the disko devices
    // 3.2 prompt for luks password
    // 4. run disko
    // 5. select system to build
    // 6. build
    // 7. ?? myabe install luks key in distro
    //
    // inquire::Select::new("What is your favourite color?", vec!["red", "blue"]).prompt()?;

    let disks = list_devices()?;
    dbg!(disks);
    Ok(())
}

fn map_disko_anchors(
    anchors: Vec<String>,
    mut disks: Vec<String>,
) -> Result<HashMap<String, String>> {
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
fn replace_disko_devices(mut disko: String, map: HashMap<String, String>) -> String {
    for (anchor, disk) in map {
        disko = disko.replace(&format!("INSTALLER_DISK_{anchor}"), &disk);
    }
    disko
}

/// returns all anchors marked with `INSTALLER_DISK`
fn get_disko_anchors(disko: &str) -> Result<Vec<String>> {
    let mut anchors = Vec::new();
    let mut remainder = disko;
    while let Some((_rest, anchor)) = remainder.split_once("INSTALLER_DISK_") {
        let anchor = anchor
            .split_once('"')
            .ok_or_eyre("Unexpected end of `INSTALLER_DISK`_ anchor")?;
        remainder = anchor.1;
        anchors.push(anchor.0.to_owned());
    }
    Ok(anchors)
}

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
