use std::{collections::HashMap, fs};

use color_eyre::Result;

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
        if fs::read_to_string(path.join("hidden"))
            .map(|s| s.trim() == "1")
            .unwrap_or(false)
        {
            continue;
        }

        out.push(entry.file_name().to_string_lossy().into_owned());
    }
    Ok(out)
}
