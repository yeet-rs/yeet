use std::fs::read_link;

use color_eyre::{Result, eyre::Context as _};

pub fn get_active_version() -> Result<String> {
    Ok(read_link("/run/current-system")
        .context("Current system has no `/run/current-system`")?
        .to_string_lossy()
        .to_string())
}
