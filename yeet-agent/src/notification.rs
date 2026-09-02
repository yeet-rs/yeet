use std::fs;

use color_eyre::eyre::Result;
use tokio::process::Command;

#[tracing::instrument(err)]
pub fn notify(body: &str, summary: &str) -> Result<()> {
    notify_rust::Notification::new()
        .summary(summary)
        .body(body)
        .appname("Yeet")
        .show()?;
    Ok(())
}

#[tracing::instrument(err)]
pub fn notify_all(body: &str, summary: &str) -> Result<()> {
    let user_dirs = {
        let dirs = fs::read_dir("/run/user")?;
        dirs.flatten()
            // .into_iter()
            .map(|dir| dir.path())
            .filter_map(|path| {
                path.file_name()
                    .map(|file_name| file_name.to_string_lossy().to_string())
            })
            .flat_map(|file_name| file_name.parse::<u32>())
    };

    for user in user_dirs {
        let dbus_address = format!("unix:path=/run/user/{user}/bus");
        let current_exe = std::env::current_exe().unwrap_or_else(|_| "yeet".into());
        let _cmd = Command::new(current_exe)
            .arg("notify")
            .uid(user)
            .arg("--body")
            .arg(body)
            .arg("--summary")
            .arg(summary)
            .env("DBUS_SESSION_BUS_ADDRESS", &dbus_address)
            // .env("DISPLAY", ":0")
            .spawn();
    }
    Ok(())
}
