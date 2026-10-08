use color_eyre::{
    Result,
    eyre::{OptionExt as _, bail},
};

use std::{
    fmt::Debug,
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Command, Stdio},
};

use tracing::instrument;

#[instrument(err, ret)]
pub fn build(modules: &[String], attr: &str) -> Result<PathBuf> {
    cliclack::log::remark(format!("Building {attr} with {modules:?}"))?;
    // --expr resolves relative paths against CWD. pin it down
    let expr = format!(
        "import <nixpkgs/nixos/lib/eval-config.nix> {{ system = null; modules = [ {} ]; }}",
        modules
            .into_iter()
            .map(|module| format!("{}.nix", module))
            .collect::<Vec<_>>()
            .join(" ")
    );

    let child = Command::new("nom")
        .current_dir("/etc/yeet")
        .arg("build")
        .arg("--impure")
        .arg("--expr")
        .arg(&expr)
        .arg(attr)
        .arg("--no-link")
        .arg("--json")
        .stdout(Stdio::piped())
        .stderr(std::io::stderr())
        .spawn()?;

    let output = child.wait_with_output()?;

    if !output.status.success() {
        cliclack::log::error(String::from_utf8_lossy(&output.stderr))?;

        bail!("Could not build the attr {attr}")
    }
    cliclack::log::success("Build successful")?;

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
    cliclack::clear_screen()?;
    let (stderr_read, stderr_write) = std::io::pipe()?;
    let child = Command::new("nixos-install")
        .arg("--system")
        .arg(system)
        .arg("--no-root-passwd")
        .arg("--cores")
        .arg("0")
        .stderr(stderr_write)
        .spawn()?;

    let mut stderr = BufReader::new(stderr_read);

    let bar = {
        let size: u64 = {
            let mut size = String::new();
            stderr.read_line(&mut size)?;
            cliclack::log::remark(&size)?;
            size.chars()
                .skip_while(|ch| !ch.is_digit(10))
                .take_while(|ch| ch.is_digit(10))
                .map(|ch| ch.to_string())
                .collect::<Vec<_>>()
                .concat()
                .parse::<u64>()
                .unwrap_or(1000)
                + 20
        };
        let bar = cliclack::progress_bar(size);
        bar.start("Starting installation");
        bar
    };

    loop {
        let mut line = String::new();
        if stderr.read_line(&mut line)? == 0 {
            break;
        }
        // show what it is currently doing
        bar.set_message(&line);
        if line.starts_with("copying path") {
            bar.inc(1);
        }
    }
    let output = child.wait_with_output()?;

    if !output.status.success() {
        cliclack::log::error(String::from_utf8_lossy(&output.stderr))?;
        bar.error("Could not Install NixOS");
        bail!("Could not install the NixOS system")
    }

    bar.stop("Installation completed");
    Ok(())
}
