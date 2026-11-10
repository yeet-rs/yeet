//! Plays the admin in the vm test (nix-build -A tests.set-password).
//!
//! yeet host set-password is interactive and a test script can't really type into prompts.
//! This does the same api calls and hashes the same way, but takes everything as args.
//! The admin key is a fixed test key so please never point this at a real server

use std::{io::Read as _, time::Duration};

use clap::{Parser, Subcommand};
use color_eyre::{Result, eyre::eyre};
use ed25519_dalek::SigningKey;
use httpsig_hyper::prelude::{AlgorithmName, SecretKey};

/// Same hashing as the cli, so the vm test checks the real code
#[path = "../src/hash.rs"]
mod hash;

/// Seed of the test admin key
const ADMIN_SEED: [u8; 32] = [4; 32];
/// How long to wait for the agent to report
const TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Parser)]
struct Args {
    /// Base URL of the Yeet Server
    #[arg(long)]
    url: url::Url,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create the first admin. Only works on an empty server
    Bootstrap,
    /// Accept the verification code a host logged
    Accept { code: u32, hostname: String },
    /// Queue a password change and wait for the result.
    /// Reads the password from stdin and prints the final task status as json
    SetPassword { hostname: String, username: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let args = Args::parse();
    let url = &args.url;
    let admin = &SecretKey::from_bytes(&AlgorithmName::Ed25519, &ADMIN_SEED)?;

    match args.command {
        Command::Bootstrap => {
            api::create_user(
                url,
                admin,
                api::CreateUser {
                    key: SigningKey::from_bytes(&ADMIN_SEED).verifying_key(),
                    level: api::AuthLevel::Admin,
                    username: "admin".into(),
                    all_tag: true,
                },
            )
            .await?;
        }
        Command::Accept { code, hostname } => {
            api::accept_attempt(url, admin, code, &hostname).await?;
        }
        Command::SetPassword { hostname, username } => {
            let host = api::list_hosts(url, admin)
                .await?
                .into_iter()
                .find(|host| host.hostname == hostname)
                .ok_or_else(|| eyre!("No host named {hostname}"))?;

            let hashed_password = {
                let mut password = String::new();
                std::io::stdin().read_to_string(&mut password)?;
                hash::hash_password(password.trim_end_matches('\n'))?
            };

            let task = api::HostTask::SetPassword {
                username,
                hashed_password,
            };
            let id = api::create_task(url, admin, host.id, &task).await?;

            let start = tokio::time::Instant::now();
            let status = loop {
                let status = api::task_status(url, admin, id).await?;
                if status.state != api::TaskState::Pending || start.elapsed() >= TIMEOUT {
                    break status;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            };
            print_json(&status)?;
        }
    }
    Ok(())
}

#[expect(clippy::print_stdout, reason = "the test script parses stdout")]
fn print_json(status: &api::TaskStatus) -> Result<()> {
    println!("{}", serde_json::to_string(status)?);
    Ok(())
}
