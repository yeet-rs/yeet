//! Plays the admin in the vm test (nix-build -A tests.vm).
//!
//! The real cli is interactive and a test script can't really type into prompts.
//! This does the same api calls but takes everything as args.
//! The admin key is a fixed test key so please never point this at a real server

use clap::{Parser, Subcommand};
use color_eyre::Result;
use ed25519_dalek::SigningKey;
use httpsig_hyper::prelude::{AlgorithmName, SecretKey};

/// Seed of the test admin key
const ADMIN_SEED: [u8; 32] = [4; 32];

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
    }
    Ok(())
}
