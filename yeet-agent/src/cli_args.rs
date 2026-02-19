use std::{env::current_dir, path::PathBuf};

use build::CLAP_LONG_VERSION;
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use shadow_rs::shadow;
use url::Url;

shadow!(build);

#[derive(Parser)]
#[clap(long_version = CLAP_LONG_VERSION)]
#[command(version, about, long_about = None)]
pub struct Yeet {
    #[command(flatten)]
    pub config: ClapConfig,
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Args, Serialize, Deserialize)]
pub struct ClapConfig {
    /// Base URL of the Yeet Server
    #[arg(long, global = true)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<Url>,

    /// Cachix cache name
    #[arg(long, global = true)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cachix: Option<String>,

    /// Cachix signing key
    #[arg(long, global = true)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cachix_key: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Config {
    pub url: Option<Url>,
    pub cachix: Option<String>,
    pub cachix_key: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AgentConfig {
    pub server: Url,
    pub sleep: u64,
    pub facter: bool,
    pub key: PathBuf,
}

#[expect(clippy::doc_markdown, reason = "No Markdown for clap")]
#[derive(Subcommand)]
pub enum Commands {
    #[command(hide = true)]
    /// Used to notify all users
    Notify,
    Agent {
        /// URL of the Yeet Server
        #[arg(long)]
        server: Url,

        /// Path to ed25519 key which is used for authentication
        #[arg(long)]
        key: PathBuf,

        /// Seconds to wait between updates.
        /// Lower bound, may be higher between switching versions
        #[arg(short, long, default_value = "30")]
        sleep: u64,

        /// Collect facter with nixos-facter
        #[arg(long)]
        facter: bool,
    },
    /// Approve a pending key verification with the corresponding code
    Approve {
        /// Hostname
        #[arg(index = 1)]
        name: Option<String>,
        /// Verification code
        #[arg(index = 2)]
        code: Option<u32>,
        /// Facter output file
        #[arg(long)]
        facter: Option<PathBuf>,
    },
    /// Build and then publish some or all hosts in a flake
    Publish {
        /// Path to flake
        #[arg(long, default_value = current_dir().unwrap().into_os_string())]
        path: PathBuf,

        /// Hosts to build - default is all
        #[arg(long)]
        host: Vec<String>,

        /// Sets the `NIXOS_VARIANT` variable when building NixOS. You have to set `system.nixos.variantName = lib.maybeEnv "NIXOS_VARIANT" "No VARIANT"`
        #[arg(long)]
        variant: Option<String>,

        /// Which hosts should be built? Defaults to current ARCH
        #[arg(
            long,
            default_value_t = std::env::consts::ARCH == "aarch64",
            default_missing_value = (std::env::consts::ARCH == "aarch64").to_string(),
            num_args = 0..=1,
            require_equals = false)]
        darwin: bool,
    },

    /// Query the status of all or your local hosts
    /// Requires either admin credentials or sudo
    Status {
        /// Instead of printing, output everything as json
        #[arg(long)]
        json: bool,
    },

    /// Detach your current system from the yeet server
    Detach {
        /// NixOS system path to switch to
        #[arg(long)]
        version: Option<api::StorePath>,
        /// Which hosts should be built? Defaults to current ARCH
        #[arg(
            long,
            default_value_t = std::env::consts::ARCH == "aarch64",
            default_missing_value = (std::env::consts::ARCH == "aarch64").to_string(),
            num_args = 0..=1,
            require_equals = false)]
        darwin: bool,
        /// Path to flake
        #[arg(long, default_value = current_dir().unwrap().into_os_string())]
        path: PathBuf,
        /// This will bypass signaling the detachement to the server. Bypassing the permission check.
        /// Required if your host is offline. The consequence will be that once your client gains connectivity to the yeet server,
        /// your client will siwtch to the server version meaning that you will lose the changes made by the detachement.
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Attach your system to the server
    Attach,
    /// Query the status of all hosts
    Hosts {
        /// Filter for some hosts
        #[arg(long)]
        full: bool,
    },

    /// These are the raw subcommands to execute functions on the server
    Server(ServerArgs),
    Host(HostArgs),
    Secret(crate::cli::secret::SecretArgs),
}
#[derive(Args)]
pub struct HostArgs {
    #[command(subcommand)]
    pub command: HostCommands,
}

#[derive(Subcommand)]
pub enum HostCommands {
    /// Rename an existing yeet host
    Rename {
        /// The current name of the host
        #[arg(long)]
        name: Option<String>,
        /// The new name for the host
        #[arg(long)]
        new: Option<String>,
    },
    /// Delete an host including all authentication info
    Remove {
        /// The name of the host
        #[arg(long)]
        name: Option<String>,
    },
}

#[derive(Args)]
pub struct ServerArgs {
    #[command(subcommand)]
    pub command: ServerCommands,
    /// Path to ed25519 key which is used for authentication
    #[arg(long, global = true)]
    pub httpsig_key: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum ServerCommands {
    /// Update a host e.g. push a new `store_path` TODO: batch update
    Update {
        /// Name of the host
        #[arg(long)]
        host: String,

        /// The new store path
        #[arg(long)]
        store_path: String,

        /// The public key the agent should use to verify the update
        #[arg(long)]
        public_key: String,

        /// The substitutor the agent should use to fetch the update
        #[arg(long)]
        substitutor: String,
    },
    /// Check if a key is verified
    VerifyStatus,
    /// Adds a key to the server for verification
    AddVerification {
        /// Store path of the current running system
        #[arg(long)]
        store_path: String,
        /// The public key the of the verification attempt
        #[arg(long)]
        public_key: PathBuf,
        /// Facter input file
        #[arg(long)]
        facter: Option<PathBuf>,
    },
    /// Add a new admin or build key to the server
    AddKey {
        /// Public key to add
        #[arg(index = 1)]
        key: PathBuf,
        /// Should the key be added as admin or as build
        #[arg(value_enum, index = 2)]
        admin: AuthLevel,
    },
    /// Remove a key from the server (can also used to remove hosts)
    RemoveKey {
        /// Public key to remove
        #[arg(index = 1)]
        key: PathBuf,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum AuthLevel {
    /// New Admin Level key [CAUTION]
    Admin,
    /// New key for build pipelines
    Build,
}
