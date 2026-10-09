use std::path::PathBuf;

use clap::Subcommand;

use shadow_rs::shadow;
use url::Url;

shadow!(build);

#[derive(Subcommand)]
pub enum Commands {
    #[command(hide = true)]
    /// Used to notify all users
    Notify {
        #[arg(long)]
        body: String,
        #[arg(long)]
        summary: String,
    },

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

        /// In unattended mode all updates are installed immediately
        #[arg(long)]
        attended: bool,
    },
}
