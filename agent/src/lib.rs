use std::path::PathBuf;

use serde::{Deserialize, Serialize};

// pub(crate) mod agent;
// pub(crate) mod nix;
// pub(crate) mod notification;
pub mod varlink;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// URL of the Yeet Server
    pub server: url::Url,
    /// Path to ed25519 key which is used for authentication
    pub key: PathBuf,
    /// Seconds to wait between updates.
    /// Lower bound, may be higher between switching versions
    pub sleep: u64,
    /// Collect facter with nixos-facter
    pub facter: bool,
    /// In unattended mode all updates are installed immediately
    pub attended: bool,
}
