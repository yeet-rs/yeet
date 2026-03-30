use std::{collections::HashMap, fmt::Display};

use colored::Colorize as _;
use ed25519_dalek::VerifyingKey;

use serde::{Deserialize, Serialize};

use crate::{StorePath, request, tag};

crate::db_id!(HostID);

// State the Server wants the client to be in

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "hazard", derive(sqlx::Type))]
pub enum ProvisionState {
    NotSet,
    Detached,
    Provisioned,
}

impl Display for ProvisionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let colored = match self {
            ProvisionState::NotSet => "Not set".blue(),
            ProvisionState::Detached => "Detached".yellow(),
            ProvisionState::Provisioned => "Provisioned".green(),
        };
        write!(f, "{colored}")
    }
}
// impl ColoredDisplay for api::ProvisionState {
//     fn colored_display(&self) -> StyledObject<&'static str> {
//         match self {
//             api::ProvisionState::NotSet => "Not set".blue(),
//             api::ProvisionState::Detached => "Detached".yellow(),
//             api::ProvisionState::Provisioned => "Provisioned".green(),
//         }
//     }
// }

impl Default for ProvisionState {
    #[inline]
    fn default() -> Self {
        Self::NotSet
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Host {
    pub id: HostID,
    pub key: VerifyingKey,
    pub hostname: String,
    pub state: ProvisionState,
    pub last_ping: jiff::Timestamp,
    pub version: Option<StorePath>,
    pub latest_update: Option<StorePath>,
    pub tags: Vec<tag::Tag>,
}

impl Display for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.hostname)?;
        write!(f, " {}", self.state)?;

        let commit_ver = match &self.version {
            Some(version) => {
                let pos = version.rfind('.').map_or(0, |i| i.saturating_add(1));
                #[expect(clippy::string_slice)]
                version[pos..].to_owned()
            }
            None => "Not Set".blue().to_string(),
        };
        write!(f, "({commit_ver})")?;

        let up_to_date = if self.version == self.latest_update {
            "Up to date ".green()
        } else {
            "Outdated   ".red()
        };
        write!(f, " {up_to_date}")?;
        write!(
            f,
            " {}",
            crate::time_diff(
                self.last_ping,
                jiff::Unit::Second,
                30_f64,
                jiff::Unit::Second
            )
        )
    }
}

impl PartialEq for Host {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.key == other.key
            && self.hostname == other.hostname
            && self.state == other.state
            // && self.last_ping == other.last_ping
            && self.version == other.version
            && self.latest_update == other.latest_update
    }
}
impl Eq for Host {}

request! (
    list_hosts(),
    get("/host") -> Vec<Host>
);

request! (
    rename_host(host: HostID, new_name: &str),
    put("/host/{host}/rename/{new_name}") -> StatusCode
);

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Represents a Host Update Request
/// The Agent uses the substitutor to fetch the update via nix
// TODO: Split into remote lookup
pub struct HostUpdateRequest {
    /// The hosts to update identified by their name
    pub hosts: HashMap<String, StorePath>,
    /// The public key the agent should use to verify the update
    pub public_key: String,
    /// The substitutor the agent should use to fetch the update
    pub substitutor: String,
}

request! (
    update_hosts(update: HostUpdateRequest),
    post("/host/update") -> StatusCode,
    body: &update
);
