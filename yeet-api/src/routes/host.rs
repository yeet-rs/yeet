use std::collections::HashMap;

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
