use std::path::Display;

use ed25519_dalek::VerifyingKey;
use jiff::Zoned;
use serde::{Deserialize, Serialize};

use crate::{ProvisionState, StorePath};

#[derive(Clone, Copy, Debug, sqlx::Type, Deserialize, Serialize, PartialEq, Eq)]
#[sqlx(transparent)]
#[serde(transparent)]
pub struct HostID(i64);

impl std::fmt::Display for HostID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(feature = "hazard")]
impl HostID {
    pub fn new(id: i64) -> Self {
        Self(id)
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
