use std::collections::HashMap;

use ed25519_dalek::VerifyingKey;

use http::StatusCode;
use httpsig_hyper::prelude::SigningKey;
use url::Url;

use crate::httpsig::{ErrorForJson as _, ReqwestSig as _, ResponseError, sig_param};
use serde::{Deserialize, Serialize};

use crate::StorePath;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "hazard", derive(sqlx::Type))]
#[cfg_attr(feature = "hazard", sqlx(transparent))]
#[serde(transparent)]
pub struct HostID(i64);

impl std::fmt::Display for HostID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(feature = "hazard")]
impl HostID {
    #[must_use]
    pub fn new(id: i64) -> Self {
        Self(id)
    }
}

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

pub async fn list_hosts<K: SigningKey + Sync>(
    url: &Url,
    key: &K,
) -> Result<Vec<Host>, ResponseError> {
    reqwest::Client::new()
        .get(url.join("/host/list")?)
        .sign(&sig_param(key)?, key)
        .await?
        .send()
        .await?
        .error_for_json()
        .await
}

pub async fn rename_host<K: SigningKey + Sync>(
    url: &Url,
    key: &K,
    host: HostID,
    new_name: &str,
) -> Result<StatusCode, ResponseError> {
    reqwest::Client::new()
        .put(url.join(&format!("/host/{host}/rename/{new_name}"))?)
        .sign(&sig_param(key)?, key)
        .await?
        .send()
        .await?
        .error_for_code()
        .await
}

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

pub async fn update_hosts<K: SigningKey + Sync>(
    url: &Url,
    key: &K,
    update: &HostUpdateRequest,
) -> Result<StatusCode, ResponseError> {
    reqwest::Client::new()
        .post(url.join("/host/update")?)
        .json(update)
        .sign(&sig_param(key)?, key)
        .await?
        .send()
        .await?
        .error_for_code()
        .await
}
