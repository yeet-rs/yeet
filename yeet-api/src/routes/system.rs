use http::StatusCode;
use httpsig_hyper::prelude::SigningKey;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::StorePath;
use crate::httpsig::{ErrorForJson as _, ReqwestSig as _, ResponseError, sig_param};

// Action the server want the client to take

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum AgentAction {
    Nothing,
    Detach,
    SwitchTo(RemoteStorePath),
}

impl Default for AgentAction {
    #[inline]
    fn default() -> Self {
        Self::Nothing
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct VersionRequest {
    pub store_path: StorePath,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
/// Represents a Version
/// Each Version can have its own nix cache
pub struct RemoteStorePath {
    /// The public key the cache uses to sign the store path
    pub public_key: String,
    /// The store path to fetch from the nix cache
    pub store_path: StorePath,
    /// The substitutor (nix cache) to fetch the store path from
    pub substitutor: String,
}

pub async fn detach_self<K: SigningKey + Sync>(
    url: &Url,
    key: &K,
) -> Result<StatusCode, ResponseError> {
    reqwest::Client::new()
        .put(url.join("/system/self/detach")?)
        .sign(&sig_param(key)?, key)
        .await?
        .send()
        .await?
        .error_for_code()
        .await
}

pub async fn attach_self<K: SigningKey + Sync>(
    url: &Url,
    key: &K,
) -> Result<StatusCode, ResponseError> {
    reqwest::Client::new()
        .put(url.join("/system/self/attach")?)
        .sign(&sig_param(key)?, key)
        .await?
        .send()
        .await?
        .error_for_code()
        .await
}

pub async fn check_system<K: SigningKey + Sync>(
    url: &Url,
    key: &K,
    version: &VersionRequest,
) -> Result<AgentAction, ResponseError> {
    reqwest::Client::new()
        .post(url.join("/system/check")?)
        .json(version)
        .sign(&sig_param(key)?, key)
        .await?
        .send()
        .await?
        .error_for_json()
        .await
}
