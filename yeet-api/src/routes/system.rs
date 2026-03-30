use serde::{Deserialize, Serialize};

use crate::{StorePath, request};

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

request! (
    detach_self(),
    put("/system/self/detach") -> StatusCode
);

request! (
    attach_self(),
    put("/system/self/attach") -> StatusCode
);

request! (
    check_system(version: VersionRequest),
    post("/system/check") -> AgentAction,
    body: &version
);
