//! API for yeet

use std::collections::HashMap;

use ed25519_dalek::VerifyingKey;
use jiff::Zoned;
use serde::{Deserialize, Serialize};

pub mod httpsig;
pub mod key;
pub mod secret;
pub mod status;

pub type StorePath = String;

mod routes {
    pub mod secret;
}

pub mod auth;
pub use routes::secret::*;
pub use secret::*;

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Represents a Host Update Request
/// The Agent uses the substitutor to fetch the update via nix
#[expect(
    clippy::exhaustive_structs,
    reason = "API Structs should be breaking change"
)]
pub struct HostUpdateRequest {
    /// The hosts to update identified by their name
    pub hosts: HashMap<String, StorePath>,
    /// The public key the agent should use to verify the update
    pub public_key: String,
    /// The substitutor the agent should use to fetch the update
    pub substitutor: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Delete a host
pub struct HostRemoveRequest {
    pub hostname: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Rename
pub struct HostRenameRequest {
    pub current_name: String,
    pub new_name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
/// Represents a Version
/// Each Version can have its own nix cache
#[expect(
    clippy::exhaustive_structs,
    reason = "API Structs should be breaking change"
)]
pub struct RemoteStorePath {
    /// The public key the cache uses to sign the store path
    pub public_key: String,
    /// The store path to fetch from the nix cache
    pub store_path: StorePath,
    /// The substitutor (nix cache) to fetch the store path from
    pub substitutor: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationAttempt {
    pub key: VerifyingKey,
    pub store_path: StorePath,
    pub artifacts: VerificationArtifacts,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationArtifacts {
    pub nixos_facter: Option<String>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationAcceptance {
    pub code: u32,
    pub hostname: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub struct AddKey {
    pub key: VerifyingKey,
    pub level: AuthLevel,
}

#[expect(clippy::exhaustive_structs)]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Copy)]
pub enum AuthLevel {
    Build,
    Admin,
}

// values that are needed at start:
// - name
// possible states: (we need to track 3 different states) key state, server state, client state
//
// key: nothing | set
// server: nothing | version | detached
// client: nothing | version
//
//
// client.version requires key.set
// key.set requires client.version
//
//
// (key.nothing, client.nothing, server.nothing | server.version | server.detached)
// (key.set, client.version, server.nothing | server.version | server.detached)
//
// a struct with the following maps represets all possible states
//
// name -> key
// name -> server.state
// key -> client.state
//
// the requirements that a host (name) cannot have a client.state without a key is upheld
// Further there are no shenanigans between the states. A consumer now gets the client state and it is either there or not
//
// And now we can even remove the name because that is now just extra information
// We only need the following association key -> id
// but key is not available at the start so we require name and bind and id to it
// Id is a word with many prejudice so lets use handle
//
// key -> handle
// handle -> server.state
// key -> client.state
//
//
// new_key_type! { struct HostHandle; }
// Everything that a host should only ever have once provisioned is stored under a KeyHandle
// Things that are extra information and should always be accessible are under the HostHandle
// pub struct Hosts {
//     keyids: HashMap<String, VerifyingKey>, // These are registred keys used by httpsig - we need a hashmap because we have no way to store a handle - keyid is derived

//     keys: SlotMap<HostHandle, VerifyingKey>,
//     client_state: SecondaryMap<HostHandle, Vec<(StorePath, Zoned)>>, // Client should only have a state with a key
//     last_ping: SecondaryMap<HostHandle, Option<Zoned>>,
//     server_state: SecondaryMap<HostHandle, ServerState>,
//     names: SecondaryMap<HostHandle, String>,

//     unregistered: Vec<String>,
// }

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct Host {
    pub name: String,
    pub last_ping: Zoned,
    pub provision_state: ProvisionState,
    // Version with date when the update occured
    pub version_history: Vec<(StorePath, Zoned)>,
    pub detach_allowed: Option<bool>,
}

impl Host {
    #[must_use]
    pub fn latest_store_path(&self) -> &StorePath {
        &self
            .version_history
            .last()
            .expect("version_history cannot be empty")
            .0
    }
    pub fn update_store_path(&mut self, store_path: String) {
        self.version_history.push((store_path, Zoned::now()));
    }

    pub fn push_update(&mut self, version: RemoteStorePath) {
        if self.is_provisioned() || self.is_notset() {
            self.provision_state = ProvisionState::Provisioned(version);
        } else if self.is_detached() {
            self.provision_state = ProvisionState::Detached(version)
        }
    }

    pub fn detach(&mut self) {
        if let ProvisionState::Provisioned(version) = &self.provision_state {
            self.provision_state = ProvisionState::Detached(version.clone());
        }
    }

    pub fn attach(&mut self) {
        if let ProvisionState::Detached(version) = &self.provision_state {
            self.provision_state = ProvisionState::Provisioned(version.clone());
        }
    }

    pub fn ping(&mut self) {
        self.last_ping = Zoned::now();
    }

    // pub fn provision_store_path(&self) -> Option<&String> {
    //     match self.provision_state {
    //         ProvisionState::NotSet | ProvisionState::Detached => None,
    //         ProvisionState::Provisioned(ref store_path) => Some(store_path),
    //     }
    // }

    #[must_use]
    pub fn is_detached(&self) -> bool {
        match self.provision_state {
            ProvisionState::NotSet | ProvisionState::Provisioned(_) => false,
            ProvisionState::Detached(_) => true,
        }
    }

    #[must_use]
    pub fn is_provisioned(&self) -> bool {
        match self.provision_state {
            ProvisionState::Provisioned(_) => true,
            ProvisionState::NotSet | ProvisionState::Detached(_) => false,
        }
    }

    #[must_use]
    pub fn is_notset(&self) -> bool {
        match self.provision_state {
            ProvisionState::Provisioned(_) | ProvisionState::Detached(_) => false,
            ProvisionState::NotSet => true,
        }
    }
}

// State the Server wants the client to be in
#[expect(clippy::exhaustive_structs)]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum ProvisionState {
    NotSet,
    Detached(RemoteStorePath),
    Provisioned(RemoteStorePath),
}

impl ProvisionState {
    pub fn store_path(&self) -> Option<&StorePath> {
        match self {
            ProvisionState::Provisioned(remote_store_path) => Some(&remote_store_path.store_path),
            _ => None,
        }
    }
}

impl Default for ProvisionState {
    #[inline]
    fn default() -> Self {
        Self::NotSet
    }
}

// Action the server want the client to take
#[expect(clippy::exhaustive_structs)]
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
#[expect(clippy::exhaustive_structs)]
pub struct VersionRequest {
    pub store_path: StorePath,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum SetDetachPermission {
    Global(bool),
    PerHost(Vec<(String, bool)>),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum DetachAction {
    DetachSelf,
    // DetachHost(String),
    AttachSelf,
    AttachHost(String),
}

#[inline]
pub fn hash(value: impl std::hash::Hash) -> u64 {
    ahash::RandomState::with_seeds(1, 2, 3, 4).hash_one(value)
}

#[inline]
pub fn hash_hex(value: impl std::hash::Hash) -> String {
    format!("{:x}", hash(value))
}
