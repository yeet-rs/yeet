use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet, hash_map},
    str::FromStr,
};

use age::secrecy::ExposeSecret as _;
use axum::http::StatusCode;
use axum_thiserror::ErrorStatus;
use ed25519_dalek::VerifyingKey;
use httpsig_hyper::prelude::{AlgorithmName, PublicKey, VerifyingKey as _};
use jiff::{ToSpan as _, Zoned};
use rand::Rng as _;
use serde::{Deserialize, Serialize};
use serde_json_any_key::any_key_map;
use thiserror::Error;

use crate::secret_store::{SecretStore, SecretStoreError};

#[derive(Error, Debug, ErrorStatus)]
pub enum StateError {
    #[error("Key is authenticated but associated host not found")]
    #[status(StatusCode::FORBIDDEN)]
    HostNotFound,

    #[error("The request is authenticated but you lack admin credentials")]
    #[status(StatusCode::FORBIDDEN)]
    AuthMissingAdmin,

    #[error("The request is authenticated but you lack build credentials")]
    #[status(StatusCode::FORBIDDEN)]
    AuthMissingBuild,

    #[error(
        "There are too many open verification attempts - limit the visibility of the server to the network"
    )]
    #[status(StatusCode::REQUEST_TIMEOUT)]
    TooManyVerificationAttempts,

    #[error("Key already in an verification attempt")]
    #[status(StatusCode::BAD_REQUEST)]
    KeyPendingVerification,

    #[error("Provided key is already verified")]
    #[status(StatusCode::BAD_REQUEST)]
    KeyAlreadyInUse,

    #[error("Verification attempt with code {0} not found")]
    #[status(StatusCode::BAD_REQUEST)]
    AttemptNotFound(u32),

    #[error("You have no permission to detach your host")]
    #[status(StatusCode::FORBIDDEN)]
    DetachNotAllowed,

    #[error("Could not decrypt the store key")]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    StoreKeyDecryptionError(&'static str),

    #[error("The provided recipient key is invalid")]
    #[status(StatusCode::BAD_REQUEST)]
    RecipientKeyError(&'static str),

    #[error("Error while accessing the secret store")]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    SecretStoreError(#[from] SecretStoreError),
}

type Result<T> = core::result::Result<T, StateError>;

type Hostname = String;

#[derive(Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AppState {
    admin_credentials: HashSet<VerifyingKey>,
    build_machines_credentials: HashSet<VerifyingKey>,
    // hostname -> Hosts
    hosts: HashMap<Hostname, api::Host>,
    //  keyid -> Key for httpsig
    keyids: HashMap<String, VerifyingKey>,
    // Maps key to the hostname
    #[serde(with = "any_key_map")]
    host_by_key: HashMap<VerifyingKey, Hostname>,
    // 6 digit number -> unverified pub key
    verification_attempt: HashMap<u32, (api::VerificationAttempt, Zoned)>,
    // Should hosts be allowed to detach by themself in general
    detach_allowed: bool,
    // Secrets encrypted with `server_key`
    #[serde(default)]
    secrets: SecretStore,
    // Server key used for response signatures (TODO), certificate pinning (TODO) and for secret decryption
    #[serde(default = "create_age_identity")]
    age_identity: String,
}

fn create_age_identity() -> String {
    age::x25519::Identity::generate()
        .to_string()
        .expose_secret()
        .to_string()
}

impl AppState {
    #[expect(unused_must_use)]
    fn drain_verification_attempts(&mut self) {
        self.verification_attempt.extract_if(|_key, (_kv, time)| {
            matches!(
                (&Zoned::now() - &*time).abs().compare(15.minutes()),
                Ok(Ordering::Greater)
            )
        });
    }

    /// Agent want to authenticate so he sends a request
    /// This can be approved by an admin with `verify_attempt`
    pub fn add_verification_attempt(&mut self, attempt: api::VerificationAttempt) -> Result<u32> {
        self.drain_verification_attempts();
        if self.verification_attempt.len() >= 10 {
            return Err(StateError::TooManyVerificationAttempts);
        }

        // check if key already exists
        if self
            .verification_attempt
            .values()
            .any(|(k, _z)| k.key == attempt.key)
        {
            return Err(StateError::KeyPendingVerification);
        }

        // check if key already is in registered keys
        if self.keyids.values().any(|key| key == &attempt.key) {
            return Err(StateError::KeyAlreadyInUse);
        }

        // attempt is safe to add -> create a random number
        let verification = rand::rng().random_range(100_000..=999_999);

        self.verification_attempt
            .insert(verification, (attempt, Zoned::now()));

        Ok(verification)
    }

    /// Verify an existing verification attempt
    /// Host needs to be pre-register
    pub fn verify_attempt(
        &mut self,
        acceptance: api::VerificationAcceptance,
    ) -> Result<api::VerificationArtifacts> {
        self.drain_verification_attempts();

        let (attempt, first_ping) = self
            .verification_attempt
            .remove(&acceptance.code)
            .ok_or(StateError::AttemptNotFound(acceptance.code))?;

        let signing_key = PublicKey::from_bytes(AlgorithmName::Ed25519, attempt.key.as_bytes())
            .expect("Verifying key already is validated");

        self.host_by_key
            .insert(attempt.key, acceptance.hostname.clone());
        self.hosts.insert(
            acceptance.hostname.clone(),
            api::Host {
                name: acceptance.hostname,
                last_ping: first_ping.clone(),
                provision_state: api::ProvisionState::NotSet,
                version_history: vec![(attempt.store_path, first_ping)],
                detach_allowed: None,
            },
        );
        self.keyids.insert(signing_key.key_id(), attempt.key);
        Ok(attempt.artifacts)
    }

    /// This is the "ping" command every client should send in a specific interval.
    /// Based on the provision state and the last known version this function takes different parts
    ///
    /// `host.latest_store_path()`
    /// `host.provision_state`
    ///
    /// `host.last_ping` = `Zoned::now`
    ///
    /// ====== if `host.provision_state` == Provisioned
    ///
    /// # this is the path when the client did the update
    /// # if "host version is behind but sent version and provision version match"
    /// if `host.latest_store_path()` != `store_path` and `store_path` == `host.provision_state`
    ///     `host.version_history.insert(store_path`, `Zoned::now`)
    ///     -> Nothing
    ///
    /// # this is the path when the client gets notified of an update
    /// # if "host AND sent version is behind but server version is different"
    /// but because there could be a race condition e.g. Update1(v1) -> client does update1 in this time server gets Update2
    /// therefore we need to check if sent version is behind server version
    /// if `host.latest_store_path()` == `store_path` && `host.latest_store_path()` != `host.provision_state`
    ///     -> `SwitchTo(host.provision_state)`
    ///
    /// # Lastly if all 3 are the same do nothing
    /// -> Nothing
    ///
    /// ====== if `host.provision_state` == Detached
    ///
    /// # check if `store_path` is the same as `host.latest_store_path()` if not the update `host.latest_store_path()`
    /// -> Detach
    ///
    /// ====== if `host.provision_state` == `NotSet`
    /// -> Nothing
    pub fn system_check(
        &mut self,
        store_path: String,
        key: &VerifyingKey,
    ) -> Result<api::AgentAction> {
        let hostname = self.host_by_key.get(key).ok_or(StateError::HostNotFound)?;
        let host = self
            .hosts
            .get_mut(hostname)
            .ok_or(StateError::HostNotFound)?;

        let action = match host.provision_state.clone() {
            api::ProvisionState::NotSet => api::AgentAction::Nothing,
            // Host is detached -> only updated the latest version
            api::ProvisionState::Detached(_) => {
                if host.latest_store_path() != &store_path {
                    host.update_store_path(store_path);
                }
                api::AgentAction::Detach
            }

            api::ProvisionState::Provisioned(version) => {
                // Host has completed an update -> update last seen store path
                if &store_path != host.latest_store_path() {
                    host.update_store_path(store_path.clone());
                }
                // Host is on the newest version
                if store_path == version.store_path {
                    api::AgentAction::Nothing
                } else {
                    // Host needs to update
                    // TODO: we do not see if we updated fast in succession we only see the latest
                    api::AgentAction::SwitchTo(version.clone())
                }
            }
        };

        host.ping();

        Ok(action)
    }

    /// Endpoint to set a new version for a host.
    /// The whole request needs to be signed by a build machine.
    /// The update consist of a simple `name` -> `version` and a `substitutor` which is where the agent should get its update
    /// This means that for each origin e.g. cachix, you need to call update seperately
    pub fn update_hosts(
        &mut self,
        mut hosts: HashMap<String, api::StorePath>,
        public_key: String,
        substitutor: String,
        netrc: Option<String>,
    ) {
        let _unknown_hosts = hosts
            .extract_if(|name, _store| !self.hosts.contains_key(name))
            .collect::<HashMap<String, api::StorePath>>();

        for (name, store_path) in hosts {
            let host = self
                .hosts
                .get_mut(&name)
                .expect("Race condition because we checked above - maybe change this TOCTOU");
            let version = api::RemoteStorePath {
                store_path: store_path.clone(),
                substitutor: substitutor.clone(),
                public_key: public_key.clone(),
                netrc: netrc.clone(),
            };

            host.push_update(version);
        }
    }

    pub fn auth_build(&self, key: &VerifyingKey) -> Result<()> {
        if self.admin_credentials.contains(key) || self.build_machines_credentials.contains(key) {
            Ok(())
        } else {
            Err(StateError::AuthMissingBuild)
        }
    }

    pub fn auth_admin(&self, key: &VerifyingKey) -> Result<()> {
        if self.admin_credentials.contains(key) {
            Ok(())
        } else {
            Err(StateError::AuthMissingAdmin)
        }
    }

    pub(crate) fn hosts(&self) -> hash_map::Values<'_, String, api::Host> {
        self.hosts.values()
    }

    pub(crate) fn hosts_by_key(&self) -> HashMap<Hostname, VerifyingKey> {
        self.host_by_key
            .clone()
            .into_iter()
            .map(|(k, v)| (v, k))
            .collect()
    }

    pub fn add_key(&mut self, key: VerifyingKey, level: api::AuthLevel) {
        let signing_key = PublicKey::from_bytes(AlgorithmName::Ed25519, key.as_bytes())
            .expect("Could not convert ED25519 key to httpsig key - wtf");
        if level == api::AuthLevel::Admin {
            self.admin_credentials.insert(key);
        } else {
            self.build_machines_credentials.insert(key);
        }
        self.keyids.insert(signing_key.key_id(), key);
    }

    pub fn remove_key(&mut self, key: &VerifyingKey) {
        let signing_key = PublicKey::from_bytes(AlgorithmName::Ed25519, key.as_bytes())
            .expect("Could not convert ED25519 key to httpsig key - wtf");
        self.admin_credentials.remove(key);
        self.build_machines_credentials.remove(key);
        self.host_by_key.remove(key);
        self.keyids.remove(&signing_key.key_id());
    }

    pub fn remove_host(&mut self, hostname: &Hostname) -> Result<api::Host> {
        let host = self
            .hosts
            .remove(hostname)
            .ok_or(StateError::HostNotFound)?;

        let keys = self.host_by_key.extract_if(|_key, name| name == hostname);

        for (key, _hostname) in keys {
            let _ = self.keyids.extract_if(|_id, k| k == &key);
        }

        self.secrets.remove_host(hostname);

        Ok(host)
    }

    pub fn rename_host(&mut self, old_name: &Hostname, new_name: Hostname) -> Result<()> {
        let mut host = self
            .hosts
            .remove(old_name)
            .ok_or(StateError::HostNotFound)?;
        host.name.clone_from(&new_name); // Make sure the two names are the same
        self.hosts.insert(new_name.clone(), host);

        if let Some((_key, hostname)) = self
            .host_by_key
            .iter_mut()
            .find(|(_key, name)| *name == old_name)
        {
            hostname.clone_from(&new_name);
        }
        self.secrets.rename_host(old_name.clone(), new_name);

        Ok(())
    }

    pub fn set_global_detach_permission(&mut self, allowed: bool) {
        self.detach_allowed = allowed;
    }

    pub fn get_global_detach_permission(&self) -> bool {
        self.detach_allowed
    }

    pub fn set_detach_permissions(&mut self, hosts: Vec<(Hostname, bool)>) {
        for (hostname, allowed) in hosts {
            let Some(host) = self.hosts.get_mut(&hostname) else {
                continue;
            };
            host.detach_allowed = Some(allowed);
        }
    }

    pub fn is_detach_allowed(&self, key: &VerifyingKey) -> Result<bool> {
        let host = {
            let hostname = self.host_by_key.get(key).ok_or(StateError::HostNotFound)?;
            self.hosts.get(hostname).ok_or(StateError::HostNotFound)?
        };

        Ok(host.detach_allowed.unwrap_or(self.detach_allowed))
    }

    pub fn detach_self(&mut self, key: &VerifyingKey) -> Result<()> {
        let host = {
            let hostname = self.host_by_key.get(key).ok_or(StateError::HostNotFound)?;
            self.hosts
                .get_mut(hostname)
                .ok_or(StateError::HostNotFound)?
        };

        {
            let allowed = host.detach_allowed.unwrap_or(self.detach_allowed);

            if !allowed {
                return Err(StateError::DetachNotAllowed);
            }
        };

        host.detach();
        Ok(())
    }

    // Warning: This should only ever be called by admins because it will bypass detach permissions
    pub fn detach_host(&mut self, hostname: &Hostname) -> Result<()> {
        let host = self
            .hosts
            .get_mut(hostname)
            .ok_or(StateError::HostNotFound)?;

        host.detach();
        Ok(())
    }

    pub fn attach_self(&mut self, key: &VerifyingKey) -> Result<()> {
        let host = {
            let hostname = self.host_by_key.get(key).ok_or(StateError::HostNotFound)?;
            self.hosts
                .get_mut(hostname)
                .ok_or(StateError::HostNotFound)?
        };

        host.attach();
        Ok(())
    }

    pub fn attach_host(&mut self, hostname: &Hostname) -> Result<()> {
        let host = self
            .hosts
            .get_mut(hostname)
            .ok_or(StateError::HostNotFound)?;

        host.attach();
        Ok(())
    }

    pub fn has_admin_credential(&self) -> bool {
        !self.admin_credentials.is_empty()
    }

    pub fn get_key_by_id<S: AsRef<str>>(&self, keyid: S) -> Option<VerifyingKey> {
        self.keyids.get(keyid.as_ref()).copied()
    }

    pub fn add_secret<S: Into<String>, V: Into<Vec<u8>>>(
        &mut self,
        name: S,
        secret: V,
    ) -> Result<()> {
        let store_key = age::x25519::Identity::from_str(&self.age_identity)
            .map_err(StateError::StoreKeyDecryptionError)?;
        self.secrets.add_secret(name, secret, &store_key)?;
        Ok(())
    }

    pub fn rename_secret<S: Into<String>>(&mut self, current_name: S, new_name: S) {
        self.secrets.rename_secret(current_name, new_name);
    }
    pub fn remove_secret<S: Into<String>>(&mut self, secret_name: S) {
        self.secrets.remove_secret(secret_name);
    }

    pub fn secret_add_access_for<S: Into<String>>(&mut self, secret: S, host: S) {
        self.secrets.add_access_for(secret, host);
    }
    pub fn secret_remove_access_for<S: Into<String>>(&mut self, secret: S, host: S) {
        self.secrets.remove_access_for(secret, host);
    }
    pub fn get_all_acl(&self) -> HashMap<String, Vec<String>> {
        self.secrets.get_all_acl()
    }
    pub fn list_secrets(&self) -> Vec<String> {
        self.secrets.list_secrets()
    }
    pub fn get_server_recipient(&self) -> Result<String> {
        Ok(age::x25519::Identity::from_str(&self.age_identity)
            .map_err(StateError::StoreKeyDecryptionError)?
            .to_public()
            .to_string())
    }
    pub fn get_secret(
        &self,
        secret: String,
        recipient: String,
        key: &VerifyingKey,
    ) -> Result<Option<Vec<u8>>> {
        let store_key = age::x25519::Identity::from_str(&self.age_identity)
            .map_err(StateError::StoreKeyDecryptionError)?;

        let recipient =
            age::x25519::Recipient::from_str(&recipient).map_err(StateError::RecipientKeyError)?;

        let hostname = self.host_by_key.get(key).ok_or(StateError::HostNotFound)?;

        Ok(self
            .secrets
            .get_secret_for(&secret, &store_key, hostname, &recipient)?)
    }
}
