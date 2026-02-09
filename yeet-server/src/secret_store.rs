use std::collections::HashMap;

use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

#[derive(thiserror::Error, Debug, axum_thiserror::ErrorStatus)]
pub enum SecretStoreError {
    #[error("Could not decrypt the secret with the provided Identity")]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    DecryptionError(#[from] age::DecryptError),
    #[error("Could not encryot the secret with the provided Recipient")]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    EncryptError(#[from] age::EncryptError),
}

type Result<T> = core::result::Result<T, SecretStoreError>;

/// Store age encrypted secret with a name. Names have to be unique
/// The idea is that all secrets are encrypted with a single age encryption key
/// Then once a client want to get the secret you call `get_secret_for` which will
/// test if the host is allowed to access the secret and if true will decrypt the
/// secret and re-encrypt it for the host. This ensures encryption at rest and
/// handles ACLs
///
/// A possible hardening method would to instead use a single server key to encrypt the secrets
/// encrypt them with all the hosts that have currently access. The contra is that
/// the all the keys are non ephemeral but then secrets are truly encrypted at rest
/// because an attack would need to also obtain the identity key of a hosts that
/// has access to the secrets
#[derive(Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SecretStore {
    // secret_name -> secret
    secrets: HashMap<String, Vec<u8>>,
    // secret_name -> host
    acl: HashMap<String, Vec<String>>,
}

impl SecretStore {
    pub fn new() -> Self {
        Self {
            secrets: HashMap::new(),
            acl: HashMap::new(),
        }
    }
    /// Add a new secret - `store_key` required to test if it is an actual encrypted secret and not bogus
    pub fn add_secret<I: age::Identity, S: Into<String>, V: Into<Vec<u8>>>(
        &mut self,
        secret_name: S,
        secret: V,
        store_key: &I,
    ) -> Result<()> {
        let secret = secret.into();
        // test if secret is decryptable
        let _: Vec<u8> = age::decrypt(store_key, &secret)?;
        self.secrets.insert(secret_name.into(), secret);
        Ok(())
    }

    /// Security: the caller is responsible to make sure that `recipient` equals `host`
    ///     If this identity is not verified a malicious actor could insert his identity
    ///     and retrieve a secret that is checked by another acl
    ///     This is because each identity is thought to be ephemeral
    /// Prepares a secret for a host by decrypting and the encrypting it
    /// Returns `Ok(None)` if the host is not allowed to access the secret or if the secret does not exist
    pub fn get_secret_for<S: AsRef<str>, R: age::Recipient, I: age::Identity>(
        &self,
        secret: S,
        store_key: &I,
        host: S,
        recipient: &R,
    ) -> Result<Option<Vec<u8>>> {
        if let Some(acl) = self.acl.get(secret.as_ref())
            && acl.contains(&host.as_ref().to_owned())
        {
        } else {
            return Ok(None);
        }
        let Some(secret) = self.secrets.get(secret.as_ref()) else {
            return Ok(None);
        };
        let decrypted = age::decrypt(store_key, secret)?;
        Ok(Some(age::encrypt(recipient, &decrypted)?))
    }

    /// Adds the specified host to the acl of a secret
    pub fn add_access_for<S: Into<String>>(&mut self, secret: S, host: S) {
        self.acl.entry(secret.into()).or_default().push(host.into());
    }

    /// Removes the specified host to the acl of a secret
    pub fn remove_access_for<S: Into<String>>(&mut self, secret: S, host: S) {
        let host = host.into();
        self.acl
            .entry(secret.into())
            .or_default()
            .retain(|h| h != &host);
    }

    /// Overvwrite the whole acl of a secret
    #[cfg(test)]
    fn set_access_for<S: Into<String>>(&mut self, secret: S, hosts: Vec<String>) {
        self.acl.insert(secret.into(), hosts);
    }

    /// Get the acl of a secret
    #[cfg(test)]
    fn get_acl_by_secret<S: AsRef<str>>(&self, secret: S) -> Vec<String> {
        self.acl.get(secret.as_ref()).cloned().unwrap_or(Vec::new())
    }

    /// Get the whole acl
    pub fn get_all_acl(&self) -> HashMap<String, Vec<String>> {
        self.acl.clone()
    }

    /// list secrets
    pub fn list_secrets(&self) -> Vec<String> {
        self.secrets.keys().cloned().collect()
    }

    /// renames the host in all acls
    pub fn rename_host<S: Into<String>>(&mut self, current: S, new: S) {
        let old = current.into();
        let new = new.into();
        for host in self.acl.iter_mut().flat_map(|(_k, acl)| acl.iter_mut()) {
            if host == &old {
                host.clone_from(&new);
            }
        }
    }

    /// renames the host in all acls
    pub fn remove_host<S: Into<String>>(&mut self, host: S) {
        let host = host.into();
        self.acl
            .iter_mut()
            .for_each(|(_k, acl)| acl.retain(|h| h != &host));
    }

    /// Rename a secret including its acl
    pub fn rename_secret<S: Into<String>>(&mut self, current: S, new: S) {
        let old = current.into();
        let new = new.into();
        if let Some(secret) = self.secrets.remove(&old) {
            self.secrets.insert(new.clone(), secret);
        }
        if let Some(acl) = self.acl.remove(&old) {
            self.acl.insert(new, acl);
        }
    }

    /// Delete a secret
    pub fn remove_secret<S: Into<String>>(&mut self, secret: S) {
        let secret = secret.into();
        self.secrets.remove(&secret);
        self.acl.remove(&secret);
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use crate::secret_store::SecretStore;

    #[test]
    fn create_and_retrieve_secret() {
        let store_key = age::x25519::Identity::generate();
        let host = age::x25519::Identity::generate();
        let mut store = SecretStore::new();

        let encrypted = age::encrypt(&store_key.to_public(), b"secret_text").unwrap();

        store
            .add_secret("my_secret", encrypted, &store_key)
            .unwrap();
        store.add_access_for("my_secret", "myhost");
        let encrypted_for_host = store
            .get_secret_for("my_secret", &store_key, "myhost", &host.to_public())
            .unwrap()
            .unwrap();

        let decrypted = age::decrypt(&host, &encrypted_for_host).unwrap();
        assert_eq!(decrypted, b"secret_text");
    }

    #[test]
    fn create_and_retrieve_without_allow() {
        let store_key = age::x25519::Identity::generate();
        let host = age::x25519::Identity::generate();
        let mut store = SecretStore::new();

        let encrypted = age::encrypt(&store_key.to_public(), b"secret_text").unwrap();

        store
            .add_secret("my_secret", encrypted, &store_key)
            .unwrap();
        let secret = store
            .get_secret_for("my_secret", &store_key, "myhost", &host.to_public())
            .unwrap();

        assert!(secret.is_none());
    }

    #[test]
    fn remove_access() {
        let store_key = age::x25519::Identity::generate();
        let host = age::x25519::Identity::generate();
        let mut store = SecretStore::new();

        let encrypted = age::encrypt(&store_key.to_public(), b"secret_text").unwrap();

        store
            .add_secret("my_secret", encrypted, &store_key)
            .unwrap();
        store.add_access_for("my_secret", "myhost");
        let _: Vec<u8> = store
            .get_secret_for("my_secret", &store_key, "myhost", &host.to_public())
            .unwrap()
            .unwrap();

        store.remove_access_for("my_secret", "myhost");

        let secret = store
            .get_secret_for("my_secret", &store_key, "myhost", &host.to_public())
            .unwrap();

        assert!(secret.is_none());
    }

    #[test]
    fn remove_access_set() {
        let store_key = age::x25519::Identity::generate();
        let host = age::x25519::Identity::generate();
        let mut store = SecretStore::new();

        let encrypted = age::encrypt(&store_key.to_public(), b"secret_text").unwrap();

        store
            .add_secret("my_secret", encrypted, &store_key)
            .unwrap();
        store.set_access_for("my_secret", vec!["myhost".to_owned()]);
        let _: Vec<u8> = store
            .get_secret_for("my_secret", &store_key, "myhost", &host.to_public())
            .unwrap()
            .unwrap();

        store.set_access_for("my_secret", vec![]);

        let secret = store
            .get_secret_for("my_secret", &store_key, "myhost", &host.to_public())
            .unwrap();

        assert!(secret.is_none());
    }

    #[test]
    fn getterss() {
        let store_key = age::x25519::Identity::generate();
        let mut store = SecretStore::new();

        let encrypted = age::encrypt(&store_key.to_public(), b"secret_text").unwrap();

        store
            .add_secret("my_secret", encrypted.clone(), &store_key)
            .unwrap();
        store.add_secret("secret2", encrypted, &store_key).unwrap();

        store.set_access_for("my_secret", vec!["myhost".to_owned()]);

        store.set_access_for("secret2", vec!["h1".to_owned(), "h2".to_owned()]);

        assert_eq!(
            store.get_acl_by_secret("my_secret"),
            vec!["myhost".to_owned()]
        );

        assert_eq!(
            store.get_all_acl(),
            HashMap::from([
                ("my_secret".to_owned(), vec!["myhost".to_owned()]),
                ("secret2".to_owned(), vec!["h1".to_owned(), "h2".to_owned()])
            ])
        );

        let mut sorted = store.list_secrets();
        sorted.sort();
        assert_eq!(sorted, vec!["my_secret".to_owned(), "secret2".to_owned()]);
    }

    #[test]
    fn non_encrypted() {
        let store_key = age::x25519::Identity::generate();
        let mut store = SecretStore::new();

        assert!(
            store
                .add_secret("my_secret", b"secret_text", &store_key)
                .is_err()
        );
    }

    #[test]
    fn rename_host() {
        let store_key = age::x25519::Identity::generate();
        let mut store = SecretStore::new();

        let encrypted = age::encrypt(&store_key.to_public(), b"secret_text").unwrap();

        store
            .add_secret("my_secret", encrypted, &store_key)
            .unwrap();
        store.set_access_for("my_secret", vec!["myhost".to_owned()]);

        store.set_access_for("my_secret", vec!["myhost".to_owned()]);
        store.rename_host("myhost", "newhost");

        assert_eq!(
            store.get_acl_by_secret("my_secret"),
            vec!["newhost".to_owned()]
        );
    }

    #[test]
    fn rename_secret() {
        let store_key = age::x25519::Identity::generate();
        let mut store = SecretStore::new();

        let encrypted = age::encrypt(&store_key.to_public(), b"secret_text").unwrap();

        store
            .add_secret("my_secret", encrypted, &store_key)
            .unwrap();
        store.set_access_for("my_secret", vec!["myhost".to_owned()]);

        store.rename_secret("my_secret", "newscret");

        assert!(store.get_acl_by_secret("my_secret").is_empty());
        assert_eq!(
            store.get_acl_by_secret("newscret"),
            vec!["myhost".to_owned()]
        );
    }

    #[test]
    fn remove_secret() {
        let store_key = age::x25519::Identity::generate();
        let mut store = SecretStore::new();

        let encrypted = age::encrypt(&store_key.to_public(), b"secret_text").unwrap();

        store
            .add_secret("my_secret", encrypted, &store_key)
            .unwrap();
        store.set_access_for("my_secret", vec!["myhost".to_owned()]);

        store.remove_secret("my_secret");

        assert!(store.get_acl_by_secret("my_secret").is_empty());
        assert!(store.list_secrets().is_empty());
    }

    #[test]
    fn remove_host() {
        let store_key = age::x25519::Identity::generate();
        let mut store = SecretStore::new();

        let encrypted = age::encrypt(&store_key.to_public(), b"secret_text").unwrap();

        store
            .add_secret("my_secret", encrypted, &store_key)
            .unwrap();
        store.set_access_for("my_secret", vec!["myhost".to_owned()]);

        store.remove_host("myhost");

        assert!(store.get_acl_by_secret("my_secret").is_empty());
    }
}
