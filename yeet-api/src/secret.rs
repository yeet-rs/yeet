use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// The key is the name of the Secret, not to be confused with `Secret.name`
pub type Secrets = HashMap<String, Secret>;

#[derive(Debug, Serialize, Deserialize)]
pub struct Secret {
    /// this is not the name of the Secret. This is the name of the file
    /// Name of the file used in `yeet.secretsDir`
    pub name: String,

    /// Path where the decrypted secret is installed.
    pub path: String,

    /// Permissions mode of the decrypted secret in a format understood by chmod.
    pub mode: String,

    /// User of the decrypted secret.
    pub owner: String,

    /// Group of the decrypted secret.
    pub group: String,

    /// symlinking secrets to their destination
    /// Else they get copied to their destination
    pub symlink: bool,
}
