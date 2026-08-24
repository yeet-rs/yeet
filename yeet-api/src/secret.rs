use std::collections::HashMap;

use base64::prelude::*;
use jiff::fmt::Write;
use rand::prelude::*;
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

    /// length of the generated secret.
    /// Default is 32 bytes
    /// Ignored if format is None
    pub bytes: usize,

    /// Format to generate
    pub format: Option<Format>,
}

impl Secret {
    pub fn is_generated(&self) -> bool {
        self.format.is_some()
    }

    /// create a secret based on the length and format
    #[must_use]
    pub fn generate(&self) -> Option<Vec<u8>> {
        let Some(format) = &self.format else {
            return None;
        };

        // create random data with the specified length
        let mut data = Vec::new();
        data.resize(self.bytes, 0);
        rand::rng().fill_bytes(&mut data);

        // convert the data to the required format
        Some(match format {
            Format::Base64 => BASE64_STANDARD.encode(data).into_bytes(),
            Format::Hex => data
                .iter()
                .flat_map(|byte| format!("{:X}", byte).into_bytes())
                .collect::<Vec<_>>(),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Base64,
    Hex,
}
