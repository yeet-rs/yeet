use std::collections::HashMap;

use base64::prelude::*;
use rand::prelude::*;
use serde::{Deserialize, Serialize};

use crate::eff_large_wordlist::EFF_LARGE_WORDLIST;
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
    #[serde(alias = "bytes")]
    pub length: usize,

    /// Format to generate
    pub format: Option<Format>,

    /// Secret template
    pub template: Option<String>,
}

impl Secret {
    #[must_use]
    pub fn is_generated(&self) -> bool {
        self.format.is_some()
    }

    /// create a secret based on the length and format
    #[must_use]
    pub fn generate(&self) -> Option<Vec<u8>> {
        let Some(format) = &self.format else {
            return None;
        };

        // convert the data to the required format
        Some(match format {
            Format::Base64 => {
                let mut data = vec![0; self.length];
                rand::rng().fill_bytes(&mut data);
                BASE64_STANDARD.encode(data).into_bytes()
            }
            Format::Hex => {
                let mut data = vec![0; self.length];
                rand::rng().fill_bytes(&mut data);
                data.iter()
                    .flat_map(|byte| format!("{byte:X}").into_bytes())
                    .collect::<Vec<_>>()
            }
            Format::Wordlist => {
                let mut wordlist = String::new();
                for _ in 0..self.length {
                    let i = rand::rng().random_range(0..7777);
                    wordlist.push_str(EFF_LARGE_WORDLIST[i]);
                    wordlist.push(' ');
                }
                wordlist.pop(); // remove the last ' '
                wordlist.into_bytes()
            }
        })
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Base64,
    Hex,
    /// Uses the EFF large wordlist
    Wordlist,
}
