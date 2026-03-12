use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationAttempt {
    pub key: VerifyingKey,
    pub nixos_facter: Option<String>,
}
