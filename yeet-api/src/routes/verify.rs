use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::request;

#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationAttempt {
    pub key: VerifyingKey,
    pub nixos_facter: Option<String>,
}

request! (
    add_verification_attempt(attempt: VerificationAttempt),
    post("/verification/add") -> i64,
    body: &attempt
);

request! (
    accept_attempt(id: u32, hostname: &str),
    put("/verification/{id}/accept") -> Option<String>,
    body: hostname
);

request! (
    is_host_verified(),
    get("/system/verify") -> StatusCode
);
