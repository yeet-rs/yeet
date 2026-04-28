use ed25519_dalek::VerifyingKey;
use http::StatusCode;
use httpsig_hyper::prelude::SigningKey;
use serde::{Deserialize, Serialize};

use crate::{ReqwestSig as _, ResponseError, request, sig_param};

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

pub async fn is_host_verified<K: SigningKey + Sync>(
    url: &url::Url,
    key: &K,
) -> Result<StatusCode, ResponseError> {
    Ok(reqwest::Client::new()
        .get(url.join("/verification/check")?)
        .sign(&sig_param(key)?, key)
        .await?
        .send()
        .await?
        .status())
}
