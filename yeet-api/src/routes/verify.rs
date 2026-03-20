use ed25519_dalek::VerifyingKey;
use http::StatusCode;
use httpsig_hyper::prelude::*;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::httpsig::{ErrorForJson as _, ReqwestSig as _, ResponseError, sig_param};

#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationAttempt {
    pub key: VerifyingKey,
    pub nixos_facter: Option<String>,
}

pub async fn add_verification_attempt(
    url: &Url,
    attempt: &VerificationAttempt,
) -> Result<i64, ResponseError> {
    reqwest::Client::new()
        .post(url.join("/verification/add")?)
        .json(attempt)
        .send()
        .await?
        .error_for_json()
        .await
}

pub async fn accept_attempt<K: SigningKey + Sync>(
    url: &Url,
    key: &K,
    id: u32,
    hostname: &str,
) -> Result<Option<String>, ResponseError> {
    reqwest::Client::new()
        .put(url.join(&format!("/verification/{id}/accept"))?)
        .json(hostname)
        .sign(&sig_param(key)?, key)
        .await?
        .send()
        .await?
        .error_for_json()
        .await
}

pub async fn is_host_verified<K: SigningKey + Sync>(
    url: &Url,
    key: &K,
) -> Result<StatusCode, ResponseError> {
    Ok(reqwest::Client::new()
        .get(url.join("/system/verify")?)
        .sign(&sig_param(key)?, key)
        .await?
        .send()
        .await?
        .status())
}
