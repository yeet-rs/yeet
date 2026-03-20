use ed25519_dalek::VerifyingKey;
use http::StatusCode;
use httpsig_hyper::prelude::SigningKey;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::httpsig::{ErrorForJson as _, ReqwestSig as _, ResponseError, sig_param};

#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub struct AddKey {
    pub key: VerifyingKey,
    pub level: AuthLevel,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Copy)]
#[cfg_attr(feature = "hazard", derive(sqlx::Type))]
pub enum AuthLevel {
    Build,
    Admin,
}

pub async fn add_key<K: SigningKey + Sync>(
    url: &Url,
    key: &K,
    add_key: &AddKey,
) -> Result<StatusCode, ResponseError> {
    reqwest::Client::new()
        .post(url.join("/key/add")?)
        .json(add_key)
        .sign(&sig_param(key)?, key)
        .await?
        .send()
        .await?
        .error_for_code()
        .await
}

pub async fn delete_key<K: SigningKey + Sync>(
    url: &Url,
    key: &K,
    delete_key: &VerifyingKey,
) -> Result<StatusCode, ResponseError> {
    reqwest::Client::new()
        .delete(url.join("/key/delete")?)
        .json(delete_key)
        .sign(&sig_param(key)?, key)
        .await?
        .send()
        .await?
        .error_for_code()
        .await
}
