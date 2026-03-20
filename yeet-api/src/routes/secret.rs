use http::StatusCode;
use httpsig_hyper::prelude::*;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    HostID,
    httpsig::{ErrorForJson as _, ReqwestSig as _, ResponseError, sig_param},
};

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "hazard", derive(sqlx::Type))]
#[cfg_attr(feature = "hazard", sqlx(transparent))]
#[serde(transparent)]
pub struct SecretID(i64);

impl std::fmt::Display for SecretID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(feature = "hazard")]
impl SecretID {
    #[must_use]
    pub fn new(id: i64) -> Self {
        Self(id)
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Hash)]
pub struct SecretName {
    pub id: SecretID,
    pub name: String,
}

impl std::fmt::Display for SecretName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GetSecretRequest {
    pub recipient: String,
    pub secret: String,
}

pub async fn add_secret<K: SigningKey + Sync>(
    url: &Url,
    key: &K,
    name: &str,
    secret: &[u8],
) -> Result<SecretName, ResponseError> {
    reqwest::Client::new()
        .post(url.join(&format!("/secret/add/{name}"))?)
        .json(secret)
        .sign(&sig_param(key)?, key)
        .await?
        .send()
        .await?
        .error_for_json()
        .await
}

pub async fn rename_secret<K: SigningKey + Sync>(
    url: &Url,
    key: &K,
    id: SecretID,
    new_name: &str,
) -> Result<StatusCode, ResponseError> {
    reqwest::Client::new()
        .put(url.join(&format!("/secret/{id}/rename/{new_name}"))?)
        .sign(&sig_param(key)?, key)
        .await?
        .send()
        .await?
        .error_for_code()
        .await
}

pub async fn delete_secret<K: SigningKey + Sync>(
    url: &Url,
    key: &K,
    id: SecretID,
) -> Result<StatusCode, ResponseError> {
    reqwest::Client::new()
        .delete(url.join(&format!("/secret/{id}/delete"))?)
        .sign(&sig_param(key)?, key)
        .await?
        .send()
        .await?
        .error_for_code()
        .await
}

pub async fn allow_host<K: SigningKey + Sync>(
    url: &Url,
    key: &K,
    secret: SecretID,
    host: HostID,
) -> Result<StatusCode, ResponseError> {
    reqwest::Client::new()
        .put(url.join(&format!("/secret/{secret}/allow/{host}"))?)
        .sign(&sig_param(key)?, key)
        .await?
        .send()
        .await?
        .error_for_code()
        .await
}

pub async fn block_host<K: SigningKey + Sync>(
    url: &Url,
    key: &K,
    secret: SecretID,
    host: HostID,
) -> Result<StatusCode, ResponseError> {
    reqwest::Client::new()
        .put(url.join(&format!("/secret/{secret}/block/{host}"))?)
        .sign(&sig_param(key)?, key)
        .await?
        .send()
        .await?
        .error_for_code()
        .await
}

pub async fn list_secrets<K: SigningKey + Sync>(
    url: &Url,
    key: &K,
) -> Result<Vec<SecretName>, ResponseError> {
    reqwest::Client::new()
        .get(url.join("/secret/list")?)
        .sign(&sig_param(key)?, key)
        .await?
        .send()
        .await?
        .error_for_json()
        .await
}

pub async fn list_secret_acl<K: SigningKey + Sync>(
    url: &Url,
    key: &K,
) -> Result<Vec<(SecretName, Vec<HostID>)>, ResponseError> {
    reqwest::Client::new()
        .get(url.join("/secret/acl")?)
        .sign(&sig_param(key)?, key)
        .await?
        .send()
        .await?
        .error_for_json()
        .await
}

pub async fn server_age_key<K: SigningKey + Sync>(
    url: &Url,
    key: &K,
) -> Result<String, ResponseError> {
    reqwest::Client::new()
        .get(url.join("/secret/server_key")?)
        .sign(&sig_param(key)?, key)
        .await?
        .send()
        .await?
        .error_for_json()
        .await
}

pub async fn get_secret<K: SigningKey + Sync>(
    url: &Url,
    key: &K,
    name: String,
) -> Result<Option<Vec<u8>>, ResponseError> {
    let identity = age::x25519::Identity::generate();
    let request = GetSecretRequest {
        recipient: identity.to_public().to_string(),
        secret: name,
    };

    let response = reqwest::Client::new()
        .post(url.join("/secret")?)
        .json(&request)
        .sign(&sig_param(key)?, key)
        .await?
        .send()
        .await?
        .error_for_json::<Option<Vec<u8>>>()
        .await?;

    if let Some(ciphertext) = response {
        Ok(Some(age::decrypt(&identity, &ciphertext)?))
    } else {
        Ok(None)
    }
}
