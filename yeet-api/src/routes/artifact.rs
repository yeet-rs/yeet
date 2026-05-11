use http::StatusCode;
use httpsig_hyper::prelude::SigningKey;
use serde::{Deserialize, Serialize};

use crate::{
    ErrorForJson as _, HostID, ReqwestSig as _, ResponseError, request, server_age_key, sig_param,
};

crate::db_id!(ArtifactID);

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Hash)]
pub struct Artifact {
    pub id: ArtifactID,
    pub name: String,
    pub host: HostID,
    pub creation_time: jiff::Timestamp,
}

impl std::fmt::Display for Artifact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)?;
        write!(f, "({})", self.id)?;
        write!(f, " - {}", self.host)?;
        write!(f, " created at {}", self.creation_time)
    }
}

request! (
    list_artifacts(),
    get("/artifact") -> Vec<Artifact>
);

#[tracing::instrument(skip(key, artifact), fields(url = %url))]
pub async fn store_artifact<K: SigningKey + Sync>(
    url: &url::Url,
    key: &K,
    name: &str,
    artifact: &[u8],
) -> Result<StatusCode, ResponseError> {
    let recipient: age::x25519::Recipient = {
        let recipient = server_age_key(url, key).await?;

        recipient
            .parse()
            .map_err(|error: &'static str| ResponseError::IdentityError { error })?
    };
    let artifact = age::encrypt(&recipient, artifact)?;

    reqwest::Client::new()
        .post(url.join(&format!("/artifact/store/{name}"))?)
        .json(&artifact)
        .sign(&sig_param(key)?, key)
        .await?
        .send()
        .await?
        .error_for_code()
        .await
}

/// this should only ever be called as a `host`
#[tracing::instrument(skip(key), fields(url = %url))]
pub async fn get_artifact_by_name<K: SigningKey + Sync>(
    url: &url::Url,
    key: &K,
    name: String,
) -> Result<Option<Vec<u8>>, ResponseError> {
    let identity = age::x25519::Identity::generate();

    let response = reqwest::Client::new()
        .post(url.join(&format!("/artifact/name/{name}"))?)
        .json(&identity.to_public().to_string())
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

#[tracing::instrument(skip(key), fields(url = %url))]
pub async fn get_artifact_by_id<K: SigningKey + Sync>(
    url: &url::Url,
    key: &K,
    id: ArtifactID,
) -> Result<Vec<u8>, ResponseError> {
    let identity = age::x25519::Identity::generate();

    let response = reqwest::Client::new()
        .post(url.join(&format!("/artifact/id/{id}"))?)
        .json(&identity.to_public().to_string())
        .sign(&sig_param(key)?, key)
        .await?
        .send()
        .await?
        .error_for_json::<Vec<u8>>()
        .await?;

    Ok(age::decrypt(&identity, &response)?)
}
