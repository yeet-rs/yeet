use httpsig_hyper::prelude::*;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    HostID,
    httpsig::{ErrorForJson as _, ReqwestSig as _, ResponseError, sig_param},
    request, tag,
};

crate::db_id!(SecretID);

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Hash)]
pub struct SecretName {
    pub id: SecretID,
    pub name: String,
    pub tags: Vec<tag::Tag>,
    pub hosts: Vec<HostID>,
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

pub async fn create_secret<K: SigningKey + Sync>(
    url: &Url,
    key: &K,
    name: &str,
    secret: &[u8],
) -> Result<SecretName, ResponseError> {
    let recipient: age::x25519::Recipient = {
        let recipient = server_age_key(&url, key).await?;

        recipient
            .parse()
            .map_err(|error: &'static str| ResponseError::IdentityError { error })?
    };
    let secret = age::encrypt(&recipient, secret)?;

    let response = reqwest::Client::new()
        .post(url.join(&format!("/secret/add/{name}"))?)
        .json(&secret)
        .sign(&sig_param(key)?, key)
        .await?
        .send()
        .await?
        .error_for_json::<SecretName>()
        .await?;
    Ok(response)
}

request! (
    rename_secret(id: SecretID, new_name: &str),
    put("/secret/{id}/rename/{new_name}") -> StatusCode
);

request! (
    delete_secret(id: SecretID),
    delete("/secret/{id}/delete") -> StatusCode
);

request! (
    allow_host(secret: SecretID, host: HostID),
    put("/secret/{secret}/allow/{host}") -> StatusCode
);

request! (
    block_host(secret: SecretID, host: HostID),
    put("/secret/{secret}/block/{host}") -> StatusCode
);

request! (
    list_secrets(),
    get("/secret/list") -> Vec<SecretName>
);

request! (
    server_age_key(),
    get("/secret/server_key") -> String
);

/// This has to do more that a normal fetch so we implement i manually
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
