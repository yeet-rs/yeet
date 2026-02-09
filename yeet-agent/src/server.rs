use std::sync::LazyLock;

use api::httpsig::ReqwestSig as _;
use http::StatusCode;
use httpsig_hyper::prelude::*;
use reqwest::{Client, Response};
use rootcause::{Report, report};
use serde::de::DeserializeOwned;
use url::Url;

#[expect(clippy::expect_used, reason = "Is there another way?")]
static COMPONENTS: LazyLock<Vec<message_component::HttpMessageComponentId>> = LazyLock::new(|| {
    ["date", "@path", "@method", "content-digest"]
        .iter()
        .map(|component| message_component::HttpMessageComponentId::try_from(*component))
        .collect::<Result<Vec<_>, _>>()
        .expect("Could not create HTTP Signature components")
});

pub async fn status<K: SigningKey + Sync>(url: &Url, key: &K) -> Result<Vec<api::Host>, Report> {
    Client::new()
        .get(url.join("/status")?)
        .sign(&sig_param(key)?, key)
        .await?
        .send()
        .await?
        .error_for_json()
        .await
}

pub mod key {
    use api::httpsig::ReqwestSig as _;
    use http::StatusCode;
    use httpsig_hyper::prelude::*;
    use reqwest::Client;
    use rootcause::Report;
    use url::Url;

    use crate::server::{ErrorForJson as _, sig_param};

    pub async fn add_key<K: SigningKey + Sync>(
        url: &Url,
        key: &K,
        add_key: &api::AddKey,
    ) -> Result<StatusCode, Report> {
        Client::new()
            .post(url.join("/key/add")?)
            .json(add_key)
            .sign(&sig_param(key)?, key)
            .await?
            .send()
            .await?
            .error_for_code()
            .await
    }

    pub async fn remove_key<K: SigningKey + Sync>(
        url: &Url,
        key: &K,
        remove_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<StatusCode, Report> {
        Client::new()
            .post(url.join("/key/remove")?)
            .json(remove_key)
            .sign(&sig_param(key)?, key)
            .await?
            .send()
            .await?
            .error_for_code()
            .await
    }
}

pub mod host {
    use api::httpsig::ReqwestSig as _;
    use http::StatusCode;
    use httpsig_hyper::prelude::*;
    use reqwest::Client;
    use rootcause::Report;
    use url::Url;

    use crate::server::{ErrorForJson as _, sig_param};

    pub async fn remove_host<K: SigningKey + Sync>(
        url: &Url,
        key: &K,
        request: &api::HostRemoveRequest,
    ) -> Result<api::Host, Report> {
        Client::new()
            .post(url.join("/host/remove")?)
            .json(request)
            .sign(&sig_param(key)?, key)
            .await?
            .send()
            .await?
            .error_for_json()
            .await
    }

    pub async fn rename_host<K: SigningKey + Sync>(
        url: &Url,
        key: &K,
        request: &api::HostRenameRequest,
    ) -> Result<StatusCode, Report> {
        Client::new()
            .post(url.join("/host/rename")?)
            .json(request)
            .sign(&sig_param(key)?, key)
            .await?
            .send()
            .await?
            .error_for_code()
            .await
    }
}
pub mod system {

    use api::httpsig::ReqwestSig as _;
    use http::StatusCode;
    use httpsig_hyper::prelude::*;
    use reqwest::Client;
    use rootcause::Report;
    use url::Url;

    use crate::server::{ErrorForJson as _, sig_param};

    pub async fn check<K: SigningKey + Sync>(
        url: &Url,
        key: &K,
        version: &api::VersionRequest,
    ) -> Result<api::AgentAction, Report> {
        Client::new()
            .post(url.join("/system/check")?)
            .json(version)
            .sign(&sig_param(key)?, key)
            .await?
            .send()
            .await?
            .error_for_json()
            .await
    }

    pub async fn update<K: SigningKey + Sync>(
        url: &Url,
        key: &K,
        host_update_request: &api::HostUpdateRequest,
    ) -> Result<StatusCode, Report> {
        Client::new()
            .post(url.join("/system/update")?)
            .json(host_update_request)
            .sign(&sig_param(key)?, key)
            .await?
            .send()
            .await?
            .error_for_code()
            .await
    }

    pub async fn is_host_verified<K: SigningKey + Sync>(
        url: &Url,
        key: &K,
    ) -> Result<StatusCode, Report> {
        Ok(Client::new()
            .get(url.join("/system/verify")?)
            .sign(&sig_param(key)?, key)
            .await?
            .send()
            .await?
            .status())
    }

    pub async fn add_verification_attempt(
        url: &Url,
        attempt: &api::VerificationAttempt,
    ) -> Result<u32, Report> {
        Client::new()
            .post(url.join("/system/verify")?)
            .json(attempt)
            .send()
            .await?
            .error_for_json()
            .await
    }

    pub async fn verify_attempt<K: SigningKey + Sync>(
        url: &Url,
        key: &K,
        acceptance: &api::VerificationAcceptance,
    ) -> Result<api::VerificationArtifacts, Report> {
        Client::new()
            .post(url.join("/system/verify/accept")?)
            .json(acceptance)
            .sign(&sig_param(key)?, key)
            .await?
            .send()
            .await?
            .error_for_json()
            .await
    }

    pub async fn detach<K: SigningKey + Sync>(
        url: &Url,
        key: &K,
        detach: &api::DetachAction,
    ) -> Result<StatusCode, Report> {
        Client::new()
            .post(url.join("/system/detach")?)
            .json(detach)
            .sign(&sig_param(key)?, key)
            .await?
            .send()
            .await?
            .error_for_code()
            .await
    }

    pub async fn detach_permission<K: SigningKey + Sync>(
        url: &Url,
        key: &K,
    ) -> Result<bool, Report> {
        Client::new()
            .get(url.join("/system/detach/permission")?)
            .sign(&sig_param(key)?, key)
            .await?
            .send()
            .await?
            .error_for_json()
            .await
    }
}

pub mod detach {
    use api::httpsig::ReqwestSig as _;
    use http::StatusCode;
    use httpsig_hyper::prelude::*;
    use reqwest::Client;
    use rootcause::Report;
    use url::Url;

    use crate::server::{ErrorForJson as _, sig_param};

    pub async fn set_detach_permission<K: SigningKey + Sync>(
        url: &Url,
        key: &K,
        permission: &api::SetDetachPermission,
    ) -> Result<StatusCode, Report> {
        Client::new()
            .post(url.join("/detach/permission")?)
            .json(permission)
            .sign(&sig_param(key)?, key)
            .await?
            .send()
            .await?
            .error_for_code()
            .await
    }

    pub async fn get_detach_permission<K: SigningKey + Sync>(
        url: &Url,
        key: &K,
    ) -> Result<bool, Report> {
        Client::new()
            .get(url.join("/detach/permission")?)
            .sign(&sig_param(key)?, key)
            .await?
            .send()
            .await?
            .error_for_json()
            .await
    }
}

pub mod secret {
    use std::collections::HashMap;

    use api::httpsig::ReqwestSig as _;
    use http::StatusCode;
    use httpsig_hyper::prelude::*;
    use reqwest::Client;
    use rootcause::Report;
    use url::Url;

    use crate::server::{ErrorForJson as _, sig_param};

    pub async fn get_secret<K: SigningKey + Sync>(
        url: &Url,
        key: &K,
        secret: &api::GetSecretRequest,
    ) -> Result<Option<Vec<u8>>, Report> {
        Client::new()
            .post(url.join("/secret")?)
            .json(secret)
            .sign(&sig_param(key)?, key)
            .await?
            .send()
            .await?
            .error_for_json()
            .await
    }

    pub async fn add_secret<K: SigningKey + Sync>(
        url: &Url,
        key: &K,
        secret: &api::AddSecretRequest,
    ) -> Result<StatusCode, Report> {
        Client::new()
            .post(url.join("/secret/add")?)
            .json(secret)
            .sign(&sig_param(key)?, key)
            .await?
            .send()
            .await?
            .error_for_code()
            .await
    }

    pub async fn rename_secret<K: SigningKey + Sync>(
        url: &Url,
        key: &K,
        secret: &api::RenameSecretRequest,
    ) -> Result<StatusCode, Report> {
        Client::new()
            .post(url.join("/secret/rename")?)
            .json(secret)
            .sign(&sig_param(key)?, key)
            .await?
            .send()
            .await?
            .error_for_code()
            .await
    }

    pub async fn remove_secret<K: SigningKey + Sync>(
        url: &Url,
        key: &K,
        secret: &api::RemoveSecretRequest,
    ) -> Result<StatusCode, Report> {
        Client::new()
            .post(url.join("/secret/remove")?)
            .json(secret)
            .sign(&sig_param(key)?, key)
            .await?
            .send()
            .await?
            .error_for_code()
            .await
    }

    pub async fn acl<K: SigningKey + Sync>(
        url: &Url,
        key: &K,
        acl: &api::AclSecretRequest,
    ) -> Result<StatusCode, Report> {
        Client::new()
            .post(url.join("/secret/acl")?)
            .json(acl)
            .sign(&sig_param(key)?, key)
            .await?
            .send()
            .await?
            .error_for_code()
            .await
    }

    pub async fn get_all_acl<K: SigningKey + Sync>(
        url: &Url,
        key: &K,
    ) -> Result<HashMap<String, Vec<String>>, Report> {
        Client::new()
            .post(url.join("/secret/acl/all")?)
            .sign(&sig_param(key)?, key)
            .await?
            .send()
            .await?
            .error_for_json()
            .await
    }

    pub async fn list<K: SigningKey + Sync>(url: &Url, key: &K) -> Result<Vec<String>, Report> {
        Client::new()
            .get(url.join("/secret/list")?)
            .sign(&sig_param(key)?, key)
            .await?
            .send()
            .await?
            .error_for_json()
            .await
    }

    pub async fn get_server_recipient<K: SigningKey + Sync>(
        url: &Url,
        key: &K,
    ) -> Result<String, Report> {
        Client::new()
            .get(url.join("/secret/server_key")?)
            .sign(&sig_param(key)?, key)
            .await?
            .send()
            .await?
            .error_for_json()
            .await
    }
}

fn sig_param<K: SigningKey + Sync>(key: &K) -> Result<HttpSignatureParams, Report> {
    let mut signature_params = HttpSignatureParams::try_new(&COMPONENTS)?;
    signature_params.set_key_info(key);
    Ok(signature_params)
}

#[expect(async_fn_in_trait)]
pub trait ErrorForJson {
    async fn error_for_json<T: DeserializeOwned>(self) -> Result<T, Report>;
    async fn error_for_code(self) -> Result<StatusCode, Report>;
}

impl ErrorForJson for Response {
    async fn error_for_json<T: DeserializeOwned>(self) -> Result<T, Report> {
        if self.status().is_success() {
            Ok(self.json::<T>().await?)
        } else {
            Err(report!("{}: {}", self.status(), self.text().await?))
        }
    }

    async fn error_for_code(self) -> Result<StatusCode, Report> {
        if self.status().is_success() {
            Ok(self.status())
        } else {
            Err(report!("{}: {}", self.status(), self.text().await?))
        }
    }
}
