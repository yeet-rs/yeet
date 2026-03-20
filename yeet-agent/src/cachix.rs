use std::ffi::OsStr;

use api::ErrorForJson as _;
use reqwest::Client;
use rootcause::{Report, bail};
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use url::Url;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CachixInfo {
    pub github_username: String,
    pub is_public: bool,
    pub name: String,
    pub permission: String,
    pub preferred_compression_method: String,
    pub public_signing_keys: Vec<String>,
    pub uri: String,
}

pub async fn get_cachix_info<S: AsRef<str>>(cache: S) -> Result<CachixInfo, Report> {
    Ok(Client::new()
        .get(Url::parse("https://app.cachix.org/api/v1/cache/")?.join(cache.as_ref())?)
        .send()
        .await?
        .error_for_json::<CachixInfo>()
        .await?)
}

pub async fn push_paths<I, S, C>(closures: I, cache: C) -> Result<(), Report>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
    C: AsRef<str>,
{
    let exit = Command::new("cachix")
        .args(["push", cache.as_ref()])
        .args(closures)
        .status()
        .await?;
    if !exit.success() {
        bail!("Failed to push closures to cachix");
    }
    Ok(())
}
