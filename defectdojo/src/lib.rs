mod asset;
mod engagement;
mod finding;
mod organziation;
mod scan;
mod test;

pub use asset::*;
pub use engagement::*;
pub use finding::*;
pub use organziation::*;
pub use scan::*;
pub use test::*;

pub(crate) type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Clone)]

pub struct Client {
    url: url::Url,
    client: reqwest::Client,
}

impl Client {
    #[must_use]
    pub fn new(url: reqwest::Url, token: &str) -> Result<Self> {
        let mut headers = reqwest::header::HeaderMap::new();

        headers.insert("Authorization", format!("Token {}", token).parse()?);
        let client = reqwest::Client::builder()
            .default_headers(headers)
            .build()?;
        Ok(Self { url, client })
    }
}

#[derive(Default, Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SearchResult<T> {
    pub count: u32,
    pub next: Option<url::Url>,
    pub prefetch: Option<serde_json::Value>,
    pub previous: Option<url::Url>,
    pub results: Vec<T>,
}

impl<T: DeserializeOwned> SearchResult<T> {
    pub async fn next(&self, client: &Client) -> Result<SearchResult<T>> {
        let Some(next) = &self.next else {
            return Err(Error::NoNextOnSearch);
        };

        Ok(client
            .client
            .get(next.clone())
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
    pub async fn previous(&self, client: &Client) -> Result<SearchResult<T>> {
        let Some(previous) = &self.previous else {
            return Err(Error::NoPreviousOnSearch);
        };

        Ok(client
            .client
            .get(previous.clone())
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
}

macro_rules! api_id {
    ($name:ident) => {
        #[derive(
            Clone,
            Copy,
            Debug,
            serde::Deserialize,
            serde::Serialize,
            PartialEq,
            Eq,
            Hash,
            PartialOrd,
            Ord,
        )]
        #[serde(transparent)]
        pub struct $name(pub(crate) u32);

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl From<u32> for $name {
            fn from(value: u32) -> Self {
                $name(value)
            }
        }
    };
}

pub(crate) use api_id;
use serde::de::DeserializeOwned;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Search result has no next search")]
    NoNextOnSearch,
    #[error("Search result has no previous search")]
    NoPreviousOnSearch,
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    InvalidHeader(#[from] reqwest::header::InvalidHeaderValue),
    #[error(transparent)]
    URL(#[from] url::ParseError),
}
