pub mod assets;
pub mod organziation;

pub(crate) type Result<T> = core::result::Result<T, Error>;

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
    pub next: serde_json::Value,
    pub prefetch: serde_json::Value,
    pub previous: serde_json::Value,
    pub results: Vec<T>,
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
    };
}

pub(crate) use api_id;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    InvalidHeader(#[from] reqwest::header::InvalidHeaderValue),
    #[error(transparent)]
    URL(#[from] url::ParseError),
}
