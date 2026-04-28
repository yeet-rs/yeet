//! API for yeet

mod httpsig;
mod key;
mod secret;

mod routes {
    pub mod artifact;
    pub mod health;
    pub mod host;
    pub mod key;
    pub mod osquery;
    pub mod secret;
    pub mod system;
    pub mod tag;
    pub mod user;
    pub mod verify;
}

pub use httpsig::*;
pub use key::*;
pub use routes::{
    artifact::*, health::*, host::*, key::*, osquery::*, secret::*, system::*, tag, user::*,
    verify::*,
};
pub use secret::*;

pub type StorePath = String;

#[inline]
pub fn hash(value: impl std::hash::Hash) -> u64 {
    ahash::RandomState::with_seeds(1, 2, 3, 4).hash_one(value)
}

#[inline]
pub fn hash_hex(value: impl std::hash::Hash) -> String {
    format!("{:x}", hash(value))
}

/// # Panics
/// idk maybe
#[must_use]
#[expect(clippy::unwrap_used, clippy::arithmetic_side_effects)]
pub fn time_diff(
    timestamp: jiff::Timestamp,
    unit: jiff::Unit,
    threshold: f64,
    smallest: jiff::Unit,
) -> String {
    use colored::Colorize as _;

    let span = (timestamp - jiff::Timestamp::now())
        .round(
            jiff::SpanRound::new()
                .largest(jiff::Unit::Month)
                .smallest(smallest)
                .relative(&jiff::Zoned::now())
                .mode(jiff::RoundMode::Trunc),
        )
        .unwrap();

    if span.total((unit, &jiff::Zoned::now())).unwrap().abs() < threshold {
        format!("{span:#}").green().bold()
    } else {
        format!("{span:#}").red().bold()
    }
    .to_string()
}

macro_rules! db_id {
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
        #[cfg_attr(feature = "hazard", derive(sqlx::Type))]
        #[cfg_attr(feature = "hazard", sqlx(transparent))]
        #[serde(transparent)]
        pub struct $name(pub(crate) i64);

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        #[cfg(feature = "hazard")]
        impl $name {
            #[must_use]
            pub fn new(id: i64) -> Self {
                Self(id)
            }
        }
    };
}

pub(crate) use db_id;

macro_rules! request {
    // With body, StatusCode return
    (
        $fn_name:ident($($param:ident: $param_ty:ty),* $(,)?),
        $method:ident($path:expr) -> StatusCode,
        body: $body:expr
    ) => {
        pub async fn $fn_name<K: httpsig_hyper::prelude::SigningKey + Sync>(
            url: &url::Url,
            key: &K,
            $($param: $param_ty),*
        ) -> Result<http::StatusCode, crate::ResponseError> {
            use crate::httpsig::{ErrorForJson as _, ReqwestSig as _, sig_param};
            reqwest::Client::new()
                .$method(url.join(&format!($path))?)
                .json($body)
                .sign(&sig_param(key)?, key)
                .await?
                .send()
                .await?
                .error_for_code()
                .await
        }
    };

    // Without body, StatusCode return
    (
        $fn_name:ident($($param:ident: $param_ty:ty),* $(,)?),
        $method:ident($path:expr) -> StatusCode
    ) => {
        pub async fn $fn_name<K: httpsig_hyper::prelude::SigningKey + Sync>(
            url: &url::Url,
            key: &K,
            $($param: $param_ty),*
        ) -> Result<http::StatusCode, crate::ResponseError> {
            use crate::httpsig::{ErrorForJson as _, ReqwestSig as _, sig_param};
            reqwest::Client::new()
                .$method(url.join(&format!($path))?)
                .sign(&sig_param(key)?, key)
                .await?
                .send()
                .await?
                .error_for_code()
                .await
        }
    };

    // With body, generic JSON return type
    (
        $fn_name:ident($($param:ident: $param_ty:ty),* $(,)?),
        $method:ident($path:expr) -> $ret:ty,
        body: $body:expr
    ) => {
        pub async fn $fn_name<K: httpsig_hyper::prelude::SigningKey + Sync>(
            url: &url::Url,
            key: &K,
            $($param: $param_ty),*
        ) -> Result<$ret, crate::ResponseError> {
            use crate::httpsig::{ErrorForJson as _, ReqwestSig as _, sig_param};
            reqwest::Client::new()
                .$method(url.join(&format!($path))?)
                .json($body)
                .sign(&sig_param(key)?, key)
                .await?
                .send()
                .await?
                .error_for_json()
                .await
        }
    };

    // Without body, generic JSON return type
    (
        $fn_name:ident($($param:ident: $param_ty:ty),* $(,)?),
        $method:ident($path:expr) -> $ret:ty
    ) => {
        pub async fn $fn_name<K: httpsig_hyper::prelude::SigningKey + Sync>(
            url: &url::Url,
            key: &K,
            $($param: $param_ty),*
        ) -> Result<$ret, crate::ResponseError> {
            use crate::httpsig::{ErrorForJson as _, ReqwestSig as _, sig_param};
            reqwest::Client::new()
                .$method(url.join(&format!($path))?)
                .sign(&sig_param(key)?, key)
                .await?
                .send()
                .await?
                .error_for_json()
                .await
        }
    };
}
pub(crate) use request;
