//! API for yeet

mod httpsig;
mod key;
mod secret;

mod routes {
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
pub use routes::tag;
pub use routes::{host::*, key::*, osquery::*, secret::*, system::*, user::*, verify::*};
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

macro_rules! db_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq, Hash)]
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
