use std::collections::HashMap;

use crate::httpsig::{ErrorForJson as _, ReqwestSig as _, ResponseError, sig_param};
use httpsig_hyper::prelude::SigningKey;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "hazard", derive(sqlx::Type))]
#[cfg_attr(feature = "hazard", sqlx(transparent))]
#[serde(transparent)]
pub struct NodeID(i64);

impl std::fmt::Display for NodeID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(feature = "hazard")]
impl NodeID {
    #[must_use]
    pub fn new(id: i64) -> Self {
        Self(id)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "hazard", derive(sqlx::Type))]
#[cfg_attr(feature = "hazard", sqlx(transparent))]
#[serde(transparent)]
pub struct QueryID(i64);

impl std::fmt::Display for QueryID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(feature = "hazard")]
impl QueryID {
    #[must_use]
    pub fn new(id: i64) -> Self {
        Self(id)
    }
}

#[derive(Debug, Serialize, Deserialize)]

pub struct Node {
    pub id: NodeID,
    pub host_identifier: String,
    // pub platform_type: String,
    pub host_details: osquery_tls::EnrollmentHostDetails,
}

pub async fn list_nodes<K: SigningKey + Sync>(
    url: &Url,
    key: &K,
) -> Result<Vec<Node>, ResponseError> {
    reqwest::Client::new()
        .get(url.join("/osquery/nodes")?)
        .sign(&sig_param(key)?, key)
        .await?
        .send()
        .await?
        .error_for_json()
        .await
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateQuery {
    pub sql: String,
}

pub async fn create_query<K: SigningKey + Sync>(
    url: &Url,
    key: &K,
    query: &CreateQuery,
) -> Result<QueryID, ResponseError> {
    reqwest::Client::new()
        .post(url.join("/osquery/query/create")?)
        .json(query)
        .sign(&sig_param(key)?, key)
        .await?
        .send()
        .await?
        .error_for_json()
        .await
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QueryFulfillment {
    pub responses: Vec<QueryResponse>,
    pub missing: Vec<NodeID>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QueryResponse {
    pub node: NodeID,
    pub response: Vec<IndexMap<String, String>>,
    pub status: i64,
}

pub async fn query_response_all<K: SigningKey + Sync>(
    url: &Url,
    key: &K,
    query: QueryID,
) -> Result<QueryFulfillment, ResponseError> {
    reqwest::Client::new()
        .get(url.join(&format!("/osquery/query/response/{query}"))?)
        .sign(&sig_param(key)?, key)
        .await?
        .send()
        .await?
        .error_for_json()
        .await
}
