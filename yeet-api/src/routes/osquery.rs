use std::fmt::Display;

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::request;

crate::db_id!(NodeID);
crate::db_id!(QueryID);

#[derive(Debug, Serialize, Deserialize)]
pub struct Node {
    pub id: NodeID,
    pub host_identifier: String,
    // pub platform_type: String,
    pub host_details: osquery_tls::EnrollmentHostDetails,
}

impl PartialEq for Node {
    fn eq(&self, other: &Self) -> bool {
        self.host_identifier == other.host_identifier
    }
}
impl Eq for Node {}

#[expect(clippy::non_canonical_partial_ord_impl)]
impl PartialOrd for Node {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.host_identifier.partial_cmp(&other.host_identifier)
    }
}
impl Ord for Node {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.host_identifier.cmp(&other.host_identifier)
    }
}

impl Display for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // TODO: include more info
        write!(f, "{}", self.host_identifier)
    }
}

request! (
    list_nodes(),
    get("/osquery/nodes") -> Vec<Node>
);

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateQuery {
    pub sql: String,
    pub nodes: Vec<NodeID>,
}

request! (
    create_query(query: CreateQuery),
    post("/osquery/query/create") -> QueryID,
    body: &query
);

#[derive(Debug, Serialize, Deserialize)]
pub struct QueryFulfillment {
    pub responses: Vec<QueryResponse>,
    pub missing: Vec<NodeID>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QueryResponse {
    pub node: NodeID,
    /// Query as colum -> row values
    pub response: IndexMap<String, Vec<String>>,
    pub status: i64,
}
