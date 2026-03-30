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

request! (
    list_nodes(),
    get("/osquery/nodes") -> Vec<Node>
);

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateQuery {
    pub sql: String,
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
    pub response: IndexMap<String, Vec<String>>,
    pub status: i64,
}

request! (
    query_response_all(query: QueryID),
    get("/osquery/query/response/{query}") -> QueryFulfillment
);
