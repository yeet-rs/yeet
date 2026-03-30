//! <https://osquery.readthedocs.io/en/stable/deployment/remote/#remote-server-api>
#![expect(clippy::exhaustive_structs)]

use std::collections::HashMap;

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]

pub struct EnrollmentRequest {
    pub enroll_secret: Option<String>,
    /// Determined by the `--host_identifier` flag
    pub host_identifier: String,
    // A dictionary of keys mapping to helpful osquery tables.
    pub host_details: EnrollmentHostDetails,
    pub platform_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnrollmentHostDetails {
    pub os_version: HashMap<String, String>,
    pub osquery_info: HashMap<String, String>,
    pub system_info: HashMap<String, String>,
    pub platform_info: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnrollmentResponse {
    /// Optionally blank
    pub node_key: Option<String>,
    /// Optional, return true to indicate failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_invalid: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DistributedReadRequest {
    pub node_key: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
/// TODO: Discovery queries on distributed queries
pub struct DistributedReadResponse {
    pub queries: HashMap<String, String>,
    /// Optional, return true to indicate re-enrollmen.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_invalid: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DistributedWriteRequest {
    pub node_key: Option<String>,
    pub queries: HashMap<String, Vec<IndexMap<String, String>>>,
    /// As of osquery version 2.1.2, the distributed write API includes a top-level statuses key.
    /// These error codes correspond to `SQLite` error codes.
    /// Consider non-0 values to indicate query execution failures.
    pub statuses: HashMap<String, u32>,
    /// Optional, return true to indicate re-enrollmen.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_invalid: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DistributedWriteResponse {
    pub node_invalid: Option<bool>,
}

#[cfg(test)]
mod test_lib {
    use crate::EnrollmentResponse;

    #[test]
    fn serialization() {
        let response = serde_json::to_string(&EnrollmentResponse {
            node_key: Some("this_is_a_node_secret".to_owned()),
            node_invalid: None,
        })
        .unwrap();

        // https://github.com/osquery/osquery/blob/8eb8c0d9aab923c4744e330f24581ce150b22098/tools/tests/test_http_server.py#L124
        assert_eq!(response, r#"{"node_key":"this_is_a_node_secret"}"#)
    }
}
