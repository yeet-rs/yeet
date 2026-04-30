//! <https://osquery.readthedocs.io/en/stable/deployment/remote/#remote-server-api>
#![expect(clippy::exhaustive_structs)]

use std::collections::HashMap;

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EnrollmentRequest {
    pub enroll_secret: Option<String>,
    /// Determined by the `--host_identifier` flag
    pub host_identifier: String,
    // A dictionary of keys mapping to helpful osquery tables.
    pub host_details: EnrollmentHostDetails,
    pub platform_type: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
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
pub struct NodeKey {
    pub node_key: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EmptyResponse {
    node_invalid: bool,
}

impl EmptyResponse {
    #[must_use]
    pub fn valid() -> Self {
        Self {
            node_invalid: false,
        }
    }
    #[must_use]
    pub fn invalid() -> Self {
        Self { node_invalid: true }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoteLoggingRequest {
    #[serde(flatten)]
    pub data: LogType,
    pub node_key: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[serde(tag = "log_type", content = "data")]
pub enum LogType {
    Result(Vec<ResultLog>),
    Status(Vec<StatusLog>),
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StatusLog {
    /// e.g. "Fri Mar 27 15:42:13 2026 UTC"
    pub calendar_time: String,
    /// e.g. `tls_enroll.cpp`
    pub filename: String,
    pub host_identifier: String,
    pub line: u32,
    /// e.g. "Failed enrollment request to..."
    pub message: String,
    /// e.g. 2 (maybe an u16)
    pub severity: i32,
    /// e.g. 1775122921
    pub unix_time: i64,
    /// e.g. 5.21.0
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ResultLog {
    /// e.g. "Fri Mar 27 15:42:13 2026 UTC"
    pub calendar_time: String,
    #[serde(flatten)]
    pub action: EventLogAction,
    pub counter: i64,
    pub epoch: i64,
    pub host_identifier: String,
    /// pack name e.g. "pack_<`pack_id`>_<`pack_name`>"
    pub name: String,
    /// This is an indicator for all results, true if osquery attempted to log numerics as numbers, otherwise false indicates they were logged as strings.
    pub numerics: bool,
    pub unix_time: i64,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "action", rename_all = "lowercase")]
pub enum EventLogAction {
    Removed {
        columns: IndexMap<String, String>,
    },
    Added {
        columns: IndexMap<String, String>,
    },
    Snapshot {
        snapshot: Vec<IndexMap<String, String>>,
    },
}

#[cfg(test)]
mod test_lib {
    use indexmap::IndexMap;

    use crate::{EnrollmentResponse, EventLogAction, LogType, RemoteLoggingRequest, ResultLog};

    #[test]
    fn enrollemnt_response_serialization() {
        let response = serde_json::to_string(&EnrollmentResponse {
            node_key: Some("this_is_a_node_secret".to_owned()),
            node_invalid: None,
        })
        .unwrap();

        // https://github.com/osquery/osquery/blob/8eb8c0d9aab923c4744e330f24581ce150b22098/tools/tests/test_http_server.py#L124
        assert_eq!(response, r#"{"node_key":"this_is_a_node_secret"}"#)
    }

    #[test]
    fn remote_log_result_serialization() {
        let log = LogType::Result(vec![
            ResultLog {
                calendar_time: "Wed Apr 15 06:11:00 2026 UTC".into(),
                action: EventLogAction::Removed {
                    columns: IndexMap::from([("build_platform".into(), "linux".into())]),
                },
                counter: 2,
                epoch: 0,
                host_identifier: "myhost".into(),
                name: "pack_test_osquery_info".into(),
                numerics: false,
                unix_time: 1776233460,
            },
            ResultLog {
                calendar_time: "Wed Apr 15 06:11:00 2026 UTC".into(),
                action: EventLogAction::Added {
                    columns: IndexMap::from([("timezone".into(), "UTC".into())]),
                },
                counter: 2,
                epoch: 0,
                host_identifier: "myhost".into(),
                name: "pack_test_osquery_info".into(),
                numerics: false,
                unix_time: 1776233460,
            },
        ]);
        let remote_log = RemoteLoggingRequest {
            node_key: Some("06831371-158a-46e3-869e-85b0cd7a2079".into()),
            data: log,
        };

        // normally this json is much bigger because of colums
        let json = serde_json::json!( {
          "data": [
            {
              "action": "removed",
              "calendarTime": "Wed Apr 15 06:11:00 2026 UTC",
              "columns": {
                "build_platform": "linux"
              },
              "counter": 2,
              "epoch": 0,
              "hostIdentifier": "myhost",
              "name": "pack_test_osquery_info",
              "numerics": false,
              "unixTime": 1776233460
            },
            {
              "action": "added",
              "calendarTime": "Wed Apr 15 06:11:00 2026 UTC",
              "columns": {
                "timezone": "UTC",
              },
              "counter": 2,
              "epoch": 0,
              "hostIdentifier": "myhost",
              "name": "pack_test_osquery_info",
              "numerics": false,
              "unixTime": 1776233460
            }
          ],
          "log_type": "result",
          "node_key": "06831371-158a-46e3-869e-85b0cd7a2079"
        });

        assert_eq!(remote_log, serde_json::from_value(json).unwrap())
    }
}
