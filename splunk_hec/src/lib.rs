use indexmap::IndexMap;
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct SplunkConfig {
    index: String,
    /// Splunk server url
    server: url::Url,
    token: String,
    yeet_server: url::Url,
    reqwest_client: reqwest::Client,
}

impl SplunkConfig {
    #[must_use]
    pub fn new(index: String, yeet_server: url::Url, server: url::Url, token: String) -> Self {
        Self {
            index,
            server,
            yeet_server,
            token,
            reqwest_client: Client::new(),
        }
    }
    /// Only ever send events that correlate to the same timestamp
    pub async fn send_msgs(
        &self,
        msgs: Vec<SplunkMessageType>,
        time: jiff::Timestamp,
    ) -> Result<reqwest::Response, reqwest::Error> {
        let mut events = Vec::new();
        for msg in msgs {
            let msg = SplunkMessage {
                time: time.as_nanosecond(),
                host: self.yeet_server.to_string(),
                index: self.index.clone(),
                sourcetype: Some(msg.sourcetype()),
                message_type: msg,
            };
            events.push(msg);
        }

        self.reqwest_client
            .post(self.server.as_str())
            .json(&events)
            .header("Authorization", format!("Splunk {}", self.token))
            .send()
            .await?
            .error_for_status()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SplunkMessage {
    time: i128,
    /// Yeet Server
    host: String,
    index: String,
    sourcetype: Option<String>,
    #[serde(flatten)]
    message_type: SplunkMessageType,
}

/// Unique id for each query job
pub type SearchID = i64;

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum SplunkMessageType {
    QueryJob {
        event: QueryMetadata,
    },
    /// Instead of sending the response as a whole we send each row as a seperate event
    QueryRow {
        /// The query output in a row based table
        /// Each Vec element is a row and the Map is column name -> value
        event: IndexMap<String, String>,
        fields: RowMetadata,
    },
}
impl SplunkMessageType {
    #[must_use]
    pub fn sourcetype(&self) -> String {
        match self {
            SplunkMessageType::QueryJob { .. } => "osquery_query_log".to_owned(),
            SplunkMessageType::QueryRow { .. } => "osquery_response".to_owned(),
        }
    }
    #[must_use]
    pub fn query(sid: SearchID, nodes: Vec<String>, user: String, query: String) -> Self {
        Self::QueryJob {
            event: QueryMetadata {
                sid,
                nodes,
                user,
                query,
            },
        }
    }
    #[must_use]
    pub fn response(
        sid: SearchID,
        hostname: String,
        status: i64,
        event: IndexMap<String, String>,
    ) -> Self {
        Self::QueryRow {
            event,
            fields: RowMetadata {
                sid,
                hostname,
                status,
            },
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RowMetadata {
    /// Corresponding `QueryJob`
    sid: SearchID,
    /// osqueryd `host_identifier`
    hostname: String,
    /// "`SQLite`" (osquery) Status of the response. If it is non 0 `response` will be empty
    status: i64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct QueryMetadata {
    sid: SearchID,
    /// List of target nodes (osqueryd `host_identifier`)
    /// If hostnames are not unique or consistent in your environment, you can launch osqueryd with `--host_identifier=uuid`
    nodes: Vec<String>,
    /// Yeet user that created the query
    user: String,
    /// actual query that is sent to the nodes
    query: String, // Yeet version
                   // version: String,
}
