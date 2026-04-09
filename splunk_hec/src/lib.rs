use indexmap::IndexMap;
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct SplunkConfig {
    index: String,
    sourcetype: Option<String>,
    /// Splunk server url
    server: url::Url,
    token: String,
    yeet_server: url::Url,
    reqwest_client: reqwest::Client,
}

impl SplunkConfig {
    pub fn new(index: String, yeet_server: url::Url, server: url::Url, token: String) -> Self {
        Self {
            index,
            sourcetype: Some("_json".to_owned()),
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
                sourcetype: self.sourcetype.clone(),
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
    #[serde(rename = "event")]
    message_type: SplunkMessageType,
}

/// Unique id for each query job
pub type SearchID = i64;

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum SplunkMessageType {
    QueryJob {
        sid: SearchID,
        /// List of target nodes (osqueryd `host_identifier`)
        /// If hostnames are not unique or consistent in your environment, you can launch osqueryd with `--host_identifier=uuid`
        nodes: Vec<String>,
        /// Yeet user that created the query
        user: String,
        /// actual query that is sent to the nodes
        query: String, // Yeet version
                       // version: String,
    },
    /// Instead of sending the response as a whole we send each row as a seperate event
    QueryRow {
        /// Corresponding `QueryJob`
        osquery_sid: SearchID,
        /// osqueryd `host_identifier`
        osquery_hostname: String,
        /// The query output in a row based table
        /// Each Vec element is a row and the Map is column name -> value
        #[serde(flatten)]
        row: IndexMap<String, String>,
        /// "SQLite" (osquery) Status of the response. If it is non 0 `response` will be empty
        osquery_status: i64,
    },
}
