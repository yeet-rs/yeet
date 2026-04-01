use indexmap::IndexMap;
use reqwest::Client;
use serde::{Deserialize, Serialize};

/// Unique id for each query job
pub type SearchID = String;

#[derive(Serialize, Deserialize, Debug)]
pub struct SplunkMessage {
    time: i64,
    /// Yeet Server
    host: String,
    index: String,
    sourcetype: Option<String>,
    #[serde(rename = "event")]
    message_type: SplunkMessageType,
}

impl SplunkMessage {
    /// URL is normally like this
    /// domain:8088/services/collector/event?channel=<token>
    pub async fn send(&self, url: &str, token: &str) -> Result<reqwest::Response, reqwest::Error> {
        Client::new()
            .post(url)
            .json(self)
            .header("Authorization", format!("Splunk {}", token))
            .send()
            .await
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum SplunkMessageType {
    QueryJobLog {
        sid: SearchID,
        /// List of target hostnames
        nodes: Vec<String>,
        user: String,
        version: String,
    },
    QueryResponse {
        sid: SearchID,
        hostname: String,
        response: IndexMap<String, Vec<String>>,
    },
}
