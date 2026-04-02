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
    pub async fn send_msg(
        &self,
        msg: SplunkMessageType,
        time: i64,
    ) -> Result<reqwest::Response, reqwest::Error> {
        let msg = SplunkMessage {
            time,
            host: self.yeet_server.to_string(),
            index: self.index.clone(),
            sourcetype: self.sourcetype.clone(),
            message_type: msg,
        };
        self.reqwest_client
            .post(self.server.as_str())
            .json(&msg)
            .header("Authorization", format!("Splunk {}", self.token))
            .send()
            .await
    }
}

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
        /// Yeet version
        version: String,
    },
    QueryResponse {
        /// Corresponding `QueryJob`
        sid: SearchID,
        /// osqueryd `host_identifier`
        hostname: String,
        /// The query output in a row based table
        /// Each Vec element is a row and the Map is column name -> value
        response: Vec<IndexMap<String, String>>,
    },
}
