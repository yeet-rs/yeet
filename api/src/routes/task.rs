use httpsig_hyper::prelude::SigningKey;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    HostID,
    httpsig::{ErrorForJson as _, ReqwestSig as _, ResponseError, sig_param},
    request, server_age_key,
};

crate::db_id!(TaskID);

/// One-shot thing the agent of a host should do.
///
/// Can contain secrets, so this only ever goes over the wire age encrypted.
/// Never as plain json in a request body
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum HostTask {
    /// Task type this version doesn't know about. Agents report it as unsupported
    #[serde(other)]
    Unknown,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "hazard", derive(sqlx::Type))]
pub enum TaskState {
    Pending,
    Done,
    Failed,
    /// Computed by the server from the expiry time, never stored
    Expired,
}

impl std::fmt::Display for TaskState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = match self {
            Self::Pending => "Pending",
            Self::Done => "Done",
            Self::Failed => "Failed",
            Self::Expired => "Expired",
        };
        write!(f, "{state}")
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TaskReport {
    pub state: TaskState,
    /// Human readable reason, mostly for failed tasks
    pub message: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PendingTask {
    pub id: TaskID,
    /// The task as json, age encrypted for the recipient of the request
    pub task: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GetTasksRequest {
    /// Ephemeral age public key (age1...) the tasks get encrypted for
    pub recipient: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TaskStatus {
    pub id: TaskID,
    pub host: HostID,
    pub state: TaskState,
    pub message: Option<String>,
    pub creation_time: jiff::Timestamp,
    /// Time of the latest history row
    pub update_time: jiff::Timestamp,
    pub expires_at: jiff::Timestamp,
}

/// Queue a task for a host. Gets encrypted to the server key before sending
#[tracing::instrument(skip(key, task), fields(url = %url))]
pub async fn create_task<K: SigningKey + Sync>(
    url: &Url,
    key: &K,
    host: HostID,
    task: &HostTask,
) -> Result<TaskID, ResponseError> {
    let recipient: age::x25519::Recipient = {
        let recipient = server_age_key(url, key).await?;

        recipient
            .parse()
            .map_err(|error: &'static str| ResponseError::IdentityError { error })?
    };
    let ciphertext: Vec<u8> = age::encrypt(&recipient, &serde_json::to_vec(task)?)?;

    let id = reqwest::Client::new()
        .post(url.join(&format!("/task/create/{host}"))?)
        .json(&ciphertext)
        .sign(&sig_param(key)?, key)
        .await?
        .send()
        .await?
        .error_for_json::<TaskID>()
        .await?;
    Ok(id)
}

/// Fetch and decrypt all pending tasks of the calling host.
/// Every task has to be reported back afterwards, otherwise it stays pending
#[tracing::instrument(skip(key), fields(url = %url))]
pub async fn get_tasks<K: SigningKey + Sync>(
    url: &Url,
    key: &K,
) -> Result<Vec<(TaskID, HostTask)>, ResponseError> {
    let identity = age::x25519::Identity::generate();
    let request = GetTasksRequest {
        recipient: identity.to_public().to_string(),
    };

    let pending = reqwest::Client::new()
        .post(url.join("/system/tasks")?)
        .json(&request)
        .sign(&sig_param(key)?, key)
        .await?
        .send()
        .await?
        .error_for_json::<Vec<PendingTask>>()
        .await?;

    // one broken task fails the whole fetch. shouldn't happen anyway so no point in skipping it
    pending
        .into_iter()
        .map(|PendingTask { id, task }| {
            let plaintext = age::decrypt(&identity, &task)?;
            let host_task = serde_json::from_slice::<HostTask>(&plaintext)?;
            Ok((id, host_task))
        })
        .collect()
}

request!(
    task_status(task: TaskID),
    get("/task/{task}") -> TaskStatus
);

request!(
    report_task(task: TaskID, report: TaskReport),
    put("/system/tasks/{task}") -> StatusCode,
    body: &report
);
