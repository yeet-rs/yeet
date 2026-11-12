//! Runs the one-shot tasks the server queued for this host

use color_eyre::Result;
use httpsig_hyper::prelude::SecretKey;
use tracing::warn;
use url::Url;

/// Fetch all pending tasks, run them and report back.
/// If one report fails the other tasks still run
#[tracing::instrument(err, skip(key))]
pub async fn run_pending_tasks(url: &Url, key: &SecretKey) -> Result<()> {
    let tasks = api::get_tasks(url, key).await?;
    if tasks.is_empty() {
        return Ok(());
    }

    for (id, task) in tasks {
        let report = execute(&task);
        if let Err(err) = api::report_task(url, key, id, report).await {
            warn!("Could not report task {id}: {err}");
        }
    }
    Ok(())
}

/// Can't fail, whatever happens ends up in the report
fn execute(task: &api::HostTask) -> api::TaskReport {
    let result: Result<(), String> = match task {
        api::HostTask::Unknown => Err("Unsupported task type, update yeet-agent".to_owned()),
    };

    match result {
        Ok(()) => api::TaskReport {
            state: api::TaskState::Done,
            message: None,
        },
        Err(reason) => {
            warn!("Task failed: {reason}");
            api::TaskReport {
                state: api::TaskState::Failed,
                message: Some(reason),
            }
        }
    }
}
