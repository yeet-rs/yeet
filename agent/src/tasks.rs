//! Runs the one-shot tasks the server queued for this host

use std::{fs, io::ErrorKind};

use color_eyre::Result;
use httpsig_hyper::prelude::SecretKey;
use serde::Deserialize;
use tracing::{info, warn};
use url::Url;

use crate::accounts::Account;

/// Written into the system closure by yeet.nix
const POLICY_PATH: &str = "/run/current-system/yeet-password-policy.json";

/// Local policy of this host, the server can't change any of this
#[derive(Debug, Deserialize, Default)]
struct PasswordPolicy {
    enable: bool,
    #[serde(default)]
    declarative_users: Vec<String>,
}

/// No file means the feature is off
fn read_policy() -> Result<PasswordPolicy> {
    match fs::read_to_string(POLICY_PATH) {
        Ok(content) => Ok(serde_json::from_str(&content)?),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(PasswordPolicy::default()),
        Err(err) => Err(err.into()),
    }
}

/// Everything we can check without D-Bus. Own function so it can be unit tested
fn check_static(
    policy: &PasswordPolicy,
    username: &str,
    hashed_password: &str,
) -> Result<(), String> {
    if !policy.enable {
        return Err(
            "Password changes are not enabled on this host (services.yeet.passwordChange.enable)"
                .to_owned(),
        );
    }
    if username == "root" {
        return Err("Changing the password of root is not permitted".to_owned());
    }
    if policy.declarative_users.iter().any(|user| user == username) {
        return Err(format!(
            "The password of {username} is set in the NixOS configuration and would be reverted"
        ));
    }
    // "$6$salt$hash" splits into "", "6", "salt", "hash"
    if !hashed_password.starts_with('$') || hashed_password.split('$').count() < 4 {
        return Err("The password is not a crypt(3) hash".to_owned());
    }
    Ok(())
}

async fn set_password(
    policy: &Result<PasswordPolicy>,
    username: &str,
    hashed_password: &str,
) -> Result<(), String> {
    let policy = policy
        .as_ref()
        .map_err(|err| format!("Invalid password policy on host: {err:#}"))?;
    check_static(policy, username, hashed_password)?;

    let account = Account::find(username)
        .await
        .map_err(|err| format!("{err:#}"))?;

    let info = account.info().await.map_err(|err| format!("{err:#}"))?;
    if info.system_account || info.uid < 1000 {
        return Err(format!(
            "{username} is a system account, changing its password is not permitted"
        ));
    }
    if !info.local_account {
        return Err(format!(
            "{username} is not a local account (e.g. LDAP), its password can not be changed here"
        ));
    }

    account
        .set_password(hashed_password)
        .await
        .map_err(|err| format!("{err:#}"))?;
    info!("Changed password of user {username}");
    Ok(())
}

/// Fetch all pending tasks, run them and report back.
/// If one report fails the other tasks still run
#[tracing::instrument(err, skip(key))]
pub async fn run_pending_tasks(url: &Url, key: &SecretKey) -> Result<()> {
    let tasks = api::get_tasks(url, key).await?;
    if tasks.is_empty() {
        return Ok(());
    }

    // read it every time since the active system and with it the policy can change
    let policy = read_policy();

    for (id, task) in tasks {
        let report = execute(task, &policy).await;
        if let Err(err) = api::report_task(url, key, id, report).await {
            warn!("Could not report task {id}: {err}");
        }
    }
    Ok(())
}

/// Can't fail, whatever happens ends up in the report
async fn execute(task: api::HostTask, policy: &Result<PasswordPolicy>) -> api::TaskReport {
    let result = match task {
        api::HostTask::SetPassword {
            username,
            hashed_password,
        } => set_password(policy, &username, &hashed_password).await,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled() -> PasswordPolicy {
        PasswordPolicy {
            enable: true,
            declarative_users: vec!["bob".to_owned()],
        }
    }

    #[test]
    fn static_checks() {
        assert!(check_static(&PasswordPolicy::default(), "alice", "$6$s$h").is_err());
        check_static(&enabled(), "alice", "$6$s$h").unwrap();
        assert!(check_static(&enabled(), "root", "$6$s$h").is_err());
        assert!(check_static(&enabled(), "bob", "$6$s$h").is_err());
        assert!(check_static(&enabled(), "alice", "hunter2").is_err());
        assert!(check_static(&enabled(), "alice", "$6$hunter2").is_err());
    }

    #[test]
    fn policy_json() {
        let policy: PasswordPolicy = serde_json::from_str(r#"{"enable": true}"#).unwrap();
        assert!(policy.enable);
        assert_eq!(policy.declarative_users, Vec::<String>::new());

        let policy: PasswordPolicy =
            serde_json::from_str(r#"{"enable": true, "declarative_users": ["bob"]}"#).unwrap();
        assert_eq!(policy.declarative_users, ["bob"]);
    }
}
