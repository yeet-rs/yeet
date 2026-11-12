use std::str::FromStr as _;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};

use crate::{
    YeetState,
    db::{self, task::ReportTaskError},
    error::{BadRequest as _, InternalError as _, WithStatusCode as _},
    httpsig::{HttpSig, User, VerifiedJson},
};

/// Queue a task for a host. Needs admin and tag access to the host
pub async fn create(
    State(state): State<YeetState>,
    User(user): User,
    Path(host): Path<api::HostID>,
    VerifiedJson(payload): VerifiedJson<Vec<u8>>,
) -> Result<(StatusCode, Json<api::TaskID>), (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::tag::auth_admin(&mut conn, user).await?;
    db::tag::auth_tag(&mut conn, user, host.into()).await?;

    let task = db::task::create_task(&mut conn, host, user, payload, &*state.age_key)
        .await
        .bad_request()?;

    log::info!("User {user} created task {task} for host {host}");
    Ok((StatusCode::CREATED, Json(task)))
}

/// Status of a task. Needs admin and tag access to the host of the task
pub async fn status(
    State(state): State<YeetState>,
    User(user): User,
    Path(task): Path<api::TaskID>,
) -> Result<Json<api::TaskStatus>, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::tag::auth_admin(&mut conn, user).await?;

    let Some(host) = db::task::task_host(&mut conn, task)
        .await
        .internal_server()?
    else {
        return Err((StatusCode::NOT_FOUND, "Task does not exist".to_owned()));
    };
    db::tag::auth_tag(&mut conn, user, host.into()).await?;

    // only None if someone deleted the task in the meantime
    let Some(status) = db::task::task_status(&mut conn, task)
        .await
        .internal_server()?
    else {
        return Err((StatusCode::NOT_FOUND, "Task does not exist".to_owned()));
    };
    Ok(Json(status))
}

/// Pending tasks of the calling host, encrypted for the recipient it sent
pub async fn pending(
    State(state): State<YeetState>,
    HttpSig(key): HttpSig,
    VerifiedJson(api::GetTasksRequest { recipient }): VerifiedJson<api::GetTasksRequest>,
) -> Result<Json<Vec<api::PendingTask>>, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;

    let Some(host) = db::hosts::host_by_verify_key(&mut conn, key)
        .await
        .internal_server()?
    else {
        return Err((
            StatusCode::FORBIDDEN,
            "Unknown keyid. You are not a registered host".to_owned(),
        ));
    };

    let recipient =
        age::x25519::Recipient::from_str(&recipient).with_code(StatusCode::BAD_REQUEST)?;

    let tasks = db::task::pending_tasks_for(&mut conn, host, &*state.age_key, &recipient)
        .await
        .internal_server()?;
    log::debug!("Host {host} fetched {} tasks", tasks.len());
    Ok(Json(tasks))
}

/// The calling host reports the outcome of one of its tasks
pub async fn report(
    State(state): State<YeetState>,
    HttpSig(key): HttpSig,
    Path(task): Path<api::TaskID>,
    VerifiedJson(report): VerifiedJson<api::TaskReport>,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;

    let Some(host) = db::hosts::host_by_verify_key(&mut conn, key)
        .await
        .internal_server()?
    else {
        return Err((
            StatusCode::FORBIDDEN,
            "Unknown keyid. You are not a registered host".to_owned(),
        ));
    };

    // report gets moved into report_task so grab what we want to log first
    let reported_state = report.state;
    let message = report.message.clone().unwrap_or_default();

    match db::task::report_task(&mut conn, host, task, report).await {
        Ok(()) => {}
        Err(err @ ReportTaskError::NotFound) => {
            return Err((StatusCode::NOT_FOUND, err.to_string()));
        }
        Err(err @ ReportTaskError::InvalidState) => {
            return Err((StatusCode::BAD_REQUEST, err.to_string()));
        }
        Err(err @ ReportTaskError::SQLX(_)) => {
            return Err((StatusCode::INTERNAL_SERVER_ERROR, err.to_string()));
        }
    }

    log::info!("Host {host} reported task {task}: {reported_state} {message}");
    Ok(StatusCode::OK)
}
