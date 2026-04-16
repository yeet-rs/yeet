use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use sqlx::types::Json;

#[derive(Debug, Serialize, Deserialize, sqlx::Type)]
pub enum SplunkStatus {
    /// The message has not yet been sent
    NotSent,
    /// The message delivery has been successfull
    Sent,
    /// This message will never be sent to splunk
    Internal,
}

// TODO: what do we want to do if this thread errors
pub async fn run(
    config: splunk_hec::SplunkConfig,
    mut receiver: tokio::sync::mpsc::Receiver<()>,
    pool: sqlx::SqlitePool,
) -> Result<(), sqlx::Error> {
    while let Some(()) = receiver.recv().await {
        let mut conn = pool.acquire().await?;

        let s_q = send_queries(&mut conn, &config).await?;
        let s_r = send_responses(&mut conn, &config).await?;
        let s_s = send_statuses(&mut conn, &config).await?;
        let s_rs = send_results(&mut conn, &config).await?;
        let d_r = delete_responses(&mut conn).await?;
        let d_q = delete_queries(&mut conn).await?;
        let d_s = delete_statuses(&mut conn).await?;
        let d_rs = delete_results(&mut conn).await?;

        log::info!(
            "SPLUNK SYNC
      Sent Queries: {all_queries}/{ok_queries}(OK)/{err_queries}(ERR)
    Sent Responses: {all_responses}/{ok_responses}(OK)/{err_respnses}(ERR)
     Sent Statuses: {all_status}/{ok_status}(OK)/{err_status}(ERR)
      Sent Results: {all_results}/{ok_results}(OK)/{err_results}(ERR)
   Deleted Queries: {d_q}
 Deleted Responses: {d_r}
  Deleted Statuses: {d_s}
   Deleted Results: {d_rs}",
            all_queries = s_q.0,
            ok_queries = s_q.1,
            err_queries = s_q.0.saturating_sub(s_q.1),
            all_responses = s_r.0,
            ok_responses = s_r.1,
            err_respnses = s_r.0.saturating_sub(s_r.1),
            all_status = s_s.0,
            ok_status = s_s.1,
            err_status = s_s.0.saturating_sub(s_s.1),
            all_results = s_rs.0,
            ok_results = s_rs.1,
            err_results = s_rs.0.saturating_sub(s_rs.1),
        );
    }
    Ok(())
}

async fn delete_statuses(conn: &mut sqlx::SqliteConnection) -> Result<u64, sqlx::Error> {
    let deleted_statuses = sqlx::query!(
        r#"
        DELETE FROM osquery_status_log
        WHERE splunk_status = $1"#,
        SplunkStatus::Sent
    )
    .execute(&mut *conn)
    .await?;

    Ok(deleted_statuses.rows_affected())
}

async fn delete_results(conn: &mut sqlx::SqliteConnection) -> Result<u64, sqlx::Error> {
    let deleted_results = sqlx::query!(
        r#"
        DELETE FROM osquery_result_log
        WHERE splunk_status = $1"#,
        SplunkStatus::Sent
    )
    .execute(&mut *conn)
    .await?;

    Ok(deleted_results.rows_affected())
}

async fn delete_responses(conn: &mut sqlx::SqliteConnection) -> Result<u64, sqlx::Error> {
    let deleted_responses = sqlx::query!(
        r#"
        DELETE FROM osquery_dq_responses
        WHERE query_id IN (
            SELECT id FROM osquery_dq_queries
            WHERE persistent = 0
        ) AND splunk_status = $1"#,
        SplunkStatus::Sent
    )
    .execute(&mut *conn)
    .await?;

    Ok(deleted_responses.rows_affected())
}
async fn delete_queries(conn: &mut sqlx::SqliteConnection) -> Result<u64, sqlx::Error> {
    let queries = sqlx::query!(
        r#"
        DELETE FROM osquery_dq_queries
        WHERE id IN (
            SELECT odq.id FROM osquery_dq_queries odq
            LEFT JOIN osquery_dq_requests ore on ore.query_id = odq.id
            LEFT JOIN osquery_dq_responses odr on odr.query_id = odq.id
            WHERE odq.splunk_status = $1
            AND persistent = 0
            AND odr.id IS NULL
            AND ore.query_id IS NULL
        )"#,
        SplunkStatus::Sent
    )
    .execute(conn)
    .await?;

    Ok(queries.rows_affected())
}

/// Send all `osquery_dq_responses` with state `SplunkStatus::NotSent` to splunk
async fn send_responses(
    conn: &mut sqlx::SqliteConnection,
    config: &splunk_hec::SplunkConfig,
) -> Result<(u64, u64), sqlx::Error> {
    let unsent_dq_responses = sqlx::query!(
        r#"
        SELECT
            odr.id,
            odr.query_id,
            odr.status,
            osn.host_identifier,
            odr.response_time as "response_time: jiff_sqlx::Timestamp",
            odr.response

        FROM osquery_dq_responses odr
        JOIN osquery_nodes osn on odr.node_id = osn.id
        WHERE odr.splunk_status = $1"#,
        SplunkStatus::NotSent
    )
    .fetch_all(&mut *conn)
    .await?;

    let all = unsent_dq_responses.len() as u64;

    let mut successfull: u64 = 0;

    for node_response in unsent_dq_responses {
        let rows = {
            let columns: IndexMap<String, Vec<String>> =
                serde_json::from_str(&node_response.response).unwrap_or_default();
            crate::routes::osquery::column_to_row(&columns)
        };

        let mut query_rows = Vec::new();

        for row in rows {
            let row = splunk_hec::SplunkMessageType::response(
                node_response.query_id,
                node_response.host_identifier.clone(),
                node_response.status,
                row,
            );
            query_rows.push(row);
        }

        // If we have no response we still want to send a single response log with metadata
        if query_rows.is_empty() {
            let row = splunk_hec::SplunkMessageType::response(
                node_response.query_id,
                node_response.host_identifier.clone(),
                node_response.status,
                IndexMap::new(),
            );
            query_rows.push(row);
        }

        let response = config
            .send_msgs(query_rows, node_response.response_time.to_jiff())
            .await;

        match response {
            // only update that it was sent if it was sent successfull
            Ok(response) if response.status().is_success() => {
                sqlx::query!(
                    r#"UPDATE osquery_dq_responses
                    SET splunk_status = $1
                    WHERE id = $2"#,
                    SplunkStatus::Sent,
                    node_response.id
                )
                .execute(&mut *conn)
                .await?;
                successfull = successfull.saturating_add(1);
            }
            Ok(response) => log::error!(
                "Splunk responded with a non success:\n{:#?}",
                response.text().await
            ),
            Err(err) => log::error!("Failed to send splunk logs: {err}"),
        }
    }

    Ok((all, successfull))
}

/// Send all `osquery_status_log` with state `SplunkStatus::NotSent` to splunk
async fn send_statuses(
    conn: &mut sqlx::SqliteConnection,
    config: &splunk_hec::SplunkConfig,
) -> Result<(u64, u64), sqlx::Error> {
    let unsent_status_log = sqlx::query!(
        r#"
        SELECT
            osl.id,
            osn.host_identifier,
            osl.unix_time,
            osl.filename,
            osl.line,
            osl.message,
            osl.severity,
            osl.version,
            osl.received_time as "received_time: jiff_sqlx::Timestamp"

        FROM osquery_status_log osl
        JOIN osquery_nodes osn on osl.node_id = osn.id
        WHERE osl.splunk_status = $1"#,
        SplunkStatus::NotSent
    )
    .fetch_all(&mut *conn)
    .await?;

    let all = unsent_status_log.len() as u64;

    let mut successfull: u64 = 0;

    for status in unsent_status_log {
        let msg = splunk_hec::SplunkMessageType::status(
            status.host_identifier,
            status.unix_time,
            status.filename,
            status.line as u32,
            status.message,
            status.severity as i32,
            status.version,
        );

        let response = config
            .send_msgs(vec![msg], status.received_time.to_jiff())
            .await;

        match response {
            // only update that it was sent if it was sent successfull
            Ok(response) if response.status().is_success() => {
                sqlx::query!(
                    r#"UPDATE osquery_status_log
                    SET splunk_status = $1
                    WHERE id = $2"#,
                    SplunkStatus::Sent,
                    status.id
                )
                .execute(&mut *conn)
                .await?;
                successfull = successfull.saturating_add(1);
            }
            Ok(response) => log::error!(
                "Splunk responded with a non success:\n{:#?}",
                response.text().await
            ),
            Err(err) => log::error!("Failed to send splunk logs: {err}"),
        }
    }

    Ok((all, successfull))
}

/// Send all `osquery_result_log` with state `SplunkStatus::NotSent` to splunk
async fn send_results(
    conn: &mut sqlx::SqliteConnection,
    config: &splunk_hec::SplunkConfig,
) -> Result<(u64, u64), sqlx::Error> {
    let unsent_result_log = sqlx::query!(
        r#"
        SELECT
            orl.id,
            osn.host_identifier,
            orl.unix_time,
            orl.numerics as "numerics: bool",
            orl.epoch,
            orl.pack_name,
            orl.log,
            orl.received_time as "received_time: jiff_sqlx::Timestamp"

        FROM osquery_result_log orl
        JOIN osquery_nodes osn on orl.node_id = osn.id
        WHERE orl.splunk_status = $1"#,
        SplunkStatus::NotSent
    )
    .fetch_all(&mut *conn)
    .await?;

    let all = unsent_result_log.len() as u64;

    let mut successfull: u64 = 0;

    for result in unsent_result_log {
        let log = serde_json::from_str(&result.log)
            .expect("If it serializes the inverse also work - trust me bro");

        let msg = splunk_hec::SplunkMessageType::result(
            result.host_identifier,
            result.unix_time,
            result.numerics,
            result.epoch,
            result.pack_name,
            log,
        );

        let response = config
            .send_msgs(vec![msg], result.received_time.to_jiff())
            .await;

        match response {
            // only update that it was sent if it was sent successfull
            Ok(response) if response.status().is_success() => {
                sqlx::query!(
                    r#"UPDATE osquery_result_log
                    SET splunk_status = $1
                    WHERE id = $2"#,
                    SplunkStatus::Sent,
                    result.id
                )
                .execute(&mut *conn)
                .await?;
                successfull = successfull.saturating_add(1);
            }
            Ok(response) => log::error!(
                "Splunk responded with a non success:\n{:#?}",
                response.text().await
            ),
            Err(err) => log::error!("Failed to send splunk logs: {err}"),
        }
    }

    Ok((all, successfull))
}

/// Send all `osquery_dq_queries` with state `SplunkStatus::NotSent` to splunk
async fn send_queries(
    conn: &mut sqlx::SqliteConnection,
    config: &splunk_hec::SplunkConfig,
) -> Result<(u64, u64), sqlx::Error> {
    let unsent_dq_queries = sqlx::query!(
        r#"
        SELECT
            q.id,
            q.query,
            u.username,
            q.creation_time as "creation_time: jiff_sqlx::Timestamp",
            json_group_array(
                osn.host_identifier
            ) as "nodes!: Json<Vec<String>>"
        FROM osquery_dq_queries q
        JOIN users u on q.user_id = u.id
        LEFT JOIN osquery_dq_requests odreq on odreq.query_id = q.id -- these nodes have not yet responded
        LEFT JOIN osquery_dq_responses odr on odr.query_id = q.id -- these nodes have already responded
        JOIN osquery_nodes osn on odr.node_id = osn.id or odreq.node_id = osn.id
        WHERE q.splunk_status = $1
        GROUP BY q.id, u.username"#,
        SplunkStatus::NotSent
    )
    .fetch_all(&mut *conn)
    .await?;

    let all = unsent_dq_queries.len() as u64;
    let mut successfull: u64 = 0;

    for query in unsent_dq_queries {
        let response = config
            .send_msgs(
                vec![splunk_hec::SplunkMessageType::query(
                    query.id,
                    query.nodes.0,
                    query.username,
                    query.query,
                )],
                query.creation_time.to_jiff(),
            )
            .await;

        match response {
            // only update that it was sent if it was sent successfull
            Ok(response) if response.status().is_success() => {
                sqlx::query!(
                    r#"UPDATE osquery_dq_queries
                    SET splunk_status = $1
                    WHERE id = $2"#,
                    SplunkStatus::Sent,
                    query.id
                )
                .execute(&mut *conn)
                .await?;
                successfull = successfull.saturating_add(1);
            }
            Ok(response) => log::error!(
                "Splunk responded with a non success:\n{:#?}",
                response.text().await
            ),
            Err(err) => log::error!("Failed to send splunk logs: {err}"),
        }
    }
    Ok((all, successfull))
}
