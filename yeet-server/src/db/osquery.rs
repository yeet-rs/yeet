use uuid::Uuid;

error_set::error_set! {
    EnrollError := {
        #[display("Enroll secret not set or does not match")]
        SecretMismatch,
        #[display("Enroll secret is not yet set")]
        SecretNotSet,
        Decrypt(age::DecryptError),
        SQLXE(sqlx::Error),
    }
}

/// The node needs to provide the same content as the `osquery-enroll` secret
/// As a response the ode receives an unique UUIDv7 this is the nodes `node_key`
pub async fn enroll_node<I: age::Identity>(
    conn: &mut sqlx::SqliteConnection,
    store_key: &I,
    enroll_request: osquery_tls::EnrollmentRequest,
) -> Result<Uuid, EnrollError> {
    // we hardcode the name of the enroll secret
    let Some(enroll_secret) =
        sqlx::query_scalar!(r#"SELECT secret FROM secrets WHERE name = "osquery-enroll""#)
            .fetch_optional(&mut *conn)
            .await?
    else {
        return Err(EnrollError::SecretNotSet);
    };

    let enroll_secret = age::decrypt(store_key, &enroll_secret)?;

    if Some(String::from_utf8_lossy(&enroll_secret).to_string()) != enroll_request.enroll_secret {
        println!("secret mismatch");
        return Err(EnrollError::SecretMismatch);
    }
    let node_key = uuid::Uuid::now_v7();
    let details = sqlx::types::Json::from(enroll_request.host_details);

    sqlx::query!(
        r#"INSERT INTO osquery_nodes (node_key, host_identifier, platform_type, host_details)
           VALUES ($1,$2,$3,$4)"#,
        node_key,
        enroll_request.host_identifier,
        enroll_request.platform_type,
        details
    )
    .execute(conn)
    .await?;

    Ok(node_key)
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use crate::db;

    #[sqlx::test]
    async fn enroll_new_node(pool: sqlx::SqlitePool) {
        let mut conn = crate::sql_conn(pool).await;

        let store_key = age::x25519::Identity::generate();

        let encrypted = age::encrypt(&store_key.to_public(), b"my-secret-enroll-secret").unwrap();

        let _enroll_secret =
            db::secrets::add_secret(&mut conn, "enroll-secret", encrypted, &store_key)
                .await
                .unwrap();

        db::osquery::enroll_node(
            &mut conn,
            &store_key,
            osquery_tls::EnrollmentRequest {
                enroll_secret: Some("my-secret-enroll-secret".to_owned()),
                host_identifier: "unique-host".into(),
                host_details: osquery_tls::EnrollmentHostDetails {
                    os_version: HashMap::new(),
                    osquery_info: HashMap::new(),
                    system_info: HashMap::new(),
                    platform_info: HashMap::new(),
                },
                platform_type: "9".into(),
            },
        )
        .await
        .unwrap();
    }
}
