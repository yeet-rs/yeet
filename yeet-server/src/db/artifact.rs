use jiff_sqlx::ToSqlx as _;

error_set::error_set! {
    StoreArtifactError := {
        #[display("Secret is not encrytped")]
        UnencryptedSecretError(age::DecryptError),
        SQLXError(sqlx::Error),
    }
}

/// The artifact needs to be encrypted with the servers identity key
/// retrieve it with GET `/secret/server_key`
/// Add a new artifact - `store_key` required to test if it is an actual encrypted secret and not bogus
pub async fn store_artifact<I: age::Identity, S: Into<String>, V: Into<Vec<u8>>>(
    conn: &mut sqlx::SqliteConnection,
    name: S,
    host: api::HostID,
    artifact: V,
    store_key: &I,
) -> Result<(), StoreArtifactError> {
    let secret = artifact.into();
    let name = name.into();
    // test if secret is decryptable
    let _: Vec<u8> = age::decrypt(store_key, &secret)?;
    let now = jiff::Timestamp::now().to_sqlx();
    sqlx::query!(
        r#"INSERT INTO artifacts (name, artifact, host_id, creation_time) VALUES ($1, $2, $3, $4)"#,
        name,
        secret,
        host,
        now
    )
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn list(
    conn: &mut sqlx::SqliteConnection,
    user: api::UserID,
) -> Result<Vec<api::Artifact>, sqlx::Error> {
    let artifacts = sqlx::query!(
        r#"
        SELECT
            a.id as "id!: api::ArtifactID",
            a.name,
            a.creation_time as "creation_time: jiff_sqlx::Timestamp",
            h.id as "host_id: api::HostID"
        FROM artifacts a

        -- Join Hosts (Secret ACL)
        LEFT JOIN hosts h ON a.host_id = h.id

        -- Join View to find authorized Secrets
        JOIN access a_h
            ON h.id = a_h.resource_id
            AND a_h.resource_type = $2
            AND a_h.user_id = $1
        "#,
        user,
        api::tag::ResourceType::Host
    )
    .map(|row| api::Artifact {
        id: row.id,
        name: row.name,
        host: row.host_id,
        creation_time: row.creation_time.to_jiff(),
    })
    .fetch_all(conn)
    .await?;

    Ok(artifacts)
}

error_set::error_set! {
    GetArtifactError := {
        #[display("Could not encrypt the artifact for the target: {0}")]
        Encrypt(age::EncryptError),
        Decrypt(age::DecryptError),
        SQLX(sqlx::Error),
    }
}

pub async fn get_latest<R: age::Recipient, I: age::Identity>(
    conn: &mut sqlx::SqliteConnection,
    artifact: &str,
    store_key: &I,
    host: api::HostID,
    recipient: &R,
) -> Result<Option<Vec<u8>>, GetArtifactError> {
    let Some(artifact) = sqlx::query_scalar!(
        r#"SELECT artifact FROM artifacts WHERE name = $1 AND host_id = $2"#,
        artifact,
        host
    )
    .fetch_optional(&mut *conn)
    .await?
    else {
        return Ok(None);
    };

    let decrypted = age::decrypt(store_key, &artifact)?;
    Ok(Some(age::encrypt(recipient, &decrypted)?))
}

pub async fn get_artifact<R: age::Recipient, I: age::Identity>(
    conn: &mut sqlx::SqliteConnection,
    artifact: api::ArtifactID,
    store_key: &I,
    recipient: &R,
) -> Result<Vec<u8>, GetArtifactError> {
    let artifact = sqlx::query_scalar!(r#"SELECT artifact FROM artifacts WHERE id = $1"#, artifact)
        .fetch_one(&mut *conn)
        .await?;

    let decrypted = age::decrypt(store_key, &artifact)?;
    Ok(age::encrypt(recipient, &decrypted)?)
}

pub async fn get_owner(
    conn: &mut sqlx::SqliteConnection,
    artifact: api::ArtifactID,
) -> Result<api::HostID, sqlx::Error> {
    let id = sqlx::query_scalar!(
        r#"SELECT host_id as "id: api::HostID" FROM artifacts WHERE id = $1"#,
        artifact
    )
    .fetch_one(&mut *conn)
    .await?;

    Ok(id)
}
