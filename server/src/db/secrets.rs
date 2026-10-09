//! Store age encrypted secret with a name. Names have to be unique
//! The idea is that all secrets are encrypted with a single age encryption key
//! Then once a client want to get the secret you call `get_secret_for` which will
//! test if the host is allowed to access the secret and if true will decrypt the
//! secret and re-encrypt it for the host. This ensures encryption at rest and
//! handles ACLs
//!
//! A possible hardening method would to instead use a single server key to encrypt the secrets
//! encrypt them with all the hosts that have currently access. The contra is that
//! the all the keys are non ephemeral but then secrets are truly encrypted at rest
//! because an attack would need to also obtain the identity key of a hosts that
//! has access to the secrets

use sqlx::types::Json;

error_set::error_set! {
    AddSecretError := {
        #[display("Secret is not encrytped")]
        UnencryptedSecretError(age::DecryptError),
        SQLXError(sqlx::Error),
    }
}

/// The secrets needs to be encrypted with the servers identity key
/// retrieve it with GET `/secret/server_key`
/// Add a new secret - `store_key` required to test if it is an actual encrypted secret and not bogus
pub async fn add_secret<I: age::Identity, S: Into<String>, V: Into<Vec<u8>>>(
    conn: &mut sqlx::SqliteConnection,
    name: S,
    secret: V,
    store_key: &I,
) -> Result<api::SecretName, AddSecretError> {
    let secret = secret.into();
    let name = name.into();
    // test if secret is decryptable
    let _: Vec<u8> = age::decrypt(store_key, &secret)?;
    let row = sqlx::query!(
        r#"INSERT INTO secrets (name, secret) VALUES ($1, $2)"#,
        name,
        secret
    )
    .execute(conn)
    .await?;
    Ok(api::SecretName {
        id: api::SecretID::new(row.last_insert_rowid()),
        name,
        tags: Vec::new(),
        hosts: Vec::new(),
    })
}

error_set::error_set! {
    GetSecretError := {
        #[display("Could not encrypt the secret for the target: {0}")]
        Encrypt(age::EncryptError),
        Decrypt(age::DecryptError),
        SQLX(sqlx::Error),
    }
}

/// Security: the caller is responsible to make sure that `recipient` equals `host`
///     If this identity is not verified a malicious actor could insert his identity
///     and retrieve a secret that is checked by another acl
///     This is because each identity is thought to be ephemeral
/// Prepares a secret for a host by decrypting and the encrypting it
/// Returns `Ok(None)` if the host is not allowed to access the secret or if the secret does not exist
pub async fn get_secret_for<R: age::Recipient, I: age::Identity>(
    conn: &mut sqlx::SqliteConnection,
    secret: &str,
    store_key: &I,
    host: api::HostID,
    recipient: &R,
) -> Result<Option<Vec<u8>>, GetSecretError> {
    // TODO transaction so that no TOCTOU can occur

    let Some(secret) = sqlx::query_scalar!(
        r#"SELECT id as "id: api::SecretID" FROM secrets WHERE name = $1"#,
        secret
    )
    .fetch_optional(&mut *conn)
    .await?
    else {
        return Ok(None);
    };

    // return if the host has no access
    if !check_acl(conn, secret, host).await? {
        return Ok(None);
    }

    // since we checked the acl this means that the secret has to exist
    let secret = sqlx::query_scalar!(r#"SELECT secret FROM secrets WHERE id = $1"#, secret)
        .fetch_one(conn)
        .await?;

    let decrypted = age::decrypt(store_key, &secret)?;
    Ok(Some(age::encrypt(recipient, &decrypted)?))
}

async fn check_acl(
    conn: &mut sqlx::SqliteConnection,
    secret: api::SecretID,
    host: api::HostID,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar!(
        r#"SELECT EXISTS(SELECT 1 FROM secrets_acl WHERE secret_id = $1 AND host_id = $2) AS 'exists!: bool'"#,
        secret,
        host
    )
    .fetch_one(conn)
    .await
}

/// Adds the specified host to the acl of a secret
/// Can fail if the secret or host do not exist
pub async fn add_access_for(
    conn: &mut sqlx::SqliteConnection,
    secret: api::SecretID,
    host: api::HostID,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"INSERT INTO secrets_acl (secret_id, host_id) VALUES ($1,$2)"#,
        secret,
        host
    )
    .execute(conn)
    .await?;
    Ok(())
}

/// Removes the specified host to the acl of a secret
pub async fn remove_access_for(
    conn: &mut sqlx::SqliteConnection,
    secret: api::SecretID,
    host: api::HostID,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"DELETE FROM secrets_acl WHERE secret_id = $1 AND host_id = $2"#,
        secret,
        host
    )
    .execute(conn)
    .await?;
    Ok(())
}

/// Removes the specified host to the acl of a secret
pub async fn remove_secret(
    conn: &mut sqlx::SqliteConnection,
    secret: api::SecretID,
) -> Result<(), sqlx::Error> {
    sqlx::query!(r#"DELETE FROM secrets WHERE id = $1"#, secret)
        .execute(conn)
        .await?;
    Ok(())
}

pub async fn list_secrets(
    conn: &mut sqlx::SqliteConnection,
    user: api::UserID,
) -> Result<Vec<api::SecretName>, sqlx::Error> {
    let secrets = sqlx::query!(
        r#"
        SELECT
            s.id as "id!: api::SecretID",
            s.name,
            -- Gather tags authorized for this User+Secret via the View
            json_group_array(
                json_object('id', t.id, 'name', t.name)
            ) FILTER (WHERE t.id IS NOT NULL) as "tags!: Json<Vec<api::tag::Tag>>",
            -- Gather hosts authorized for this User+Host via the View
            json_group_array(sacl.host_id)
                FILTER (WHERE a_h.resource_id IS NOT NULL)
                as "hosts!: Json<Vec<api::HostID>>"
        FROM secrets s

        -- Join View to find authorized Secrets
        JOIN access a_s
            ON s.id = a_s.resource_id
            AND a_s.resource_type = $2
            AND a_s.user_id = $1
        -- Get tag details for the secret
        LEFT JOIN tags t ON t.id = a_s.tag_id

        -- Join Hosts (Secret ACL)
        LEFT JOIN secrets_acl sacl ON s.id = sacl.secret_id

        -- Join View to verify the User is allowed to see these specific Hosts
        LEFT JOIN access a_h
            ON sacl.host_id = a_h.resource_id
            AND a_h.resource_type = $3
            AND a_h.user_id = $1
        GROUP BY s.id, s.name
        "#,
        user,
        api::tag::ResourceType::Secret,
        api::tag::ResourceType::Host
    )
    .map(|row| api::SecretName {
        id: row.id,
        name: row.name,
        tags: row.tags.0,
        hosts: row.hosts.0,
    })
    .fetch_all(conn)
    .await?;

    Ok(secrets)
}

/// Rename a secret including its acl
pub async fn rename_secret(
    conn: &mut sqlx::SqliteConnection,
    id: api::SecretID,
    new: String,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        UPDATE secrets
        SET name = $1
        WHERE id = $2"#,
        new,
        id
    )
    .execute(conn)
    .await?;
    Ok(())
}
