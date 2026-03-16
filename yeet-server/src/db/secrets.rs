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

use std::collections::HashMap;

use futures::TryStreamExt as _;

error_set::error_set! {
    AddSecretError := {
        #[display("Secret is not encrytped")]
        UnencryptedSecretError(age::DecryptError),
        SQLXError(sqlx::Error),
    }
}

/// Add a new secret - `store_key` required to test if it is an actual encrypted secret and not bogus
pub async fn add_secret<I: age::Identity, S: Into<String>, V: Into<Vec<u8>>>(
    conn: &mut sqlx::SqliteConnection,
    name: S,
    secret: V,
    store_key: &I,
) -> Result<api::SecretID, AddSecretError> {
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
    Ok(api::SecretID::new(row.last_insert_rowid()))
}

error_set::error_set! {
    GetSecretError := {
        #[display("Could not encrypt the secret for the target: {0}")]
        EncryptError(age::EncryptError),
        DecryptError(age::DecryptError),
        SQLXError(sqlx::Error),
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
    Ok(sqlx::query_scalar!(
        r#"SELECT EXISTS(SELECT 1 FROM secrets_acl WHERE secret_id = $1 AND host_id = $2) AS 'exists!: bool'"#,
        secret,
        host
    )
    .fetch_one(conn)
    .await?)
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

/// list secrets
pub async fn list_secrets(
    conn: &mut sqlx::SqliteConnection,
) -> Result<Vec<api::SecretName>, sqlx::Error> {
    let secrets = sqlx::query!(r#"SELECT id, name FROM secrets"#)
        .map(|r| api::SecretName {
            id: api::SecretID::new(r.id),
            name: r.name,
        })
        .fetch_all(conn)
        .await?;

    Ok(secrets)
}

/// list acl
pub async fn list_acl(
    conn: &mut sqlx::SqliteConnection,
) -> Result<HashMap<api::SecretID, Vec<api::HostID>>, sqlx::Error> {
    let secrets = sqlx::query!(r#"SELECT secret_id, host_id FROM secrets_acl"#)
        .fetch(conn)
        .map_ok(|r| (api::SecretID::new(r.secret_id), api::HostID::new(r.host_id)))
        .try_fold(
            HashMap::<_, Vec<_>>::new(),
            |mut acc, (key, value)| async move {
                acc.entry(key).or_default().push(value);
                Ok(acc)
            },
        )
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

#[cfg(test)]
mod test {

    use ed25519_dalek::{SigningKey, VerifyingKey};

    use crate::db::{self};

    #[sqlx::test]
    async fn create_and_retrieve_secret(pool: sqlx::SqlitePool) {
        let mut conn = pool.acquire().await.unwrap();
        sqlx::migrate!("../migrations")
            .run(&mut conn)
            .await
            .unwrap();

        let store_key = age::x25519::Identity::generate();
        let host = age::x25519::Identity::generate();
        let my_host = db::hosts::add_host(
            &mut conn,
            "keyid".to_owned(),
            VerifyingKey::default(),
            "hostname".to_owned(),
        )
        .await
        .unwrap();

        let encrypted = age::encrypt(&store_key.to_public(), b"secret_text").unwrap();

        let my_secret = db::secrets::add_secret(&mut conn, "my_secret", encrypted, &store_key)
            .await
            .unwrap();

        db::secrets::add_access_for(&mut conn, my_secret, my_host)
            .await
            .unwrap();

        let encrypted_for_host = db::secrets::get_secret_for(
            &mut conn,
            "my_secret",
            &store_key,
            my_host,
            &host.to_public(),
        )
        .await
        .unwrap()
        .unwrap();

        let decrypted = age::decrypt(&host, &encrypted_for_host).unwrap();
        assert_eq!(decrypted, b"secret_text");
    }

    #[sqlx::test]
    async fn retrieve_without_access(pool: sqlx::SqlitePool) {
        let mut conn = pool.acquire().await.unwrap();
        sqlx::migrate!("../migrations")
            .run(&mut conn)
            .await
            .unwrap();

        let store_key = age::x25519::Identity::generate();
        let host = age::x25519::Identity::generate();

        let encrypted = age::encrypt(&store_key.to_public(), b"secret_text").unwrap();

        let _my_secret = db::secrets::add_secret(&mut conn, "my_secret", encrypted, &store_key)
            .await
            .unwrap();

        let secret = db::secrets::get_secret_for(
            &mut conn,
            "my_secret",
            &store_key,
            api::HostID::new(1),
            &host.to_public(),
        )
        .await
        .unwrap();

        assert!(secret.is_none());
    }

    #[sqlx::test]
    async fn remove_access(pool: sqlx::SqlitePool) {
        let mut conn = pool.acquire().await.unwrap();
        sqlx::migrate!("../migrations")
            .run(&mut conn)
            .await
            .unwrap();

        let store_key = age::x25519::Identity::generate();
        let host = age::x25519::Identity::generate();
        let my_host = db::hosts::add_host(
            &mut conn,
            "keyid".to_owned(),
            VerifyingKey::default(),
            "hostname".to_owned(),
        )
        .await
        .unwrap();

        let encrypted = age::encrypt(&store_key.to_public(), b"secret_text").unwrap();

        let secret = db::secrets::add_secret(&mut conn, "my_secret", encrypted, &store_key)
            .await
            .unwrap();

        db::secrets::add_access_for(&mut conn, secret, my_host)
            .await
            .unwrap();

        let _: Vec<u8> = db::secrets::get_secret_for(
            &mut conn,
            "my_secret",
            &store_key,
            my_host,
            &host.to_public(),
        )
        .await
        .unwrap()
        .unwrap();

        db::secrets::remove_access_for(&mut conn, secret, my_host)
            .await
            .unwrap();

        let secret = db::secrets::get_secret_for(
            &mut conn,
            "my_secret",
            &store_key,
            my_host,
            &host.to_public(),
        )
        .await
        .unwrap();

        assert!(secret.is_none());
    }

    #[sqlx::test]
    async fn check_acl(pool: sqlx::SqlitePool) {
        let mut conn = pool.acquire().await.unwrap();
        sqlx::migrate!("../migrations")
            .run(&mut conn)
            .await
            .unwrap();
        let store_key = age::x25519::Identity::generate();

        let my_host = db::hosts::add_host(
            &mut conn,
            "keyid".to_owned(),
            VerifyingKey::default(),
            "hostname".to_owned(),
        )
        .await
        .unwrap();

        let h2 = db::hosts::add_host(
            &mut conn,
            "keyid2".to_owned(),
            SigningKey::from_bytes(&[1; 32]).verifying_key(),
            "hostname2".to_owned(),
        )
        .await
        .unwrap();

        let encrypted = age::encrypt(&store_key.to_public(), b"secret_text").unwrap();

        let my_secret =
            db::secrets::add_secret(&mut conn, "my_secret", encrypted.clone(), &store_key)
                .await
                .unwrap();
        let secret2 = db::secrets::add_secret(&mut conn, "secret2", encrypted, &store_key)
            .await
            .unwrap();

        db::secrets::add_access_for(&mut conn, my_secret, my_host)
            .await
            .unwrap();

        db::secrets::add_access_for(&mut conn, secret2, my_host)
            .await
            .unwrap();

        db::secrets::add_access_for(&mut conn, secret2, h2)
            .await
            .unwrap();

        assert!(
            db::secrets::check_acl(&mut conn, my_secret, my_host)
                .await
                .unwrap()
        );

        assert!(
            db::secrets::check_acl(&mut conn, secret2, my_host)
                .await
                .unwrap()
        );

        assert!(
            db::secrets::check_acl(&mut conn, secret2, h2)
                .await
                .unwrap()
        );
    }

    #[sqlx::test]
    async fn non_encrypted(pool: sqlx::SqlitePool) {
        let mut conn = pool.acquire().await.unwrap();
        sqlx::migrate!("../migrations")
            .run(&mut conn)
            .await
            .unwrap();
        let store_key = age::x25519::Identity::generate();

        assert!(
            db::secrets::add_secret(&mut conn, "my_secret", b"secret_text", &store_key)
                .await
                .is_err()
        );
    }

    #[sqlx::test]
    fn rename_secret(pool: sqlx::SqlitePool) {
        let mut conn = pool.acquire().await.unwrap();
        sqlx::migrate!("../migrations")
            .run(&mut conn)
            .await
            .unwrap();
        let store_key = age::x25519::Identity::generate();

        let encrypted = age::encrypt(&store_key.to_public(), b"secret_text").unwrap();

        let my_secret = db::secrets::add_secret(&mut conn, "my_secret", encrypted, &store_key)
            .await
            .unwrap();

        db::secrets::rename_secret(&mut conn, my_secret, "newsecret".to_owned())
            .await
            .unwrap();

        assert!(
            db::secrets::list_secrets(&mut conn)
                .await
                .unwrap()
                .contains(&api::SecretName {
                    id: my_secret,
                    name: "newsecret".to_owned()
                })
        );
    }

    #[sqlx::test]
    fn remove_secret(pool: sqlx::SqlitePool) {
        let mut conn = pool.acquire().await.unwrap();
        sqlx::migrate!("../migrations")
            .run(&mut conn)
            .await
            .unwrap();
        let store_key = age::x25519::Identity::generate();

        let my_host = db::hosts::add_host(
            &mut conn,
            "keyid".to_owned(),
            VerifyingKey::default(),
            "hostname".to_owned(),
        )
        .await
        .unwrap();

        let encrypted = age::encrypt(&store_key.to_public(), b"secret_text").unwrap();

        let my_secret = db::secrets::add_secret(&mut conn, "my_secret", encrypted, &store_key)
            .await
            .unwrap();

        db::secrets::add_access_for(&mut conn, my_secret, my_host)
            .await
            .unwrap();

        db::secrets::remove_secret(&mut conn, my_secret)
            .await
            .unwrap();

        assert!(
            db::secrets::list_secrets(&mut conn)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(db::secrets::list_acl(&mut conn).await.unwrap().is_empty());
    }

    #[sqlx::test]
    fn remove_host(pool: sqlx::SqlitePool) {
        let mut conn = pool.acquire().await.unwrap();
        sqlx::migrate!("../migrations")
            .run(&mut conn)
            .await
            .unwrap();
        let store_key = age::x25519::Identity::generate();

        let my_host = db::hosts::add_host(
            &mut conn,
            "keyid".to_owned(),
            VerifyingKey::default(),
            "hostname".to_owned(),
        )
        .await
        .unwrap();

        let encrypted = age::encrypt(&store_key.to_public(), b"secret_text").unwrap();

        let my_secret = db::secrets::add_secret(&mut conn, "my_secret", encrypted, &store_key)
            .await
            .unwrap();

        db::secrets::add_access_for(&mut conn, my_secret, my_host)
            .await
            .unwrap();

        db::hosts::remove_host(&mut conn, my_host).await.unwrap();

        assert!(
            !db::secrets::list_secrets(&mut conn)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(db::secrets::list_acl(&mut conn).await.unwrap().is_empty());
    }
}
