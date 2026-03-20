use std::{collections::HashMap, str::FromStr};

use ed25519_dalek::SigningKey;
use httpsig_hyper::prelude::{AlgorithmName, SecretKey};

use yeet_api as api;

#[sqlx::test]
/// This does not test authentication / system checks
fn api_e2e_with_credentials(pool: sqlx::SqlitePool) {
    let _handle = yeetd::launch("4337", "localhost", pool, age::x25519::Identity::generate()).await;

    let url = url::Url::from_str("http://localhost:4337").unwrap();

    // first we need to add our admin credentials.
    // The api will allow us to add it when no credentials are specified yet

    let admin_key = SigningKey::from_bytes(&[4; 32]);
    let key = SecretKey::from_bytes(&AlgorithmName::Ed25519, &[4; 32]).unwrap();

    api::add_key(
        &url,
        &key,
        &api::AddKey {
            key: admin_key.verifying_key(),
            level: api::AuthLevel::Admin,
        },
    )
    .await
    .unwrap();

    // The first thing a new host does is to create a verification attempt
    let new_host = SigningKey::from_bytes(&[3; 32]);
    let client_key = SecretKey::from_bytes(&AlgorithmName::Ed25519, &[3; 32]).unwrap();

    let code = api::add_verification_attempt(
        &url,
        &api::VerificationAttempt {
            key: new_host.verifying_key(),
            nixos_facter: Some("Just some facts about a host".into()),
        },
    )
    .await
    .unwrap();

    assert!(code >= 100_000 && code <= 999_999);

    // The next thing is for an admin to approve this request
    let facter = api::accept_attempt(&url, &key, code as u32, "mysuperhostname")
        .await
        .unwrap();

    assert_eq!(facter, Some("Just some facts about a host".into()));

    // Now that we have a host we may want to list it
    let hosts = api::list_hosts(&url, &key).await.unwrap();
    assert_eq!(
        hosts.first().unwrap().hostname,
        "mysuperhostname".to_owned()
    );
    assert_eq!(hosts.first().unwrap().state, api::ProvisionState::NotSet);
    assert_eq!(hosts.first().unwrap().version, None);
    assert_eq!(hosts.first().unwrap().latest_update, None);

    // lets push an update to the host
    api::update_hosts(
        &url,
        &key,
        &api::HostUpdateRequest {
            hosts: HashMap::from([("mysuperhostname".into(), "mysuperversion".into())]),
            public_key: "mypublickey".into(),
            substitutor: "mycache".into(),
        },
    )
    .await
    .unwrap();
    // Now it should be provisioned and have an latest_update. no latest_version tough
    let hosts = api::list_hosts(&url, &key).await.unwrap();

    assert_eq!(
        hosts.first().unwrap().state,
        api::ProvisionState::Provisioned
    );
    assert_eq!(hosts.first().unwrap().version, None);
    assert_eq!(
        hosts.first().unwrap().latest_update,
        Some("mysuperversion".into())
    );

    // We simulate that the hosts now has pinged the system but provided an old version
    // Yeet now tasks the agent to update
    let action = api::check_system(
        &url,
        &client_key,
        &api::VersionRequest {
            store_path: "myoldversion".into(),
        },
    )
    .await
    .unwrap();

    assert_eq!(
        action,
        api::AgentAction::SwitchTo(api::RemoteStorePath {
            public_key: "mypublickey".into(),
            store_path: "mysuperversion".into(),
            substitutor: "mycache".into()
        })
    );

    // If we do not udpate yet but look at the host we see that he has now an latest version
    let hosts = api::list_hosts(&url, &key).await.unwrap();
    assert_eq!(hosts.first().unwrap().version, Some("myoldversion".into()));

    // The agent now signals the server that he has done the update
    let action = api::check_system(
        &url,
        &client_key,
        &api::VersionRequest {
            store_path: "mysuperversion".into(),
        },
    )
    .await
    .unwrap();
    // The server is satisfied and does not require the agent to do anything
    assert_eq!(action, api::AgentAction::Nothing);

    // The server reflects the update
    let hosts = api::list_hosts(&url, &key).await.unwrap();
    assert_eq!(
        hosts.first().unwrap().version,
        Some("mysuperversion".into())
    );

    // Kinda bored of `mysuperhostname` lets rename it
    api::rename_host(&url, &key, hosts.first().unwrap().id, "mynewname")
        .await
        .unwrap();

    let hosts = api::list_hosts(&url, &key).await.unwrap();
    assert_eq!(hosts.first().unwrap().hostname, "mynewname".to_owned());

    // The agent now decide he no longer wants to listen to the server and detaches

    api::detach_self(&url, &client_key).await.unwrap();

    // This is shown as state: Detach
    let hosts = api::list_hosts(&url, &key).await.unwrap();
    assert_eq!(hosts.first().unwrap().state, api::ProvisionState::Detached);

    // And as `AgentAction::Detach`
    let action = api::check_system(
        &url,
        &client_key,
        &api::VersionRequest {
            store_path: "mydetachedversion".into(),
        },
    )
    .await
    .unwrap();
    assert_eq!(action, api::AgentAction::Detach);

    // But the version information is still logged
    let hosts = api::list_hosts(&url, &key).await.unwrap();
    assert_eq!(
        hosts.first().unwrap().version,
        Some("mydetachedversion".into())
    );

    // even if we push an update the agent stays detached
    api::update_hosts(
        &url,
        &key,
        &api::HostUpdateRequest {
            hosts: HashMap::from([("mynewname".into(), "mynewversion".into())]),
            public_key: "mypublickey".into(),
            substitutor: "mycache".into(),
        },
    )
    .await
    .unwrap();

    let hosts = api::list_hosts(&url, &key).await.unwrap();
    assert_eq!(hosts.first().unwrap().state, api::ProvisionState::Detached);

    // Ok but now stop fooling around and attach again
    api::attach_self(&url, &client_key).await.unwrap();

    // The agent is managed again
    let hosts = api::list_hosts(&url, &key).await.unwrap();
    assert_eq!(
        hosts.first().unwrap().state,
        api::ProvisionState::Provisioned
    );

    // And forced to switch to the new version
    let action = api::check_system(
        &url,
        &client_key,
        &api::VersionRequest {
            store_path: "mydetachedversion".into(),
        },
    )
    .await
    .unwrap();

    assert_eq!(
        action,
        api::AgentAction::SwitchTo(api::RemoteStorePath {
            public_key: "mypublickey".into(),
            store_path: "mynewversion".into(),
            substitutor: "mycache".into()
        })
    );
    // lets be nice and do the update
    let action = api::check_system(
        &url,
        &client_key,
        &api::VersionRequest {
            store_path: "mynewversion".into(),
        },
    )
    .await
    .unwrap();

    assert_eq!(action, api::AgentAction::Nothing);
    // make sure the server tells the same story
    let hosts = api::list_hosts(&url, &key).await.unwrap();
    assert_eq!(hosts.first().unwrap().version, Some("mynewversion".into()));

    // Ok now maybe we want to create a secret for the host
    // first we have to get the encryption key of the server
    let server_key = api::server_age_key(&url, &key).await.unwrap();
    let server_key = age::x25519::Recipient::from_str(&server_key).unwrap();
    let _ups = api::add_secret(
        &url,
        &key,
        "mysecret",
        &age::encrypt(&server_key, b"secretstuff").unwrap(),
    )
    .await
    .unwrap();

    // the client tries to get the secret but fails because he is not authorized
    // but first the client needs to generate a recipient key

    let secret = api::get_secret(&url, &client_key, "mysecret".into())
        .await
        .unwrap();
    assert!(secret.is_none());

    // so lets give the client permission. but oh wait i forgor the note the secretid and hostid
    // lets list all secrets
    let secrets = api::list_secrets(&url, &key).await.unwrap();
    let secret = secrets.first().unwrap();
    assert_eq!(secret.name, "mysecret".to_owned());

    // and hosts
    let hosts = api::list_hosts(&url, &key).await.unwrap();
    let host = hosts.first().unwrap();
    assert_eq!(host.hostname, "mynewname".to_owned());

    // now allow the host
    api::allow_host(&url, &key, secret.id, host.id)
        .await
        .unwrap();

    // the client can now get the secret
    let secret = api::get_secret(&url, &client_key, "mysecret".into())
        .await
        .unwrap();
    assert_eq!(secret, Some(b"secretstuff".to_vec()));
}
