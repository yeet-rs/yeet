use std::{collections::HashMap, str::FromStr};

use ed25519_dalek::SigningKey;

#[sqlx::test]
#[cfg(feature = "test-server")]
/// This does not test authentication / system checks
fn server_e2e_with_secret(pool: sqlx::SqlitePool) {
    let server = yeetd::test_server(pool.clone()).await;

    let new_host = SigningKey::from_bytes(&[3; 32]);

    // The first thing a new host does is to create a verification attempt
    let code: i64 = server
        .post("/verification/add")
        .json(&api::verify::VerificationAttempt {
            key: new_host.verifying_key(),
            nixos_facter: Some("Just some facts about a host".into()),
        })
        .await
        .json();

    assert!(code >= 100_000 && code <= 999_999);

    // The next thing is for an admin to approve this request
    let facter: Option<String> = server
        .put(&format!("/verification/{code}/accept"))
        .json("mysuperhostname")
        .await
        .json();

    assert_eq!(facter, Some("Just some facts about a host".into()));

    // Now that we have a host we may want to list it
    let hosts: Vec<api::host::Host> = server.get("/host/list").await.json();
    assert_eq!(
        hosts.first().unwrap().hostname,
        "mysuperhostname".to_owned()
    );
    assert_eq!(hosts.first().unwrap().state, api::ProvisionState::NotSet);
    assert_eq!(hosts.first().unwrap().version, None);
    assert_eq!(hosts.first().unwrap().latest_update, None);

    // lets push an update to the host
    server
        .post("/host/update")
        .json(&api::HostUpdateRequest {
            hosts: HashMap::from([("mysuperhostname".into(), "mysuperversion".into())]),
            public_key: "mypublickey".into(),
            substitutor: "mycache".into(),
        })
        .await;
    // Now it should be provisioned and have an latest_update. no latest_version tough
    let hosts: Vec<api::host::Host> = server.get("/host/list").await.json();

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
    let action: api::AgentAction = server
        .post("/system/check")
        .add_header(
            "key",
            serde_json::to_string(&new_host.verifying_key()).unwrap(),
        )
        .json(&api::VersionRequest {
            store_path: "myoldversion".into(),
        })
        .await
        .json();

    assert_eq!(
        action,
        api::AgentAction::SwitchTo(api::RemoteStorePath {
            public_key: "mypublickey".into(),
            store_path: "mysuperversion".into(),
            substitutor: "mycache".into()
        })
    );

    // If we do not udpate yet but look at the host we see that he has now an latest version
    let hosts: Vec<api::host::Host> = server.get("/host/list").await.json();
    assert_eq!(hosts.first().unwrap().version, Some("myoldversion".into()));

    // The agent now signals the server that he has done the update
    let action: api::AgentAction = server
        .post("/system/check")
        .add_header(
            "key",
            serde_json::to_string(&new_host.verifying_key()).unwrap(),
        )
        .json(&api::VersionRequest {
            store_path: "mysuperversion".into(),
        })
        .await
        .json();
    // The server is satisfied and does not require the agent to do anything
    assert_eq!(action, api::AgentAction::Nothing);

    // The server reflects the update
    let hosts: Vec<api::host::Host> = server.get("/host/list").await.json();
    assert_eq!(
        hosts.first().unwrap().version,
        Some("mysuperversion".into())
    );

    // Kinda bored of `mysuperhostname` lets rename it
    server
        .put(&format!(
            "/host/{}/rename/mynewname",
            hosts.first().unwrap().id
        ))
        .await;
    let hosts: Vec<api::host::Host> = server.get("/host/list").await.json();
    assert_eq!(hosts.first().unwrap().hostname, "mynewname".to_owned());

    // The agent now decide he no longer wants to listen to the server and detaches
    server
        .put("/system/self/detach")
        .add_header(
            "key",
            serde_json::to_string(&new_host.verifying_key()).unwrap(),
        )
        .await;
    // This is shown as state: Detach
    let hosts: Vec<api::host::Host> = server.get("/host/list").await.json();
    assert_eq!(hosts.first().unwrap().state, api::ProvisionState::Detached);

    // And as `AgentAction::Detach`
    let action: api::AgentAction = server
        .post("/system/check")
        .add_header(
            "key",
            serde_json::to_string(&new_host.verifying_key()).unwrap(),
        )
        .json(&api::VersionRequest {
            store_path: "mydetachedversion".into(),
        })
        .await
        .json();
    assert_eq!(action, api::AgentAction::Detach);

    // But the version information is still logged
    let hosts: Vec<api::host::Host> = server.get("/host/list").await.json();
    assert_eq!(
        hosts.first().unwrap().version,
        Some("mydetachedversion".into())
    );

    // even if we push an update the agent stays detached
    server
        .post("/host/update")
        .json(&api::HostUpdateRequest {
            hosts: HashMap::from([("mynewname".into(), "mynewversion".into())]),
            public_key: "mypublickey".into(),
            substitutor: "mycache".into(),
        })
        .await;
    let hosts: Vec<api::host::Host> = server.get("/host/list").await.json();
    assert_eq!(hosts.first().unwrap().state, api::ProvisionState::Detached);

    // Ok but now stop fooling around and attach again
    server
        .put("/system/self/attach")
        .add_header(
            "key",
            serde_json::to_string(&new_host.verifying_key()).unwrap(),
        )
        .await;

    // The agent is managed again
    let hosts: Vec<api::host::Host> = server.get("/host/list").await.json();
    assert_eq!(
        hosts.first().unwrap().state,
        api::ProvisionState::Provisioned
    );

    // And forced to switch to the new version
    let action: api::AgentAction = server
        .post("/system/check")
        .add_header(
            "key",
            serde_json::to_string(&new_host.verifying_key()).unwrap(),
        )
        .json(&api::VersionRequest {
            store_path: "mydetachedversion".into(),
        })
        .await
        .json();

    assert_eq!(
        action,
        api::AgentAction::SwitchTo(api::RemoteStorePath {
            public_key: "mypublickey".into(),
            store_path: "mynewversion".into(),
            substitutor: "mycache".into()
        })
    );
    // lets be nice and do the update
    let action: api::AgentAction = server
        .post("/system/check")
        .add_header(
            "key",
            serde_json::to_string(&new_host.verifying_key()).unwrap(),
        )
        .json(&api::VersionRequest {
            store_path: "mynewversion".into(),
        })
        .await
        .json();
    assert_eq!(action, api::AgentAction::Nothing);
    // make sure the server tells the same story
    let hosts: Vec<api::host::Host> = server.get("/host/list").await.json();
    assert_eq!(hosts.first().unwrap().version, Some("mynewversion".into()));

    // Ok now maybe we want to create a secret for the host
    // first we have to get the encryption key of the server
    let server_key: String = server.get("/secret/server_key").await.json();
    let server_key = age::x25519::Recipient::from_str(&server_key).unwrap();
    server
        .post("/secret/add/mysecret")
        .json(&age::encrypt(&server_key, b"secretstuff").unwrap())
        .await;

    // the client tries to get the secret but fails because he is not authorized
    // but first the client needs to generate a recipient key
    let client_key = age::x25519::Identity::generate();
    let secret: Option<Vec<u8>> = server
        .post("/secret")
        .add_header(
            "key",
            serde_json::to_string(&new_host.verifying_key()).unwrap(),
        )
        .json(&api::GetSecretRequest {
            recipient: client_key.to_public().to_string(),
            secret: "mysecret".into(),
        })
        .await
        .json();
    assert!(secret.is_none());

    // so lets give the client permission. but oh wait i forgor the note the secretid and hostid
    // lets list all secrets
    let secrets: Vec<api::SecretName> = server.get("/secret/list").await.json();
    let secret = secrets.first().unwrap();
    assert_eq!(secret.name, "mysecret".to_owned());

    // and hosts
    let hosts: Vec<api::host::Host> = server.get("/host/list").await.json();
    let host = hosts.first().unwrap();
    assert_eq!(host.hostname, "mynewname".to_owned());

    // now allow the host
    server
        .put(&format!("/secret/{}/allow/{}", secret.id, host.id))
        .await;

    // the client can now get the secret
    let secret: Option<Vec<u8>> = server
        .post("/secret")
        .add_header(
            "key",
            serde_json::to_string(&new_host.verifying_key()).unwrap(),
        )
        .json(&api::GetSecretRequest {
            recipient: client_key.to_public().to_string(),
            secret: "mysecret".into(),
        })
        .await
        .json();
    let secret = age::decrypt(&client_key, &secret.unwrap()).unwrap();
    assert_eq!(secret, b"secretstuff");
}
