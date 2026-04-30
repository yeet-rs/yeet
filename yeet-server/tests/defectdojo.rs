use std::str::FromStr;

use tokio::time::sleep;

static URL: Option<&'static str> = option_env!("YEET_DEFECTDOJO_URL");
static TOKEN: Option<&'static str> = option_env!("YEET_DEFECTDOJO_TOKEN");
static ORG: Option<&'static str> = option_env!("YEET_DEFECTDOJO_ORGANIZATION");

#[sqlx::test]
#[ignore]
async fn asset_creation(pool: sqlx::SqlitePool) {
    let _tracer = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .or_else(|_| tracing_subscriber::EnvFilter::try_new("info"))
                .expect("Could not init tracing logger"),
        )
        .try_init();

    let mut conn = pool.acquire().await.unwrap();
    sqlx::migrate!("../migrations")
        .run(&mut conn)
        .await
        .unwrap();

    let config = {
        let client =
            defectdojo::Client::new(URL.unwrap().parse().unwrap(), TOKEN.unwrap()).unwrap();
        yeetd::defectdojo::Config {
            client,
            organization: u32::from_str(&ORG.unwrap()).unwrap().into(),
        }
    };

    let uuid = uuid::Uuid::now_v7();
    sqlx::query!(
        r#"INSERT INTO osquery_nodes (node_key, host_identifier, platform_type)
       VALUES ($1,$2,$3)"#,
        uuid,
        "host1",
        "9"
    )
    .execute(&mut *conn)
    .await
    .unwrap();

    let (tx, rx) = tokio::sync::mpsc::channel(5);
    {
        let config = config.clone();
        let _detached = tokio::spawn(async move { yeetd::defectdojo::run(config, rx, pool).await });
    }

    tx.send_timeout(
        yeetd::defectdojo::Action::CreateNode("host2".to_owned()),
        std::time::Duration::from_secs(1),
    )
    .await
    .unwrap();
    sleep(std::time::Duration::from_secs(1)).await;
    let host1 = defectdojo::Asset::find(&config.client)
        .name("host1")
        .send()
        .await
        .unwrap();
    let host2 = defectdojo::Asset::find(&config.client)
        .name("host2")
        .send()
        .await
        .unwrap();

    assert_eq!(host1.results.len(), 1);
    assert_eq!(host2.results.len(), 1);

    host1
        .results
        .first()
        .unwrap()
        .delete(&config.client)
        .await
        .unwrap();
    host2
        .results
        .first()
        .unwrap()
        .delete(&config.client)
        .await
        .unwrap();
}
