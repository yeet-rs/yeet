use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Config {
    pub client: defectdojo::Client,
    pub organization: defectdojo::OrganizationID,
}

pub enum Action {
    CreateNode(String),
}

error_set::error_set! {
    DefectdojoError := {
        #[display("Seach returned more than one result for an asset")]
        DuplicateAsset,
        DefectDojo(defectdojo::Error),
        SQLXE(sqlx::Error),
    }
}

pub async fn run(
    config: Config,
    mut receiver: tokio::sync::mpsc::Receiver<Action>,
    pool: sqlx::SqlitePool,
) -> Result<(), DefectdojoError> {
    let mut assets = collect_existing_assets(&mut *pool.acquire().await?, &config).await?;
    while let Some(action) = receiver.recv().await {
        match action {
            Action::CreateNode(node) =>
            {
                #[expect(clippy::map_entry)]
                if assets.contains_key(&node) {
                    log::warn!(
                        "Node {node} was requested to be create in defectdojo altough it was alredy created"
                    );
                } else {
                    let id = create_asset(&config, node.clone()).await?;
                    assets.insert(node, id);
                }
            }
        }
    }
    Ok(())
}

async fn collect_existing_assets(
    conn: &mut sqlx::SqliteConnection,
    config: &Config,
    // todo mixed error
) -> Result<HashMap<String, defectdojo::AssetID>, DefectdojoError> {
    log::info!("Collecting all defectdojo assets");
    let nodes = sqlx::query_scalar!(r#"SELECT host_identifier FROM osquery_nodes"#)
        .fetch_all(conn)
        .await?;

    let mut assets = HashMap::new();

    for node in nodes {
        let search_result: defectdojo::SearchResult<defectdojo::Asset> =
            // TODO unwrap
            defectdojo::Asset::find(&config.client)
                .name(&node)
                .send()
                .await?;
        if search_result.count > 1 {
            return Err(DefectdojoError::DuplicateAsset);
        }

        match search_result.results.first() {
            Some(asset) => assets.insert(node, asset.id),
            // TODO unwrap
            None => assets.insert(node.clone(), create_asset(config, node).await?),
        };
    }

    Ok(assets)
}

async fn create_asset(
    config: &Config,
    node: String,
) -> Result<defectdojo::AssetID, defectdojo::Error> {
    log::info!("Creating `{node}` in defectdojo");
    let asset = defectdojo::Asset::create(&config.client)
        .organization(config.organization)
        .description("value")
        .name(node)
        .send()
        .await?;
    Ok(asset.id)
}
