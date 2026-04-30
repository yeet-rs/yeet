// /// Node `host_identifier` -> defectojo asset id
// pub defectdojo_assets: HashMap<String, u32>,

pub struct Config {
    pub client: defectdojo::Client,
    pub organization_name: String,
}

pub enum Action {
    AddNode(api::NodeID),
}

pub async fn run(
    config: Config,
    mut receiver: tokio::sync::mpsc::Receiver<Action>,
    pool: sqlx::SqlitePool,
) -> Result<(), sqlx::Error> {
    while let Some(action) = receiver.recv().await {
        match action {
            Action::AddNode(node_id) => todo!(),
        }
    }
    Ok(())
}
