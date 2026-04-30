use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::assets::AssetID;

crate::api_id!(EngagementID);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Engagement {
    pub id: EngagementID,
    pub active: bool,
    pub api_test: bool,
    pub branch_tag: Value,
    pub build_id: Value,
    pub build_server: Value,
    pub check_list: bool,
    pub commit_hash: Value,
    pub created: String,
    pub deduplication_on_engagement: bool,
    pub description: Value,
    pub done_testing: bool,
    pub engagement_type: String,
    pub files: Vec<Value>,
    pub first_contacted: Value,
    pub lead: Value,
    pub name: String,
    pub notes: Vec<Value>,
    pub orchestration_engine: Value,
    pub pen_test: bool,
    pub preset: Value,
    pub product: i64,
    pub progress: String,
    pub reason: Value,
    pub report_type: Value,
    pub requester: Value,
    pub risk_acceptance: Vec<Value>,
    pub source_code_management_server: Value,
    pub source_code_management_uri: Value,
    pub status: String,
    pub tags: Vec<Value>,
    pub target_end: String,
    pub target_start: String,
    pub test_strategy: Value,
    pub threat_model: bool,
    pub tmodel_path: String,
    pub tracker: Value,
    pub updated: String,
    pub version: Value,
}

#[bon::bon]
impl Engagement {
    #[builder(finish_fn = "send", on(String, into))]
    pub async fn create(
        #[builder(start_fn)] client: &crate::Client,
        #[builder(into)] asset: AssetID,
        target_start: String,
        target_end: String,
        name: Option<String>,
        // #[builder(into)] organization: OrganizationID,
    ) -> crate::Result<Engagement> {
        Ok(client
            .client
            .post(client.url.join("/api/v2/engagements/")?)
            .json(&serde_json::json!({
                "product": asset,
                "target_start": target_start,
                "target_end": target_end,
                "name": name,
                // "description": description,
                // "organization": organization,
            }))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
}

#[cfg(test)]
mod test {
    use crate::engagement::Engagement;

    static TOKEN: Option<&'static str> = option_env!("DEFECTDOJO_TOKEN");
    static URL: Option<&'static str> = option_env!("DEFECTDOJO_URL");

    #[tokio::test]
    async fn create_engagement() {
        let client = crate::Client::new(URL.unwrap().parse().unwrap(), TOKEN.unwrap()).unwrap();

        let engagement = Engagement::create(&client)
            .asset(26)
            .target_start("2026-04-30")
            .target_end("2026-04-30")
            .name("next-one")
            .send()
            .await
            .unwrap();

        dbg!(engagement);

        // let asset = Asset::create(&client)
        //     .name("yeet_asset")
        //     .description("hello_from_yeet")
        //     .organization(3)
        //     .send()
        //     .await
        //     .unwrap();

        // let asset: crate::SearchResult<Asset> = Asset::find(&client)
        //     .name("yeet_asset")
        //     .send()
        //     .await
        //     .unwrap();

        // asset.results[0].delete(&client).await.unwrap();

        // dbg!(asset);
    }
}
