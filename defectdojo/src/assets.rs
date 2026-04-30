use serde::{Deserialize, Serialize};

use serde_json::Value;

use crate::organziation::OrganizationID;

crate::api_id!(AssetID);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Asset {
    pub id: AssetID,
    pub findings_count: i64,
    pub findings_list: Vec<Value>,
    pub tags: Vec<Value>,
    pub asset_meta: Vec<Value>,
    pub organization: i64,
    pub asset_numeric_grade: Value,
    pub enable_asset_tag_inheritance: bool,
    pub asset_managers: Value,
    pub business_criticality: Value,
    pub platform: Value,
    pub lifecycle: Value,
    pub origin: Value,
    pub parent: Value,
    pub prioritization_engine: i64,
    pub created: String,
    pub name: String,
    pub description: String,
    pub user_records: Value,
    pub revenue: Value,
    pub external_audience: bool,
    pub internet_accessible: bool,
    pub enable_simple_risk_acceptance: bool,
    pub enable_full_risk_acceptance: bool,
    pub disable_sla_breach_notifications: bool,
    pub technical_contact: Value,
    pub team_manager: Value,
    pub sla_configuration: i64,
    pub members: Vec<Value>,
    pub authorization_groups: Vec<Value>,
    pub regulations: Vec<Value>,
}

#[bon::bon]
impl Asset {
    #[builder(finish_fn = "send", on(String, into))]
    pub async fn create(
        #[builder(start_fn)] client: &crate::Client,
        name: String,
        description: String,
        #[builder(into)] organization: OrganizationID,
    ) -> crate::Result<Asset> {
        Ok(client
            .client
            .post(client.url.join("/api/v2/assets/")?)
            .json(&serde_json::json!( {
                "name": name,
                "description": description,
                "organization": organization,
            }))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
    #[builder(finish_fn = "send", on(String, into))]
    pub async fn find(
        #[builder(start_fn)] client: &crate::Client,
        name: Option<String>,
    ) -> crate::Result<crate::SearchResult<Asset>> {
        Ok(client
            .client
            .get(client.url.join("/api/v2/assets/")?)
            .query(&[("name", name)])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn delete(&self, client: &crate::Client) -> crate::Result<()> {
        client
            .client
            .delete(client.url.join(&format!("/api/v2/assets/{}", self.id))?)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::assets::Asset;

    static TOKEN: Option<&'static str> = option_env!("DEFECTDOJO_TOKEN");
    static URL: Option<&'static str> = option_env!("DEFECTDOJO_URL");

    #[tokio::test]
    async fn create_asset() {
        let client = crate::Client::new(URL.unwrap().parse().unwrap(), TOKEN.unwrap()).unwrap();

        let asset = Asset::create(&client)
            .name("yeet_asset")
            .description("hello_from_yeet")
            .organization(3)
            .send()
            .await
            .unwrap();

        let asset: crate::SearchResult<Asset> = Asset::find(&client)
            .name("yeet_asset")
            .send()
            .await
            .unwrap();

        asset.results[0].delete(&client).await.unwrap();
    }
}
