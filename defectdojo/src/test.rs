use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::engagement::EngagementID;

crate::api_id!(TestTypeID);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TestType {
    pub active: bool,
    pub dynamic_tool: bool,
    pub id: TestTypeID,
    pub name: String,
    pub soc: bool,
    pub static_tool: bool,
}

#[bon::bon]
impl TestType {
    #[builder(finish_fn = "send", on(String, into))]
    pub async fn find(
        #[builder(start_fn)] client: &crate::Client,
        name: Option<String>,
        active: Option<bool>,
    ) -> crate::Result<crate::SearchResult<TestType>> {
        Ok(client
            .client
            .get(client.url.join("/api/v2/test_types/")?)
            .query(&[("name", name)])
            .query(&[("active", active)])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
}

crate::api_id!(TestID);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Test {
    pub api_scan_configuration: Value,
    pub branch_tag: Value,
    pub build_id: Value,
    pub commit_hash: Value,
    pub created: String,
    pub deduplication: bool,
    pub description: Value,
    pub engagement: i64,
    pub environment: Value,
    pub false_positive_history: bool,
    pub files: Vec<Value>,
    pub finding_groups: Vec<Value>,
    pub id: TestID,
    pub lead: Value,
    pub notes: Vec<Value>,
    pub percent_complete: Value,
    pub processing: bool,
    pub scan_type: Value,
    pub status: String,
    pub tags: Vec<Value>,
    pub target_end: String,
    pub target_start: String,
    pub test_type: i64,
    pub test_type_name: String,
    pub title: Value,
    pub updated: String,
    pub version: Value,
}

#[bon::bon]
impl Test {
    #[builder(finish_fn = "send", on(String, into))]
    pub async fn create(
        #[builder(start_fn)] client: &crate::Client,
        #[builder(into)] engagement: EngagementID,
        #[builder(into)] test_type: TestTypeID,
        target_start: String,
        target_end: String,
        // title: Option<String>,
        // #[builder(into)] organization: OrganizationID,
    ) -> crate::Result<Test> {
        Ok(client
            .client
            .post(client.url.join("/api/v2/tests/")?)
            .json(&serde_json::json!({
                "engagement": engagement,
                "target_start": target_start,
                "target_end": target_end,
                "test_type": test_type
                // "name": name,
                // "description": description,
                // "organization": organization,
            }))
            .send()
            .await?
            // .error_for_status()?
            .json()
            .await?)
    }
}

#[cfg(test)]
mod test {
    use crate::test::Test;

    static TOKEN: Option<&'static str> = option_env!("DEFECTDOJO_TOKEN");
    static URL: Option<&'static str> = option_env!("DEFECTDOJO_URL");

    #[tokio::test]
    async fn create_test() {
        let client = crate::Client::new(URL.unwrap().parse().unwrap(), TOKEN.unwrap()).unwrap();
        // let test_type = TestType::find(&client).active(true).send().await.unwrap();
        // dbg!(&test_type);

        // let next = test_type.next(&client).await.unwrap();
        // dbg!(next);

        let test = Test::create(&client)
            .engagement(7)
            .target_start("2026-04-30")
            .target_end("2026-04-30")
            .test_type(233)
            .send()
            .await
            .unwrap();
        dbg!(test);
    }
}
