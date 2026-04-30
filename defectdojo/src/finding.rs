use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::test::{TestID, TestTypeID};

crate::api_id!(FindingID);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub active: bool,
    pub component_name: Value,
    pub component_version: Value,
    pub created: String,
    pub cvssv3: Value,
    pub cvssv3_score: Value,
    pub cvssv4: Value,
    pub cvssv4_score: Value,
    pub cwe: i64,
    pub date: String,
    pub defect_review_requested_by: Value,
    pub description: String,
    pub duplicate: bool,
    pub duplicate_finding: Value,
    pub dynamic_finding: bool,
    pub effort_for_fixing: Value,
    pub endpoints: Vec<Value>,
    pub endpoints_to_add: Value,
    pub epss_percentile: Value,
    pub epss_score: Value,
    pub false_p: bool,
    pub file_path: Value,
    pub files: Vec<Value>,
    pub fix_available: Value,
    pub fix_version: Value,
    pub found_by: Vec<i64>,
    pub hash_code: String,
    pub id: FindingID,
    pub impact: Value,
    pub is_mitigated: bool,
    pub kev_date: Value,
    pub known_exploited: bool,
    pub last_reviewed: Value,
    pub last_reviewed_by: Value,
    pub last_status_update: String,
    pub line: Value,
    pub mitigated: Value,
    pub mitigated_by: Value,
    pub mitigation: Value,
    pub mitigation_policy: i64,
    pub nb_occurences: Value,
    pub notes: Vec<Value>,
    pub numerical_severity: String,
    pub out_of_scope: bool,
    pub overridden_priority_risk_calculation: bool,
    pub owners: Value,
    pub param: Value,
    pub payload: Value,
    pub planned_remediation_date: Value,
    pub planned_remediation_version: Value,
    pub priority: Value,
    pub publish_date: Value,
    pub push_to_integrator: bool,
    pub push_to_jira: bool,
    pub ransomware_used: bool,
    pub references: Value,
    pub reporter: i64,
    pub review_requested_by: Value,
    pub reviewers: Vec<Value>,
    pub risk: Option<String>,
    pub risk_accepted: bool,
    pub sast_sink_object: Value,
    pub sast_source_file_path: Value,
    pub sast_source_line: Value,
    pub sast_source_object: Value,
    pub scanner_confidence: Value,
    pub service: Value,
    pub severity: String,
    pub severity_justification: Value,
    pub sla_expiration_date: String,
    pub sla_start_date: Value,
    pub sonarqube_issue: Value,
    pub static_finding: bool,
    pub steps_to_reproduce: Value,
    pub tags: Vec<Value>,
    pub test: TestID,
    pub thread_id: Value,
    pub title: String,
    pub under_defect_review: bool,
    pub under_review: bool,
    pub unique_id_from_tool: Value,
    pub updated: String,
    pub url: Value,
    pub verified: bool,
    pub vuln_id_from_tool: Value,
    pub vulnerability_ids: Vec<Value>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}
impl Severity {
    pub fn as_defectdojo_numerical(&self) -> &'static str {
        match self {
            Severity::Info => "S4",
            Severity::Low => "S3",
            Severity::Medium => "S2",
            Severity::High => "S1",
            Severity::Critical => "S0",
        }
    }
}

#[bon::bon]
impl Finding {
    #[builder(finish_fn = "send", on(String, into))]
    pub async fn create(
        #[builder(start_fn)] client: &crate::Client,
        #[builder(into)] test: TestID,
        active: bool,
        description: String,
        found_by: Vec<TestTypeID>,
        severity: Severity,
        title: String,
        verified: bool,
        component_name: Option<String>,
        component_version: Option<String>,
    ) -> crate::Result<Finding> {
        Ok(client
            .client
            .post(client.url.join("/api/v2/findings/")?)
            .json(&serde_json::json!({
                "test": test,
                "active": active,
                "description": description,
                "found_by": found_by,
                "severity": severity,
                "title": title,
                "verified": verified,
                "numerical_severity": severity.as_defectdojo_numerical(),
                "component_name": component_name,
                "component_version": component_version,
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
        #[builder(into)] id: Option<FindingID>,
    ) -> crate::Result<crate::SearchResult<Finding>> {
        Ok(client
            .client
            .get(client.url.join("/api/v2/findings/")?)
            .query(&[("id", id)])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
}

#[cfg(test)]
mod test {
    use crate::finding::{Finding, Severity};

    static TOKEN: Option<&'static str> = option_env!("DEFECTDOJO_TOKEN");
    static URL: Option<&'static str> = option_env!("DEFECTDOJO_URL");

    #[tokio::test]
    #[ignore]
    async fn create_finding() {
        let client = crate::Client::new(URL.unwrap().parse().unwrap(), TOKEN.unwrap()).unwrap();
        // let test_type = TestType::find(&client).active(true).send().await.unwrap();
        // dbg!(&test_type);

        // let next = test_type.next(&client).await.unwrap();
        // dbg!(next);

        let finding = Finding::create(&client)
            .test(7)
            .active(true)
            .description("New finding")
            .found_by(vec![233.into()])
            .severity(Severity::Low)
            .title("This is a low finding")
            .component_name("custom-kernel")
            .component_version("1.5")
            .verified(false)
            .send()
            .await
            .unwrap();

        dbg!(finding);
    }
}
