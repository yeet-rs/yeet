use std::borrow::Cow;

use reqwest::multipart::{Form, Part};
use serde::{Deserialize, Serialize};

use crate::{engagement::EngagementID, test::TestID};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Scan;

#[bon::bon]
impl Scan {
    #[builder(finish_fn = "send", on(String, into))]
    pub async fn import(
        #[builder(start_fn)] client: &crate::Client,
        scan_type: String,
        file: impl Into<Cow<'static, [u8]>>,
        asset_name: Option<String>,
        engagement_name: Option<String>,
        background_import: Option<bool>,
        close_old_findings: Option<bool>,
        #[builder(into)] engagement: Option<EngagementID>,
        #[builder(into)] test: Option<TestID>,
        title: Option<String>,
    ) -> crate::Result<serde_json::Value> {
        let url = if test.is_some() {
            client.url.join("/api/v2/reimport-scan/")?
        } else {
            client.url.join("/api/v2/import-scan/")?
        };

        let mut form = Form::new().text("scan_type", scan_type);

        form = option_part(form, "product_name", asset_name);
        form = option_part(form, "engagement_name", engagement_name);
        form = option_part(form, "engagement", engagement.map(|id| id.0.to_string()));
        form = option_part(form, "test", test.map(|id| id.0.to_string()));
        form = option_part(
            form,
            "close_old_findings",
            close_old_findings.map(|bool| bool.to_string()),
        );
        form = option_part(
            form,
            "background_import",
            background_import.map(|bool| bool.to_string()),
        );
        form = option_part(form, "test_title", title);

        form = form.part("file", Part::bytes(file).file_name("findings.json"));

        Ok(client
            .client
            .post(url)
            .multipart(form)
            .send()
            .await?
            // .error_for_status()?
            .json()
            .await?)
    }
}

fn option_part<T: Into<Cow<'static, str>>, N: Into<Cow<'static, str>>>(
    form: Form,
    name: N,
    option: Option<T>,
) -> Form {
    if let Some(value) = option {
        form.text(name, value)
    } else {
        form
    }
}

#[cfg(test)]
mod test {
    use crate::{finding, scan::Scan};

    static TOKEN: Option<&'static str> = option_env!("DEFECTDOJO_TOKEN");
    static URL: Option<&'static str> = option_env!("DEFECTDOJO_URL");

    #[tokio::test]
    #[ignore]

    async fn import() {
        let client = crate::Client::new(URL.unwrap().parse().unwrap(), TOKEN.unwrap()).unwrap();
        // let test_type = TestType::find(&client).active(true).send().await.unwrap();
        // dbg!(&test_type);

        // let next = test_type.next(&client).await.unwrap();
        // dbg!(next);

        let finding = finding::Finding::find(&client).id(10).send().await.unwrap();
        dbg!(finding);

        let finding = Scan::import(&client)
            .test(16)
            // .engagement(7)
            .asset_name("yeet_asset")
            .engagement_name("hi-there")
            .scan_type("Generic Findings Import")
            .title("Yeet osquery scan")
            .close_old_findings(true)
            // .background_import(true)
            .file(
                serde_json::to_vec(&serde_json::json!({
                    "findings": [
                        {
                            "title": "Hey look at me!",
                            "severity": "Critical",
                            "description":"angry 2",
                            "file_path": "pkg:cargo/edge@1.10.1",
                            "component_name": "edge",
                            "component_version": "1.10.1",
                            "endpoints": [
                                {
                                   // "host": "testhost"
                                   // "purl_type": "windows",
                                   // "namespace": "microsoft",
                                   // "name": "edgeing",
                                   // "version": "1.0",
                                }
                            ]
                        }
                    ]
                }))
                .unwrap(),
            )
            // .asset("yeet_asset")
            .send()
            .await
            .unwrap();

        dbg!(finding);
    }
}
