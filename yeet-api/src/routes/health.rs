pub async fn is_healthy(url: &url::Url) -> bool {
    let Ok(url) = url.join("/health") else {
        return false;
    };

    let Ok(response) = reqwest::Client::new().get(url).send().await else {
        return false;
    };

    response.status().is_success()
}
