use std::sync::LazyLock;

use http::StatusCode;
use httpsig_hyper::{
    ContentDigest as _, MessageSignatureReq as _, RequestContentDigest as _,
    prelude::{HttpSignatureParams, SigningKey},
};
use reqwest::RequestBuilder;
use serde::de::DeserializeOwned;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SignatureError {
    #[error(transparent)]
    HyperDigestError(#[from] httpsig_hyper::HyperDigestError),
    #[error(transparent)]
    HyperSigError(#[from] httpsig_hyper::HyperSigError),
    #[error(transparent)]
    ReqwestError(#[from] reqwest::Error),
}

pub trait ReqwestSig {
    fn sign<T: SigningKey + Sync>(
        self,
        signature_params: &HttpSignatureParams,
        signing_key: &T,
    ) -> impl Future<Output = Result<RequestBuilder, SignatureError>> + Send;
}

impl ReqwestSig for RequestBuilder {
    async fn sign<T: SigningKey + Sync>(
        self,
        signature_params: &HttpSignatureParams,
        signing_key: &T,
    ) -> Result<RequestBuilder, SignatureError> {
        let (client, request) = self.build_split();
        let req: http::Request<_> = request?.try_into()?;
        let mut req = req
            .set_content_digest(&httpsig_hyper::ContentDigestType::Sha256)
            .await?;
        req.set_message_signature(signature_params, signing_key, None)
            .await?;
        let (parts, body) = req.into_parts();
        let body: reqwest::Body = body.into_bytes().await?.into();
        let request = http::Request::from_parts(parts, body).try_into()?;
        Ok(RequestBuilder::from_parts(client, request))
    }
}

#[expect(clippy::expect_used, reason = "Is there another way?")]
pub static HTTPSIG_COMPONENTS: LazyLock<Vec<message_component::HttpMessageComponentId>> =
    LazyLock::new(|| {
        ["date", "@path", "@method", "content-digest"]
            .iter()
            .map(|component| message_component::HttpMessageComponentId::try_from(*component))
            .collect::<Result<Vec<_>, _>>()
            .expect("Could not create HTTP Signature components")
    });

use httpsig_hyper::prelude::*;

/// Set the key info on the defined httpsig components
/// # Errors
/// Will throw `InvalidSignatureParams` if there are duplicate components
pub fn sig_param<K: SigningKey + Sync>(key: &K) -> HttpSigResult<HttpSignatureParams> {
    let mut signature_params = HttpSignatureParams::try_new(&HTTPSIG_COMPONENTS)?;
    signature_params.set_key_info(key);
    Ok(signature_params)
}

error_set::error_set! {
    #[expect(clippy::exhaustive_enums)]
    ResponseError := {
        #[display("The server responded with a non success code: {code}: {error}")]
        ServerError{code: StatusCode, error: String},
        ReqwestError(reqwest::Error),
        #[display("The url was invalid: {0}")]
        URLParseError(url::ParseError),
        #[display("Could not set the signature params: {0}")]
        SignatureParamError(HttpSigError),
        #[display("Could not sign the request: {0}")]
        SignatureError(SignatureError),
        #[display("Could not decrypt the secret: {0}")]
        DecryptError(age::DecryptError),
        #[display("Could not encrypt the secret: {0}")]
        EncryptError(age::EncryptError),
        #[display("Could not parse the provided identity: {error}")]
        IdentityError{error: &'static str},
    }
}

#[expect(async_fn_in_trait)]
pub trait ErrorForJson {
    async fn error_for_json<T: DeserializeOwned>(self) -> Result<T, ResponseError>;
    async fn error_for_code(self) -> Result<StatusCode, ResponseError>;
}

impl ErrorForJson for reqwest::Response {
    async fn error_for_json<T: DeserializeOwned>(self) -> Result<T, ResponseError> {
        if self.status().is_success() {
            Ok(self.json::<T>().await?)
        } else {
            Err(ResponseError::ServerError {
                code: self.status(),
                error: self.text().await?,
            })
        }
    }

    async fn error_for_code(self) -> Result<StatusCode, ResponseError> {
        if self.status().is_success() {
            Ok(self.status())
        } else {
            Err(ResponseError::ServerError {
                code: self.status(),
                error: self.text().await?,
            })
        }
    }
}

#[cfg(test)]
mod test_ureq_sign {
    use std::sync::LazyLock;

    use httpsig_hyper::prelude::*;
    use reqwest::Client;

    use crate::httpsig::ReqwestSig as _;

    static COMPONENTS: LazyLock<Vec<message_component::HttpMessageComponentId>> =
        LazyLock::new(|| {
            ["date", "@target-uri", "@method", "content-digest"]
                .iter()
                .map(|v| message_component::HttpMessageComponentId::try_from(*v))
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        });

    const EDDSA_SECRET_KEY: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIDx2kNPzVZ7AmTCEY99KU4gw3DoCc9Unq+YCmVLAychJ
-----END PRIVATE KEY-----
";

    #[tokio::test]
    async fn test_reqwest() {
        let mut signature_params = HttpSignatureParams::try_new(&COMPONENTS).unwrap();
        let signing_key = SecretKey::from_pem(&AlgorithmName::Ed25519, EDDSA_SECRET_KEY).unwrap();
        signature_params.set_key_info(&signing_key);

        let req = Client::new()
            .get("https://example.com")
            .body("Hi")
            .sign(&signature_params, &signing_key)
            .await
            .unwrap()
            .build()
            .unwrap();

        assert!(req.headers().contains_key("signature-input"));
        assert!(req.headers().contains_key("signature"));
        assert!(req.headers().contains_key("content-digest"));
    }
}
