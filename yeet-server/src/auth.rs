use axum_login::{AuthUser, AuthnBackend, UserId};
use openidconnect::{
    AccessTokenHash, AuthorizationCode, ClaimsVerificationError, ClientId, ClientSecret,
    ConfigurationError, CsrfToken, HttpClientError, IssuerUrl, Nonce, OAuth2TokenResponse,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RequestTokenError,
    SignatureVerificationError, SigningError, StandardErrorResponse, TokenResponse,
    core::{CoreAuthenticationFlow, CoreClient, CoreErrorResponseType, CoreProviderMetadata},
    reqwest::{self, Client},
    url::Url,
};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};

#[derive(Clone, Serialize, Deserialize, FromRow, Debug)]
pub struct User {
    pub id: api::UserID,
    pub oidc_id: String,
}

impl AuthUser for User {
    type Id = String;

    fn id(&self) -> Self::Id {
        self.oidc_id.clone()
    }

    fn session_auth_hash(&self) -> &[u8] {
        self.oidc_id.as_bytes()
    }
}

#[derive(Debug, Deserialize)]
pub struct UserCredentials {
    pub code: String,
    pub old_state: CsrfToken,
    pub new_state: CsrfToken,
    pub pkce_verifier: PkceCodeVerifier,
    pub nonce: Nonce,
}

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error(transparent)]
    Sqlx(sqlx::Error),

    #[error(transparent)]
    OpenIDConnectConfiguration(ConfigurationError),

    #[error(transparent)]
    OpenIDRequestToken(
        RequestTokenError<
            HttpClientError<reqwest::Error>,
            StandardErrorResponse<CoreErrorResponseType>,
        >,
    ),

    #[error(transparent)]
    OpenIDInvalidToken(ClaimsVerificationError),

    #[error(transparent)]
    OpenIDSignatureVerification(SignatureVerificationError),

    #[error(transparent)]
    OpenIDSigning(SigningError),
}

#[derive(Debug, Clone)]
pub struct UserBackend {
    db: SqlitePool,
    /// the oauth provider identifies us with this id (public)
    client_id: ClientId,
    /// This has to be kept secret
    client_secret: Option<ClientSecret>,
    /// this is where we are gonna send the user to login
    issuer_url: IssuerUrl,
    /// this should point to an url that resolves to /oauth/callback
    redirect_url: RedirectUrl,
    http_client: Client,
}

impl UserBackend {
    pub fn new(
        db: SqlitePool,
        client_id: ClientId,
        client_secret: Option<ClientSecret>,
        issuer_url: IssuerUrl,
        redirect_url: RedirectUrl,
    ) -> Self {
        let http_client = reqwest::ClientBuilder::new()
            // Following redirects opens the client up to SSRF vulnerabilities.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("Client should build");

        Self {
            db,
            client_id,
            client_secret,
            issuer_url,
            redirect_url,
            http_client,
        }
    }

    ///Fetch the openid document to create a new auth url
    pub async fn authorize_url(&self) -> (Url, CsrfToken, Nonce, PkceCodeVerifier) {
        let provider_metadata =
            CoreProviderMetadata::discover_async(self.issuer_url.clone(), &self.http_client)
                .await
                .expect("Unable to get the core provider metadata");

        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            self.client_id.clone(),
            self.client_secret.clone(),
        )
        .set_redirect_uri(self.redirect_url.clone());

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let (auth_url, csrf_token, nonce) = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .set_pkce_challenge(pkce_challenge)
            .url();

        (auth_url, csrf_token, nonce, pkce_verifier)
    }
}

impl AuthnBackend for UserBackend {
    type User = User;
    type Credentials = UserCredentials;
    type Error = BackendError;

    async fn authenticate(
        &self,
        creds: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error> {
        // Ensure the CSRF state has not been tampered with.
        if creds.old_state.secret() != creds.new_state.secret() {
            return Ok(None);
        };

        // Retrieve the provider's metadata
        let provider_metadata =
            CoreProviderMetadata::discover_async(self.issuer_url.clone(), &self.http_client)
                .await
                .expect("Unable to get the core provider metadata");

        // Create the OpenID client from the provider's metadata, client_id,
        // client_secret and redirect_url
        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            self.client_id.clone(),
            self.client_secret.clone(),
        )
        .set_redirect_uri(self.redirect_url.clone());

        // Process authorization code, expecting a token response back.
        let token_response = client
            .exchange_code(AuthorizationCode::new(creds.code))
            .map_err(BackendError::OpenIDConnectConfiguration)?
            // Set the PKCE code verifier.
            .set_pkce_verifier(creds.pkce_verifier)
            .request_async(&self.http_client)
            .await
            .map_err(BackendError::OpenIDRequestToken)?;

        // Retrieve the ID token
        let id_token = token_response
            .id_token()
            .expect("The provider MUST return an ID token for a valid token response");

        // Verify and decode the ID token
        let id_token_verifier = client.id_token_verifier();
        let claims = id_token
            .claims(&id_token_verifier, &creds.nonce)
            .map_err(BackendError::OpenIDInvalidToken)?;

        // Check the access token hasn't been tampered with
        if let Some(expected_access_token_hash) = claims.access_token_hash() {
            let actual_access_token_hash = AccessTokenHash::from_token(
                token_response.access_token(),
                id_token
                    .signing_alg()
                    .map_err(BackendError::OpenIDSignatureVerification)?,
                id_token
                    .signing_key(&id_token_verifier)
                    .map_err(BackendError::OpenIDSignatureVerification)?,
            )
            .map_err(BackendError::OpenIDSigning)?;
            if actual_access_token_hash != *expected_access_token_hash {
                return Ok(None);
            }
        }

        // Retrieve the locally-unique identifier from the decoded ID token
        let unique_identifier = claims.subject().as_str();
        let username = claims
            .preferred_username()
            .map(|name| name.to_string())
            .unwrap_or("name not set".to_owned());
        log::trace!("{claims:#?}");
        log::debug!("authenticating user `{username}` with id {unique_identifier}");

        // Persist user in our database so we can use `get_user`.
        let user = sqlx::query_as!(
            User,
            r#"insert into users (oidc_id, username, all_tag, level)
            values ($1,$2,$3,$4)
            on conflict(oidc_id) do update
            set oidc_id = excluded.oidc_id
            returning id as "id: api::UserID", oidc_id as "oidc_id!""#,
            unique_identifier,
            username,
            false,
            api::AuthLevel::Admin
        )
        .fetch_one(&self.db)
        .await
        .map_err(Self::Error::Sqlx)?;

        Ok(Some(user))
    }

    async fn get_user(&self, user_id: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
        sqlx::query_as!(
            User,
            r#"select id as "id!: api::UserID", oidc_id as "oidc_id!" from users where oidc_id = $1 and oidc_id NOT NULL"#,
            user_id
        )
        .fetch_optional(&self.db)
        .await
        .map_err(Self::Error::Sqlx)
    }
}

// We use a type alias for convenience.
//
// Note that we've supplied our concrete backend here.
pub type UserSession = axum_login::AuthSession<UserBackend>;
