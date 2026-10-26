//! The review API over HTTP: bearer authentication, bounded bodies, explicit
//! timeouts, no redirects, and bounded retries for reads.

use std::time::Duration;

use reqwest::{Method, StatusCode, header};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use url::Url;
use uuid::Uuid;

use crate::model::{
    CommitReviewRequest, CommitReviewResponse, FileReviewRequest, FileReviewResponse,
    PatchReviewRequest, PatchReviewResponse, RepositoryNames, ReviewDetail, ReviewPage, RunNowMode,
    RunNowRequest, RunNowResponse, StopResponse,
};
use crate::origin::Origin;
use crate::text::terminal_safe;

pub const USER_AGENT: &str = concat!("proofline-cli/", env!("CARGO_PKG_VERSION"));
const MAX_BODY: usize = 8 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const READ_ATTEMPTS: u32 = 4;
const MAX_RETRY_AFTER: u64 = 60;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{origin} returned HTTP {status}: {detail}")]
    Problem {
        origin: String,
        status: u16,
        detail: String,
    },
    #[error("could not reach {origin}: {reason}")]
    Transport { origin: String, reason: String },
    #[error("{origin} sent a response this CLI cannot read: {reason}")]
    Protocol { origin: String, reason: String },
}

/// Closed transport failures for the stdio bridge. Upstream bodies and client
/// diagnostics never become a JSON-RPC error or a terminal message.
#[derive(Debug, thiserror::Error)]
pub(crate) enum McpHttpError {
    #[error("the MCP server refused the request with HTTP {0}")]
    Http(u16),
    #[error("the MCP request timed out")]
    Timeout,
    #[error("the MCP server could not be reached")]
    Transport,
    #[error("the MCP server changed the JSON-only stateless transport")]
    Protocol,
    #[error("the MCP response body exceeds 8 MiB")]
    TooLarge,
}

impl McpHttpError {
    pub(crate) fn category(&self) -> &'static str {
        match self {
            Self::Http(_) => "http",
            Self::Timeout => "timeout",
            Self::Transport => "transport",
            Self::Protocol => "protocol",
            Self::TooLarge => "response_size",
        }
    }

    fn transport(error: &reqwest::Error) -> Self {
        if error.is_timeout() {
            Self::Timeout
        } else {
            Self::Transport
        }
    }
}

#[derive(Debug)]
enum BodyError {
    Transport(reqwest::Error),
    TooLarge,
}

async fn read_body(mut response: reqwest::Response) -> Result<Vec<u8>, BodyError> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(BodyError::Transport)? {
        if chunk.len() > MAX_BODY - body.len() {
            return Err(BodyError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn json_content_type(headers: &header::HeaderMap) -> bool {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    let Some(value) = values.next() else {
        return false;
    };
    values.next().is_none()
        && value.to_str().is_ok_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
        })
}

impl ApiError {
    pub const fn status(&self) -> Option<u16> {
        match self {
            Self::Problem { status, .. } => Some(*status),
            Self::Transport { .. } | Self::Protocol { .. } => None,
        }
    }
}

#[derive(Deserialize)]
struct Problem {
    title: Option<String>,
    detail: Option<String>,
}

/// A response that arrived with an HTTP status, and its bounded body.
pub struct Reply {
    pub headers: header::HeaderMap,
    pub status: StatusCode,
    pub body: Vec<u8>,
}

impl std::fmt::Debug for Reply {
    // A token response body carries a credential, so only its size is shown.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reply")
            .field("status", &self.status)
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct Http {
    client: reqwest::Client,
    origin: Origin,
}

impl Http {
    pub fn new(origin: Origin) -> Result<Self, ApiError> {
        let client = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(Duration::from_secs(10))
            // A redirect would carry the credential to another origin.
            .redirect(reqwest::redirect::Policy::none())
            // Api::get owns the read retry budget; the client never replays a POST.
            .retry(reqwest::retry::never())
            .build()
            .map_err(|error| ApiError::Transport {
                origin: origin.to_string(),
                reason: error.to_string(),
            })?;
        Ok(Self { client, origin })
    }

    pub const fn origin(&self) -> &Origin {
        &self.origin
    }

    pub fn transport(&self, error: &reqwest::Error) -> ApiError {
        ApiError::Transport {
            origin: self.origin.to_string(),
            // reqwest's message names the URL, which carries no secret here.
            reason: error.to_string(),
        }
    }

    pub fn protocol(&self, reason: impl Into<String>) -> ApiError {
        ApiError::Protocol {
            origin: self.origin.to_string(),
            reason: reason.into(),
        }
    }

    /// Sends one request and reads at most 8 MiB of its body.
    pub async fn send(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<(Reply, Option<u64>), ApiError> {
        let response = request
            .send()
            .await
            .map_err(|error| self.transport(&error))?;
        let status = response.status();
        let headers = response.headers().clone();
        let retry_after = response.headers().get(header::RETRY_AFTER).map(|value| {
            value
                .to_str()
                .ok()
                .and_then(|text| text.trim().parse::<u64>().ok())
        });
        let body = read_body(response).await.map_err(|error| match error {
            BodyError::Transport(error) => self.transport(&error),
            BodyError::TooLarge => self.protocol("the response body exceeds 8 MiB"),
        })?;
        // A present but unreadable Retry-After is refused rather than guessed.
        let retry_after = match retry_after {
            None => None,
            Some(Some(seconds)) => Some(seconds),
            Some(None) => Some(u64::MAX),
        };
        Ok((
            Reply {
                status,
                body,
                headers,
            },
            retry_after,
        ))
    }

    /// Sends one MCP POST to this origin. Check the transport metadata before
    /// reading a body, and never follow a redirect or retry a refused request.
    pub(crate) async fn mcp(
        &self,
        token: &SecretString,
        body: Vec<u8>,
        protocol: Option<&str>,
        notification: bool,
    ) -> Result<Vec<u8>, McpHttpError> {
        let mut request = self
            .client
            .post(self.origin.join(["mcp"]))
            .bearer_auth(token.expose_secret())
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header(header::ORIGIN, self.origin.as_key())
            .body(body);
        if let Some(protocol) = protocol {
            request = request.header("mcp-protocol-version", protocol);
        }
        let response = request
            .send()
            .await
            .map_err(|error| McpHttpError::transport(&error))?;
        let status = response.status();
        if !status.is_success() {
            return Err(McpHttpError::Http(status.as_u16()));
        }
        let expected_status = if notification {
            StatusCode::ACCEPTED
        } else {
            StatusCode::OK
        };
        if status != expected_status
            || response.headers().contains_key("mcp-session-id")
            || (!notification && !json_content_type(response.headers()))
        {
            return Err(McpHttpError::Protocol);
        }
        let body = read_body(response).await.map_err(|error| match error {
            BodyError::Transport(error) => McpHttpError::transport(&error),
            BodyError::TooLarge => McpHttpError::TooLarge,
        })?;
        if notification && !body.is_empty() {
            return Err(McpHttpError::Protocol);
        }
        Ok(body)
    }

    pub fn problem(&self, reply: &Reply) -> ApiError {
        let parsed = serde_json::from_slice::<Problem>(&reply.body).ok();
        let detail = parsed
            .and_then(|problem| problem.detail.or(problem.title))
            .map_or_else(
                || {
                    reply
                        .status
                        .canonical_reason()
                        .unwrap_or("unexpected status")
                        .to_owned()
                },
                |text| terminal_safe(&text),
            );
        ApiError::Problem {
            origin: self.origin.to_string(),
            status: reply.status.as_u16(),
            detail,
        }
    }

    pub fn post(&self, url: Url) -> reqwest::RequestBuilder {
        self.client.post(url)
    }

    pub fn get(&self, url: Url) -> reqwest::RequestBuilder {
        self.client.get(url)
    }
}

/// The review API, authorized by one token in one organization.
#[derive(Debug, Clone)]
pub struct Api {
    http: Http,
    token: SecretString,
    organization_id: Uuid,
}

impl Api {
    pub const fn new(http: Http, token: SecretString, organization_id: Uuid) -> Self {
        Self {
            http,
            token,
            organization_id,
        }
    }

    pub const fn origin(&self) -> &Origin {
        self.http.origin()
    }

    pub const fn organization_id(&self) -> Uuid {
        self.organization_id
    }

    fn url(&self, tail: &[&str]) -> Url {
        let organization = self.organization_id.to_string();
        let mut segments = vec!["api", "v1", "organizations", organization.as_str()];
        segments.extend_from_slice(tail);
        self.http.origin.join(segments)
    }

    fn request(&self, method: Method, url: Url) -> reqwest::RequestBuilder {
        self.http
            .client
            .request(method, url)
            .bearer_auth(self.token.expose_secret())
            .header(header::ACCEPT, "application/json")
    }

    /// GET with up to three retries on 429 and 503, honoring `Retry-After` up
    /// to 60 seconds and doubling from one second without it.
    async fn read(&self, url: Url, accept: &str) -> Result<Reply, ApiError> {
        let mut delay = 1;
        for attempt in 1..=READ_ATTEMPTS {
            let (reply, retry_after) = self
                .http
                .send(
                    self.request(Method::GET, url.clone())
                        .header(header::ACCEPT, accept),
                )
                .await?;
            if reply.status.is_success() {
                return Ok(reply);
            }
            let retryable = matches!(
                reply.status,
                StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
            );
            let wait = retry_after.unwrap_or(delay);
            if !retryable || attempt == READ_ATTEMPTS || wait > MAX_RETRY_AFTER {
                return Err(self.http.problem(&reply));
            }
            tokio::time::sleep(Duration::from_secs(wait)).await;
            delay = (delay * 2).min(MAX_RETRY_AFTER);
        }
        Err(self
            .http
            .protocol("the retry budget ended without a response"))
    }

    async fn get(&self, url: Url) -> Result<serde_json::Value, ApiError> {
        let reply = self.read(url, "application/json").await?;
        self.decode(&reply.body)
    }

    pub(crate) async fn tool_get(&self, path: &[&str]) -> Result<serde_json::Value, ApiError> {
        self.get(self.url(path)).await
    }

    pub(crate) async fn tool_post(
        &self,
        path: &[&str],
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, ApiError> {
        let (reply, _) = self
            .http
            .send(self.request(Method::POST, self.url(path)).json(body))
            .await?;
        if !reply.status.is_success() {
            return Err(self.http.problem(&reply));
        }
        self.decode(&reply.body)
    }

    pub(crate) async fn list_page(
        &self,
        repository: Option<Uuid>,
        search: Option<&str>,
        cursor: Option<&str>,
    ) -> Result<serde_json::Value, ApiError> {
        let mut url = self.url(&["reviews"]);
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("limit", "50");
            if let Some(repository) = repository {
                query.append_pair("repository", &repository.to_string());
            }
            if let Some(search) = search {
                query.append_pair("search", search);
            }
            if let Some(cursor) = cursor {
                query.append_pair("cursor", cursor);
            }
        }
        self.get(url).await
    }

    pub(crate) async fn history(
        &self,
        repository: &str,
        number: u64,
    ) -> Result<serde_json::Value, ApiError> {
        self.get(self.url(&["reviews", "pr", repository, &number.to_string()]))
            .await
    }

    pub(crate) async fn guidance(&self, repository: Uuid) -> Result<serde_json::Value, ApiError> {
        self.get(self.url(&["repositories", &repository.to_string(), "review-guidance"]))
            .await
    }

    pub(crate) async fn fix_prompt(&self, finding: Uuid) -> Result<serde_json::Value, ApiError> {
        self.get(self.url(&["findings", &finding.to_string(), "fix-prompt"]))
            .await
    }

    pub(crate) async fn rerun(&self, review: Uuid) -> Result<serde_json::Value, ApiError> {
        let (reply, _) = self
            .http
            .send(self.request(
                Method::POST,
                self.url(&["reviews", &review.to_string(), "rerun"]),
            ))
            .await?;
        if !reply.status.is_success() {
            return Err(self.http.problem(&reply));
        }
        self.decode(&reply.body)
    }

    pub(crate) async fn export(
        &self,
        dataset: &str,
        query: &[(&str, String)],
        accept: &str,
    ) -> Result<Reply, ApiError> {
        let mut url = self.url(&["exports", dataset]);
        url.query_pairs_mut()
            .extend_pairs(query.iter().map(|(key, value)| (*key, value.as_str())));
        self.read(url, accept).await
    }

    fn decode<T: DeserializeOwned>(&self, body: &[u8]) -> Result<T, ApiError> {
        serde_json::from_slice(body).map_err(|error| self.http.protocol(error.to_string()))
    }

    /// Fetches a review as the raw document and its typed reading.
    pub async fn review(
        &self,
        review_id: Uuid,
    ) -> Result<(serde_json::Value, ReviewDetail), ApiError> {
        let id = review_id.to_string();
        let raw = self.get(self.url(&["reviews", &id])).await?;
        let typed = serde_json::from_value(raw.clone())
            .map_err(|error| self.http.protocol(error.to_string()))?;
        Ok((raw, typed))
    }

    /// One page of the review collection, newest first.
    pub async fn reviews(
        &self,
        repository_id: Option<Uuid>,
        search: Option<&str>,
        cursor: Option<&str>,
    ) -> Result<ReviewPage, ApiError> {
        let mut url = self.url(&["reviews"]);
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("limit", "50");
            if let Some(repository) = repository_id {
                query.append_pair("repository", &repository.to_string());
            }
            if let Some(search) = search {
                query.append_pair("search", search);
            }
            if let Some(cursor) = cursor {
                query.append_pair("cursor", cursor);
            }
        }
        let raw = self.get(url).await?;
        serde_json::from_value(raw).map_err(|error| self.http.protocol(error.to_string()))
    }

    /// The organization's connected repositories that the token may read,
    /// including those with no review yet.
    pub async fn repository_names(&self) -> Result<RepositoryNames, ApiError> {
        let raw = self.get(self.url(&["repository-names"])).await?;
        serde_json::from_value(raw).map_err(|error| self.http.protocol(error.to_string()))
    }

    /// Requests a review of an open pull request's current head. One attempt:
    /// repeating a mutation could start another review.
    pub async fn request_review(
        &self,
        repository_id: Uuid,
        number: u64,
    ) -> Result<RunNowResponse, ApiError> {
        self.request_review_mode(repository_id, number, None).await
    }

    /// Requests a fresh full review after settlement. The server may return an
    /// active review unchanged; the caller must follow its returned identity.
    pub async fn request_full_review(
        &self,
        repository_id: Uuid,
        number: u64,
    ) -> Result<RunNowResponse, ApiError> {
        self.request_review_mode(repository_id, number, Some(RunNowMode::Full))
            .await
    }

    async fn request_review_mode(
        &self,
        repository_id: Uuid,
        number: u64,
        mode: Option<RunNowMode>,
    ) -> Result<RunNowResponse, ApiError> {
        let repository = repository_id.to_string();
        let number = number.to_string();
        let url = self.url(&[
            "repositories",
            &repository,
            "pull-requests",
            &number,
            "review",
        ]);
        let request = self.request(Method::POST, url);
        let request = match mode {
            Some(mode) => request.json(&RunNowRequest {
                mode,
                focus_text: None,
            }),
            None => request,
        };
        let (reply, _) = self.http.send(request).await?;
        if reply.status.is_success() {
            return self.decode(&reply.body);
        }
        Err(self.http.problem(&reply))
    }

    /// Requests a review of a patch on a base commit. One attempt; the server
    /// returns the existing review when it has seen this patch on this base.
    pub async fn request_patch_review(
        &self,
        repository_id: Uuid,
        request: &PatchReviewRequest,
    ) -> Result<PatchReviewResponse, ApiError> {
        let repository = repository_id.to_string();
        let url = self.url(&["repositories", &repository, "patch-reviews"]);
        let (reply, _) = self
            .http
            .send(self.request(Method::POST, url).json(request))
            .await?;
        if reply.status.is_success() {
            return self.decode(&reply.body);
        }
        Err(self.http.problem(&reply))
    }

    /// Requests whole-file review of a selection at one pushed commit.
    pub async fn request_file_review(
        &self,
        repository_id: Uuid,
        request: &FileReviewRequest,
    ) -> Result<FileReviewResponse, ApiError> {
        let repository = repository_id.to_string();
        let url = self.url(&["repositories", &repository, "file-reviews"]);
        let (reply, _) = self
            .http
            .send(self.request(Method::POST, url).json(request))
            .await?;
        if reply.status.is_success() {
            return self.decode(&reply.body);
        }
        Err(self.http.problem(&reply))
    }

    /// Requests a review of the change from one pushed commit to another. One
    /// attempt; the server returns the existing review of the same commits.
    pub async fn request_commit_review(
        &self,
        repository_id: Uuid,
        request: &CommitReviewRequest,
    ) -> Result<CommitReviewResponse, ApiError> {
        let repository = repository_id.to_string();
        let url = self.url(&["repositories", &repository, "commit-reviews"]);
        let (reply, _) = self
            .http
            .send(self.request(Method::POST, url).json(request))
            .await?;
        if reply.status.is_success() {
            return self.decode(&reply.body);
        }
        Err(self.http.problem(&reply))
    }

    /// Stops the holder's own local review in one bounded attempt. A refusal
    /// starts no replacement review, and the client never repeats the POST.
    pub async fn stop_review(
        &self,
        review_id: Uuid,
    ) -> Result<(serde_json::Value, StopResponse), ApiError> {
        let id = review_id.to_string();
        let (reply, _) = self
            .http
            .send(self.request(Method::POST, self.url(&["reviews", &id, "stop"])))
            .await?;
        if !reply.status.is_success() {
            return Err(self.http.problem(&reply));
        }
        let raw: serde_json::Value = self.decode(&reply.body)?;
        let stopped: StopResponse = serde_json::from_value(raw.clone())
            .map_err(|error| self.http.protocol(error.to_string()))?;
        if stopped.review_id != review_id || stopped.status != "STOPPED" {
            return Err(self
                .http
                .protocol("the stop response does not confirm this review is STOPPED"));
        }
        Ok((raw, stopped))
    }

    /// The console page for a review, which resolves the organization and
    /// review IDs to the current display names after sign-in.
    pub fn review_url(&self, review_id: Uuid) -> Url {
        let organization = self.organization_id.to_string();
        let review = review_id.to_string();
        self.http
            .origin
            .join(["orgs", "by-id", &organization, "reviews", &review])
    }
}
