//! The credential of a GitHub Actions job. With `permissions: id-token: write`
//! the runner can issue the job a signed OIDC token; Proofline exchanges it
//! for a one-hour token that reads the job's repository's reviews, so the
//! workflow stores no Proofline secret. A `pull_request` job can also ask,
//! once and with a freshly issued token, for a review of its head.

use anyhow::{Context as _, anyhow, bail};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use uuid::Uuid;

use crate::api::{Api, ApiError, Http};

const REQUEST_URL: &str = "ACTIONS_ID_TOKEN_REQUEST_URL";
const REQUEST_TOKEN: &str = "ACTIONS_ID_TOKEN_REQUEST_TOKEN";
pub const EVENT_NAME: &str = "GITHUB_EVENT_NAME";
const EVENT_PATH: &str = "GITHUB_EVENT_PATH";

/// Where the runner issues OIDC tokens, and the bearer for asking. Both are
/// set only in a GitHub Actions job granted `id-token: write`.
#[derive(Debug)]
pub struct Issuer {
    url: url::Url,
    token: SecretString,
}

impl Issuer {
    pub fn from_environment() -> Option<Self> {
        let url = std::env::var(REQUEST_URL).ok()?;
        let token = std::env::var(REQUEST_TOKEN).ok()?;
        if token.is_empty() {
            return None;
        }
        Some(Self {
            url: url::Url::parse(&url).ok()?,
            token: SecretString::from(token),
        })
    }

    #[cfg(test)]
    pub(crate) const fn new(url: url::Url, token: SecretString) -> Self {
        Self { url, token }
    }

    /// A newly issued OIDC token whose audience is this origin's CI routes.
    async fn token(&self, http: &Http) -> anyhow::Result<SecretString> {
        let mut request_url = self.url.clone();
        request_url
            .query_pairs_mut()
            .append_pair("audience", http.origin().join(["ci"]).as_str());
        let (reply, _) = http
            .send(
                http.get(request_url)
                    .bearer_auth(self.token.expose_secret()),
            )
            .await
            .map_err(|error| {
                let reason = match error {
                    ApiError::Transport { reason, .. } => reason,
                    other => other.to_string(),
                };
                anyhow!("GitHub Actions could not issue the job's OIDC token: {reason}")
            })?;
        if !reply.status.is_success() {
            bail!(
                "GitHub Actions refused to issue the job's OIDC token with HTTP {}",
                reply.status
            );
        }
        let issued: IssuedToken = serde_json::from_slice(&reply.body)
            .map_err(|_| anyhow!("GitHub Actions sent a malformed OIDC token response"))?;
        Ok(SecretString::from(issued.value))
    }
}

#[derive(Deserialize)]
struct PullRequestEvent {
    pull_request: PullRequest,
}

#[derive(Deserialize)]
struct PullRequest {
    head: Head,
}

#[derive(Deserialize)]
struct Head {
    sha: String,
}

/// The commit a GitHub Actions job tests, or `None` outside one. On a
/// `pull_request*` event `GITHUB_SHA` is GitHub's merge commit or the base
/// branch's head, never a commit Proofline reviewed, so the pull request's head
/// comes from the event payload the runner wrote. Any other event tests
/// `GITHUB_SHA`.
pub fn commit_under_test() -> anyhow::Result<Option<String>> {
    let event = std::env::var(EVENT_NAME).unwrap_or_default();
    if !event.starts_with("pull_request") {
        return Ok(std::env::var("GITHUB_SHA")
            .ok()
            .filter(|sha| !sha.trim().is_empty()));
    }
    let unreadable =
        || format!("the {event} event payload names no pull-request head; name it with --commit");
    let path = std::env::var_os(EVENT_PATH).with_context(unreadable)?;
    let payload = std::fs::read(path).with_context(unreadable)?;
    let parsed: PullRequestEvent = serde_json::from_slice(&payload).with_context(unreadable)?;
    Ok(Some(parsed.pull_request.head.sha))
}

/// The events whose signed `ref` is the pull request's merge ref. The exchange
/// verifies a head only against that ref, so `pull_request_target`, whose ref
/// is the base branch, names none.
const MERGE_REF_EVENTS: &[&str] = &[
    "pull_request",
    "pull_request_review",
    "pull_request_review_comment",
];

/// The head this job asks the exchange to verify: `commit` in a job whose
/// signed ref is a pull request's merge ref, `None` in any other.
pub fn pull_request_head<'a>(event: &str, commit: &'a str) -> Option<&'a str> {
    MERGE_REF_EVENTS.contains(&event).then_some(commit)
}

#[derive(Deserialize)]
struct IssuedToken {
    value: String,
}

#[derive(Deserialize)]
struct Exchanged {
    organization_id: Uuid,
    token: String,
}

/// Asks the runner for a token whose audience is this origin's CI exchange,
/// exchanges it, and returns the review API in the organization the
/// repository belongs to. `organization`, when given, must be that one. A
/// `pull_request_head` is exchanged only if it is the pull request's live
/// head; otherwise the exchange refuses and names the head to rerun at.
pub async fn api(
    http: Http,
    issuer: &Issuer,
    organization: Option<Uuid>,
    pull_request_head: Option<&str>,
) -> anyhow::Result<Api> {
    let identity = issuer.token(&http).await?;
    let mut exchange = http
        .origin()
        .join(["api", "v1", "ci", "github-actions", "credentials"]);
    if let Some(head) = pull_request_head {
        exchange
            .query_pairs_mut()
            .append_pair("pull_request_head", head);
    }
    let (reply, _) = http
        .send(http.post(exchange).bearer_auth(identity.expose_secret()))
        .await?;
    if !reply.status.is_success() {
        return Err(http.problem(&reply).into());
    }
    let exchanged: Exchanged = serde_json::from_slice(&reply.body)
        .map_err(|_| http.protocol("the credential exchange response is malformed"))?;
    if let Some(requested) = organization
        && requested != exchanged.organization_id
    {
        bail!(
            "this repository belongs to organization {}, not {requested}",
            exchanged.organization_id
        );
    }
    Ok(Api::new(
        http,
        SecretString::from(exchanged.token),
        exchanged.organization_id,
    ))
}

/// A `pull_request` job's request for a withheld review of the head it tests.
/// Proofline admits it only from the job's own signed identity, when the
/// person whose action started the run can write the repository and the head
/// is still the pull request's.
#[derive(Debug)]
pub struct ReviewRequest {
    http: Http,
    issuer: Issuer,
    head: String,
}

#[derive(Deserialize)]
struct Requested {
    review_id: Uuid,
}

impl ReviewRequest {
    /// Only a `pull_request` event: its signed ref is the pull request's merge
    /// ref, and its run tests the pull request's head. A push or deployment
    /// job asks for nothing.
    pub fn for_event(event: &str, http: Http, issuer: Issuer, head: &str) -> Option<Self> {
        (event == "pull_request").then(|| Self {
            http,
            issuer,
            head: head.to_owned(),
        })
    }

    /// Asks once, with an OIDC token issued for this request, and returns the
    /// review that owns the head, new or existing.
    pub async fn send(&self) -> anyhow::Result<Uuid> {
        let identity = self.issuer.token(&self.http).await?;
        let mut url = self
            .http
            .origin()
            .join(["api", "v1", "ci", "github-actions", "review"]);
        url.query_pairs_mut()
            .append_pair("pull_request_head", &self.head);
        let (reply, _) = self
            .http
            .send(self.http.post(url).bearer_auth(identity.expose_secret()))
            .await?;
        if !reply.status.is_success() {
            return Err(self.http.problem(&reply).into());
        }
        let requested: Requested = serde_json::from_slice(&reply.body).map_err(|_| {
            self.http
                .protocol("the review request response is malformed")
        })?;
        Ok(requested.review_id)
    }
}
