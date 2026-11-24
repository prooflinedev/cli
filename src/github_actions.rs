//! The credential of a GitHub Actions job. With `permissions: id-token: write`
//! the runner can issue the job a signed OIDC token; Proofline exchanges it
//! for a one-hour token that reads the job's repository's reviews, so the
//! workflow stores no Proofline secret. A wait that outlasts that token asks
//! the runner for a new identity and exchanges it again before the token
//! expires. A `pull_request` job can also ask, once and with a freshly issued
//! token, for a review of its head.

use std::sync::Arc;
use std::time::Duration;

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
#[derive(Debug, Clone)]
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

/// The ID of the job's own workflow run when GitHub Actions is running it.
pub(crate) fn current_run_id() -> Option<i64> {
    if std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true") {
        std::env::var("GITHUB_RUN_ID").ok()?.parse().ok()
    } else {
        None
    }
}

/// The completed run a `workflow_run` job follows: the run that triggered it,
/// its head commit, its latest attempt and how that attempt concluded, such as
/// `success`, `failure` or `cancelled`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProducingRun {
    pub head_sha: String,
    pub id: i64,
    pub attempt: Option<i64>,
    pub conclusion: Option<String>,
}

#[derive(Deserialize)]
struct WorkflowRunEvent {
    workflow_run: WorkflowRun,
}

#[derive(Deserialize)]
struct WorkflowRun {
    head_sha: String,
    id: i64,
    run_attempt: Option<i64>,
    conclusion: Option<String>,
}

const WORKFLOW_RUN_UNREADABLE: &str =
    "the workflow_run event payload names no completed run; name it with --commit and --run";

impl ProducingRun {
    /// Reads the completed run from a `workflow_run` event payload.
    pub fn parse(payload: &[u8]) -> anyhow::Result<Self> {
        let parsed: WorkflowRunEvent =
            serde_json::from_slice(payload).context(WORKFLOW_RUN_UNREADABLE)?;
        let run = parsed.workflow_run;
        if run.head_sha.trim().is_empty() {
            bail!(WORKFLOW_RUN_UNREADABLE);
        }
        Ok(Self {
            head_sha: run.head_sha,
            id: run.id,
            attempt: run.run_attempt,
            conclusion: run.conclusion,
        })
    }
}

/// The completed run this job follows on a `workflow_run` event, from the
/// payload the runner wrote, or `None` on any other event and outside GitHub
/// Actions.
pub fn producing_run() -> anyhow::Result<Option<ProducingRun>> {
    if std::env::var(EVENT_NAME).unwrap_or_default() != "workflow_run" {
        return Ok(None);
    }
    let path = std::env::var_os(EVENT_PATH).context(WORKFLOW_RUN_UNREADABLE)?;
    let payload = std::fs::read(path).context(WORKFLOW_RUN_UNREADABLE)?;
    ProducingRun::parse(&payload).map(Some)
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
    expires_at: String,
}

/// How long before its expiry a job's credential is renewed, or half its
/// lifetime when that is shorter.
const RENEW_BEFORE: Duration = Duration::from_secs(5 * 60);

/// Exchanges a runner-issued `identity` for a read credential. A
/// `pull_request_head` is exchanged only if it is the pull request's live
/// head; otherwise the exchange refuses and names the head to rerun at.
async fn exchange(
    http: &Http,
    identity: &SecretString,
    pull_request_head: Option<&str>,
) -> Result<(Uuid, Lease), ApiError> {
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
        return Err(http.problem(&reply));
    }
    let malformed = || http.protocol("the credential exchange response is malformed");
    let exchanged: Exchanged = serde_json::from_slice(&reply.body).map_err(|_| malformed())?;
    let expires_at = unix_seconds(&exchanged.expires_at).ok_or_else(malformed)?;
    let now = i64::try_from(crate::device::now()).map_err(|_| malformed())?;
    let lifetime = Duration::from_secs(u64::try_from(expires_at - now).unwrap_or(0));
    let renew_at = tokio::time::Instant::now()
        .checked_add(lifetime.saturating_sub(RENEW_BEFORE.min(lifetime / 2)))
        .ok_or_else(malformed)?;
    let lease = Lease {
        token: SecretString::from(exchanged.token),
        renew_at,
    };
    Ok((exchanged.organization_id, lease))
}

/// The seconds since the Unix epoch of an RFC 3339 time in UTC, as the
/// exchange writes `expires_at`: `2026-11-21T03:00:00Z`, with or without
/// fractional seconds. `None` for anything else.
pub(crate) fn unix_seconds(time: &str) -> Option<i64> {
    let (date, clock) = time.strip_suffix('Z')?.split_once('T')?;
    let clock = clock.split_once('.').map_or(clock, |(whole, _)| whole);
    let number = |part: &str| part.parse::<i64>().ok();
    let mut date = date.splitn(3, '-').map(number);
    let (year, month, day) = (date.next()??, date.next()??, date.next()??);
    let mut clock = clock.splitn(3, ':').map(number);
    let (hour, minute, second) = (clock.next()??, clock.next()??, clock.next()??);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..24).contains(&hour)
        || !(0..60).contains(&minute)
        || !(0..61).contains(&second)
    {
        return None;
    }
    // Days from the civil date, counting years from March so that a leap
    // day ends its year.
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let of_era = year - era * 400;
    let of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let of_era_days = of_era * 365 + of_era / 4 - of_era / 100 + of_year;
    let days = era * 146_097 + of_era_days - 719_468;
    Some(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// A read credential and when to renew it, on the clock the wait sleeps on.
#[derive(Debug, Clone)]
struct Lease {
    token: SecretString,
    renew_at: tokio::time::Instant,
}

/// A job's read credential, renewed by the exchange that granted it: a new
/// runner identity, the same pull-request head, and the organization the
/// first exchange named. It sends no review request and is never stored.
#[derive(Debug)]
pub struct Renewal {
    http: Http,
    issuer: Issuer,
    organization_id: Uuid,
    pull_request_head: Option<String>,
    lease: tokio::sync::Mutex<Lease>,
}

impl Renewal {
    /// The current credential, exchanged again once it is due for renewal.
    /// A refused renewal, or one that names another organization, ends the
    /// caller's request with [`ApiError::Renewal`] or the exchange's own error.
    pub(crate) async fn token(&self) -> Result<SecretString, ApiError> {
        let mut lease = self.lease.lock().await;
        if tokio::time::Instant::now() >= lease.renew_at {
            let identity =
                self.issuer
                    .token(&self.http)
                    .await
                    .map_err(|error| ApiError::Renewal {
                        reason: format!("{error:#}"),
                    })?;
            let (organization_id, renewed) =
                exchange(&self.http, &identity, self.pull_request_head.as_deref()).await?;
            if organization_id != self.organization_id {
                return Err(ApiError::Renewal {
                    reason: format!(
                        "the exchange named organization {organization_id}, not {}",
                        self.organization_id
                    ),
                });
            }
            *lease = renewed;
        }
        Ok(lease.token.clone())
    }
}

/// Asks the runner for a token whose audience is this origin's CI exchange,
/// exchanges it, and returns the review API in the organization the
/// repository belongs to, renewing its credential as it nears expiry.
/// `organization`, when given, must be that one. A `pull_request_head` is
/// exchanged only if it is the pull request's live head; otherwise the
/// exchange refuses and names the head to rerun at.
pub async fn api(
    http: Http,
    issuer: &Issuer,
    organization: Option<Uuid>,
    pull_request_head: Option<&str>,
) -> anyhow::Result<Api> {
    let identity = issuer.token(&http).await?;
    let (organization_id, lease) = exchange(&http, &identity, pull_request_head).await?;
    if let Some(requested) = organization
        && requested != organization_id
    {
        bail!("this repository belongs to organization {organization_id}, not {requested}");
    }
    let renewal = Renewal {
        http: http.clone(),
        issuer: issuer.clone(),
        organization_id,
        pull_request_head: pull_request_head.map(str::to_owned),
        lease: tokio::sync::Mutex::new(lease),
    };
    Ok(Api::renewing(http, Arc::new(renewal), organization_id))
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
