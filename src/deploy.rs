//! `proofline ci deploy`: waits until Proofline has recorded a named check of
//! the deploys of one commit, then ends by what those checks recorded, so the
//! pipeline decides what follows. A result is "no regression observed", never
//! a claim that the deploy is safe, and anything Proofline did not establish
//! ends as not established.

use std::io::Write as _;
use std::time::Duration;

use anyhow::bail;
use clap::{Args, ValueEnum};
use uuid::Uuid;

use crate::api::Api;
use crate::github_actions::ProducingRun;
use crate::model::{CommitDeploy, CommitDeployRollback, RollbackDeploy};
use crate::{
    FIRST_POLL_SECONDS, LONGEST_POLL_SECONDS, RepositoryArgs, Verdict, connected_repository,
    poll_deadline, say, text,
};

const SAME_RUN: &str = "Proofline records the landing of a run's deploy only after the run completes. Read it from a separate workflow: https://proofline.sh/docs/ci/#read-the-checks-from-a-separate-workflow";

/// How many reads in a row may fail in transport, time out or get a 5xx
/// answer before a wait ends with exit 4. A wait for the day check makes
/// hundreds of reads, and one blip on any of them would otherwise end it
/// (#39591). Five failures on the poll schedule span about five minutes once
/// it reads once a minute.
const FAILED_READS: u32 = 5;

/// Minutes `ci deploy` waits without `--timeout`, at least. A wait for the
/// landing, 20-minute or hour check also lasts until that check is due.
const DEFAULT_TIMEOUT_MINUTES: u64 = 30;

/// The deploy states this CLI knows. The server may add one in a minor
/// release, and a caller must read one it does not know as not established
/// (#39845).
const KNOWN_STATES: [&str; 9] = [
    "VERIFIED",
    "VERIFIED_UNTIL_SUPERSEDED",
    "SUPERSEDED",
    "INCOMPLETE",
    "UNRECORDED",
    "NOT_YET_DUE",
    "UNVERIFIED",
    "FAILED",
    "INACTIVE",
];

/// Minutes a `workflow_run` reader waits for a deploy of the completed run
/// when that run did not succeed and no selected deploy is recorded. Proofline
/// records a deploy when it admits the GitHub `deployment_status` delivery
/// that its job's end sends, before the run completes and starts the reader,
/// and a queued delivery waits only a Pub/Sub pull; the bound leaves minutes
/// for a backlog.
const UNSUCCESSFUL_RUN_MINUTES: u64 = 5;

#[derive(Debug, Args)]
pub(crate) struct CiDeployArgs {
    /// Full commit SHA the job deployed. Defaults to `COMMIT_SHA`, then the
    /// completed run's head on a `workflow_run` event, then the pull
    /// request's head on a GitHub Actions pull-request event, then
    /// `GITHUB_SHA`.
    #[arg(long, value_name = "SHA")]
    pub(crate) commit: Option<String>,
    /// Only deploys to this GitHub Environment.
    #[arg(long, value_name = "NAME")]
    environment: Option<String>,
    /// Only deploys recorded in this Proofline environment: a deploy's
    /// `environment_id` in `--json`, not the GitHub Environment name that
    /// `--environment` matches. A GitHub deployment recorded in two
    /// Proofline environments is a deploy in each, and this tells them apart.
    #[arg(long, value_name = "UUID")]
    environment_id: Option<Uuid>,
    /// Only deploys with this `CodePipeline` execution ID or Amplify job ID.
    /// Proofline records a `CodePipeline` deploy after the execution succeeds.
    /// A reader in that execution waits until its timeout.
    #[arg(long, value_name = "ID")]
    aws_run: Option<String>,
    /// Only deploys of this GitHub deployment task, such as `deploy:web`.
    #[arg(long, value_name = "TASK")]
    task: Option<String>,
    /// Only the deploy that holds this GitHub deployment: the `id` GitHub
    /// returned to the job that created it. Two deployments of one commit,
    /// environment and task outside Actions are two deploys, and this tells
    /// them apart.
    #[arg(long, value_name = "ID")]
    deployment: Option<i64>,
    /// Only deploys that this GitHub Actions run created. On a `workflow_run`
    /// event it defaults to the completed run unless `--aws-run` is given.
    #[arg(long, value_name = "ID")]
    run: Option<i64>,
    /// Only the deploy of `--run` that holds a deployment of this run attempt.
    /// A deploy that lists no attempts never matches. On a `workflow_run`
    /// event without `--run` or `--aws-run` it defaults to the completed run's attempt.
    #[arg(long, value_name = "N", requires = "run")]
    attempt: Option<i64>,
    /// The check to wait for. The checks before it count too.
    #[arg(long, value_enum, default_value_t = Until::Landing)]
    until: Until,
    /// Minutes to wait for the check. By default until the selected deploys'
    /// check is due, and at least 30. `--until 1d` needs an explicit value.
    #[arg(long, value_name = "MINUTES")]
    timeout: Option<u64>,
    /// Print the route's response as JSON instead of text.
    #[arg(long)]
    json: bool,
    #[command(flatten)]
    pub(crate) repository: RepositoryArgs,
    /// How the completed run that `--run` defaulted to concluded, from the
    /// `workflow_run` payload.
    #[arg(skip)]
    followed_conclusion: Option<String>,
}

/// The four checks of a deploy, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Until {
    /// The check when the deploy lands.
    Landing,
    /// The check 20 minutes after landing.
    #[value(name = "20m")]
    Minutes20,
    /// The check an hour after landing.
    #[value(name = "1h")]
    Hour1,
    /// The check a day after landing.
    #[value(name = "1d")]
    Day1,
}

impl Until {
    const ALL: [Self; 4] = [Self::Landing, Self::Minutes20, Self::Hour1, Self::Day1];

    /// The checkpoint's name in the API.
    const fn api_name(self) -> &'static str {
        match self {
            Self::Landing => "LANDING",
            Self::Minutes20 => "MINUTES_20",
            Self::Hour1 => "HOUR_1",
            Self::Day1 => "DAY_1",
        }
    }
}

impl CiDeployArgs {
    /// Reads the deploy of the completed run a `workflow_run` job follows. A
    /// `workflow_run` job's own `GITHUB_SHA` is the default branch's latest
    /// commit, which a later push can make another run's deploy. `--commit`
    /// and `COMMIT_SHA` (`cloud_build`) still name the commit, and `--run`
    /// keeps its own attempt, since the payload's attempt is of another run.
    pub(crate) fn follow(&mut self, produced: &ProducingRun, cloud_build: bool) {
        if self.commit.is_none() && !cloud_build {
            self.commit = Some(produced.head_sha.clone());
        }
        if self.run.is_none() && self.aws_run.is_none() {
            self.run = Some(produced.id);
            self.attempt = produced.attempt;
            self.followed_conclusion.clone_from(&produced.conclusion);
        }
    }

    /// The conclusion of the followed run when it did not succeed, which
    /// shortens the wait for a deploy to [`UNSUCCESSFUL_RUN_MINUTES`]: a run
    /// that failed at build, was cancelled or skipped its deploy job deploys
    /// nothing. A run that succeeded, a payload that names no conclusion and
    /// an explicit `--run` keep the whole wait.
    fn unsuccessful_run(&self) -> Option<&str> {
        self.followed_conclusion
            .as_deref()
            .filter(|conclusion| *conclusion != "success")
    }

    /// A deploying run cannot read its landing until the run finishes.
    pub(crate) fn check_reader_run(&self, reader_run: Option<i64>) -> anyhow::Result<()> {
        if self.run.is_some() && self.run == reader_run {
            bail!(SAME_RUN);
        }
        Ok(())
    }

    /// The wait in minutes. The day check comes due a day after landing, past
    /// any default a job could mean, so it takes an explicit one, and past
    /// the six hours a GitHub-hosted job may run, so the refusal names the
    /// later-run pattern.
    pub(crate) fn timeout_minutes(&self) -> anyhow::Result<u64> {
        match (self.timeout, self.until) {
            (Some(minutes), _) => Ok(minutes),
            (None, Until::Day1) => bail!(
                "--until 1d waits for the check a day after landing; name how long to wait with --timeout MINUTES, such as --timeout 1560. A job on a GitHub-hosted runner is stopped after six hours, before that check is due, so read it from a later run: https://proofline.sh/help/ci-deploy-later-check/"
            ),
            (None, _) => Ok(DEFAULT_TIMEOUT_MINUTES),
        }
    }

    /// Whether the wait lasts until the selected deploys' check is due: the
    /// default wait for the landing, 20-minute or hour check, which an
    /// on-time check can outlast. A landing check that reads the runtime a
    /// second time comes due 75 minutes after landing, and later while the
    /// deploy's run still has jobs pending.
    fn waits_until_due(&self) -> bool {
        self.timeout.is_none()
            && matches!(self.until, Until::Landing | Until::Minutes20 | Until::Hour1)
    }

    fn selects(&self, deploy: &CommitDeploy) -> bool {
        let matches = |wanted: Option<&str>, value: Option<&str>| {
            wanted.is_none_or(|wanted| value == Some(wanted))
        };
        self.environment_id
            .is_none_or(|id| deploy.environment_id == id)
            && matches(self.aws_run.as_deref(), deploy.aws_run_id.as_deref())
            && matches(
                self.environment.as_deref(),
                deploy.github_environment.as_deref(),
            )
            && matches(self.task.as_deref(), deploy.deployment_task.as_deref())
            && self
                .deployment
                .is_none_or(|id| deploy.github_deployment_ids.contains(&id))
            && self
                .run
                .is_none_or(|run| deploy.workflow_run_id == Some(run))
            && self
                .attempt
                .is_none_or(|attempt| deploy.workflow_run_attempts.contains(&attempt))
    }
}

/// What one deploy's checks through `--until` say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reading {
    /// The deploy failed or a check recorded `REGRESSED`.
    Regressed,
    /// The named check is not recorded yet.
    Waiting,
    /// A check through the named one recorded `SUPERSEDED`: a later deploy
    /// replaced this one, and its verification records no check after that.
    Superseded,
    /// The deploy has no verification, as when it landed while deploy checks
    /// were off, so no check of it will be recorded.
    Unverified,
    /// The deploy never landed: its GitHub deployments only went inactive, as
    /// when its job was cancelled, so no check of it will be recorded.
    Inactive,
    /// The deploy's verification ended without recording the named check,
    /// so it never will. A running verification's overdue check still waits.
    Ended,
    /// A check through the named one is not `HEALTHY`, or the deploy names a
    /// gap.
    NotEstablished,
    /// The named check is recorded, but the deploy reads a state this CLI
    /// does not know, so its checks are not read as no regression.
    UnknownState,
    /// Every check through the named one recorded `HEALTHY` and the deploy
    /// names no gap.
    NoRegression,
}

/// Older servers report only the deploy-wide gaps. Use them for a checkpoint
/// when its own gap field is absent.
fn result_and_gaps(deploy: &CommitDeploy, at: Until) -> (Option<&str>, &[String]) {
    let check = deploy
        .checkpoints
        .iter()
        .find(|check| check.checkpoint == at.api_name());
    (
        check.and_then(|check| check.result.as_deref()),
        check
            .and_then(|check| check.gaps.as_deref())
            .unwrap_or(&deploy.gaps),
    )
}

/// A failure or recorded regression decides first. A deploy that can no
/// longer record the named check, because it never landed, a later deploy
/// replaced it before then, it has no verification or its verification ended
/// without it, ends the wait for it. Otherwise every check through the
/// requested checkpoint must be healthy and gap-free, and the deploy's state
/// one the CLI knows: a state a newer server added may mean what no check here
/// shows. A known state with a later check still to come, or a later one that
/// did not record `HEALTHY`, leaves the requested check to be read on its own.
fn judge(deploy: &CommitDeploy, until: Until) -> Reading {
    let regressed = deploy
        .checkpoints
        .iter()
        .any(|recorded| recorded.result.as_deref() == Some("REGRESSED"));
    if deploy.state == "FAILED" || deploy.regressed || regressed {
        return Reading::Regressed;
    }
    if deploy.state == "UNVERIFIED" {
        return Reading::Unverified;
    }
    if deploy.state == "INACTIVE" {
        return Reading::Inactive;
    }
    let through = || {
        Until::ALL
            .into_iter()
            .filter(move |checkpoint| *checkpoint <= until)
    };
    if through().any(|checkpoint| result_and_gaps(deploy, checkpoint).0 == Some("SUPERSEDED")) {
        return Reading::Superseded;
    }
    if result_and_gaps(deploy, until).0.is_none() {
        return if deploy.verification_ended {
            Reading::Ended
        } else {
            Reading::Waiting
        };
    }
    if !KNOWN_STATES.contains(&deploy.state.as_str()) {
        return Reading::UnknownState;
    }
    let healthy = through()
        .all(|checkpoint| matches!(result_and_gaps(deploy, checkpoint), (Some("HEALTHY"), [])));
    if healthy {
        Reading::NoRegression
    } else {
        Reading::NotEstablished
    }
}

/// How the wait ends for the selected deploys' readings, or `None` while it
/// should read again. A regression ends it at once, since nothing later can
/// undo it. Otherwise it waits until every selected deploy recorded the named
/// check; at the deadline a check still missing, or no selected deploy at
/// all, is not established.
fn conclude(readings: &[Reading], deadline_passed: bool) -> Option<Verdict> {
    if readings.contains(&Reading::Regressed) {
        return Some(Verdict::Regressed);
    }
    if readings.is_empty() || readings.contains(&Reading::Waiting) {
        return deadline_passed.then_some(Verdict::NotComplete);
    }
    if readings
        .iter()
        .all(|reading| *reading == Reading::NoRegression)
    {
        Some(Verdict::Done)
    } else {
        Some(Verdict::NotComplete)
    }
}

/// Waits for the deploys of `commit` that `args` selects to record the
/// `--until` check, prints them and returns how the job ends.
pub(crate) async fn wait(
    api: &Api,
    args: &CiDeployArgs,
    commit: &str,
    reader_run: Option<i64>,
) -> anyhow::Result<Verdict> {
    let started = tokio::time::Instant::now();
    let started_unix = i64::try_from(crate::device::now()).unwrap_or(i64::MAX);
    let timeout_minutes = args.timeout_minutes()?;
    let one_read = timeout_minutes == 0;
    let mut deadline = poll_deadline(timeout_minutes)?;
    let unsuccessful = match args.unsuccessful_run() {
        Some(conclusion) => Some((conclusion, poll_deadline(UNSUCCESSFUL_RUN_MINUTES)?)),
        None => None,
    };
    let (name, repository_id) = connected_repository(api, &args.repository).await?;
    let checkpoint = args.until.api_name();
    let mut delay = FIRST_POLL_SECONDS;
    let mut ends_at = deadline;
    let mut last = None;
    let mut failures = 0;
    loop {
        let read = api.commit_deploy_verifications(repository_id, commit);
        let response = if one_read {
            Some(read.await)
        } else if tokio::time::Instant::now() >= ends_at {
            None
        } else {
            match tokio::time::timeout_at(ends_at, read).await {
                Ok(response) if tokio::time::Instant::now() < ends_at => Some(response),
                Ok(_) | Err(_) => None,
            }
        };
        let timed_out = response.is_none();
        match response {
            Some(Ok(read)) => {
                last = Some(read);
                failures = 0;
            }
            Some(Err(error)) => {
                if last.is_none() {
                    return Err(error.into());
                }
                failures += 1;
                if !error.transient() || failures >= FAILED_READS {
                    let error = anyhow::Error::from(error);
                    return Err(if failures > 1 {
                        error.context(format!("{failures} reads in a row failed"))
                    } else {
                        error
                    });
                }
                say(&format!(
                    "Reading the deploys of {name} at {commit} failed: {error}; checking again in {delay} seconds."
                ));
                delay = pause(delay, ends_at, tokio::time::Instant::now()).await;
                continue;
            }
            None => {}
        }
        let Some((raw, read)) = last.as_ref() else {
            say(&format!(
                "Proofline did not answer a verification read for {name} at {commit} within {timeout_minutes} minutes. The result is not established."
            ));
            return Ok(Verdict::NotComplete);
        };
        let selected: Vec<&CommitDeploy> = read
            .deploys
            .iter()
            .filter(|deploy| args.selects(deploy))
            .collect();
        let readings: Vec<Reading> = selected
            .iter()
            .map(|deploy| judge(deploy, args.until))
            .collect();
        if args.waits_until_due() {
            deadline = deadline.max(due(&selected, args.until, started, started_unix));
        }
        // An unsuccessful run's wait for its first selected deploy is short;
        // once one is recorded, the wait for its check is today's.
        let ended_run = unsuccessful
            .filter(|_| selected.is_empty())
            .map(|(conclusion, short)| (conclusion, deadline.min(short)));
        ends_at = ended_run.map_or(deadline, |(_, short)| short);
        let now = tokio::time::Instant::now();
        let verdict = conclude(&readings, one_read || timed_out || now >= ends_at);
        if let Some(id) = reader_run
            && verdict != Some(Verdict::Regressed)
            && selected.iter().zip(&readings).any(|(deploy, reading)| {
                deploy.workflow_run_id == Some(id) && *reading == Reading::Waiting
            })
        {
            bail!(SAME_RUN);
        }
        if let Some(verdict) = verdict {
            let mut stdout = std::io::stdout().lock();
            if args.json {
                writeln!(stdout, "{}", serde_json::to_string_pretty(raw)?)?;
            } else {
                for deploy in &selected {
                    write_lines(&mut stdout, deploy, args.until)?;
                }
            }
            drop(stdout);
            let judged: Vec<(&CommitDeploy, Reading)> = selected
                .iter()
                .copied()
                .zip(readings.iter().copied())
                .collect();
            let waited = ends_at
                .saturating_duration_since(started)
                .as_secs()
                .div_ceil(60);
            let ended = match (ended_run, args.run) {
                (Some((conclusion, _)), Some(run)) => {
                    no_deploy_from_run(run, conclusion, &name, commit, waited)
                }
                _ => ending(
                    verdict,
                    &judged,
                    read.deploys.len(),
                    &name,
                    commit,
                    checkpoint,
                    waited,
                ),
            };
            if args.aws_run.is_some() && selected.is_empty() {
                say(
                    "Proofline records a CodePipeline deploy after its execution succeeds. A reader inside that execution waits until its timeout. Read the checks from a later pipeline.",
                );
            }
            say(&ended);
            return Ok(verdict);
        }
        if selected.is_empty() {
            say(&format!(
                "No deploy of {name} at {commit} that this job selects is recorded yet; checking again in {delay} seconds."
            ));
        } else {
            say(&format!(
                "Waiting for the {checkpoint} check of {} of {name} at {commit}; checking again in {delay} seconds.",
                count(selected.len())
            ));
        }
        delay = pause(delay, ends_at, now).await;
    }
}

/// Sleeps `delay` seconds from `now`, or until `deadline` if that is sooner,
/// and returns the next poll's delay.
async fn pause(delay: u64, deadline: tokio::time::Instant, now: tokio::time::Instant) -> u64 {
    tokio::time::sleep_until(deadline.min(now + Duration::from_secs(delay))).await;
    (delay * 2).min(LONGEST_POLL_SECONDS)
}

/// When the latest of the selected deploys' `until` check is due, on the
/// clock the wait sleeps on, counted from the wait's start at `started_unix`
/// seconds: `started` for a check due before then or a time that does not
/// parse.
fn due(
    selected: &[&CommitDeploy],
    until: Until,
    started: tokio::time::Instant,
    started_unix: i64,
) -> tokio::time::Instant {
    let seconds = selected
        .iter()
        .flat_map(|deploy| &deploy.checkpoints)
        .filter(|check| check.checkpoint == until.api_name())
        .filter_map(|check| crate::github_actions::unix_seconds(&check.due_at))
        .map(|due| u64::try_from(due.saturating_sub(started_unix)).unwrap_or(0))
        .max()
        .unwrap_or(0);
    started
        .checked_add(Duration::from_secs(seconds))
        .unwrap_or(started)
}

fn count(deploys: usize) -> String {
    if deploys == 1 {
        "1 deploy".to_owned()
    } else {
        format!("{deploys} deploys")
    }
}

/// The deploy's environment, task, run and attempts, as its lines start.
fn label(deploy: &CommitDeploy) -> String {
    if let (Some(provider), Some(run)) = (&deploy.aws_provider, &deploy.aws_run_id) {
        let name = match provider.as_str() {
            "AWS_CODEPIPELINE" => "CodePipeline",
            "AWS_AMPLIFY" => "Amplify",
            other => other,
        };
        return format!("{} run {}", text::one_line(name), text::one_line(run));
    }
    let mut label = vec![
        deploy
            .github_environment
            .as_deref()
            .map_or_else(|| "(no environment)".to_owned(), text::one_line),
    ];
    if let Some(task) = &deploy.deployment_task {
        label.push(text::one_line(task));
    }
    if let Some(run) = deploy.workflow_run_id {
        label.push(format!("run {run}"));
    }
    if !deploy.workflow_run_attempts.is_empty() {
        let attempts: Vec<String> = deploy
            .workflow_run_attempts
            .iter()
            .map(i64::to_string)
            .collect();
        label.push(format!("attempt {}", attempts.join(",")));
    }
    label.join(" ")
}

/// The later checkpoints than `until` that recorded `REGRESSED`. Any of them
/// already decides the wait, so the lines and the ending name them.
fn later_regressions(deploy: &CommitDeploy, until: Until) -> impl Iterator<Item = Until> + '_ {
    Until::ALL.into_iter().filter(move |checkpoint| {
        *checkpoint > until && result_and_gaps(deploy, *checkpoint).0 == Some("REGRESSED")
    })
}

/// One line for each check of `deploy` through `until`, and for each later
/// check that recorded `REGRESSED`: the deploy, the checkpoint, its result and
/// gap codes, and the deploy's page. A rollback first gets one line naming the
/// page of the deploy it restores, when the read names one, and of each deploy
/// it rolls back. A deploy whose newest check found an earlier deploy serving
/// again first gets a `rolled back` line. Neither changes a result.
fn write_lines(
    out: &mut impl std::io::Write,
    deploy: &CommitDeploy,
    until: Until,
) -> std::io::Result<()> {
    let label = label(deploy);
    let page = deploy
        .deploy_url
        .as_deref()
        .map_or_else(String::new, |url| format!("; {}", text::one_line(url)));
    let state = text::one_line(&deploy.state);
    if let Some(rollback) = &deploy.rollback {
        writeln!(out, "{label}: {}", rollback_line(rollback))?;
    }
    if deploy.rolled_back {
        writeln!(
            out,
            "{label}: rolled back; the newest check found an earlier deploy serving again"
        )?;
    }
    let printed = Until::ALL
        .into_iter()
        .filter(|checkpoint| *checkpoint <= until)
        .chain(later_regressions(deploy, until));
    for checkpoint in printed {
        let (result, gaps) = result_and_gaps(deploy, checkpoint);
        let result = result.map_or_else(|| "NOT_RECORDED".to_owned(), text::one_line);
        let gaps = if gaps.is_empty() {
            "none".to_owned()
        } else {
            gaps.iter()
                .map(|gap| text::one_line(gap))
                .collect::<Vec<_>>()
                .join(",")
        };
        writeln!(
            out,
            "{label}: {} {result}; state {state}; gaps {gaps}{page}",
            checkpoint.api_name(),
        )?;
    }
    Ok(())
}

/// `rollback; restores PAGE; rolls back PAGE, PAGE`, each deploy named by its
/// page, else by its landing.
fn rollback_line(rollback: &CommitDeployRollback) -> String {
    let named = |deploy: &RollbackDeploy| {
        deploy
            .deploy_url
            .as_deref()
            .or(deploy.landed_at.as_deref())
            .map_or_else(|| "(no page)".to_owned(), text::one_line)
    };
    let mut parts = vec!["rollback".to_owned()];
    if let Some(restores) = &rollback.restores {
        parts.push(format!("restores {}", named(restores)));
    }
    if !rollback.rolls_back.is_empty() {
        let rolled_back: Vec<String> = rollback.rolls_back.iter().map(named).collect();
        parts.push(format!("rolls back {}", rolled_back.join(", ")));
    }
    parts.join("; ")
}

/// The line the job ends with. When every deploy that is not established
/// never landed, was replaced before the check, has no checks, or ended its
/// checks without the named one, it says so and names their pages.
fn ending(
    verdict: Verdict,
    judged: &[(&CommitDeploy, Reading)],
    recorded: usize,
    name: &str,
    commit: &str,
    checkpoint: &str,
    minutes: u64,
) -> String {
    let readings: Vec<Reading> = judged.iter().map(|(_, reading)| *reading).collect();
    match verdict {
        Verdict::Done => format!("No regression observed at {checkpoint}."),
        Verdict::Regressed => format!(
            "A deploy of {name} at {commit} failed or recorded REGRESSED: {}.",
            causes(judged)
        ),
        _ if readings.is_empty() && recorded > 0 => format!(
            "Proofline recorded {} of {name} at {commit}, and none matches --environment-id, --aws-run, --environment, --task, --deployment, --run or --attempt after {minutes} minutes. The result is not established.",
            count(recorded)
        ),
        _ if readings.is_empty() => format!(
            "No deploy of {name} at {commit} was recorded after {minutes} minutes. The result is not established."
        ),
        _ if readings.contains(&Reading::Waiting) => format!(
            "The {checkpoint} check was not recorded after {minutes} minutes. The result is not established."
        ),
        _ if readings.contains(&Reading::UnknownState) => format!(
            "A deploy of {name} at {commit} reads a state this version of the CLI does not know: {}. Its checks are not read as no regression until the CLI is updated. The result is not established.",
            unknown_states(judged)
        ),
        _ if only(&readings, Reading::Inactive) => format!(
            "The {checkpoint} check will not be recorded, because {} of {name} at {commit} never landed{}. The result is not established.",
            this(&readings, Reading::Inactive),
            pages(judged, Reading::Inactive)
        ),
        _ if only(&readings, Reading::Superseded) => format!(
            "A later deploy replaced {} of {name} at {commit} before the {checkpoint} check, so that check will not be recorded{}. The result is not established.",
            this(&readings, Reading::Superseded),
            pages(judged, Reading::Superseded)
        ),
        _ if only(&readings, Reading::Ended) => format!(
            "The deploy checks of {} of {name} at {commit} ended without recording the {checkpoint} check, so it will not be recorded{}. The result is not established.",
            this(&readings, Reading::Ended),
            pages(judged, Reading::Ended)
        ),
        _ if only(&readings, Reading::Unverified) => format!(
            "Proofline has no deploy checks of {} of {name} at {commit}, as when deploy checks were off at its landing{}. The result is not established.",
            this(&readings, Reading::Unverified),
            pages(judged, Reading::Unverified)
        ),
        _ => format!(
            "A check through {checkpoint} did not record HEALTHY, or a deploy names a gap. The result is not established."
        ),
    }
}

/// The line an unsuccessful run's reader ends with when the run recorded no
/// deploy that the job selects.
fn no_deploy_from_run(
    run: i64,
    conclusion: &str,
    name: &str,
    commit: &str,
    minutes: u64,
) -> String {
    format!(
        "Run {run} concluded {} and recorded no deploy of {name} at {commit} that this job selects; Proofline waited {minutes} minutes for one. The result is not established.",
        text::one_line(conclusion)
    )
}

/// Each regressed deploy and what decided it: its failure, and every
/// checkpoint that recorded `REGRESSED`, the later ones than `--until` too,
/// so a reader finds the cause without opening each deploy's page.
fn causes(judged: &[(&CommitDeploy, Reading)]) -> String {
    judged
        .iter()
        .filter(|(_, reading)| *reading == Reading::Regressed)
        .map(|(deploy, _)| {
            let regressed: Vec<&str> = Until::ALL
                .into_iter()
                .filter(|checkpoint| result_and_gaps(deploy, *checkpoint).0 == Some("REGRESSED"))
                .map(Until::api_name)
                .collect();
            let cause = match (deploy.state == "FAILED", regressed.is_empty()) {
                (true, true) => "failed".to_owned(),
                (true, false) => {
                    format!("failed and recorded REGRESSED at {}", regressed.join(", "))
                }
                (false, false) => format!("recorded REGRESSED at {}", regressed.join(", ")),
                (false, true) => "recorded REGRESSED".to_owned(),
            };
            format!("{} {cause}", label(deploy))
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Each deploy that reads a state the CLI does not know, by its label and
/// that state.
fn unknown_states(judged: &[(&CommitDeploy, Reading)]) -> String {
    judged
        .iter()
        .filter(|(_, reading)| *reading == Reading::UnknownState)
        .map(|(deploy, _)| format!("{} reads {}", label(deploy), text::one_line(&deploy.state)))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Whether every reading that is not `NoRegression` is `reason`.
fn only(readings: &[Reading], reason: Reading) -> bool {
    readings
        .iter()
        .filter(|reading| **reading != Reading::NoRegression)
        .all(|reading| *reading == reason)
}

/// "the deploy" or "N deploys" for the readings that are `reason`.
fn this(readings: &[Reading], reason: Reading) -> String {
    match readings
        .iter()
        .filter(|reading| **reading == reason)
        .count()
    {
        1 => "the deploy".to_owned(),
        deploys => format!("{deploys} deploys"),
    }
}

/// `: PAGE, PAGE` for the deploys whose reading is `reason` and that have a
/// page, or nothing when none has one.
fn pages(judged: &[(&CommitDeploy, Reading)], reason: Reading) -> String {
    let pages: Vec<String> = judged
        .iter()
        .filter(|(_, reading)| *reading == reason)
        .filter_map(|(deploy, _)| deploy.deploy_url.as_deref())
        .map(text::one_line)
        .collect();
    if pages.is_empty() {
        String::new()
    } else {
        format!(": {}", pages.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::{Json, Router};
    use clap::Parser as _;
    use secrecy::SecretString;
    use serde_json::{Value, json};

    use super::*;
    use crate::api::Http;
    use crate::origin::Origin;
    use crate::{CiCommand, Cli, Command, ci_commit, unavailable};

    const ORG: &str = "0190f3a0-0000-7000-8000-000000000001";
    const REPOSITORY: &str = "0190f3a0-0000-7000-8000-0000000000f0";
    const COMMIT: &str = "89abcdef0123456789abcdef0123456789abcdef";

    fn args(flags: &[&str]) -> CiDeployArgs {
        let mut line = vec!["proofline", "ci", "deploy", "--repo", "acme/app"];
        line.extend_from_slice(flags);
        match Cli::try_parse_from(line).unwrap().command {
            Command::Ci(CiCommand::Deploy(args)) => args,
            other => panic!("{other:?}"),
        }
    }

    /// A deploy of one task in run 7 whose checks recorded `results` in
    /// order, the rest not yet.
    fn deploy(task: &str, attempts: &[i64], results: &[&str], gaps: &[&str]) -> Value {
        let checkpoints: Vec<Value> = Until::ALL
            .iter()
            .enumerate()
            .map(|(index, checkpoint)| {
                json!({
                    "checkpoint": checkpoint.api_name(),
                    "result": results.get(index),
                    "due_at": "2026-11-21T00:00:00Z",
                })
            })
            .collect();
        json!({
            "environment_id": "0190f3a0-0000-7000-8000-0000000000e0",
            "github_environment": "production",
            "deployment_task": task,
            "workflow_run_id": 7,
            "workflow_run_attempt": attempts.first(),
            "workflow_run_attempts": attempts,
            "state": "NOT_YET_DUE",
            "regressed": results.contains(&"REGRESSED"),
            "checkpoints": checkpoints,
            "gaps": gaps,
            "deploy_url": "https://console.proofline.example/deploys/1",
        })
    }

    fn recorded(deploys: &[Value]) -> (u16, Value) {
        (
            200,
            json!({ "recorded": !deploys.is_empty(), "deploys": deploys }),
        )
    }

    /// Serves the repository and, on each read of the commit's deploys, the
    /// next of `answers`, repeating the last. Returns the origin and a count
    /// of the reads.
    async fn console(
        answers: Vec<(u16, Value)>,
        last_delay: Duration,
    ) -> (String, Arc<Mutex<usize>>) {
        let reads = Arc::new(Mutex::new(0_usize));
        let counted = Arc::clone(&reads);
        let app = Router::new()
            .route(
                &format!("/api/v1/organizations/{ORG}/repository-names"),
                get(|| async {
                    Json(json!({ "repositories": [{ "id": REPOSITORY, "full_name": "acme/app" }] }))
                }),
            )
            .route(
                &format!(
                    "/api/v1/organizations/{ORG}/repositories/{REPOSITORY}/commits/{COMMIT}/deploy-verifications"
                ),
                get(move || {
                    let counted = Arc::clone(&counted);
                    let answers = answers.clone();
                    async move {
                        let index = {
                            let mut reads = counted.lock().unwrap();
                            *reads += 1;
                            *reads - 1
                        };
                        if index >= answers.len() - 1 && !last_delay.is_zero() {
                            tokio::time::sleep(last_delay).await;
                        }
                        let (status, body) = answers[index.min(answers.len() - 1)].clone();
                        let status = axum::http::StatusCode::from_u16(status).unwrap();
                        (status, Json(body)).into_response()
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (origin, reads)
    }

    /// Runs `ci deploy` with `flags` against a console that answers as
    /// `answers` say, on a paused clock. Returns the result, the reads and
    /// how long the wait took on that clock.
    async fn run(
        reader_run: Option<i64>,
        flags: &[&str],
        answers: Vec<(u16, Value)>,
    ) -> (anyhow::Result<Verdict>, usize, Duration) {
        run_args(reader_run, &args(flags), answers).await
    }

    /// [`run`] with `args` already built, as when they follow a payload.
    async fn run_args(
        reader_run: Option<i64>,
        args: &CiDeployArgs,
        answers: Vec<(u16, Value)>,
    ) -> (anyhow::Result<Verdict>, usize, Duration) {
        run_args_with_delay(reader_run, args, answers, Duration::ZERO).await
    }

    async fn run_args_with_delay(
        reader_run: Option<i64>,
        args: &CiDeployArgs,
        answers: Vec<(u16, Value)>,
        last_delay: Duration,
    ) -> (anyhow::Result<Verdict>, usize, Duration) {
        // A paused clock jumps to the next timer whenever the runtime waits,
        // even on a loopback socket about to answer, which would fire the
        // client's request timeout. A 10 ms ticker bounds each jump.
        let ticker = tokio::spawn(async {
            for _ in 0..10_000_000 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
        let (origin, reads) = console(answers, last_delay).await;
        let http = Http::new(Origin::parse(&origin).unwrap()).unwrap();
        let organization: Uuid = ORG.parse().unwrap();
        let api = Api::new(http, SecretString::from("plp_stored"), organization);
        let started = tokio::time::Instant::now();
        let verdict = wait(&api, args, COMMIT, reader_run).await;
        let took = started.elapsed();
        ticker.abort();
        let reads = *reads.lock().unwrap();
        (verdict, reads, took)
    }

    /// Each exit code from a stub console: 0 for a healthy landing with no
    /// gap, 3 for a regression or a failed deploy, 2 for a gap, a check that
    /// did not record `HEALTHY`, a commit with no deploy, and a deploy that
    /// can no longer record the check, at the first read, 1 for a refusal
    /// and 4 when Proofline fails. Older responses supply only deploy-wide gaps.
    #[tokio::test(start_paused = true)]
    async fn each_result_ends_the_job_with_its_exit_code() {
        let healthy = deploy("deploy", &[1], &["HEALTHY", "HEALTHY", "HEALTHY"], &[]);
        let mut failed = healthy.clone();
        failed["state"] = json!("FAILED");
        let mut gap = healthy.clone();
        gap["gaps"] = json!(["SIGNAL_NO_DATA"]);
        let mut later_gap = gap.clone();
        for checkpoint in later_gap["checkpoints"].as_array_mut().unwrap() {
            checkpoint["gaps"] = json!([]);
        }
        later_gap["checkpoints"][1]["gaps"] = json!(["SIGNAL_NO_DATA"]);
        let mut unverified = deploy("deploy", &[1], &[], &[]);
        unverified["state"] = json!("UNVERIFIED");
        // A deploy whose GitHub deployments only went inactive, as when its
        // job was cancelled, never landed and records no check.
        let mut inactive = deploy("deploy", &[1], &[], &[]);
        inactive["state"] = json!("INACTIVE");
        // A verification that ended after its 20-minute check: its hour check
        // will never be recorded, while the checks it did record stay readable.
        let mut finished = deploy("deploy", &[1], &["HEALTHY", "HEALTHY"], &[]);
        finished["state"] = json!("UNRECORDED");
        finished["verification_ended"] = json!(true);
        let mut finished_regressed = deploy("deploy", &[1], &["HEALTHY", "REGRESSED"], &[]);
        finished_regressed["verification_ended"] = json!(true);
        // A state a newer server added is not read as no regression, while a
        // known state with a later check that did not record `HEALTHY` still
        // lets a healthy earlier check be read (#39845).
        let mut unknown = healthy.clone();
        unknown["state"] = json!("ROLLING_OUT");
        let mut unknown_regressed = deploy("deploy", &[1], &["HEALTHY", "REGRESSED"], &[]);
        unknown_regressed["state"] = json!("ROLLING_OUT");
        let mut other_regressed = deploy("deploy:api", &[1], &["HEALTHY", "REGRESSED"], &[]);
        other_regressed["state"] = json!("INCOMPLETE");
        let mut later_incomplete = deploy("deploy", &[1], &["HEALTHY", "INCOMPLETE"], &[]);
        later_incomplete["state"] = json!("INCOMPLETE");
        for (case, flags, answer, ended) in [
            (
                "healthy",
                &[][..],
                recorded(std::slice::from_ref(&healthy)),
                Verdict::Done,
            ),
            (
                "healthy at 1h",
                &["--until", "1h"][..],
                recorded(&[healthy]),
                Verdict::Done,
            ),
            (
                "regressed at landing",
                &[][..],
                recorded(&[deploy("deploy", &[1], &["REGRESSED"], &[])]),
                Verdict::Regressed,
            ),
            (
                "regressed after the named check",
                &[][..],
                recorded(&[deploy("deploy", &[1], &["HEALTHY", "REGRESSED"], &[])]),
                Verdict::Regressed,
            ),
            (
                "failed after landing",
                &[][..],
                recorded(&[failed]),
                Verdict::Regressed,
            ),
            (
                "gap",
                &[][..],
                recorded(std::slice::from_ref(&gap)),
                Verdict::NotComplete,
            ),
            (
                "gap at 20m",
                &["--until", "20m"][..],
                recorded(&[gap]),
                Verdict::NotComplete,
            ),
            (
                "gap first seen after landing",
                &[][..],
                recorded(std::slice::from_ref(&later_gap)),
                Verdict::Done,
            ),
            (
                "gap at the chosen checkpoint",
                &["--until", "20m"][..],
                recorded(std::slice::from_ref(&later_gap)),
                Verdict::NotComplete,
            ),
            (
                "gap before the chosen checkpoint",
                &["--until", "1h"][..],
                recorded(std::slice::from_ref(&later_gap)),
                Verdict::NotComplete,
            ),
            (
                "incomplete",
                &[][..],
                recorded(&[deploy("deploy", &[1], &["INCOMPLETE"], &["SIGNAL_NO_DATA"])]),
                Verdict::NotComplete,
            ),
            (
                "superseded",
                &[][..],
                recorded(&[deploy("deploy", &[1], &["SUPERSEDED"], &[])]),
                Verdict::NotComplete,
            ),
            (
                "superseded before the hour check",
                &["--until", "1h"][..],
                recorded(&[deploy("deploy", &[1], &["HEALTHY", "SUPERSEDED"], &[])]),
                Verdict::NotComplete,
            ),
            (
                "no deploy checks",
                &[][..],
                recorded(&[unverified]),
                Verdict::NotComplete,
            ),
            (
                "never landed",
                &[][..],
                recorded(std::slice::from_ref(&inactive)),
                Verdict::NotComplete,
            ),
            (
                "checks ended before the hour check",
                &["--until", "1h"][..],
                recorded(std::slice::from_ref(&finished)),
                Verdict::NotComplete,
            ),
            (
                "checks ended after the 20-minute check",
                &["--until", "20m"][..],
                recorded(std::slice::from_ref(&finished)),
                Verdict::Done,
            ),
            (
                "checks ended after a regression",
                &["--until", "1h"][..],
                recorded(&[finished_regressed]),
                Verdict::Regressed,
            ),
            (
                "unknown state",
                &[][..],
                recorded(std::slice::from_ref(&unknown)),
                Verdict::NotComplete,
            ),
            (
                "unknown state that regressed",
                &[][..],
                recorded(&[unknown_regressed]),
                Verdict::Regressed,
            ),
            (
                "unknown state beside another deploy's regression",
                &[][..],
                recorded(&[unknown.clone(), other_regressed]),
                Verdict::Regressed,
            ),
            (
                "later incomplete check on a known state",
                &[][..],
                recorded(&[later_incomplete]),
                Verdict::Done,
            ),
        ] {
            let (verdict, reads, _) = run(None, flags, vec![answer]).await;
            assert_eq!(verdict.unwrap(), ended, "{case}");
            assert_eq!(reads, 1, "{case}");
        }
        // The known states are the public contract's, so a state the server
        // adds fails here until the CLI reads it.
        let contract: Value = serde_json::from_str(include_str!(concat!(
            env!("OUT_DIR"),
            "/openapi.public.json"
        )))
        .unwrap();
        let mut documented: Vec<&str> =
            contract["components"]["schemas"]["DeployCoverageState"]["oneOf"]
                .as_array()
                .unwrap()
                .iter()
                .map(|state| state["const"].as_str().unwrap())
                .collect();
        let mut known = KNOWN_STATES.to_vec();
        documented.sort_unstable();
        known.sort_unstable();
        assert_eq!(known, documented);
        let unknown: CommitDeploy = serde_json::from_value(unknown).unwrap();
        let mut output = Vec::new();
        write_lines(&mut output, &unknown, Until::Landing).unwrap();
        let ended = ending(
            Verdict::NotComplete,
            &[(&unknown, judge(&unknown, Until::Landing))],
            1,
            "acme/app",
            COMMIT,
            "LANDING",
            0,
        );
        for shown in [String::from_utf8(output).unwrap(), ended] {
            assert!(shown.contains("ROLLING_OUT"), "{shown}");
        }
        let mut output = Vec::new();
        write_lines(
            &mut output,
            &serde_json::from_value(later_gap).unwrap(),
            Until::Minutes20,
        )
        .unwrap();
        let output = String::from_utf8(output).unwrap();
        // The ended verification's lines and last line name the missing
        // check and the deploy.
        let mut printed = Vec::new();
        let finished: CommitDeploy = serde_json::from_value(finished).unwrap();
        write_lines(&mut printed, &finished, Until::Hour1).unwrap();
        let printed = String::from_utf8(printed).unwrap();
        assert!(printed.contains("HOUR_1 NOT_RECORDED"), "{printed}");
        let last = ending(
            Verdict::NotComplete,
            &[(&finished, Reading::Ended)],
            1,
            "acme/app",
            COMMIT,
            "HOUR_1",
            30,
        );
        assert!(
            last.contains("HOUR_1") && last.contains("https://console.proofline.example/deploys/1"),
            "{last}"
        );
        let inactive: CommitDeploy = serde_json::from_value(inactive).unwrap();
        let last = ending(
            Verdict::NotComplete,
            &[(&inactive, judge(&inactive, Until::Landing))],
            1,
            "acme/app",
            COMMIT,
            "LANDING",
            30,
        );
        assert!(
            last.contains("https://console.proofline.example/deploys/1"),
            "{last}"
        );
        let mut lines = output.lines();
        assert!(
            lines
                .next()
                .unwrap()
                .contains("LANDING HEALTHY; state NOT_YET_DUE; gaps none")
        );
        assert!(
            lines
                .next()
                .unwrap()
                .contains("MINUTES_20 HEALTHY; state NOT_YET_DUE; gaps SIGNAL_NO_DATA")
        );
        // A rollback is judged on its checks like any deploy, and its one
        // extra line names the deploy it restores and those it rolls back. A
        // field a newer server adds under `rollback` is read, not refused.
        let mut rollback = deploy("deploy", &[1], &["HEALTHY", "HEALTHY", "HEALTHY"], &[]);
        rollback["rollback"] = json!({
            "restores": {
                "commit_sha": COMMIT, "landed_at": "2026-11-18T09:00:00Z",
                "deploy_url": "https://console.proofline.example/deploys/8",
            },
            "rolls_back": [{
                "commit_sha": "0123456789abcdef0123456789abcdef01234567",
                "landed_at": "2026-11-19T10:05:00Z",
                "deploy_url": "https://console.proofline.example/deploys/9",
                "removed_pull_requests": [42],
            }],
        });
        let (verdict, ..) = run(None, &[], vec![recorded(std::slice::from_ref(&rollback))]).await;
        assert_eq!(verdict.unwrap(), Verdict::Done);
        let mut printed = Vec::new();
        write_lines(
            &mut printed,
            &serde_json::from_value(rollback.clone()).unwrap(),
            Until::Landing,
        )
        .unwrap();
        let printed = String::from_utf8(printed).unwrap();
        assert_eq!(
            printed.lines().next(),
            Some(
                "production deploy run 7 attempt 1: rollback; \
                 restores https://console.proofline.example/deploys/8; \
                 rolls back https://console.proofline.example/deploys/9"
            ),
            "{printed}"
        );
        assert_eq!(printed.lines().count(), 2, "{printed}");
        // A deploy whose newest check found an earlier deploy serving again
        // says so on its own line, beside a rollback's when both apply, and
        // still exits on its checks. A later check that found none clears
        // it, and a response from before the field existed reads as none.
        let mut observed = deploy("deploy", &[1], &["HEALTHY", "REGRESSED"], &[]);
        observed["rolled_back"] = json!(true);
        observed["rollback"] = rollback["rollback"].clone();
        let (verdict, ..) = run(None, &[], vec![recorded(std::slice::from_ref(&observed))]).await;
        assert_eq!(verdict.unwrap(), Verdict::Regressed);
        let lines = |deploy: &Value| {
            let mut printed = Vec::new();
            write_lines(
                &mut printed,
                &serde_json::from_value(deploy.clone()).unwrap(),
                Until::Landing,
            )
            .unwrap();
            String::from_utf8(printed).unwrap()
        };
        let printed = lines(&observed);
        let printed: Vec<&str> = printed.lines().collect();
        // The rollback, rolled-back, landing and later regressed lines.
        assert_eq!(printed.len(), 4, "{printed:?}");
        assert!(printed[0].contains(": rollback; restores"), "{printed:?}");
        assert_eq!(
            printed[1],
            "production deploy run 7 attempt 1: rolled back; \
             the newest check found an earlier deploy serving again"
        );
        observed["rolled_back"] = json!(false);
        assert!(!lines(&observed).contains("rolled back;"));
        let older = deploy("deploy", &[1], &["HEALTHY"], &[]);
        assert!(older.get("rolled_back").is_none());
        assert_eq!(lines(&older).lines().count(), 1);
        for (status, exit_four) in [(401, false), (403, false), (503, true)] {
            let (verdict, ..) = run(None, &[], vec![(status, json!({ "detail": "no" }))]).await;
            let error = verdict.unwrap_err();
            assert_eq!(unavailable(&error), exit_four, "{status}: {error:#}");
        }
    }

    /// The wait reads until the named check is recorded, and a check or a
    /// deploy that is still missing at `--timeout` is not established.
    #[tokio::test(start_paused = true)]
    async fn the_wait_ends_when_the_check_is_recorded_or_at_the_timeout() {
        let none = recorded(&[]);
        let landed = recorded(&[deploy("deploy", &[1], &["HEALTHY"], &[])]);
        let (verdict, reads, took) = run(
            None,
            &["--until", "20m"],
            vec![
                none.clone(),
                landed.clone(),
                recorded(&[deploy("deploy", &[1], &["HEALTHY", "HEALTHY"], &[])]),
            ],
        )
        .await;
        assert_eq!(verdict.unwrap(), Verdict::Done);
        assert_eq!(reads, 3);
        assert!(took < Duration::from_secs(60), "{took:?}");

        // The fourth read begins about 35 seconds into the wait. Its healthy
        // answer arrives after the minute has ended, within the HTTP timeout.
        let healthy = recorded(&[deploy("deploy", &[1], &["HEALTHY", "HEALTHY"], &[])]);
        let (verdict, reads, took) = run_args_with_delay(
            None,
            &args(&["--until", "20m", "--timeout", "1"]),
            vec![none.clone(), none.clone(), landed.clone(), healthy],
            Duration::from_secs(28),
        )
        .await;
        assert_eq!(verdict.unwrap(), Verdict::NotComplete);
        assert_eq!(reads, 4);
        assert!(took >= Duration::from_secs(60), "{took:?}");
        assert!(took < Duration::from_secs(61), "{took:?}");

        let (verdict, reads, _) = run(Some(7), &["--until", "20m"], vec![landed.clone()]).await;
        assert!(verdict.is_err());
        assert_eq!(reads, 1);
        let (verdict, reads, _) = run(Some(7), &[], vec![landed.clone()]).await;
        assert_eq!(verdict.unwrap(), Verdict::Done);
        assert_eq!(reads, 1);

        let mut regressed = deploy("deploy:api", &[1], &["REGRESSED"], &[]);
        regressed["workflow_run_id"] = json!(8);
        let mixed = recorded(&[deploy("deploy:web", &[1], &["HEALTHY"], &[]), regressed]);
        let (verdict, reads, _) = run(Some(7), &["--until", "20m"], vec![mixed]).await;
        assert_eq!(verdict.unwrap(), Verdict::Regressed);
        assert_eq!(reads, 1);

        for (case, answer) in [("no deploy", none), ("check not recorded", landed.clone())] {
            let (verdict, reads, took) =
                run(None, &["--until", "20m", "--timeout", "3"], vec![answer]).await;
            assert_eq!(verdict.unwrap(), Verdict::NotComplete, "{case}");
            assert!(reads > 2, "{case}: {reads}");
            assert!(took >= Duration::from_secs(180), "{case}: {took:?}");
            assert!(took < Duration::from_secs(190), "{case}: {took:?}");
        }

        // A running verification's overdue hour check reads `UNRECORDED` as
        // an ended one's does, but can still be recorded, so the wait reads
        // until the timeout. So does an ended deploy beside another deploy
        // whose running verification can still record its check.
        let mut overdue = deploy("deploy:web", &[1], &["HEALTHY", "HEALTHY"], &[]);
        overdue["state"] = json!("UNRECORDED");
        overdue["verification_ended"] = json!(false);
        let mut finished = overdue.clone();
        finished["deployment_task"] = json!("deploy:api");
        finished["verification_ended"] = json!(true);
        for (case, answer) in [
            (
                "overdue while running",
                recorded(std::slice::from_ref(&overdue)),
            ),
            (
                "ended beside a running deploy",
                recorded(&[finished, overdue]),
            ),
        ] {
            let (verdict, reads, took) =
                run(None, &["--until", "1h", "--timeout", "3"], vec![answer]).await;
            assert_eq!(verdict.unwrap(), Verdict::NotComplete, "{case}");
            assert!(reads > 2, "{case}: {reads}");
            assert!(took >= Duration::from_secs(180), "{case}: {took:?}");
        }

        // A reader following a run that did not succeed stops waiting for a
        // deploy after 5 minutes, with eight reads. A deploy that run landed
        // is read as from any run, and once it is recorded its check gets
        // the whole wait. A run that succeeded, a payload without its
        // conclusion and an explicit --run wait the whole 30 minutes.
        let followed = |conclusion: Option<&str>, flags: &[&str]| {
            let payload = json!({ "workflow_run": {
                "head_sha": COMMIT, "id": 7, "run_attempt": 1, "conclusion": conclusion,
            } });
            let mut followed = args(flags);
            followed.follow(
                &ProducingRun::parse(payload.to_string().as_bytes()).unwrap(),
                false,
            );
            followed
        };
        let none = recorded(&[]);
        let unchecked = recorded(&[deploy("deploy", &[1], &[], &[])]);
        let landed = recorded(&[deploy("deploy", &[1], &["HEALTHY"], &[])]);
        for (case, conclusion, flags, answers, ended, polls, minutes) in [
            (
                "failed, no deploy",
                Some("failure"),
                &[][..],
                vec![none.clone()],
                Verdict::NotComplete,
                8,
                5,
            ),
            (
                "cancelled, other run's deploy",
                Some("cancelled"),
                &[][..],
                vec![recorded(&[{
                    let mut other = deploy("deploy", &[1], &["HEALTHY"], &[]);
                    other["workflow_run_id"] = json!(8);
                    other
                }])],
                Verdict::NotComplete,
                8,
                5,
            ),
            (
                "failed, landed deploy",
                Some("failure"),
                &[][..],
                vec![none.clone(), landed.clone()],
                Verdict::Done,
                2,
                0,
            ),
            (
                "failed, check pending",
                Some("failure"),
                &[][..],
                vec![unchecked.clone()],
                Verdict::NotComplete,
                33,
                30,
            ),
            (
                "succeeded, no deploy yet",
                Some("success"),
                &[][..],
                vec![none.clone()],
                Verdict::NotComplete,
                33,
                30,
            ),
            (
                "no conclusion",
                None,
                &[][..],
                vec![none.clone()],
                Verdict::NotComplete,
                33,
                30,
            ),
            (
                "explicit --run",
                Some("failure"),
                &["--run", "7"][..],
                vec![none.clone()],
                Verdict::NotComplete,
                33,
                30,
            ),
        ] {
            let (verdict, reads, took) =
                run_args(None, &followed(conclusion, flags), answers).await;
            assert_eq!(verdict.unwrap(), ended, "{case}");
            assert_eq!(reads, polls, "{case}");
            assert_eq!(took.as_secs() / 60, minutes, "{case}: {took:?}");
        }
        assert!(no_deploy_from_run(7, "failure", "acme/app", COMMIT, 5).contains("failure"));

        // Without --timeout, a wait for the hour check lasts until the check
        // is due, 50 minutes from now, past the 30-minute floor.
        let mut due = deploy("deploy", &[1], &["HEALTHY", "HEALTHY"], &[]);
        let due_at = i64::try_from(crate::device::now()).unwrap() + 50 * 60;
        due["checkpoints"][2]["due_at"] = json!(crate::tests::rfc3339(due_at));
        let (verdict, _, took) = run(None, &["--until", "1h"], vec![recorded(&[due])]).await;
        assert_eq!(verdict.unwrap(), Verdict::NotComplete);
        assert!(took >= Duration::from_secs(49 * 60), "{took:?}");
        assert!(took < Duration::from_secs(51 * 60), "{took:?}");

        // A landing check due 75 minutes from now that a reread records 40
        // minutes into the wait is read, past the 30-minute floor, and the
        // wait exits 0. A due time already past keeps 30 minutes.
        let mut unrecorded = deploy("deploy", &[1], &[], &[]);
        let due_at = i64::try_from(crate::device::now()).unwrap() + 75 * 60;
        unrecorded["checkpoints"][0]["due_at"] = json!(crate::tests::rfc3339(due_at));
        let mut healthy = deploy("deploy", &[1], &["HEALTHY"], &[]);
        healthy["checkpoints"][0]["due_at"] = json!(crate::tests::rfc3339(due_at));
        // Reads 0 to 4 come at 0, 5, 15, 35 and 75 seconds, then each minute;
        // read 43 is the first at least 40 minutes in.
        let mut answers = vec![recorded(&[unrecorded]); 43];
        answers.push(recorded(&[healthy]));
        let (verdict, reads, took) = run(None, &[], answers).await;
        assert_eq!(verdict.unwrap(), Verdict::Done);
        assert_eq!(reads, 44);
        assert!(took >= Duration::from_secs(40 * 60), "{took:?}");
        assert!(took < Duration::from_secs(41 * 60), "{took:?}");
        let past = recorded(&[deploy("deploy", &[1], &[], &[])]);
        let (verdict, _, took) = run(None, &[], vec![past]).await;
        assert_eq!(verdict.unwrap(), Verdict::NotComplete);
        assert!(took >= Duration::from_secs(30 * 60), "{took:?}");
        assert!(took < Duration::from_secs(31 * 60), "{took:?}");

        // A read that fails with a 5xx answer after one that answered does
        // not end the wait: it reads again on its schedule, and an answer
        // resets the count, so seven failures, at most four in a row, still
        // reach the verdict (#39591). Five in a row end it with exit 4. The
        // first read, a refusal and a deadline that has passed end it at once.
        let failed = (502, json!({ "detail": "bad gateway" }));
        let mut blips = vec![landed.clone()];
        for run in [3, 4] {
            blips.extend(std::iter::repeat_n(failed.clone(), run));
            blips.push(landed.clone());
        }
        blips.push(recorded(&[deploy(
            "deploy",
            &[1],
            &["HEALTHY", "HEALTHY"],
            &[],
        )]));
        let (verdict, reads, _) = run(None, &["--until", "20m"], blips).await;
        assert_eq!(verdict.unwrap(), Verdict::Done);
        assert_eq!(reads, 11);
        for (case, flags, answers, expected_reads, exit_four) in [
            (
                "five in a row",
                &["--until", "20m"][..],
                vec![landed.clone(), failed.clone()],
                6,
                true,
            ),
            (
                "first read",
                &["--until", "20m"][..],
                vec![failed.clone()],
                1,
                true,
            ),
            (
                "refused",
                &["--until", "20m"][..],
                vec![landed.clone(), (404, json!({ "detail": "no" }))],
                2,
                false,
            ),
            (
                "deadline",
                &["--until", "20m", "--timeout", "0"][..],
                vec![failed.clone()],
                1,
                true,
            ),
        ] {
            let (verdict, reads, _) = run(None, flags, answers).await;
            let error = verdict.unwrap_err();
            assert_eq!(unavailable(&error), exit_four, "{case}: {error:#}");
            assert_eq!(reads, expected_reads, "{case}");
        }
    }

    /// `--task` takes one task's deploy of a commit deployed by two, and
    /// `--run` with `--attempt` takes the deploy that holds that attempt; a
    /// deploy that lists no attempts never matches.
    #[tokio::test(start_paused = true)]
    async fn the_selection_decides_which_deploys_count() {
        assert!(args(&["--run", "7"]).check_reader_run(Some(7)).is_err());

        // One commit has three different landing verdicts. The Amplify job
        // and Actions run have the same numeric ID.
        let execution = "8ab8018c-91e4-482c-90bd-db212b3ec393";
        let aws = json!({
            "environment_id": ORG,
            "aws_provider": "AWS_CODEPIPELINE",
            "aws_run_id": execution,
            "state": "NOT_YET_DUE",
            "regressed": false,
            "checkpoints": [{"checkpoint": "LANDING", "result": "HEALTHY",
                             "due_at": "2026-11-21T00:00:00Z"}],
            "gaps": []
        });
        let mut amplify = aws.clone();
        amplify["aws_provider"] = json!("AWS_AMPLIFY");
        amplify["aws_run_id"] = json!("7");
        amplify["regressed"] = json!(true);
        amplify["checkpoints"][0]["result"] = json!("REGRESSED");
        let mixed = recorded(&[
            aws,
            amplify,
            deploy(
                "deploy",
                &[1],
                &["INCOMPLETE"],
                &["RUNTIME_INVENTORY_STALE"],
            ),
        ]);
        for (flags, ended) in [
            (&["--aws-run", execution][..], Verdict::Done),
            (&["--aws-run", "7"][..], Verdict::Regressed),
            (
                &["--aws-run", execution, "--environment-id", ORG][..],
                Verdict::Done,
            ),
            (&["--run", "7"][..], Verdict::NotComplete),
            (
                &["--aws-run", execution, "--run", "7", "--timeout", "0"][..],
                Verdict::NotComplete,
            ),
            (
                &["--aws-run", "missing", "--timeout", "0"][..],
                Verdict::NotComplete,
            ),
            (
                &[
                    "--aws-run",
                    execution,
                    "--environment-id",
                    REPOSITORY,
                    "--timeout",
                    "0",
                ][..],
                Verdict::NotComplete,
            ),
        ] {
            let (verdict, ..) = run(None, flags, vec![mixed.clone()]).await;
            assert_eq!(verdict.unwrap(), ended, "{flags:?}");
        }

        let tasks = recorded(&[
            deploy("deploy:web", &[1], &["HEALTHY"], &[]),
            deploy("deploy:api", &[1], &["REGRESSED"], &[]),
        ]);
        for (flags, ended) in [
            (&["--task", "deploy:web"][..], Verdict::Done),
            (&["--task", "deploy:api"][..], Verdict::Regressed),
            (&[][..], Verdict::Regressed),
        ] {
            let (verdict, ..) = run(None, flags, vec![tasks.clone()]).await;
            assert_eq!(verdict.unwrap(), ended, "{flags:?}");
        }

        // Both deploys landed healthy and only the api deploy regressed at
        // its hour check: a landing read exits 3 and its lines and ending
        // name that deploy, the hour check and its page, each once.
        let mut api = deploy(
            "deploy:api",
            &[1],
            &["HEALTHY", "HEALTHY", "REGRESSED"],
            &[],
        );
        api["deploy_url"] = json!("https://console.proofline.example/deploys/2");
        let later = recorded(&[
            deploy("deploy:web", &[1], &["HEALTHY", "HEALTHY", "HEALTHY"], &[]),
            api.clone(),
        ]);
        for (flags, ended) in [
            (&[][..], Verdict::Regressed),
            (&["--task", "deploy:web"][..], Verdict::Done),
        ] {
            let (verdict, ..) = run(None, flags, vec![later.clone()]).await;
            assert_eq!(verdict.unwrap(), ended, "{flags:?}");
        }
        let api: CommitDeploy = serde_json::from_value(api).unwrap();
        let mut printed = Vec::new();
        write_lines(&mut printed, &api, Until::Landing).unwrap();
        let printed = String::from_utf8(printed).unwrap();
        let regressed: Vec<&str> = printed
            .lines()
            .filter(|line| line.contains("REGRESSED"))
            .collect();
        assert_eq!(regressed.len(), 1, "{printed}");
        assert!(regressed[0].contains("HOUR_1"), "{printed}");
        assert!(regressed[0].ends_with("deploys/2"), "{printed}");
        let ended = ending(
            Verdict::Regressed,
            &[(&api, judge(&api, Until::Landing))],
            2,
            "acme/app",
            COMMIT,
            "LANDING",
            30,
        );
        assert!(
            ended.contains("deploy:api") && ended.contains("HOUR_1"),
            "{ended}"
        );

        let attempts = recorded(&[
            deploy("deploy", &[1, 2], &["REGRESSED"], &[]),
            deploy("deploy", &[3], &["HEALTHY"], &[]),
            deploy("deploy", &[], &["HEALTHY"], &[]),
        ]);
        for (flags, ended) in [
            (&["--run", "7", "--attempt", "3"][..], Verdict::Done),
            (&["--run", "7", "--attempt", "2"][..], Verdict::Regressed),
            (&["--run", "8", "--timeout", "1"][..], Verdict::NotComplete),
            (
                &["--run", "7", "--attempt", "4", "--timeout", "1"][..],
                Verdict::NotComplete,
            ),
        ] {
            let (verdict, ..) = run(None, flags, vec![attempts.clone()]).await;
            assert_eq!(verdict.unwrap(), ended, "{flags:?}");
        }

        // A pipeline outside Actions deploys the commit twice to one
        // environment and task: deployments 101 (A) and 102 (B), each a
        // deploy of its own. `--deployment 102` reads only B, so A's healthy
        // landing never ends B's wait and A's failure never decides it. A
        // response without the IDs, from an older server, matches no
        // `--deployment` (#38057).
        let standalone = |id: i64, results: &[&str]| {
            let mut deploy = deploy("deploy", &[], results, &[]);
            deploy["workflow_run_id"] = Value::Null;
            deploy["github_deployment_ids"] = json!([id]);
            deploy
        };
        let a = standalone(101, &["HEALTHY"]);
        let mut a_failed = a.clone();
        a_failed["state"] = json!("FAILED");
        let mut older = a.clone();
        older
            .as_object_mut()
            .unwrap()
            .remove("github_deployment_ids");
        for (case, flags, answers, ended) in [
            (
                "only A recorded",
                &["--deployment", "102", "--timeout", "1"][..],
                vec![recorded(std::slice::from_ref(&a))],
                Verdict::NotComplete,
            ),
            (
                "B recorded, then its landing",
                &["--deployment", "102"][..],
                vec![
                    recorded(std::slice::from_ref(&a)),
                    recorded(&[a.clone(), standalone(102, &[])]),
                    recorded(&[a.clone(), standalone(102, &["HEALTHY"])]),
                ],
                Verdict::Done,
            ),
            (
                "B's landing missing",
                &["--deployment", "102", "--timeout", "1"][..],
                vec![recorded(&[a.clone(), standalone(102, &[])])],
                Verdict::NotComplete,
            ),
            (
                "B regressed",
                &["--deployment", "102"][..],
                vec![recorded(&[a.clone(), standalone(102, &["REGRESSED"])])],
                Verdict::Regressed,
            ),
            (
                "A failed, B healthy",
                &["--deployment", "102", "--environment", "production"][..],
                vec![recorded(&[a_failed.clone(), standalone(102, &["HEALTHY"])])],
                Verdict::Done,
            ),
            (
                "A failed, B healthy, unfiltered",
                &[][..],
                vec![recorded(&[a_failed, standalone(102, &["HEALTHY"])])],
                Verdict::Regressed,
            ),
            (
                "unknown deployment",
                &["--deployment", "999", "--timeout", "1"][..],
                vec![recorded(&[a.clone(), standalone(102, &["HEALTHY"])])],
                Verdict::NotComplete,
            ),
            (
                "older response",
                &["--deployment", "101", "--timeout", "1"][..],
                vec![recorded(&[older])],
                Verdict::NotComplete,
            ),
        ] {
            let (verdict, reads, _) = run(None, flags, answers.clone()).await;
            assert_eq!(verdict.unwrap(), ended, "{case}");
            if ended == Verdict::NotComplete {
                assert!(reads > 1, "{case} waits for its deadline: {reads}");
            } else {
                assert_eq!(reads, answers.len(), "{case}");
            }
        }

        // One GitHub deployment recorded in two Proofline environments, A
        // healthy and B regressed: the copies share the commit, GitHub
        // Environment, task, run, attempt and deployment ID, and only
        // `environment_id` tells them apart. Selecting A exits 0 and B exits
        // 3, while an unfiltered job still exits 3 and an environment with no
        // copy waits for its deadline.
        let a = "0190f3a0-0000-7000-8000-0000000000a1";
        let b = "0190f3a0-0000-7000-8000-0000000000b2";
        let copy = |environment: &str, results: &[&str]| {
            let mut deploy = deploy("deploy", &[1], results, &[]);
            deploy["environment_id"] = json!(environment);
            deploy["github_deployment_ids"] = json!([101]);
            deploy
        };
        let shared = recorded(&[copy(a, &["HEALTHY"]), copy(b, &["REGRESSED"])]);
        for (flags, ended) in [
            (
                &["--environment-id", a, "--run", "7", "--attempt", "1"][..],
                Verdict::Done,
            ),
            (
                &["--environment-id", b, "--deployment", "101"][..],
                Verdict::Regressed,
            ),
            (&[][..], Verdict::Regressed),
            (
                &[
                    "--environment-id",
                    "0190f3a0-0000-7000-8000-0000000000c3",
                    "--timeout",
                    "1",
                ][..],
                Verdict::NotComplete,
            ),
        ] {
            let (verdict, reads, _) = run(None, flags, vec![shared.clone()]).await;
            assert_eq!(verdict.unwrap(), ended, "{flags:?}");
            assert_eq!(reads > 1, ended == Verdict::NotComplete, "{flags:?}");
        }
        assert!(
            Cli::try_parse_from([
                "proofline",
                "ci",
                "deploy",
                "--environment-id",
                "production"
            ])
            .is_err(),
            "a malformed UUID is refused before any read"
        );

        // A `workflow_run` reader follows the completed run: its head, run
        // and attempt, so a newer run's deploy is never taken as its own. An
        // explicit flag or `COMMIT_SHA` wins, and `--run` keeps its own attempt.
        let payload = json!({ "workflow_run": { "head_sha": COMMIT, "id": 7, "run_attempt": 3 } });
        let produced = ProducingRun::parse(payload.to_string().as_bytes()).unwrap();
        let mut followed = args(&[]);
        followed.follow(&produced, false);
        assert_eq!(followed.commit.as_deref(), Some(COMMIT));
        assert_eq!((followed.run, followed.attempt), (Some(7), Some(3)));
        let newer = recorded(&[deploy("deploy", &[3], &["HEALTHY"], &[]), {
            let mut newer = deploy("deploy", &[1], &["REGRESSED"], &[]);
            newer["workflow_run_id"] = json!(8);
            newer
        }]);
        let (verdict, ..) = run(None, &["--run", "7", "--attempt", "3"], vec![newer]).await;
        assert_eq!(verdict.unwrap(), Verdict::Done);
        let mut explicit = args(&[
            "--commit",
            "0123456789abcdef0123456789abcdef01234567",
            "--run",
            "8",
        ]);
        explicit.follow(&produced, false);
        assert_eq!(
            explicit.commit.as_deref(),
            Some("0123456789abcdef0123456789abcdef01234567")
        );
        assert_eq!((explicit.run, explicit.attempt), (Some(8), None));
        let mut aws_reader = args(&["--aws-run", execution]);
        aws_reader.follow(&produced, false);
        assert_eq!((aws_reader.run, aws_reader.attempt), (None, None));
        let mut cloud_build = args(&[]);
        cloud_build.follow(&produced, true);
        assert_eq!(cloud_build.commit, None);
        for unreadable in [
            json!({}),
            json!({ "workflow_run": { "head_sha": "", "id": 7 } }),
        ] {
            assert!(ProducingRun::parse(unreadable.to_string().as_bytes()).is_err());
        }
    }

    /// A ref is refused before anything is read, and the day check needs an
    /// explicit wait.
    #[test]
    fn a_ref_and_an_implicit_day_wait_are_refused() {
        assert!(ci_commit(Some("main")).is_err());
        assert!(ci_commit(Some("89abcdef0123")).is_err());
        assert!(args(&["--until", "1d"]).timeout_minutes().is_err());
        for (flags, until_due) in [
            (&["--until", "20m"][..], true),
            (&["--until", "1h"][..], true),
            (&[][..], true),
            (&["--timeout", "30"][..], false),
            (&["--until", "1h", "--timeout", "5"][..], false),
        ] {
            assert_eq!(args(flags).waits_until_due(), until_due, "{flags:?}");
        }
        assert_eq!(
            args(&["--until", "1d", "--timeout", "1560"])
                .timeout_minutes()
                .unwrap(),
            1560
        );
        assert!(
            Cli::try_parse_from(["proofline", "ci", "deploy", "--attempt", "2"]).is_err(),
            "--attempt names an attempt of --run"
        );
    }
}
