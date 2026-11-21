//! `proofline ci deploy`: waits until Proofline has recorded a named check of
//! the deploys of one commit, then ends by what those checks recorded, so the
//! pipeline decides what follows. A result is "no regression observed", never
//! a claim that the deploy is safe, and anything Proofline did not establish
//! ends as not established.

use std::io::Write as _;
use std::time::Duration;

use anyhow::bail;
use clap::{Args, ValueEnum};

use crate::api::Api;
use crate::model::{CommitDeploy, CommitDeployRollback, RollbackDeploy};
use crate::{
    FIRST_POLL_SECONDS, LONGEST_POLL_SECONDS, RepositoryArgs, Verdict, connected_repository,
    poll_deadline, say, text,
};

/// Minutes `ci deploy` waits without `--timeout`.
const DEFAULT_TIMEOUT_MINUTES: u64 = 30;

#[derive(Debug, Args)]
pub(crate) struct CiDeployArgs {
    /// Full commit SHA the job deployed. Defaults to `COMMIT_SHA`, then the
    /// pull request's head on a GitHub Actions pull-request event, then
    /// `GITHUB_SHA`.
    #[arg(long, value_name = "SHA")]
    pub(crate) commit: Option<String>,
    /// Only deploys to this GitHub Environment.
    #[arg(long, value_name = "NAME")]
    environment: Option<String>,
    /// Only deploys of this GitHub deployment task, such as `deploy:web`.
    #[arg(long, value_name = "TASK")]
    task: Option<String>,
    /// Only deploys that this GitHub Actions run created. It never defaults to
    /// the reading job's own run.
    #[arg(long, value_name = "ID")]
    run: Option<i64>,
    /// Only the deploy of `--run` that holds a deployment of this run attempt.
    /// A deploy that lists no attempts never matches.
    #[arg(long, value_name = "N", requires = "run")]
    attempt: Option<i64>,
    /// The check to wait for. The checks before it count too.
    #[arg(long, value_enum, default_value_t = Until::Landing)]
    until: Until,
    /// Minutes to wait for the check, 30 by default. `--until 1d` needs an
    /// explicit value.
    #[arg(long, value_name = "MINUTES")]
    timeout: Option<u64>,
    /// Print the route's response as JSON instead of text.
    #[arg(long)]
    json: bool,
    #[command(flatten)]
    pub(crate) repository: RepositoryArgs,
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
    /// The wait in minutes. The day check comes due a day after landing, past
    /// any default a job could mean, so it takes an explicit one.
    pub(crate) fn timeout_minutes(&self) -> anyhow::Result<u64> {
        match (self.timeout, self.until) {
            (Some(minutes), _) => Ok(minutes),
            (None, Until::Day1) => bail!(
                "--until 1d waits for the check a day after landing; name how long to wait with --timeout MINUTES, such as --timeout 1560"
            ),
            (None, _) => Ok(DEFAULT_TIMEOUT_MINUTES),
        }
    }

    fn selects(&self, deploy: &CommitDeploy) -> bool {
        let matches = |wanted: Option<&str>, value: Option<&str>| {
            wanted.is_none_or(|wanted| value == Some(wanted))
        };
        matches(
            self.environment.as_deref(),
            deploy.github_environment.as_deref(),
        ) && matches(self.task.as_deref(), deploy.deployment_task.as_deref())
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
    /// A check through the named one is not `HEALTHY`, or the deploy names a
    /// gap.
    NotEstablished,
    /// Every check through the named one recorded `HEALTHY` and the deploy
    /// names no gap.
    NoRegression,
}

/// Reads one deploy at `until`. The response's gaps are the deploy's, not a
/// check's, so any gap leaves every check unestablished: a gap a later check
/// recorded cannot be told apart from one an earlier check recorded. A failed
/// deploy or a regression decides first, whatever else was recorded.
fn judge(deploy: &CommitDeploy, until: Until) -> Reading {
    let result = |checkpoint: Until| {
        deploy
            .checkpoints
            .iter()
            .find(|recorded| recorded.checkpoint == checkpoint.api_name())
            .and_then(|recorded| recorded.result.as_deref())
    };
    let regressed = deploy
        .checkpoints
        .iter()
        .any(|recorded| recorded.result.as_deref() == Some("REGRESSED"));
    if deploy.state == "FAILED" || deploy.regressed || regressed {
        return Reading::Regressed;
    }
    if result(until).is_none() {
        return Reading::Waiting;
    }
    let healthy = Until::ALL
        .iter()
        .filter(|checkpoint| **checkpoint <= until)
        .all(|checkpoint| result(*checkpoint) == Some("HEALTHY"));
    if healthy && deploy.gaps.is_empty() {
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
pub(crate) async fn wait(api: &Api, args: &CiDeployArgs, commit: &str) -> anyhow::Result<Verdict> {
    let minutes = args.timeout_minutes()?;
    let deadline = poll_deadline(minutes)?;
    let (name, repository_id) = connected_repository(api, &args.repository).await?;
    let checkpoint = args.until.api_name();
    let mut delay = FIRST_POLL_SECONDS;
    loop {
        let (raw, read) = api
            .commit_deploy_verifications(repository_id, commit)
            .await?;
        let selected: Vec<&CommitDeploy> = read
            .deploys
            .iter()
            .filter(|deploy| args.selects(deploy))
            .collect();
        let readings: Vec<Reading> = selected
            .iter()
            .map(|deploy| judge(deploy, args.until))
            .collect();
        let now = tokio::time::Instant::now();
        if let Some(verdict) = conclude(&readings, now >= deadline) {
            let mut stdout = std::io::stdout().lock();
            if args.json {
                writeln!(stdout, "{}", serde_json::to_string_pretty(&raw)?)?;
            } else {
                for deploy in &selected {
                    write_lines(&mut stdout, deploy, args.until)?;
                }
            }
            drop(stdout);
            say(&ending(
                verdict,
                &readings,
                read.deploys.len(),
                &name,
                commit,
                checkpoint,
                minutes,
            ));
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
        let pause = Duration::from_secs(delay).min(deadline.saturating_duration_since(now));
        tokio::time::sleep(pause).await;
        delay = (delay * 2).min(LONGEST_POLL_SECONDS);
    }
}

fn count(deploys: usize) -> String {
    if deploys == 1 {
        "1 deploy".to_owned()
    } else {
        format!("{deploys} deploys")
    }
}

/// One line for each check of `deploy` through `until`: the deploy, the
/// checkpoint, its result, the deploy's gap codes and its page. A rollback
/// first gets one line naming the page of the deploy it restores, when the
/// read names one, and of each deploy it rolls back. It changes no result.
fn write_lines(
    out: &mut impl std::io::Write,
    deploy: &CommitDeploy,
    until: Until,
) -> std::io::Result<()> {
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
    let gaps = if deploy.gaps.is_empty() {
        "none".to_owned()
    } else {
        deploy
            .gaps
            .iter()
            .map(|gap| text::one_line(gap))
            .collect::<Vec<_>>()
            .join(",")
    };
    let page = deploy
        .deploy_url
        .as_deref()
        .map_or_else(String::new, |url| format!("; {}", text::one_line(url)));
    let state = text::one_line(&deploy.state);
    if let Some(rollback) = &deploy.rollback {
        writeln!(out, "{}: {}", label.join(" "), rollback_line(rollback))?;
    }
    for checkpoint in Until::ALL.iter().filter(|checkpoint| **checkpoint <= until) {
        let result = deploy
            .checkpoints
            .iter()
            .find(|recorded| recorded.checkpoint == checkpoint.api_name())
            .and_then(|recorded| recorded.result.as_deref())
            .map_or_else(|| "NOT_RECORDED".to_owned(), text::one_line);
        writeln!(
            out,
            "{}: {} {result}; state {state}; gaps {gaps}{page}",
            label.join(" "),
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

/// The line the job ends with.
fn ending(
    verdict: Verdict,
    readings: &[Reading],
    recorded: usize,
    name: &str,
    commit: &str,
    checkpoint: &str,
    minutes: u64,
) -> String {
    match verdict {
        Verdict::Done => format!("No regression observed at {checkpoint}."),
        Verdict::Regressed => {
            format!("A deploy of {name} at {commit} failed or recorded REGRESSED.")
        }
        _ if readings.is_empty() && recorded > 0 => format!(
            "Proofline recorded {} of {name} at {commit}, and none matches --environment, --task, --run or --attempt after {minutes} minutes. The result is not established.",
            count(recorded)
        ),
        _ if readings.is_empty() => format!(
            "No deploy of {name} at {commit} was recorded after {minutes} minutes. The result is not established."
        ),
        _ if readings.contains(&Reading::Waiting) => format!(
            "The {checkpoint} check was not recorded after {minutes} minutes. The result is not established."
        ),
        _ => format!(
            "A check through {checkpoint} did not record HEALTHY, or a deploy names a gap. The result is not established."
        ),
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
    use uuid::Uuid;

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
    async fn console(answers: Vec<(u16, Value)>) -> (String, Arc<Mutex<usize>>) {
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
        flags: &[&str],
        answers: Vec<(u16, Value)>,
    ) -> (anyhow::Result<Verdict>, usize, Duration) {
        // A paused clock jumps to the next timer whenever the runtime waits,
        // even on a loopback socket about to answer, which would fire the
        // client's request timeout. A 10 ms ticker bounds each jump.
        let ticker = tokio::spawn(async {
            for _ in 0..10_000_000 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
        let (origin, reads) = console(answers).await;
        let http = Http::new(Origin::parse(&origin).unwrap()).unwrap();
        let organization: Uuid = ORG.parse().unwrap();
        let api = Api::new(http, SecretString::from("plp_stored"), organization);
        let started = tokio::time::Instant::now();
        let verdict = wait(&api, &args(flags), COMMIT).await;
        let took = started.elapsed();
        ticker.abort();
        let reads = *reads.lock().unwrap();
        (verdict, reads, took)
    }

    /// Each exit code from a stub console: 0 for a healthy landing with no
    /// gap, 3 for a regression or a failed deploy, 2 for a gap, a check that
    /// did not record `HEALTHY` and a commit with no deploy, 1 for a refusal
    /// and 4 when Proofline fails. Any gap on the deploy leaves every
    /// `--until` unestablished, since the response cannot say which check
    /// recorded it.
    #[tokio::test(start_paused = true)]
    async fn each_result_ends_the_job_with_its_exit_code() {
        let healthy = deploy("deploy", &[1], &["HEALTHY", "HEALTHY", "HEALTHY"], &[]);
        let mut failed = healthy.clone();
        failed["state"] = json!("FAILED");
        let gap = deploy("deploy", &[1], &["HEALTHY", "HEALTHY"], &["SIGNAL_NO_DATA"]);
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
        ] {
            let (verdict, reads, _) = run(flags, vec![answer]).await;
            assert_eq!(verdict.unwrap(), ended, "{case}");
            assert_eq!(reads, 1, "{case}");
        }
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
        let (verdict, ..) = run(&[], vec![recorded(std::slice::from_ref(&rollback))]).await;
        assert_eq!(verdict.unwrap(), Verdict::Done);
        let mut printed = Vec::new();
        write_lines(
            &mut printed,
            &serde_json::from_value(rollback).unwrap(),
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
        for (status, exit_four) in [(401, false), (403, false), (503, true)] {
            let (verdict, ..) = run(&[], vec![(status, json!({ "detail": "no" }))]).await;
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

        for (case, answer) in [("no deploy", none), ("check not recorded", landed)] {
            let (verdict, reads, took) =
                run(&["--until", "20m", "--timeout", "3"], vec![answer]).await;
            assert_eq!(verdict.unwrap(), Verdict::NotComplete, "{case}");
            assert!(reads > 2, "{case}: {reads}");
            assert!(took >= Duration::from_secs(180), "{case}: {took:?}");
            assert!(took < Duration::from_secs(190), "{case}: {took:?}");
        }
    }

    /// `--task` takes one task's deploy of a commit deployed by two, and
    /// `--run` with `--attempt` takes the deploy that holds that attempt; a
    /// deploy that lists no attempts never matches.
    #[tokio::test(start_paused = true)]
    async fn the_selection_decides_which_deploys_count() {
        let tasks = recorded(&[
            deploy("deploy:web", &[1], &["HEALTHY"], &[]),
            deploy("deploy:api", &[1], &["REGRESSED"], &[]),
        ]);
        for (flags, ended) in [
            (&["--task", "deploy:web"][..], Verdict::Done),
            (&["--task", "deploy:api"][..], Verdict::Regressed),
            (&[][..], Verdict::Regressed),
        ] {
            let (verdict, ..) = run(flags, vec![tasks.clone()]).await;
            assert_eq!(verdict.unwrap(), ended, "{flags:?}");
        }

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
            let (verdict, ..) = run(flags, vec![attempts.clone()]).await;
            assert_eq!(verdict.unwrap(), ended, "{flags:?}");
        }
    }

    /// A ref is refused before anything is read, and the day check needs an
    /// explicit wait.
    #[test]
    fn a_ref_and_an_implicit_day_wait_are_refused() {
        assert!(ci_commit(Some("main")).is_err());
        assert!(ci_commit(Some("89abcdef0123")).is_err());
        assert!(args(&["--until", "1d"]).timeout_minutes().is_err());
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
