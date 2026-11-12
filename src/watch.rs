//! Continuous local review daemon.
//!
//! Watches the checkout's uncommitted changes against its merge base,
//! debounces rapid filesystem modifications, dedupes identical diffs,
//! and automatically requests and displays incremental reviews.

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::Result;
use clap::Args;
use sha2::{Digest, Sha256};
use tokio::time::sleep;

use crate::api::Api;
use crate::git::{self, LocalSelection};
use crate::model::PatchReviewRequest;
use crate::preflight;
use crate::{OutputArgs, OutputFormat, RepositoryArgs, Verdict, connected_repository, say, show};

#[derive(Debug, Clone, Args)]
pub struct WatchSelectionArgs {
    /// Review the original index against the base, excluding unstaged changes.
    #[arg(long, conflicts_with = "include_untracked")]
    pub staged: bool,

    /// Add untracked files that Git does not ignore to the working-tree review.
    #[arg(long, conflicts_with = "staged")]
    pub include_untracked: bool,
}

#[derive(Debug, Clone, Args)]
pub struct WatchArgs {
    /// Debounce duration in milliseconds after the last detected change before reviewing.
    #[arg(long, value_name = "MILLIS", default_value = "500")]
    pub debounce: u64,

    /// Polling interval in milliseconds to check for working-tree changes.
    #[arg(long, value_name = "MILLIS", default_value = "1000")]
    pub interval: u64,

    /// Review only this literal repository-relative file in the local patch.
    #[arg(long, value_name = "PATH")]
    pub path: Option<String>,

    /// Include secret-shaped patch content from this exact repository-relative path.
    #[arg(long, value_name = "PATH")]
    pub allow_path: Vec<String>,

    #[command(flatten)]
    pub(crate) local_selection: WatchSelectionArgs,

    #[command(flatten)]
    pub(crate) repository: RepositoryArgs,

    #[command(flatten)]
    pub(crate) output: OutputArgs,
}

/// Computes the SHA-256 digest of patch bytes for deduplication.
pub(crate) fn compute_patch_fingerprint(patch_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(patch_bytes);
    hasher.finalize().into()
}

/// The state of the watcher across polling intervals.
#[derive(Debug, Default)]
pub(crate) struct WatchState {
    pub(crate) last_reviewed_hash: Option<[u8; 32]>,
    pub(crate) pending_hash: Option<[u8; 32]>,
    pub(crate) pending_change_time: Option<Instant>,
}

impl WatchState {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Evaluates whether a new patch hash should trigger a review given the debounce duration.
    /// Returns true if the change has settled and is ready for review.
    pub(crate) fn evaluate_change(
        &mut self,
        current_hash: [u8; 32],
        debounce_dur: Duration,
        now: Instant,
    ) -> bool {
        // If identical to the last successfully reviewed patch, ignore.
        if self.last_reviewed_hash == Some(current_hash) {
            self.pending_hash = None;
            self.pending_change_time = None;
            return false;
        }

        // If this hash is different from the currently pending one, reset debounce clock.
        if self.pending_hash != Some(current_hash) {
            self.pending_hash = Some(current_hash);
            self.pending_change_time = Some(now);
            return false;
        }

        // If debounce time has elapsed, trigger review.
        if let Some(change_time) = self.pending_change_time
            && now.saturating_duration_since(change_time) >= debounce_dur
        {
            self.last_reviewed_hash = Some(current_hash);
            self.pending_hash = None;
            self.pending_change_time = None;
            return true;
        }

        false
    }

    pub(crate) fn reset_clean(&mut self) {
        self.last_reviewed_hash = None;
        self.pending_hash = None;
        self.pending_change_time = None;
    }
}

/// Runs the continuous review daemon.
pub async fn run(api: &Api, args: &WatchArgs) -> Result<Verdict> {
    let selection = if args.local_selection.staged {
        LocalSelection::Staged
    } else if args.local_selection.include_untracked {
        LocalSelection::IncludeUntracked
    } else {
        LocalSelection::Tracked
    };

    say("Proofline watch mode active. Watching for local changes... (Press Ctrl+C to stop)");

    let debounce_dur = Duration::from_millis(args.debounce);
    let interval_dur = Duration::from_millis(args.interval);
    let mut state = WatchState::new();

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                say("\nStopping Proofline watch mode.");
                return Ok(Verdict::Done);
            }
            () = sleep(interval_dur) => {
                let changes = match git::local_changes(
                    Path::new("."),
                    &args.repository.remote,
                    selection,
                    args.path.as_deref(),
                ).await {
                    Ok(changes) => changes,
                    Err(error) => {
                        say(&format!("warning: could not inspect git status: {error}"));
                        continue;
                    }
                };

                let files = changes.files();
                if files == 0 {
                    state.reset_clean();
                    continue;
                }

                let current_hash = compute_patch_fingerprint(changes.patch.as_bytes());
                let now = Instant::now();

                if !state.evaluate_change(current_hash, debounce_dur, now) {
                    continue;
                }

                if let Err(error) = preflight::check(&changes, &args.allow_path) {
                    say(&format!("Preflight check refused patch: {error}. Waiting for fixes..."));
                    continue;
                }

                let (repo_name, repo_id) = match connected_repository(api, &args.repository).await {
                    Ok(result) => result,
                    Err(error) => {
                        say(&format!("Could not connect repository: {error}"));
                        continue;
                    }
                };

                say(&format!(
                    "\nChanges detected: reviewing {files} changed {} in {repo_name}...",
                    if files == 1 { "file" } else { "files" }
                ));

                let request = PatchReviewRequest {
                    base_commit_sha: changes.base_commit_sha,
                    patch: changes.patch,
                    trigger_source: None,
                    verify_finding_ids: Vec::new(),
                };

                let requested = match api.request_patch_review(repo_id, &request).await {
                    Ok(requested) => requested,
                    Err(error) => {
                        say(&format!("Failed to request review: {error}"));
                        continue;
                    }
                };

                say(&format!(
                    "{} review of uncommitted changes on {}.",
                    if requested.existing { "Found existing" } else { "Requested" },
                    request.base_commit_sha
                ));

                let _ = show(
                    api,
                    requested.review_id,
                    true,
                    &args.output,
                    OutputFormat::from_json(args.output.json),
                ).await;

                say("\nWatching for local changes... (Press Ctrl+C to stop)");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_fingerprint_is_deterministic() {
        let diff_a = b"diff --git a/foo.rs b/foo.rs\n+println!(\"hello\");";
        let diff_b = b"diff --git a/foo.rs b/foo.rs\n+println!(\"hello\");";
        let diff_c = b"diff --git a/foo.rs b/foo.rs\n+println!(\"world\");";

        let hash_a = compute_patch_fingerprint(diff_a);
        let hash_b = compute_patch_fingerprint(diff_b);
        let hash_c = compute_patch_fingerprint(diff_c);

        assert_eq!(hash_a, hash_b);
        assert_ne!(hash_a, hash_c);
    }

    #[test]
    fn state_evaluates_debounce_and_deduplication() {
        let mut state = WatchState::new();
        let hash1 = [1u8; 32];
        let hash2 = [2u8; 32];
        let debounce = Duration::from_millis(500);
        let start = Instant::now();

        // Initial change observed at start: should not trigger immediately
        assert!(!state.evaluate_change(hash1, debounce, start));

        // 200ms later with same hash: still in debounce window
        let t1 = start + Duration::from_millis(200);
        assert!(!state.evaluate_change(hash1, debounce, t1));

        // 600ms later with same hash: debounce expired, should trigger review!
        let t2 = start + Duration::from_millis(600);
        assert!(state.evaluate_change(hash1, debounce, t2));

        // Subsequent poll with identical hash: already reviewed, should NOT trigger
        let t3 = start + Duration::from_millis(1000);
        assert!(!state.evaluate_change(hash1, debounce, t3));

        // New change arrives: resets debounce, does not trigger immediately
        let t4 = start + Duration::from_millis(1500);
        assert!(!state.evaluate_change(hash2, debounce, t4));

        // 600ms after new change: triggers review for new change!
        let t5 = t4 + Duration::from_millis(600);
        assert!(state.evaluate_change(hash2, debounce, t5));
    }

    #[test]
    fn reset_clean_clears_state() {
        let mut state = WatchState::new();
        let hash = [1u8; 32];
        let debounce = Duration::from_millis(100);
        let t0 = Instant::now();
        assert!(!state.evaluate_change(hash, debounce, t0));
        assert!(state.evaluate_change(hash, debounce, t0 + Duration::from_millis(200)));

        // After clean reset (e.g. user committed changes), state is cleared
        state.reset_clean();
        assert_eq!(state.last_reviewed_hash, None);
        assert_eq!(state.pending_hash, None);
        assert_eq!(state.pending_change_time, None);
    }
}
