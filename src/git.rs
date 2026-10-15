//! What the current checkout names: its GitHub repository, its commit and its
//! local changes.

use std::path::{Path, PathBuf};

use tokio::process::Command;

/// The largest patch the server reviews.
pub const MAX_PATCH_BYTES: usize = 5 << 20;
const MAX_PATCH_FILES: usize = 3_000;

#[derive(Debug, thiserror::Error)]
pub enum GitError {
    #[error("could not run git: {0}")]
    Unavailable(String),
    #[error("git {command} failed: {stderr}")]
    Failed { command: String, stderr: String },
    #[error("the remote URL {0:?} does not name an owner/repository; pass --repo owner/name")]
    UnknownRemote(String),
    #[error("{0:?} is not a full commit SHA")]
    NotSha(String),
    #[error(
        "the checkout has no base to review against: set an upstream branch with `git branch --set-upstream-to`, or run `git remote set-head {0} --auto`"
    )]
    NoBase(String),
    #[error("the local changes include text that is not UTF-8, which Proofline cannot review")]
    NotUtf8,
    #[error("the local changes make a {0} MiB patch; Proofline reviews patches up to 5 MiB")]
    TooLarge(usize),
    #[error("the local changes include {0} files; Proofline reviews patches up to 3,000 files")]
    TooManyFiles(usize),
    #[error("could not read the local patch's Git path metadata; no review was requested")]
    InvalidDiff,
    #[error("{0:?} names no commit in this checkout")]
    UnknownRevision(String),
    #[error(
        "commit {0} has no parent, so it has no change to compare; name a base with --range BASE..HEAD"
    )]
    NoParent(String),
    #[error("{0:?} is not a range; write it as BASE..HEAD")]
    NotRange(String),
    #[error("name between 1 and 20 exact repository-relative file paths")]
    FileCount,
    #[error("{0:?} is not a regular tracked file at commit {1}; no review was requested")]
    NotTrackedFile(String, String),
}

/// Two exact commits of a pushed change: the head, and the base it is
/// compared with. Resolved once from what the person named; the server
/// verifies both on GitHub and resolves nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushedChange {
    pub base_commit_sha: String,
    pub head_commit_sha: String,
}

/// The one commit `revision` names in the checkout at `dir`. A revision
/// that starts with `-` would be read as an option, so it is refused.
async fn resolve(dir: &Path, revision: &str) -> Result<String, GitError> {
    if revision.is_empty() || revision.starts_with('-') {
        return Err(GitError::UnknownRevision(revision.to_owned()));
    }
    let spec = format!("{revision}^{{commit}}");
    let output = git_in(dir, None, &["rev-parse", "--verify", "--quiet", &spec])
        .await
        .map_err(|error| match error {
            GitError::Failed { .. } => GitError::UnknownRevision(revision.to_owned()),
            error => error,
        })?;
    commit_sha(String::from_utf8_lossy(&output).trim())
}

/// Resolve a whole-file selection once, using only the named commit's tree.
/// Working-tree and index contents never contribute to this request.
pub async fn named_files(
    dir: &Path,
    revision: &str,
    paths: &[String],
) -> Result<(String, Vec<String>), GitError> {
    if paths.is_empty() || paths.len() > 20 {
        return Err(GitError::FileCount);
    }
    let commit = resolve(dir, revision).await?;
    let mut selected = paths.to_vec();
    selected.sort();
    selected.dedup();
    for path in &selected {
        if path.chars().count() > 1_000
            || path.contains('\0')
            || path.split('/').any(|part| matches!(part, "" | "." | ".."))
        {
            return Err(GitError::NotTrackedFile(path.clone(), commit.clone()));
        }
        let entries = git_in(
            dir,
            None,
            &[
                "--literal-pathspecs",
                "ls-tree",
                "-z",
                "--full-tree",
                &commit,
                "--",
                path,
            ],
        )
        .await?;
        let found = entries.split(|byte| *byte == 0).any(|entry| {
            let Some(separator) = entry.iter().position(|byte| *byte == b'\t') else {
                return false;
            };
            let (metadata, remainder) = entry.split_at(separator);
            let found = &remainder[1..];
            found == path.as_bytes()
                && (metadata.starts_with(b"100644 blob ") || metadata.starts_with(b"100755 blob "))
        });
        if !found {
            return Err(GitError::NotTrackedFile(path.clone(), commit.clone()));
        }
    }
    Ok((commit, selected))
}

/// The change one commit makes: the commit against its first parent.
pub async fn pushed_commit(dir: &Path, revision: &str) -> Result<PushedChange, GitError> {
    let head_commit_sha = resolve(dir, revision).await?;
    let base_commit_sha = resolve(dir, &format!("{head_commit_sha}^1"))
        .await
        .map_err(|error| match error {
            GitError::UnknownRevision(_) => GitError::NoParent(head_commit_sha.clone()),
            error => error,
        })?;
    Ok(PushedChange {
        base_commit_sha,
        head_commit_sha,
    })
}

/// The change from `BASE` to `HEAD` in a `BASE..HEAD` range.
pub async fn pushed_range(dir: &Path, range: &str) -> Result<PushedChange, GitError> {
    let (base, head) = range
        .split_once("..")
        .filter(|(base, head)| !base.is_empty() && !head.is_empty() && !head.starts_with('.'))
        .ok_or_else(|| GitError::NotRange(range.to_owned()))?;
    Ok(PushedChange {
        base_commit_sha: resolve(dir, base).await?,
        head_commit_sha: resolve(dir, head).await?,
    })
}

async fn git(args: &[&str]) -> Result<String, GitError> {
    let output = Command::new("git")
        .args(args)
        .output()
        .await
        .map_err(|error| GitError::Unavailable(error.to_string()))?;
    if !output.status.success() {
        return Err(GitError::Failed {
            command: args.join(" "),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Runs git in `dir` and returns its standard output untouched.
async fn git_in(dir: &Path, index: Option<&Path>, args: &[&str]) -> Result<Vec<u8>, GitError> {
    let mut command = Command::new("git");
    command.arg("-C").arg(dir).args(args);
    if let Some(index) = index {
        command.env("GIT_INDEX_FILE", index);
    }
    let output = command
        .output()
        .await
        .map_err(|error| GitError::Unavailable(error.to_string()))?;
    if !output.status.success() {
        return Err(GitError::Failed {
            command: args.join(" "),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    Ok(output.stdout)
}

async fn line_in(dir: &Path, args: &[&str]) -> Result<String, GitError> {
    let output = git_in(dir, None, args).await?;
    Ok(String::from_utf8_lossy(&output).trim().to_owned())
}

/// The checkout's local changes against the commit they build on.
#[derive(Debug)]
pub struct LocalChanges {
    pub base_commit_sha: String,
    /// `git diff` text, empty when nothing changed.
    pub patch: String,
    pub(crate) paths: Vec<PatchPaths>,
}

#[derive(Debug)]
pub(crate) struct PatchPaths {
    pub old: Option<String>,
    pub new: Option<String>,
}

impl LocalChanges {
    pub fn files(&self) -> usize {
        self.patch
            .lines()
            .filter(|line| line.starts_with("diff --git "))
            .count()
    }
}

/// The merge-base of `commit` with the first of `targets` that exists.
async fn merge_base(
    dir: &Path,
    remote: &str,
    commit: &str,
    targets: &[&str],
) -> Result<String, GitError> {
    for target in targets {
        if line_in(dir, &["rev-parse", "--verify", "--quiet", target])
            .await
            .is_ok()
        {
            return commit_sha(&line_in(dir, &["merge-base", commit, target]).await?);
        }
    }
    Err(GitError::NoBase(remote.to_owned()))
}

/// The merge-base of `HEAD` with its upstream branch, or with `remote`'s
/// default branch when there is no upstream.
async fn base(dir: &Path, remote: &str) -> Result<String, GitError> {
    let default = format!("refs/remotes/{remote}/HEAD");
    merge_base(dir, remote, "HEAD", &["@{upstream}", default.as_str()]).await
}

/// Which local bytes contribute to the patch against its pinned base.
#[derive(Debug, Clone, Copy)]
pub enum LocalSelection {
    /// Tracked working-tree files, including staged additions and deletions.
    Tracked,
    /// The original index, without reading unstaged or untracked file contents.
    Staged,
    /// The working tree, with untracked files that Git does not ignore.
    IncludeUntracked,
}

/// Local changes against one merge-base. A copied index collects the selected
/// bytes, so the person's index is untouched.
pub async fn local_changes(
    dir: &Path,
    remote: &str,
    selection: LocalSelection,
) -> Result<LocalChanges, GitError> {
    let root = line_in(dir, &["rev-parse", "--show-toplevel"]).await?;
    let root = Path::new(&root);
    let base_commit_sha = base(root, remote).await?;
    let scratch = tempfile::tempdir()
        .map_err(|error| GitError::Unavailable(format!("no temporary directory: {error}")))?;
    let index = scratch.path().join("index");
    let current = line_in(
        root,
        &["rev-parse", "--path-format=absolute", "--git-path", "index"],
    )
    .await?;
    match tokio::fs::copy(&current, &index).await {
        Ok(_) => {}
        // A repository with nothing staged yet has no index.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(GitError::Unavailable(format!(
                "could not copy the index: {error}"
            )));
        }
    }
    let add = match selection {
        LocalSelection::Tracked => Some("--update"),
        LocalSelection::Staged => None,
        LocalSelection::IncludeUntracked => Some("--all"),
    };
    if let Some(add) = add {
        git_in(
            root,
            Some(&index),
            &["-c", "advice.addEmbeddedRepo=false", "add", add],
        )
        .await?;
    }
    diff(root, Some(&index), base_commit_sha, None).await
}

/// The commits a push sends: `head` against `base`, under the same fixed
/// options as a local review. Both are full commit SHAs from Git's pre-push
/// input or a merge-base.
pub async fn range_changes(dir: &Path, base: &str, head: &str) -> Result<LocalChanges, GitError> {
    let root = line_in(dir, &["rev-parse", "--show-toplevel"]).await?;
    let head = commit_sha(head)?;
    diff(Path::new(&root), None, commit_sha(base)?, Some(&head)).await
}

/// The base of a branch the remote does not have yet: its merge-base with
/// `remote`'s default branch.
pub async fn new_branch_base(dir: &Path, remote: &str, head: &str) -> Result<String, GitError> {
    let default = format!("refs/remotes/{remote}/HEAD");
    merge_base(dir, remote, &commit_sha(head)?, &[default.as_str()]).await
}

/// The patch from `base_commit_sha` to `head`, or to `index` when `head` is
/// `None`.
async fn diff(
    root: &Path,
    index: Option<&Path>,
    base_commit_sha: String,
    head: Option<&str>,
) -> Result<LocalChanges, GitError> {
    let mut args = vec![
        "-c",
        "core.quotePath=false",
        // The server accepts renames and refuses copies, whatever the
        // person's configuration asks for.
        "-c",
        "diff.renames=true",
        "-c",
        "diff.suppressBlankEmpty=false",
        "diff",
    ];
    if head.is_none() {
        args.push("--cached");
    }
    args.extend([
        // Read exact paths and the patch from one snapshot. Git's text
        // headers quote control characters and can contain spaces.
        "--raw",
        "-z",
        "--patch",
        "--find-renames",
        "--no-relative",
        "--no-ext-diff",
        "--no-textconv",
        "--no-color",
        "--src-prefix=a/",
        "--dst-prefix=b/",
        &base_commit_sha,
    ]);
    args.extend(head);
    args.push("--");
    let output = git_in(root, index, &args).await?;
    let (paths, patch) = diff_paths(&output)?;
    if patch.len() > MAX_PATCH_BYTES {
        return Err(GitError::TooLarge(patch.len().div_ceil(1 << 20)));
    }
    if paths.len() > MAX_PATCH_FILES {
        return Err(GitError::TooManyFiles(paths.len()));
    }
    let patch = String::from_utf8(patch.to_vec()).map_err(|_| GitError::NotUtf8)?;
    if paths.len()
        != patch
            .lines()
            .filter(|line| line.starts_with("diff --git "))
            .count()
    {
        return Err(GitError::InvalidDiff);
    }
    Ok(LocalChanges {
        base_commit_sha,
        patch,
        paths,
    })
}

/// Separates `--raw -z --patch` metadata from the unchanged text patch.
fn diff_paths(mut output: &[u8]) -> Result<(Vec<PatchPaths>, &[u8]), GitError> {
    let mut paths = Vec::new();
    while !output.is_empty() {
        let header = nul_field(&mut output)?;
        if header.is_empty() {
            break;
        }
        if !header.starts_with(b":") {
            return Err(GitError::InvalidDiff);
        }
        let status = header
            .split(|byte| *byte == b' ')
            .next_back()
            .and_then(|status| status.first())
            .ok_or(GitError::InvalidDiff)?;
        let first = diff_path(&mut output)?;
        let file = match status {
            b'A' => PatchPaths {
                old: None,
                new: Some(first),
            },
            b'D' => PatchPaths {
                old: Some(first),
                new: None,
            },
            b'R' | b'C' => PatchPaths {
                old: Some(first),
                new: Some(diff_path(&mut output)?),
            },
            b'M' | b'T' => PatchPaths {
                old: Some(first.clone()),
                new: Some(first),
            },
            _ => return Err(GitError::InvalidDiff),
        };
        paths.push(file);
    }
    Ok((paths, output))
}

fn nul_field<'a>(output: &mut &'a [u8]) -> Result<&'a [u8], GitError> {
    let bytes = *output;
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(GitError::InvalidDiff)?;
    let (field, rest) = bytes.split_at(end);
    *output = rest.get(1..).ok_or(GitError::InvalidDiff)?;
    Ok(field)
}

fn diff_path(output: &mut &[u8]) -> Result<String, GitError> {
    let path = nul_field(output)?;
    if path.is_empty() {
        return Err(GitError::InvalidDiff);
    }
    String::from_utf8(path.to_vec()).map_err(|_| GitError::NotUtf8)
}

/// A Git configuration value as Git reads it in `dir`, or `None` when unset.
pub async fn config(dir: &Path, key: &str) -> Result<Option<String>, GitError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["config", "--get", key])
        .output()
        .await
        .map_err(|error| GitError::Unavailable(error.to_string()))?;
    match output.status.code() {
        Some(0) => Ok(Some(
            String::from_utf8_lossy(&output.stdout).trim().to_owned(),
        )),
        // `git config --get` exits 1 for a key that is not set.
        Some(1) => Ok(None),
        _ => Err(GitError::Failed {
            command: format!("config --get {key}"),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        }),
    }
}

/// The directory Git runs this repository's hooks from. Linked worktrees
/// share it.
pub async fn hooks_dir(dir: &Path) -> Result<PathBuf, GitError> {
    line_in(
        dir,
        &["rev-parse", "--path-format=absolute", "--git-path", "hooks"],
    )
    .await
    .map(PathBuf::from)
}

/// `owner/name` of the remote, read from its URL.
pub async fn repository(remote: &str) -> Result<String, GitError> {
    let url = git(&["remote", "get-url", remote]).await?;
    full_name(&url).ok_or(GitError::UnknownRemote(url))
}

/// The checkout's `HEAD` commit.
pub async fn head() -> Result<String, GitError> {
    let sha = git(&["rev-parse", "--verify", "HEAD^{commit}"]).await?;
    commit_sha(&sha)
}

/// Accepts only a full hexadecimal SHA-1 or SHA-256 object name. A branch
/// name or abbreviation is refused: evidence is read at one exact commit.
pub fn commit_sha(raw: &str) -> Result<String, GitError> {
    let sha = raw.trim().to_ascii_lowercase();
    if matches!(sha.len(), 40 | 64) && sha.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(sha)
    } else {
        Err(GitError::NotSha(raw.to_owned()))
    }
}

/// `owner/name` from an HTTPS, SSH or scp-style remote URL.
pub fn full_name(url: &str) -> Option<String> {
    let path = url
        .split_once("://")
        .map_or_else(
            // scp style: git@github.com:owner/name.git
            || url.split_once(':').map(|(_, path)| path),
            |(_, rest)| rest.split_once('/').map(|(_, path)| path),
        )?
        .trim_end_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path);
    let mut parts = path.rsplit('/');
    let name = parts.next().filter(|part| !part.is_empty())?;
    let owner = parts.next().filter(|part| !part.is_empty())?;
    Some(format!("{owner}/{name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_owner_and_name_from_remote_urls() {
        for url in [
            "https://github.com/acme/web.git",
            "https://github.com/acme/web",
            "https://github.com/acme/web/",
            "git@github.com:acme/web.git",
            "ssh://git@github.com/acme/web.git",
            "ssh://git@github.example.com:2222/acme/web",
        ] {
            assert_eq!(full_name(url).as_deref(), Some("acme/web"), "{url}");
        }
        assert_eq!(full_name("https://github.com/"), None);
        assert_eq!(full_name("/srv/repo"), None);
    }

    #[test]
    fn only_full_commit_shas_are_accepted() {
        let sha = "A".repeat(40);
        assert_eq!(commit_sha(&sha).unwrap(), "a".repeat(40));
        assert!(commit_sha(&"b".repeat(64)).is_ok());
        assert!(commit_sha("main").is_err());
        assert!(commit_sha("abc1234").is_err());
        assert!(commit_sha(&"g".repeat(40)).is_err());
    }

    fn run(dir: &Path, args: &[&str]) -> String {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success(), "git {args:?}: {output:?}");
        String::from_utf8(output.stdout).unwrap()
    }

    #[tokio::test]
    async fn pushed_changes_resolve_names_once_to_exact_commits() {
        let repo = tempfile::tempdir().unwrap();
        let dir = repo.path();
        run(dir, &["init", "-q", "-b", "main"]);
        run(dir, &["config", "user.email", "dev@example.com"]);
        run(dir, &["config", "user.name", "dev"]);
        let commit = |message: &str| {
            run(dir, &["commit", "-q", "--allow-empty", "-m", message]);
            run(dir, &["rev-parse", "HEAD"]).trim().to_owned()
        };
        let (root, middle, tip) = (commit("root"), commit("middle"), commit("tip"));
        run(dir, &["tag", "release", &middle]);

        let change = |base: &str, head: &str| PushedChange {
            base_commit_sha: base.to_owned(),
            head_commit_sha: head.to_owned(),
        };
        assert_eq!(
            pushed_commit(dir, "HEAD").await.unwrap(),
            change(&middle, &tip)
        );
        assert_eq!(
            pushed_commit(dir, "release").await.unwrap(),
            change(&root, &middle)
        );
        assert_eq!(
            pushed_range(dir, "release..main").await.unwrap(),
            change(&middle, &tip)
        );
        assert!(matches!(
            pushed_commit(dir, &root).await,
            Err(GitError::NoParent(sha)) if sha == root
        ));
        for refused in ["main...release", "main..", "..main", "main"] {
            assert!(
                matches!(pushed_range(dir, refused).await, Err(GitError::NotRange(_))),
                "{refused}"
            );
        }
        for unknown in ["no-such-branch", "--all", ""] {
            assert!(
                matches!(
                    pushed_commit(dir, unknown).await,
                    Err(GitError::UnknownRevision(_))
                ),
                "{unknown}"
            );
        }
    }

    #[tokio::test]
    async fn local_changes_cover_the_work_tree_and_leave_the_index_alone() {
        let repo = tempfile::tempdir().unwrap();
        let dir = repo.path();
        run(dir, &["init", "-q", "-b", "main"]);
        for (key, value) in [
            ("user.email", "dev@example.com"),
            ("user.name", "dev"),
            // The server refuses copies and prefix-less paths.
            ("diff.renames", "copies"),
            ("diff.noprefix", "true"),
        ] {
            run(dir, &["config", key, value]);
        }
        let body = "one\ntwo\nthree\nfour\nfive\n";
        std::fs::write(dir.join("kept.txt"), body).unwrap();
        std::fs::write(dir.join("moved.txt"), "alpha\nbeta\ngamma\n").unwrap();
        std::fs::write(dir.join("deleted.txt"), "remove me\n").unwrap();
        std::fs::write(dir.join(".gitignore"), "target/\n").unwrap();
        run(dir, &["add", "."]);
        run(dir, &["commit", "-qm", "base"]);
        let base = run(dir, &["rev-parse", "HEAD"]).trim().to_owned();
        run(dir, &["update-ref", "refs/remotes/origin/main", &base]);
        run(
            dir,
            &[
                "symbolic-ref",
                "refs/remotes/origin/HEAD",
                "refs/remotes/origin/main",
            ],
        );

        let unchanged = local_changes(dir, "origin", LocalSelection::Tracked)
            .await
            .unwrap();
        assert_eq!(
            (unchanged.base_commit_sha.as_str(), unchanged.patch.as_str()),
            (base.as_str(), "")
        );

        std::fs::write(dir.join("committed.txt"), "unpushed commit\n").unwrap();
        run(dir, &["add", "committed.txt"]);
        run(dir, &["commit", "-qm", "local commit"]);
        std::fs::write(dir.join("kept.txt"), "one\ntwo\nTHREE\nfour\nfive\n").unwrap();
        std::fs::write(dir.join("staged.txt"), "original index\n").unwrap();
        run(dir, &["add", "kept.txt", "staged.txt"]);
        std::fs::write(dir.join("kept.txt"), "one\ntwo\nTHREE\nFOUR\nfive\n").unwrap();
        std::fs::write(dir.join("staged.txt"), "working tree\n").unwrap();
        std::fs::remove_file(dir.join("deleted.txt")).unwrap();
        std::fs::write(dir.join("copy.txt"), body).unwrap();
        run(dir, &["mv", "moved.txt", "renamed.txt"]);
        std::fs::write(dir.join("new file.txt"), "fresh\n").unwrap();
        std::fs::create_dir_all(dir.join("target")).unwrap();
        std::fs::write(dir.join("target/out"), "build\n").unwrap();
        let staged = run(dir, &["diff", "--cached", "--name-status", "--no-renames"]);
        let index = std::fs::read(dir.join(".git/index")).unwrap();

        for (selection, additional) in [
            (LocalSelection::Staged, vec![]),
            (
                LocalSelection::Tracked,
                vec!["diff --git a/deleted.txt b/deleted.txt"],
            ),
            (
                LocalSelection::IncludeUntracked,
                vec![
                    "diff --git a/copy.txt b/copy.txt",
                    "diff --git a/deleted.txt b/deleted.txt",
                    "diff --git a/new file.txt b/new file.txt",
                ],
            ),
        ] {
            let changes = local_changes(dir, "origin", selection).await.unwrap();
            assert_eq!(changes.base_commit_sha, base);
            let mut expected = vec![
                "diff --git a/committed.txt b/committed.txt",
                "diff --git a/kept.txt b/kept.txt",
                "diff --git a/moved.txt b/renamed.txt",
                "diff --git a/staged.txt b/staged.txt",
                "rename from moved.txt",
                "rename to renamed.txt",
            ];
            expected.extend(additional);
            expected.sort_unstable();
            let mut headers: Vec<&str> = changes
                .patch
                .lines()
                .filter(|line| line.starts_with("diff --git ") || line.starts_with("rename "))
                .collect();
            headers.sort_unstable();
            assert_eq!(headers, expected, "{selection:?}");
            assert!(changes.patch.contains("+unpushed commit\n"));
            match selection {
                LocalSelection::Staged => {
                    assert!(changes.patch.contains("+original index\n"));
                    assert!(!changes.patch.contains("+working tree\n"));
                    assert!(!changes.patch.contains("+FOUR\n"));
                }
                LocalSelection::Tracked | LocalSelection::IncludeUntracked => {
                    assert!(changes.patch.contains("+working tree\n"));
                    assert!(changes.patch.contains("+FOUR\n"));
                    assert!(!changes.patch.contains("+original index\n"));
                }
            }
            assert_eq!(std::fs::read(dir.join(".git/index")).unwrap(), index);
        }
        assert_eq!(
            run(dir, &["diff", "--cached", "--name-status", "--no-renames"]),
            staged
        );
    }
}
