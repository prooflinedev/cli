//! `install.sh` checks a release before installing it. These tests run the
//! installer with stand-ins for `curl` and `gh` on a PATH that holds only the
//! tools it needs, so they use no network and no real GitHub CLI.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const VERSION: &str = "9.9.9";
const INSTALLED: &str = "proofline 9.9.9";

/// Tools `install.sh` calls besides `curl` and `gh`.
const TOOLS: &[&str] = &[
    "awk",
    "cat",
    "chmod",
    "cp",
    "cut",
    "grep",
    "gzip",
    "mkdir",
    "mktemp",
    "mv",
    "rm",
    "sed",
    "sha256sum",
    "shasum",
    "sysctl",
    "tar",
    "uname",
];

const FAKE_CURL: &str = r#"#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_CURL_LOG"
out=
while [ $# -gt 1 ]; do
  case $1 in --output) out=$2; shift ;; esac
  shift
done
name=${1#https://proofline.sh/cli/download/9.9.9/}
[ "$name" != "$1" ] && [ -f "$FAKE_RELEASE/$name" ] || exit 22
cp "$FAKE_RELEASE/$name" "$out"
"#;

const FAKE_GH: &str = r#"#!/bin/sh
printf '%s\n' "$@" > "$FAKE_GH_LOG"
exit "$FAKE_GH_EXIT"
"#;

struct Fixture {
    root: tempfile::TempDir,
}

impl Fixture {
    /// A release whose archive matches its SHA256SUMS unless `corrupt` is set.
    fn new(corrupt: bool) -> Self {
        let root = tempfile::tempdir().unwrap();
        let fixture = Self { root };
        let stage = fixture.path("stage");
        let release = fixture.path("release");
        fs::create_dir_all(&stage).unwrap();
        fs::create_dir_all(&release).unwrap();
        executable(
            &stage.join("proofline"),
            &format!("#!/bin/sh\nprintf '%s\\n' '{INSTALLED}'\n"),
        );
        let archive = release.join(archive_name());
        let tar = Command::new("tar")
            .arg("-czf")
            .arg(&archive)
            .arg("-C")
            .arg(&stage)
            .arg("proofline")
            .status()
            .unwrap();
        assert!(tar.success());
        let mut digest = sha256(&archive);
        if corrupt {
            digest = "0".repeat(64);
        }
        fs::write(
            release.join("SHA256SUMS"),
            format!("{digest}  {}\n", archive_name()),
        )
        .unwrap();

        let tools = fixture.path("tools");
        fs::create_dir_all(&tools).unwrap();
        for tool in TOOLS {
            if let Some(found) = which(tool) {
                std::os::unix::fs::symlink(found, tools.join(tool)).unwrap();
            }
        }
        executable(&tools.join("curl"), FAKE_CURL);
        fixture
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }

    /// Puts the stand-in `gh` on PATH; it exits with `status`.
    fn with_gh(self, status: i32) -> Self {
        executable(&self.path("tools/gh"), FAKE_GH);
        fs::write(self.path("gh-exit"), status.to_string()).unwrap();
        self
    }

    fn install(&self, provenance: Option<&str>) -> Output {
        let gh_exit = fs::read_to_string(self.path("gh-exit")).unwrap_or_default();
        let mut command = Command::new("/bin/sh");
        command
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("install.sh"))
            .env_clear()
            .env("PATH", self.path("tools"))
            .env("HOME", self.root.path())
            .env("PROOFLINE_VERSION", VERSION)
            .env("PROOFLINE_INSTALL_DIR", self.path("bin"))
            .env("FAKE_RELEASE", self.path("release"))
            .env("FAKE_CURL_LOG", self.path("curl.log"))
            .env("FAKE_GH_LOG", self.path("gh.log"))
            .env("FAKE_GH_EXIT", gh_exit);
        if let Some(value) = provenance {
            command.env("PROOFLINE_VERIFY_PROVENANCE", value);
        }
        command.output().unwrap()
    }

    fn installed(&self) -> bool {
        self.path("bin/proofline").exists()
    }

    fn downloads(&self) -> usize {
        fs::read_to_string(self.path("curl.log")).map_or(0, |log| log.lines().count())
    }

    fn gh_arguments(&self) -> Option<Vec<String>> {
        fs::read_to_string(self.path("gh.log"))
            .ok()
            .map(|log| log.lines().map(str::to_owned).collect())
    }
}

fn archive_name() -> String {
    let arch = match std::env::consts::ARCH {
        "aarch64" => "aarch64",
        _ => "x86_64",
    };
    let os = if cfg!(target_os = "macos") {
        "apple-darwin"
    } else {
        "unknown-linux-musl"
    };
    format!("proofline-{arch}-{os}.tar.gz")
}

fn executable(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn which(tool: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|directory| directory.join(tool))
            .find(|candidate| candidate.is_file())
    })
}

fn sha256(path: &Path) -> String {
    let output = Command::new("sh")
        .arg("-c")
        .arg(r#"sha256sum "$1" 2>/dev/null || shasum -a 256 "$1""#)
        .arg("sh")
        .arg(path)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let line = String::from_utf8(output.stdout).unwrap();
    line.split_whitespace().next().unwrap().to_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn installs_without_provenance_check_by_default() {
    let fixture = Fixture::new(false).with_gh(1);
    let output = fixture.install(None);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stderr(&output).contains(&format!("installed {INSTALLED}")));
    assert_eq!(fixture.gh_arguments(), None);

    let output = Fixture::new(false).with_gh(1).install(Some("0"));
    assert!(output.status.success(), "{}", stderr(&output));
}

#[test]
fn verified_provenance_names_the_repository_workflow_and_release_refs() {
    let fixture = Fixture::new(false).with_gh(0);
    let output = fixture.install(Some("1"));
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(fixture.installed());

    let arguments = fixture.gh_arguments().expect("gh was not called");
    assert_eq!(arguments[..2], ["attestation", "verify"]);
    assert!(arguments[2].ends_with(&format!("/{}", archive_name())));
    let flag = |name: &str| {
        let at = arguments.iter().position(|argument| argument == name);
        at.map(|at| arguments[at + 1].as_str())
    };
    assert_eq!(flag("--hostname"), Some("github.com"));
    assert_eq!(flag("--repo"), Some("prooflinedev/cli"));
    assert_eq!(
        flag("--cert-identity-regex"),
        Some(
            r"^https://github\.com/prooflinedev/cli/\.github/workflows/release\.yml@refs/(tags/v9\.9\.9|heads/main)$"
        )
    );
    assert!(arguments.iter().any(|a| a == "--deny-self-hosted-runners"));
}

#[test]
fn failed_provenance_installs_nothing() {
    let fixture = Fixture::new(false).with_gh(1);
    let output = fixture.install(Some("1"));
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(stderr.contains("has no build provenance"), "{stderr}");
    assert!(stderr.contains("nothing was installed"), "{stderr}");
    assert!(!fixture.installed());
}

#[test]
fn provenance_without_gh_downloads_nothing() {
    let fixture = Fixture::new(false);
    let output = fixture.install(Some("1"));
    assert!(!output.status.success());
    assert!(stderr(&output).contains("needs the GitHub CLI (gh)"));
    assert_eq!(fixture.downloads(), 0);
    assert!(!fixture.installed());
}

#[test]
fn unknown_provenance_setting_is_refused() {
    let fixture = Fixture::new(false).with_gh(0);
    let output = fixture.install(Some("yes"));
    assert!(!output.status.success());
    assert!(stderr(&output).contains("PROOFLINE_VERIFY_PROVENANCE must be 1 or 0"));
    assert_eq!(fixture.downloads(), 0);
    assert_eq!(fixture.gh_arguments(), None);
}

#[test]
fn checksum_mismatch_stops_before_provenance_check() {
    let fixture = Fixture::new(true).with_gh(0);
    let output = fixture.install(Some("1"));
    assert!(!output.status.success());
    assert!(stderr(&output).contains("does not match SHA256SUMS"));
    assert_eq!(fixture.gh_arguments(), None);
    assert!(!fixture.installed());
}
