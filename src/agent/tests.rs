//! Only synthetic user homes reach the production installer core in these tests.

use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Cursor, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

use clap::Parser as _;
use serde_json::{Value, json};
use tempfile::TempDir;

use super::{Client, InstallArgs, InstallError, Outcome, install};
use crate::origin::Origin;
use crate::{Cli, Command as CliCommand};

const PRIVATE: &str = "installer-private-config-canary";
const CLIENTS: [Client; 4] = [Client::Codex, Client::Cursor, Client::Gemini, Client::Kiro];

#[derive(Debug)]
struct Invocation {
    result: Result<Outcome, InstallError>,
    output: String,
    diagnostics: String,
}

fn invoke(
    home: &Path,
    client: Client,
    print: bool,
    input: &mut impl BufRead,
    origin: &Origin,
    codex_home: Option<&Path>,
) -> Invocation {
    let mut output = Vec::new();
    let mut diagnostics = Vec::new();
    let result = install(
        home,
        codex_home.map(Path::as_os_str),
        &InstallArgs { client, print },
        origin,
        input,
        &mut output,
        &mut diagnostics,
    );
    Invocation {
        result,
        output: String::from_utf8(output).unwrap(),
        diagnostics: String::from_utf8(diagnostics).unwrap(),
    }
}

fn confirmed(home: &Path, client: Client) -> Invocation {
    invoke(
        home,
        client,
        false,
        &mut Cursor::new(b"yes\n"),
        &origin(),
        None,
    )
}

fn origin() -> Origin {
    Origin::parse("https://proofline.sh").unwrap()
}

fn target(home: &Path, client: Client) -> PathBuf {
    home.join(client.relative_path())
}

fn seed(home: &Path, client: Client, bytes: &[u8]) -> PathBuf {
    let path = target(home, client);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, bytes).unwrap();
    path
}

fn configuration(client: Client) -> Vec<u8> {
    match client {
        Client::Codex => format!(
            "# keep this comment\nmodel = \"chosen-model\"\nlabels = [\"one\", \"two\"]\n\n[mcp_servers.other]\ncommand = \"other-server\"\nargs = [\"a b\"]\n\n[mcp_servers.other.env]\nSECRET = \"{PRIVATE}\"\n"
        ).into_bytes(),
        Client::Cursor | Client::Gemini | Client::Kiro => serde_json::to_vec_pretty(&json!({
            "theme": "chosen-theme",
            "policy": {"trust": false, "autoApprove": [], "excluded": ["untrusted"]},
            "mcpServers": {
                "other": {"command": "other-server", "args": ["a b"], "env": {"SECRET": PRIVATE}}
            },
            "privateSetting": PRIVATE
        })).unwrap(),
    }
}

fn assert_new_server(client: Client, server: &Value, selected_origin: &str) {
    assert_eq!(server["command"], "proofline");
    assert_eq!(
        server["args"],
        json!(["--base-url", selected_origin, "mcp"])
    );
    assert_eq!(
        server.as_object().unwrap().len(),
        if client == Client::Cursor { 3 } else { 2 }
    );
    if client == Client::Cursor {
        assert_eq!(server["type"], "stdio");
    }
}

fn entries(root: &Path) -> Vec<(PathBuf, Option<Vec<u8>>)> {
    fn visit(root: &Path, current: &Path, found: &mut Vec<(PathBuf, Option<Vec<u8>>)>) {
        for entry in fs::read_dir(current).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            let relative = path.strip_prefix(root).unwrap().to_owned();
            if metadata.is_dir() {
                found.push((relative, None));
                visit(root, &path, found);
            } else {
                assert!(metadata.is_file() && !metadata.file_type().is_symlink());
                found.push((relative, Some(fs::read(&path).unwrap())));
            }
        }
    }
    let mut found = Vec::new();
    visit(root, root, &mut found);
    found.sort_by(|left, right| left.0.cmp(&right.0));
    found
}

#[test]
fn four_clients_preserve_private_settings_and_add_only_the_launcher() {
    for client in CLIENTS {
        let home = TempDir::new().unwrap();
        let original = configuration(client);
        let path = seed(home.path(), client, &original);
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let result = confirmed(home.path(), client);
        assert_eq!(result.result.unwrap(), Outcome::Installed);
        assert!(result.output.is_empty());
        assert!(!result.diagnostics.contains(PRIVATE));
        assert!(result.diagnostics.contains("Write this entry? [y/N]"));
        let actual = fs::read_to_string(&path).unwrap();
        match client {
            Client::Codex => {
                assert!(actual.contains("# keep this comment\nmodel = \"chosen-model\""));
                let expected: toml::Value =
                    toml::from_str(std::str::from_utf8(&original).unwrap()).unwrap();
                let mut parsed: toml::Value = toml::from_str(&actual).unwrap();
                let server = parsed["mcp_servers"]
                    .as_table_mut()
                    .unwrap()
                    .remove("proofline")
                    .unwrap();
                assert_eq!(server["command"].as_str(), Some("proofline"));
                assert_eq!(
                    server["args"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|value| value.as_str().unwrap())
                        .collect::<Vec<_>>(),
                    ["--base-url", "https://proofline.sh", "mcp"]
                );
                assert_eq!(server.as_table().unwrap().len(), 2);
                assert_eq!(parsed, expected);
            }
            Client::Cursor | Client::Gemini | Client::Kiro => {
                let expected: Value = serde_json::from_slice(&original).unwrap();
                let mut parsed: Value = serde_json::from_str(&actual).unwrap();
                let server = parsed["mcpServers"]
                    .as_object_mut()
                    .unwrap()
                    .remove("proofline")
                    .unwrap();
                assert_new_server(client, &server, "https://proofline.sh");
                assert_eq!(parsed, expected);
                assert_eq!(
                    parsed.as_object().unwrap().keys().collect::<Vec<_>>(),
                    expected.as_object().unwrap().keys().collect::<Vec<_>>()
                );
            }
        }
        let lock = path.parent().unwrap().join(".proofline-agent-install.lock");
        assert_eq!(fs::read(&lock).unwrap(), b"");
        #[cfg(unix)]
        {
            assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o640);
            assert_eq!(fs::metadata(&lock).unwrap().mode() & 0o777, 0o600);
        }
        assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 2);
    }
}

#[test]
fn print_decline_and_replay_never_replace_an_existing_configuration() {
    for client in CLIENTS {
        let home = TempDir::new().unwrap();
        let path = seed(home.path(), client, &configuration(client));
        let before = entries(home.path());
        let printed = invoke(
            home.path(),
            client,
            true,
            &mut Cursor::new(b"yes\n"),
            &origin(),
            None,
        );
        assert_eq!(printed.result.unwrap(), Outcome::Printed);
        assert!(printed.output.contains("proofline"));
        assert!(!printed.output.contains(PRIVATE));
        assert!(printed.diagnostics.is_empty());
        assert_eq!(entries(home.path()), before);
        for answer in [
            b"".as_slice(),
            b"\n",
            b"no\n",
            b"yes please\n",
            b"yes",
            b"y",
        ] {
            let declined = invoke(
                home.path(),
                client,
                false,
                &mut Cursor::new(answer),
                &origin(),
                None,
            );
            assert_eq!(declined.result.unwrap(), Outcome::Cancelled);
            assert_eq!(entries(home.path()), before);
        }
        assert_eq!(
            confirmed(home.path(), client).result.unwrap(),
            Outcome::Installed
        );
        let installed = entries(home.path());
        let modified = fs::metadata(&path).unwrap().modified().unwrap();
        let second = invoke(
            home.path(),
            client,
            false,
            &mut Cursor::new(b""),
            &origin(),
            None,
        );
        assert_eq!(second.result.unwrap(), Outcome::Existing);
        assert!(!second.diagnostics.contains("Write this entry?"));
        assert_eq!(entries(home.path()), installed);
        assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), modified);
    }
    let empty = TempDir::new().unwrap();
    let printed = invoke(
        &empty.path().join("does-not-exist"),
        Client::Codex,
        true,
        &mut Cursor::new(b""),
        &origin(),
        Some(Path::new("/unused/custom")),
    );
    assert_eq!(printed.result.unwrap(), Outcome::Printed);
    assert!(entries(empty.path()).is_empty());
    assert_eq!(
        invoke(
            empty.path(),
            Client::Kiro,
            false,
            &mut Cursor::new(b""),
            &origin(),
            None
        )
        .result
        .unwrap(),
        Outcome::Cancelled
    );
    assert!(entries(empty.path()).is_empty());
}

#[test]
fn custom_existing_entries_and_codex_home_are_never_overwritten() {
    for client in CLIENTS {
        let home = TempDir::new().unwrap();
        let original = match client {
            Client::Codex => format!("# {PRIVATE}\nmcp_servers.proofline = {{ command = \"custom-launcher\", args = [\"custom\"] }}\n").into_bytes(),
            Client::Cursor | Client::Gemini | Client::Kiro => format!("{{\"mcpServers\":{{\"proofline\":null}},\"private\":\"{PRIVATE}\"}}").into_bytes(),
        };
        let path = seed(home.path(), client, &original);
        let modified = fs::metadata(&path).unwrap().modified().unwrap();
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        let before = entries(home.path());
        let existing = confirmed(home.path(), client);
        assert_eq!(existing.result.unwrap(), Outcome::Existing);
        assert!(!existing.diagnostics.contains(PRIVATE));
        assert!(!existing.diagnostics.contains("Write this entry?"));
        assert_eq!(entries(home.path()), before);
        assert_eq!(fs::metadata(path).unwrap().modified().unwrap(), modified);
    }
    let home = TempDir::new().unwrap();
    let custom = home.path().join("custom-codex");
    let refusal = invoke(
        home.path(),
        Client::Codex,
        false,
        &mut Cursor::new(b"yes\n"),
        &origin(),
        Some(&custom),
    );
    assert!(matches!(refusal.result, Err(InstallError::CustomCodexHome)));
    assert!(entries(home.path()).is_empty());
    let ordinary = home.path().join(".codex");
    assert_eq!(
        invoke(
            home.path(),
            Client::Codex,
            false,
            &mut Cursor::new(b"yes\n"),
            &origin(),
            Some(&ordinary)
        )
        .result
        .unwrap(),
        Outcome::Installed
    );
}

#[derive(Debug)]
struct FailedInput;

impl Read for FailedInput {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "synthetic confirmation failure",
        ))
    }
}

impl BufRead for FailedInput {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "synthetic confirmation failure",
        ))
    }

    fn consume(&mut self, _amount: usize) {}
}

#[test]
fn toml_inline_tables_and_separate_arguments_round_trip_in_unicode_homes() {
    let root = TempDir::new().unwrap();
    let home = root.path().join("User with spaces Δ 東京");
    fs::create_dir_all(&home).unwrap();
    let path = seed(
        &home,
        Client::Codex,
        b"# inline survives\nmcp_servers = { other = { command = 'other', args = ['x y'] } }\n",
    );
    let selected = Origin::parse("http://[::1]:8080/").unwrap();
    let result = invoke(
        &home,
        Client::Codex,
        false,
        &mut Cursor::new(b"Y\r\n"),
        &selected,
        None,
    );
    assert_eq!(result.result.unwrap(), Outcome::Installed);
    let actual = fs::read_to_string(path).unwrap();
    assert!(actual.starts_with("# inline survives\n"));
    let parsed: toml::Value = toml::from_str(&actual).unwrap();
    assert_eq!(
        parsed["mcp_servers"]["other"]["args"][0].as_str(),
        Some("x y")
    );
    let args: Vec<&str> = parsed["mcp_servers"]["proofline"]["args"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert_eq!(args, ["--base-url", "http://[::1]:8080", "mcp"]);
    let cli =
        Cli::try_parse_from(std::iter::once("proofline").chain(args.iter().copied())).unwrap();
    assert_eq!(cli.base_url, "http://[::1]:8080");
    assert!(matches!(cli.command, CliCommand::Mcp));
    for client in [Client::Cursor, Client::Gemini, Client::Kiro] {
        let precision = "{\"mcpServers\":{\"other\":{\"value\":184467440737095516170}},\"precision\":1.2345678901234567890123456789}";
        seed(&home, client, precision.as_bytes());
        let result = invoke(
            &home,
            client,
            false,
            &mut Cursor::new(b"yes\n"),
            &selected,
            None,
        );
        assert_eq!(result.result.unwrap(), Outcome::Installed);
        let actual = fs::read_to_string(target(&home, client)).unwrap();
        assert!(actual.contains("184467440737095516170"));
        assert!(actual.contains("1.2345678901234567890123456789"));
        let parsed: Value = serde_json::from_str(&actual).unwrap();
        assert_new_server(
            client,
            &parsed["mcpServers"]["proofline"],
            "http://[::1]:8080",
        );
    }
}

#[derive(Debug)]
struct AtConfirmation<F> {
    input: Cursor<Vec<u8>>,
    action: Option<F>,
}

impl<F: FnOnce()> AtConfirmation<F> {
    fn new(action: F) -> Self {
        Self {
            input: Cursor::new(b"yes\n".to_vec()),
            action: Some(action),
        }
    }

    fn act(&mut self) {
        if let Some(action) = self.action.take() {
            action();
        }
    }
}

impl<F: FnOnce()> Read for AtConfirmation<F> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.act();
        self.input.read(buffer)
    }
}

impl<F: FnOnce()> BufRead for AtConfirmation<F> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.act();
        self.input.fill_buf()
    }

    fn consume(&mut self, amount: usize) {
        self.input.consume(amount);
    }
}

#[test]
fn confirmation_drift_refuses_unrelated_changes_but_adopts_an_existing_entry() {
    let home = TempDir::new().unwrap();
    let path = seed(home.path(), Client::Gemini, &configuration(Client::Gemini));
    let changed = format!("{{\"mcpServers\":{{}},\"private\":\"{PRIVATE}\",\"newSetting\":42}}\n");
    let mut input = AtConfirmation::new(|| fs::write(&path, changed.as_bytes()).unwrap());
    let result = invoke(
        home.path(),
        Client::Gemini,
        false,
        &mut input,
        &origin(),
        None,
    );
    assert!(matches!(result.result, Err(InstallError::Changed(_))));
    assert_eq!(fs::read(&path).unwrap(), changed.as_bytes());
    assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
    let added = format!(
        "{{\"mcpServers\":{{\"proofline\":{{\"command\":\"other\"}}}},\"private\":\"{PRIVATE}\"}}\n"
    );
    let mut input = AtConfirmation::new(|| fs::write(&path, added.as_bytes()).unwrap());
    let result = invoke(
        home.path(),
        Client::Gemini,
        false,
        &mut input,
        &origin(),
        None,
    );
    assert_eq!(result.result.unwrap(), Outcome::Existing);
    assert_eq!(fs::read(&path).unwrap(), added.as_bytes());
    assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
    assert!(!result.diagnostics.contains(PRIVATE));
}

#[test]
fn a_separate_writer_lock_refuses_without_replacement_and_retry_converges() {
    let home = TempDir::new().unwrap();
    let path = seed(home.path(), Client::Cursor, &configuration(Client::Cursor));
    let original = fs::read(&path).unwrap();
    let lock_path = path.parent().unwrap().join(".proofline-agent-install.lock");
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let worker = {
        let lock_path = lock_path.clone();
        let entered = Arc::clone(&entered);
        let release = Arc::clone(&release);
        std::thread::spawn(move || {
            let lease = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(lock_path)
                .unwrap();
            lease.try_lock().unwrap();
            entered.wait();
            release.wait();
            drop(lease);
        })
    };
    entered.wait();
    let busy = confirmed(home.path(), Client::Cursor);
    let retained = fs::read(&path).unwrap();
    release.wait();
    worker.join().unwrap();
    assert!(matches!(busy.result, Err(InstallError::Busy(_))));
    assert_eq!(retained, original);
    assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 2);
    #[cfg(unix)]
    let lock_inode = fs::metadata(&lock_path).unwrap().ino();
    // Another test in this process can spawn a process while the worker holds
    // the lease. The child keeps an inherited copy of the lock descriptor
    // until its exec, so the first retry can still find the lock taken. Retry
    // within a bound; a lock that stays held still fails.
    let deadline = Instant::now() + Duration::from_secs(10);
    let retried = loop {
        match confirmed(home.path(), Client::Cursor).result {
            Err(InstallError::Busy(_)) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            result => break result,
        }
    };
    assert_eq!(retried.unwrap(), Outcome::Installed);
    assert_eq!(
        confirmed(home.path(), Client::Cursor).result.unwrap(),
        Outcome::Existing
    );
    assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 2);
    #[cfg(unix)]
    assert_eq!(fs::metadata(lock_path).unwrap().ino(), lock_inode);
    let parsed: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!(parsed["mcpServers"].as_object().unwrap().len(), 2);
}

fn git(root: &Path, args: &[&str]) -> std::process::Output {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .env(
            "GIT_CONFIG_GLOBAL",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
        )
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_COMMON_DIR")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_CONFIG_COUNT")
        .env_remove("GIT_CONFIG_PARAMETERS")
        .output()
        .unwrap();
    assert!(output.status.success(), "Git fixture command failed");
    output
}

#[test]
fn actual_git_homes_and_linked_worktrees_refuse_without_repository_edits() {
    let home = TempDir::new().unwrap();
    git(home.path(), &["init", "--quiet", "--template="]);
    seed(home.path(), Client::Codex, &configuration(Client::Codex));
    let status = git(home.path(), &["status", "--porcelain"]).stdout;
    let before = entries(home.path());
    let refused = confirmed(home.path(), Client::Codex);
    assert!(matches!(refused.result, Err(InstallError::Repository(_))));
    assert_eq!(entries(home.path()), before);
    assert_eq!(git(home.path(), &["status", "--porcelain"]).stdout, status);
    git(home.path(), &["add", ".codex/config.toml"]);
    git(
        home.path(),
        &[
            "-c",
            "user.name=Installer fixture",
            "-c",
            "user.email=fixture@invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "-m",
            "Fixture",
        ],
    );
    let holder = TempDir::new().unwrap();
    let worktree = holder.path().join("linked-home");
    git(
        home.path(),
        &[
            "worktree",
            "add",
            "--quiet",
            "--detach",
            worktree.to_str().unwrap(),
        ],
    );
    assert!(fs::metadata(worktree.join(".git")).unwrap().is_file());
    let before = entries(&worktree);
    let refused = confirmed(&worktree, Client::Codex);
    assert!(matches!(refused.result, Err(InstallError::Repository(_))));
    assert_eq!(entries(&worktree), before);
    assert!(git(&worktree, &["status", "--porcelain"]).stdout.is_empty());
}

#[cfg(unix)]
#[test]
fn symlink_targets_parents_locks_and_confirmation_redirects_refuse() {
    let root = TempDir::new().unwrap();
    let foreign = root.path().join("foreign");
    fs::create_dir_all(&foreign).unwrap();
    let foreign_file = foreign.join("mcp.json");
    fs::write(&foreign_file, configuration(Client::Cursor)).unwrap();
    let original = fs::read(&foreign_file).unwrap();
    let home = root.path().join("home");
    fs::create_dir_all(home.join(".cursor")).unwrap();
    symlink(&foreign_file, target(&home, Client::Cursor)).unwrap();
    assert!(matches!(
        confirmed(&home, Client::Cursor).result,
        Err(InstallError::File(_))
    ));
    fs::remove_file(target(&home, Client::Cursor)).unwrap();
    fs::remove_dir(home.join(".cursor")).unwrap();
    symlink(&foreign, home.join(".cursor")).unwrap();
    assert!(matches!(
        confirmed(&home, Client::Cursor).result,
        Err(InstallError::Directory(_))
    ));
    fs::remove_file(home.join(".cursor")).unwrap();
    fs::create_dir_all(home.join(".cursor")).unwrap();
    symlink(
        &foreign_file,
        home.join(".cursor/.proofline-agent-install.lock"),
    )
    .unwrap();
    assert!(matches!(
        confirmed(&home, Client::Cursor).result,
        Err(InstallError::File(_))
    ));
    fs::remove_file(home.join(".cursor/.proofline-agent-install.lock")).unwrap();
    let mut input = AtConfirmation::new(|| {
        fs::remove_dir(home.join(".cursor")).unwrap();
        symlink(&foreign, home.join(".cursor")).unwrap();
    });
    let refused = invoke(&home, Client::Cursor, false, &mut input, &origin(), None);
    assert!(matches!(refused.result, Err(InstallError::Directory(_))));
    assert_eq!(fs::read(foreign_file).unwrap(), original);
    assert_eq!(fs::read_dir(foreign).unwrap().count(), 1);
}

#[test]
fn invalid_duplicate_oversized_and_readonly_documents_stay_private_and_intact() {
    for client in CLIENTS {
        let home = TempDir::new().unwrap();
        let invalid = match client {
            Client::Codex => vec![
                format!("private = '{PRIVATE}'\ninvalid = ["),
                "mcp_servers = []\n".to_owned(),
                "mcp_servers = 42\n".to_owned(),
                "mcp_servers = []\nmcp_servers = {}\n".to_owned(),
            ],
            Client::Cursor | Client::Gemini | Client::Kiro => vec![
                format!("{{\"private\":\"{PRIVATE}\", \"unfinished\": "),
                "[]".to_owned(),
                "{\"mcpServers\": []}".to_owned(),
                format!("{{\"private\":\"{PRIVATE}\",\"nested\":{{\"same\":1,\"same\":2}}}}"),
                "{ /* comment */ \"mcpServers\": {} }".to_owned(),
            ],
        };
        for document in invalid {
            let path = seed(home.path(), client, document.as_bytes());
            let before = entries(home.path());
            let refused = confirmed(home.path(), client);
            assert!(matches!(
                refused.result,
                Err(InstallError::InvalidConfig(_) | InstallError::ConfigShape { .. })
            ));
            assert!(!refused.diagnostics.contains(PRIVATE));
            let error = refused.result.unwrap_err();
            assert!(!format!("{error:?} {error}").contains(PRIVATE));
            assert_eq!(entries(home.path()), before);
            assert_eq!(fs::read(path).unwrap(), document.as_bytes());
        }
        let path = seed(home.path(), client, &vec![b' '; 1024 * 1024 + 1]);
        let before = entries(home.path());
        assert!(matches!(
            confirmed(home.path(), client).result,
            Err(InstallError::TooLarge)
        ));
        assert_eq!(entries(home.path()), before);
        fs::write(&path, configuration(client)).unwrap();
        let mut readonly = fs::metadata(&path).unwrap().permissions();
        readonly.set_readonly(true);
        fs::set_permissions(&path, readonly).unwrap();
        let before = entries(home.path());
        assert!(matches!(
            confirmed(home.path(), client).result,
            Err(InstallError::ReadOnly(_))
        ));
        assert_eq!(entries(home.path()), before);
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        #[cfg(not(unix))]
        {
            let mut permissions = fs::metadata(&path).unwrap().permissions();
            permissions.set_readonly(false);
            fs::set_permissions(&path, permissions).unwrap();
        }
        fs::remove_file(&path).unwrap();
        fs::create_dir_all(&path).unwrap();
        assert!(matches!(
            confirmed(home.path(), client).result,
            Err(InstallError::File(_))
        ));
        assert_eq!(fs::read_dir(&path).unwrap().count(), 0);
    }
}

#[test]
fn an_overlong_answer_and_unknown_client_or_output_flag_cannot_write() {
    let home = TempDir::new().unwrap();
    let answer = format!("yes{}\n", " ".repeat(1024));
    assert_eq!(
        invoke(
            home.path(),
            Client::Gemini,
            false,
            &mut Cursor::new(answer),
            &origin(),
            None
        )
        .result
        .unwrap(),
        Outcome::Cancelled
    );
    assert!(entries(home.path()).is_empty());
    assert!(matches!(
        invoke(
            home.path(),
            Client::Kiro,
            false,
            &mut FailedInput,
            &origin(),
            None
        )
        .result,
        Err(InstallError::Console { .. })
    ));
    assert!(entries(home.path()).is_empty());
    for args in [
        vec!["proofline", "agent", "install", "unknown"],
        vec![
            "proofline",
            "agent",
            "install",
            "codex",
            "--output",
            ".codex/config.toml",
        ],
        vec!["proofline", "agent", "install", "gemini", "--yes"],
    ] {
        assert!(Cli::try_parse_from(args).is_err());
    }
    let cli = Cli::try_parse_from(["proofline", "agent", "install", "kiro", "--print"]).unwrap();
    assert!(matches!(cli.command, CliCommand::Agent(_)));
    for invalid in [
        "https://user:private@proofline.sh",
        "https://proofline.sh/path",
        "https://proofline.sh/?token=private",
    ] {
        assert!(Origin::parse(invalid).is_err());
    }
}
