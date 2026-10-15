//! Official release installation and best-effort discovery between invocations.

use std::fs::{self, File};
use std::io::{IsTerminal as _, Read as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const RELEASES: &str = "https://proofline.sh/cli";
const DAY: u64 = 86_400;
const MAX_ARCHIVE: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Cache {
    checked: u64,
    latest: Option<String>,
}

fn version(value: &str) -> anyhow::Result<[u64; 3]> {
    let parts: Vec<_> = value.split('.').collect();
    if parts.len() != 3
        || parts
            .iter()
            .any(|part| part.is_empty() || !part.bytes().all(|c| c.is_ascii_digit()))
    {
        bail!("release version is not a version number");
    }
    Ok([parts[0].parse()?, parts[1].parse()?, parts[2].parse()?])
}

fn newer(value: &str) -> bool {
    match (version(value), version(env!("CARGO_PKG_VERSION"))) {
        (Ok(latest), Ok(current)) => latest > current,
        _ => false,
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn cache_path() -> Option<PathBuf> {
    if cfg!(target_os = "windows") {
        std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .map(|p| p.join("proofline/update.json"))
    } else if let Some(root) =
        std::env::var_os("XDG_CACHE_HOME").filter(|p| Path::new(p).is_absolute())
    {
        Some(PathBuf::from(root).join("proofline/update.json"))
    } else {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|p| p.join(".cache/proofline/update.json"))
    }
}

fn read_cache(path: &Path) -> anyhow::Result<Cache> {
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    file.take(1025).read_to_end(&mut bytes)?;
    if bytes.len() > 1024 {
        bail!("update cache is too large");
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn write_cache(path: &Path, cache: &Cache) -> anyhow::Result<()> {
    let directory = path.parent().context("update cache has no directory")?;
    fs::create_dir_all(directory)?;
    let mut file = tempfile::NamedTempFile::new_in(directory)?;
    serde_json::to_writer(&mut file, cache)?;
    file.persist(path)?;
    Ok(())
}

/// Reads only local state; discovery continues in a child with closed streams.
/// Call before starting the runtime, including for help and version invocations.
pub fn on_invocation() {
    if std::env::var_os("PROOFLINE_NO_UPDATE_CHECK").is_some_and(|value| value == "1") {
        return;
    }
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args
        .iter()
        .any(|arg| arg == "update" || arg == "__update-check")
    {
        return;
    }
    let Some(path) = cache_path() else {
        return;
    };
    let interactive = std::io::stderr().is_terminal() && std::io::stdout().is_terminal();
    if let Ok(Some(notice)) = prepare_check(&path, &args, interactive, start_check) {
        crate::say(&notice);
    } else {
        // Missing or failed advisory discovery never changes the command result.
    }
}

fn suggestion(cache: &Cache, args: &[std::ffi::OsString], interactive: bool) -> Option<String> {
    if !interactive
        || args.iter().any(|arg| {
            arg == "--json"
                || arg == "--schema"
                || arg == "--sarif"
                || arg == "mcp"
                || arg == "ci"
                || arg == "hook"
                || arg == "hooks"
        })
    {
        return None;
    }
    cache
        .latest
        .as_ref()
        .filter(|latest| newer(latest))
        .map(|latest| format!("proofline {latest} is available; run 'proofline update'"))
}

fn prepare_check(
    path: &Path,
    args: &[std::ffi::OsString],
    interactive: bool,
    launch: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<Option<String>> {
    let directory = path.parent().context("update cache has no directory")?;
    fs::create_dir_all(directory)?;
    // A nonblocking OS lock serializes read/attempt/spawn across CLI processes.
    // File closure releases it even if an invocation exits unexpectedly.
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(directory.join("update.lock"))?;
    if lock.try_lock().is_err() {
        return Ok(None);
    }
    // Missing or malformed advisory state starts discovery instead of failing commands.
    let cache = read_cache(path).unwrap_or(Cache {
        checked: 0,
        latest: None,
    });
    let notice = suggestion(&cache, args, interactive);
    if cache.checked <= now() && now().saturating_sub(cache.checked) < DAY {
        return Ok(notice);
    }
    // Record the attempt first, so an offline machine does not fork on every command.
    write_cache(
        path,
        &Cache {
            checked: now(),
            latest: cache.latest,
        },
    )?;
    if launch().is_err() {
        // Keep any known notice if optional discovery cannot start.
    }
    Ok(notice)
}

fn checker_command(executable: &Path) -> Command {
    let mut command = Command::new(executable);
    command.env_clear();
    // Do not pass review tokens or cloud credentials to the release checker.
    for key in ["HOME", "XDG_CACHE_HOME", "LOCALAPPDATA", "SYSTEMROOT"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command
}

fn start_check() -> anyhow::Result<()> {
    let mut command = checker_command(&std::env::current_exe()?);
    command.arg("__update-check");
    spawn_check(command)
}

fn spawn_check(mut command: Command) -> anyhow::Result<()> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let mut child = command.spawn()?;
    // Reap the child during long-lived MCP sessions; process exit never waits.
    std::thread::Builder::new()
        .name("proofline-update".to_owned())
        .spawn(move || {
            if child.wait().is_err() {
                // Optional discovery never changes the parent command result.
            }
        })?;
    Ok(())
}

fn client(timeout: Duration) -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .user_agent(concat!("proofline/", env!("CARGO_PKG_VERSION")))
        .build()?)
}

async fn download(
    client: &reqwest::Client,
    address: &str,
    limit: usize,
) -> anyhow::Result<Vec<u8>> {
    let mut response = client.get(address).send().await?.error_for_status()?;
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        bail!("release download is too large");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if chunk.len() > limit.saturating_sub(bytes.len()) {
            bail!("release download is too large");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

async fn latest(client: &reqwest::Client) -> anyhow::Result<String> {
    latest_from(client, &format!("{RELEASES}/latest")).await
}

async fn latest_from(client: &reqwest::Client, address: &str) -> anyhow::Result<String> {
    let bytes = download(client, address, 128).await?;
    let value = std::str::from_utf8(&bytes)?.trim();
    version(value)?;
    Ok(value.to_owned())
}

/// The internal child entry point. Failures are silent and retain previous state.
pub(crate) async fn check() {
    let result = async {
        let client = client(Duration::from_secs(3))?;
        let path = cache_path().context("no update cache directory")?;
        refresh(&client, &format!("{RELEASES}/latest"), path).await?;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if result.is_err() {
        // Optional release discovery has no user-visible failure.
    }
}

async fn refresh(client: &reqwest::Client, address: &str, path: PathBuf) -> anyhow::Result<()> {
    let latest = latest_from(client, address).await?;
    tokio::task::spawn_blocking(move || {
        write_cache(
            &path,
            &Cache {
                checked: now(),
                latest: Some(latest),
            },
        )
    })
    .await??;
    Ok(())
}

fn install_path(executable: &Path, directory: &Path) -> anyhow::Result<PathBuf> {
    let expected = fs::canonicalize(directory)?.join("proofline");
    if executable != expected {
        bail!(
            "this binary is outside the installer directory {}; update it through its package manager or rebuild it from source",
            directory.display()
        );
    }
    if fs::symlink_metadata(&expected)?.file_type().is_symlink() {
        bail!("the installed binary is a symbolic link; update it through its package manager");
    }
    Ok(expected)
}

fn destination() -> anyhow::Result<PathBuf> {
    let directory = match std::env::var_os("PROOFLINE_INSTALL_DIR") {
        Some(directory) => PathBuf::from(directory),
        None => {
            PathBuf::from(std::env::var_os("HOME").context("set HOME or PROOFLINE_INSTALL_DIR")?)
                .join(".local/bin")
        }
    };
    install_path(&std::env::current_exe()?, &directory)
}

fn target() -> anyhow::Result<String> {
    let os = match std::env::consts::OS {
        "linux" => "unknown-linux-musl",
        "macos" => "apple-darwin",
        os => bail!(
            "no official Proofline release is built for {os}; build https://github.com/prooflinedev/cli from source"
        ),
    };
    let mut arch = std::env::consts::ARCH;
    if cfg!(target_os = "macos") && arch == "x86_64" {
        let output = Command::new("/usr/sbin/sysctl")
            .args(["-n", "sysctl.proc_translated"])
            .output()?;
        if output.status.success() && output.stdout == b"1\n" {
            arch = "aarch64";
        }
    }
    if !matches!(arch, "x86_64" | "aarch64") {
        bail!("no official Proofline release is built for {arch}");
    }
    Ok(format!("{arch}-{os}"))
}

fn verify(archive: &[u8], sums: &[u8], name: &str) -> anyhow::Result<()> {
    let mut matches = std::str::from_utf8(sums)?.lines().filter_map(|line| {
        let mut fields = line.split_whitespace();
        let digest = fields.next()?;
        let file = fields.next()?.trim_start_matches('*');
        (file == name && fields.next().is_none()).then_some(digest)
    });
    let expected = matches
        .next()
        .context("SHA256SUMS does not list this release archive")?;
    if matches.next().is_some()
        || expected.len() != 64
        || !expected.bytes().all(|c| c.is_ascii_hexdigit())
    {
        bail!("SHA256SUMS has an invalid or duplicate archive digest");
    }
    if format!("{:x}", Sha256::digest(archive)) != expected.to_ascii_lowercase() {
        bail!("download does not match SHA256SUMS; nothing was installed");
    }
    Ok(())
}

fn verify_and_replace(
    archive: &[u8],
    sums: &[u8],
    name: &str,
    destination: &Path,
) -> anyhow::Result<()> {
    verify(archive, sums, name)?;
    replace(archive, destination)
}

fn replace(archive: &[u8], destination: &Path) -> anyhow::Result<()> {
    let directory = destination
        .parent()
        .context("installed binary has no directory")?;
    let mut file = tempfile::NamedTempFile::new_in(directory)
        .context("could not write beside the installed binary")?;
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(archive));
    let mut found = false;
    for entry in archive.entries()? {
        let mut entry = entry?;
        if entry.path()?.as_ref() != Path::new("proofline")
            || !entry.header().entry_type().is_file()
            || found
        {
            bail!("release archive must contain only one regular proofline binary");
        }
        if entry.size() > MAX_ARCHIVE as u64 {
            bail!("release binary is too large");
        }
        std::io::copy(&mut entry, &mut file)?;
        found = true;
    }
    if !found || file.as_file().metadata()?.len() == 0 {
        bail!("release archive contains no proofline binary");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.as_file()
            .set_permissions(fs::Permissions::from_mode(0o755))?;
    }
    file.as_file().sync_all()?;
    file.persist(destination)
        .context("could not replace the installed binary")?;
    Ok(())
}

/// Updates an official installer location after verifying the pinned archive.
pub(crate) async fn install() -> anyhow::Result<()> {
    let (destination, target) =
        tokio::task::spawn_blocking(|| Ok::<_, anyhow::Error>((destination()?, target()?)))
            .await??;
    let client = client(Duration::from_secs(60))?;
    let version = latest(&client).await?;
    if !newer(&version) {
        crate::say(&format!(
            "proofline {} is up to date",
            env!("CARGO_PKG_VERSION")
        ));
        return Ok(());
    }
    let name = format!("proofline-{target}.tar.gz");
    let release = format!("{RELEASES}/download/{version}");
    let sums = download(&client, &format!("{release}/SHA256SUMS"), 4096).await?;
    let archive = download(&client, &format!("{release}/{name}"), MAX_ARCHIVE).await?;
    tokio::task::spawn_blocking(move || verify_and_replace(&archive, &sums, &name, &destination))
        .await??;
    crate::say(&format!("updated proofline to {version}"));
    Ok(())
}

#[cfg(test)]
mod tests;
