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
const WINDOWS_ARCHIVE: &str = "proofline-x86_64-pc-windows-msvc.tar.gz";
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

fn subcommand(args: &[std::ffi::OsString]) -> Option<&std::ffi::OsStr> {
    let mut index = 0;
    while let Some(arg) = args.get(index) {
        if arg == "--base-url" || arg == "--org" || arg == "--ca-cert" {
            let value = args.get(index + 1)?;
            if matches!(value.as_encoded_bytes(), [b'-', _, ..]) {
                return None;
            }
            index += 2;
            continue;
        }
        let bytes = arg.as_encoded_bytes();
        if bytes.starts_with(b"--base-url=")
            || bytes.starts_with(b"--org=")
            || bytes.starts_with(b"--ca-cert=")
        {
            index += 1;
            continue;
        }
        if bytes.first().is_some_and(|byte| *byte == b'-') {
            return None;
        }
        return Some(arg.as_os_str());
    }
    None
}

fn is_exempt(args: &[std::ffi::OsString]) -> bool {
    args.iter()
        // A shell evaluates `completions` at every start-up; keep it offline.
        .any(|arg| arg == "update" || arg == "__update-check" || arg == "completions")
        // `preflight` promises offline inspection only when invoked as the subcommand.
        || subcommand(args).is_some_and(|cmd| cmd == "preflight")
}

/// Reads only local state; discovery continues in a child with closed streams.
/// Call before starting the runtime, including for help and version invocations.
pub fn on_invocation() {
    if std::env::var_os("PROOFLINE_NO_UPDATE_CHECK").is_some_and(|value| value == "1") {
        return;
    }
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if is_exempt(&args) {
        return;
    }
    let Some(path) = cache_path() else {
        return;
    };
    let interactive = std::io::stderr().is_terminal() && std::io::stdout().is_terminal();
    if let Ok(Some(latest)) = prepare_check(&path, &args, interactive, start_check) {
        crate::say(&notice(&latest, updater()));
    } else {
        // Missing or failed advisory discovery never changes the command result.
    }
}

/// Arguments whose commands print for a script, Git or a long-running
/// session, so an update notice there would corrupt what they read.
const QUIET_ARGUMENTS: [&str; 20] = [
    "reviews",
    "routing",
    "run",
    "session",
    "wiki",
    "ask",
    "architecture",
    "plan",
    "setup",
    "history",
    "guidance",
    "fix-prompt",
    "export",
    "--json",
    "--schema",
    "--sarif",
    "mcp",
    "ci",
    "hook",
    "hooks",
];

/// The newer cached version an invocation announces, if any.
fn suggestion(cache: &Cache, args: &[std::ffi::OsString], interactive: bool) -> Option<String> {
    let quiet = args.iter().any(|arg| {
        arg.to_str()
            .is_some_and(|arg| QUIET_ARGUMENTS.contains(&arg))
    });
    if !interactive || quiet {
        return None;
    }
    cache.latest.clone().filter(|latest| newer(latest))
}

/// How this binary takes a new release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Updater {
    /// `proofline update` replaces it: an official platform, and the regular
    /// file `proofline` in the installer directory.
    Command,
    /// A Windows binary, which the user replaces from the release archive.
    WindowsDownload,
    /// A source build, package-manager installation or copy elsewhere.
    Original,
}

/// Reads only local files, so the notice makes no network call.
fn updater() -> Updater {
    if cfg!(target_os = "windows") {
        return Updater::WindowsDownload;
    }
    let installed = || {
        let directory = installer_directory().ok()?;
        install_path(&std::env::current_exe().ok()?, &directory).ok()
    };
    if release_os().is_ok() && release_arch(std::env::consts::ARCH) && installed().is_some() {
        Updater::Command
    } else {
        Updater::Original
    }
}

fn notice(latest: &str, updater: Updater) -> String {
    match updater {
        Updater::Command => format!("proofline {latest} is available; run 'proofline update'"),
        Updater::WindowsDownload => format!(
            "proofline {latest} is available; download {RELEASES}/download/{latest}/{WINDOWS_ARCHIVE} and check it against SHA256SUMS beside it"
        ),
        Updater::Original => {
            format!("proofline {latest} is available; update this binary the way it was installed")
        }
    }
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
    let announced = suggestion(&cache, args, interactive);
    if cache.checked <= now() && now().saturating_sub(cache.checked) < DAY {
        return Ok(announced);
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
    Ok(announced)
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
    Ok(crate::api::client_builder()
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
    let outside = || {
        anyhow::anyhow!(
            "this binary is outside the installer directory {}; if the installer put it elsewhere, set PROOFLINE_INSTALL_DIR to that directory, otherwise update it through its package manager or rebuild it from source",
            directory.display()
        )
    };
    // A missing installer directory holds no installed binary either.
    let expected = fs::canonicalize(directory)
        .map_err(|_| outside())?
        .join("proofline");
    // Checked first: on Linux `current_exe` already names the link's target,
    // so the comparison below would hide why the update is refused.
    if fs::symlink_metadata(&expected).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        bail!("the installed binary is a symbolic link; update it through its package manager");
    }
    // `current_exe` is not canonical on every platform (macOS reports the path
    // the binary was started through), while `expected` is.
    if fs::canonicalize(executable).ok().as_deref() != Some(expected.as_path()) {
        return Err(outside());
    }
    Ok(expected)
}

fn installer_directory() -> anyhow::Result<PathBuf> {
    Ok(match std::env::var_os("PROOFLINE_INSTALL_DIR") {
        Some(directory) => PathBuf::from(directory),
        None => {
            PathBuf::from(std::env::var_os("HOME").context("set HOME or PROOFLINE_INSTALL_DIR")?)
                .join(".local/bin")
        }
    })
}

fn destination() -> anyhow::Result<PathBuf> {
    install_path(&std::env::current_exe()?, &installer_directory()?)
}

/// The release target's operating system part. Windows releases exist, but
/// only as an archive the user verifies and extracts.
fn release_os() -> anyhow::Result<&'static str> {
    Ok(match std::env::consts::OS {
        "linux" => "unknown-linux-musl",
        "macos" => "apple-darwin",
        "windows" => bail!(
            "proofline update does not install Windows binaries; download {WINDOWS_ARCHIVE} and SHA256SUMS from {RELEASES}/download/VERSION/, with VERSION from {RELEASES}/latest, compare the archive's SHA-256 with Get-FileHash, and replace proofline.exe with the one it holds"
        ),
        os => bail!(
            "no official Proofline release is built for {os}; build https://github.com/prooflinedev/cli from source"
        ),
    })
}

fn release_arch(arch: &str) -> bool {
    matches!(arch, "x86_64" | "aarch64")
}

fn target() -> anyhow::Result<String> {
    let os = release_os()?;
    let mut arch = std::env::consts::ARCH;
    if cfg!(target_os = "macos") && arch == "x86_64" {
        let output = Command::new("/usr/sbin/sysctl")
            .args(["-n", "sysctl.proc_translated"])
            .output()?;
        if output.status.success() && output.stdout == b"1\n" {
            arch = "aarch64";
        }
    }
    if !release_arch(arch) {
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
    // The platform first: a Windows shell may have no HOME, and the refusal
    // for the missing variable would hide the one that applies.
    let (target, destination) =
        tokio::task::spawn_blocking(|| Ok::<_, anyhow::Error>((target()?, destination()?)))
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
