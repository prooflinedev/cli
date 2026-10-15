//! Confirmed user-file writes; the lock coordinates this installer's writers.

use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions, Permissions, TryLockError};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

use tempfile::NamedTempFile;

use super::{Client, InstallError, config};
use crate::origin::Origin;

const MAX_BYTES: u64 = 1024 * 1024;
const LOCK_NAME: &str = ".proofline-agent-install.lock";

#[derive(Debug)]
pub(super) struct Layout {
    home: PathBuf,
    parent: PathBuf,
    target: PathBuf,
    client: Client,
}

#[derive(Debug, PartialEq, Eq)]
struct Identity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(not(unix))]
    created: SystemTime,
}

impl Identity {
    fn read(path: &Path, metadata: &Metadata) -> Result<Self, InstallError> {
        #[cfg(unix)]
        {
            // Check metadata access on every platform; creation time is not
            // available on every Unix filesystem and is not needed here.
            metadata
                .modified()
                .map_err(|error| InstallError::io("inspect", path, error))?;
            Ok(Self {
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {
                created: metadata
                    .created()
                    .map_err(|error| InstallError::io("inspect creation time for", path, error))?,
            })
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Stamp {
    identity: Identity,
    modified: SystemTime,
    length: u64,
    readonly: bool,
    #[cfg(unix)]
    mode: u32,
}

impl Stamp {
    fn read(path: &Path, metadata: &Metadata) -> Result<Self, InstallError> {
        Ok(Self {
            identity: Identity::read(path, metadata)?,
            modified: metadata
                .modified()
                .map_err(|error| InstallError::io("inspect", path, error))?,
            length: metadata.len(),
            readonly: metadata.permissions().readonly(),
            #[cfg(unix)]
            mode: metadata.mode(),
        })
    }
}

struct RecordedFile {
    bytes: Vec<u8>,
    stamp: Stamp,
    permissions: Permissions,
}

impl fmt::Debug for RecordedFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordedFile")
            .field("bytes", &self.bytes.len())
            .field("stamp", &self.stamp)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub(super) struct Snapshot {
    directories: Vec<(PathBuf, Option<Identity>)>,
    file: Option<RecordedFile>,
}

impl Snapshot {
    pub(super) fn bytes(&self) -> Option<&[u8]> {
        self.file.as_ref().map(|file| file.bytes.as_slice())
    }

    fn same_file(&self, other: &Self) -> bool {
        match (&self.file, &other.file) {
            (None, None) => true,
            (Some(left), Some(right)) => left.bytes == right.bytes && left.stamp == right.stamp,
            (None, Some(_)) | (Some(_), None) => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Saved {
    Existing,
    Installed,
}

impl Layout {
    pub(super) fn new(home: &Path, client: Client) -> Result<Self, InstallError> {
        let home = home
            .canonicalize()
            .map_err(|error| InstallError::io("resolve the user home", home, error))?;
        let target = home.join(client.relative_path());
        let parent = target.parent().ok_or(InstallError::Home)?.to_owned();
        Ok(Self {
            home,
            parent,
            target,
            client,
        })
    }

    pub(super) fn target(&self) -> &Path {
        &self.target
    }

    pub(super) fn read(&self) -> Result<Snapshot, InstallError> {
        let directories = self.directories()?;
        self.outside_repository(&directories)?;
        self.lock_metadata()?;
        let file = self.read_file()?;
        Ok(Snapshot { directories, file })
    }

    pub(super) fn writable(&self, snapshot: &Snapshot) -> Result<(), InstallError> {
        if snapshot
            .file
            .as_ref()
            .is_some_and(|file| file.permissions.readonly())
        {
            return Err(InstallError::ReadOnly(self.target.clone()));
        }
        Ok(())
    }

    pub(super) fn save(
        &self,
        before: &Snapshot,
        bytes: &[u8],
        origin: &Origin,
    ) -> Result<Saved, InstallError> {
        let after_prompt = self.read()?;
        if matches!(
            config::prepare(self.client, after_prompt.bytes(), origin)?,
            config::Update::Existing
        ) {
            return Ok(Saved::Existing);
        }
        self.writable(&after_prompt)?;
        if before.directories != after_prompt.directories || !before.same_file(&after_prompt) {
            return Err(InstallError::Changed(self.target.clone()));
        }
        fs::create_dir_all(&self.parent).map_err(|error| {
            InstallError::io(
                "create the user configuration directory",
                &self.parent,
                error,
            )
        })?;
        let created = self.read()?;
        if !before.same_file(&created) || !self.original_directories(before, &created) {
            return Err(InstallError::Changed(self.target.clone()));
        }
        let lease = self.acquire_lock()?;
        let current = self.read()?;
        if matches!(
            config::prepare(self.client, current.bytes(), origin)?,
            config::Update::Existing
        ) {
            return Ok(Saved::Existing);
        }
        self.writable(&current)?;
        if created.directories != current.directories || !before.same_file(&current) {
            return Err(InstallError::Changed(self.target.clone()));
        }
        let temporary = self.temporary(bytes, current.file.as_ref())?;
        let check = self.read().and_then(|latest| {
            if current.directories != latest.directories || !current.same_file(&latest) {
                return Err(InstallError::Changed(self.target.clone()));
            }
            self.check_lock(&lease)
        });
        if let Err(error) = check {
            temporary.close().map_err(|error| {
                InstallError::io("remove the temporary configuration", &self.parent, error)
            })?;
            return Err(error);
        }
        self.persist(temporary, current.file.is_some())?;
        Ok(Saved::Installed)
    }

    fn original_directories(&self, before: &Snapshot, current: &Snapshot) -> bool {
        before.directories.iter().all(|(path, identity)| {
            identity.as_ref().is_none_or(|identity| {
                current.directories.iter().any(|(now_path, now_identity)| {
                    now_path == path && now_identity.as_ref() == Some(identity)
                })
            })
        })
    }

    fn directories(&self) -> Result<Vec<(PathBuf, Option<Identity>)>, InstallError> {
        let mut paths = vec![self.home.clone()];
        let relative = self
            .parent
            .strip_prefix(&self.home)
            .map_err(|_| InstallError::Home)?;
        let mut selected = self.home.clone();
        for part in relative.components() {
            selected.push(part);
            paths.push(selected.clone());
        }
        paths
            .into_iter()
            .map(|path| {
                let identity = match metadata(&path)? {
                    Some(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {
                        Some(Identity::read(&path, &meta)?)
                    }
                    Some(_) => return Err(InstallError::Directory(path)),
                    None => None,
                };
                Ok((path, identity))
            })
            .collect()
    }

    fn outside_repository(
        &self,
        directories: &[(PathBuf, Option<Identity>)],
    ) -> Result<(), InstallError> {
        let nearest = directories
            .iter()
            .rev()
            .find(|(_, identity)| identity.is_some())
            .map(|(path, _)| path)
            .ok_or(InstallError::Home)?;
        for ancestor in nearest.ancestors() {
            if metadata(&ancestor.join(".git"))?.is_some() {
                return Err(InstallError::Repository(self.target.clone()));
            }
        }
        let null = if cfg!(windows) { "NUL" } else { "/dev/null" };
        let probe = Command::new("git")
            .args([
                "-c",
                "safe.directory=*",
                "rev-parse",
                "--is-inside-work-tree",
            ])
            .current_dir(nearest)
            .env("LC_ALL", "C")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_CONFIG_GLOBAL", null)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_DISCOVERY_ACROSS_FILESYSTEM", "1")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_COMMON_DIR")
            .env_remove("GIT_INDEX_FILE")
            .env_remove("GIT_CEILING_DIRECTORIES")
            .env_remove("GIT_CONFIG")
            .env_remove("GIT_CONFIG_PARAMETERS")
            .env_remove("GIT_CONFIG_COUNT")
            .output()
            .map_err(|_| InstallError::GitProbe(self.target.clone()))?;
        if probe.status.success() {
            if probe.stdout == b"true\n" {
                return Err(InstallError::Repository(self.target.clone()));
            }
            if probe.stdout == b"false\n" {
                return Ok(());
            }
        } else if probe.status.code() == Some(128)
            && probe.stderr
                == b"fatal: not a git repository (or any of the parent directories): .git\n"
        {
            return Ok(());
        }
        Err(InstallError::GitProbe(self.target.clone()))
    }

    fn read_file(&self) -> Result<Option<RecordedFile>, InstallError> {
        let Some(meta) = metadata(&self.target)? else {
            return Ok(None);
        };
        regular(&self.target, &meta)?;
        if meta.len() > MAX_BYTES {
            return Err(InstallError::TooLarge);
        }
        let stamp = Stamp::read(&self.target, &meta)?;
        let file = File::open(&self.target)
            .map_err(|error| InstallError::io("read", &self.target, error))?;
        let opened = file.metadata().map_err(|error| {
            InstallError::io("inspect the opened configuration", &self.target, error)
        })?;
        if Stamp::read(&self.target, &opened)? != stamp {
            return Err(InstallError::Changed(self.target.clone()));
        }
        let mut bytes = Vec::new();
        file.take(MAX_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| InstallError::io("read", &self.target, error))?;
        if u64::try_from(bytes.len()).map_err(|_| InstallError::TooLarge)? > MAX_BYTES {
            return Err(InstallError::TooLarge);
        }
        let Some(final_meta) = metadata(&self.target)? else {
            return Err(InstallError::Changed(self.target.clone()));
        };
        regular(&self.target, &final_meta)?;
        if Stamp::read(&self.target, &final_meta)? != stamp {
            return Err(InstallError::Changed(self.target.clone()));
        }
        Ok(Some(RecordedFile {
            bytes,
            stamp,
            permissions: meta.permissions(),
        }))
    }

    fn lock_metadata(&self) -> Result<Option<Metadata>, InstallError> {
        let path = self.parent.join(LOCK_NAME);
        let meta = metadata(&path)?;
        if let Some(meta) = &meta {
            regular(&path, meta)?;
            if meta.len() != 0 || meta.permissions().readonly() {
                return Err(InstallError::File(path));
            }
        }
        Ok(meta)
    }

    fn acquire_lock(&self) -> Result<File, InstallError> {
        self.lock_metadata()?;
        let path = self.parent.join(LOCK_NAME);
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options
            .open(&path)
            .map_err(|error| InstallError::io("open the installer lock", &path, error))?;
        self.check_lock(&file)?;
        file.try_lock().map_err(|error| match error {
            TryLockError::WouldBlock => InstallError::Busy(path.clone()),
            TryLockError::Error(source) => InstallError::io("lock", &path, source),
        })?;
        self.check_lock(&file)?;
        Ok(file)
    }

    fn check_lock(&self, file: &File) -> Result<(), InstallError> {
        let path = self.parent.join(LOCK_NAME);
        let meta = self
            .lock_metadata()?
            .ok_or_else(|| InstallError::Changed(path.clone()))?;
        let opened = file
            .metadata()
            .map_err(|error| InstallError::io("inspect the installer lock", &path, error))?;
        regular(&path, &opened)?;
        if Identity::read(&path, &meta)? != Identity::read(&path, &opened)? {
            return Err(InstallError::Changed(path));
        }
        Ok(())
    }

    fn temporary(
        &self,
        bytes: &[u8],
        original: Option<&RecordedFile>,
    ) -> Result<NamedTempFile, InstallError> {
        if u64::try_from(bytes.len()).map_err(|_| InstallError::TooLarge)? > MAX_BYTES {
            return Err(InstallError::TooLarge);
        }
        let mut file = NamedTempFile::new_in(&self.parent).map_err(|error| {
            InstallError::io("create a temporary configuration", &self.parent, error)
        })?;
        let result = (|| {
            if let Some(original) = original {
                file.as_file()
                    .set_permissions(original.permissions.clone())
                    .map_err(|error| {
                        InstallError::io("preserve configuration permissions", &self.target, error)
                    })?;
            }
            file.write_all(bytes)
                .and_then(|()| file.flush())
                .and_then(|()| file.as_file().sync_all())
                .map_err(|error| {
                    InstallError::io(
                        "write and sync the temporary configuration",
                        &self.parent,
                        error,
                    )
                })
        })();
        if let Err(error) = result {
            file.close().map_err(|cleanup| {
                InstallError::io("remove the temporary configuration", &self.parent, cleanup)
            })?;
            return Err(error);
        }
        Ok(file)
    }

    fn persist(&self, temporary: NamedTempFile, exists: bool) -> Result<(), InstallError> {
        let result = if exists {
            temporary.persist(&self.target)
        } else {
            temporary.persist_noclobber(&self.target)
        };
        match result {
            Ok(file) => file.sync_all().map_err(|error| {
                InstallError::io("sync the saved configuration", &self.target, error)
            }),
            Err(error) => {
                error.file.close().map_err(|cleanup| {
                    InstallError::io("remove the temporary configuration", &self.parent, cleanup)
                })?;
                Err(InstallError::io(
                    "save the configuration",
                    &self.target,
                    error.error,
                ))
            }
        }
    }
}

fn metadata(path: &Path) -> Result<Option<Metadata>, InstallError> {
    match fs::symlink_metadata(path) {
        Ok(meta) => Ok(Some(meta)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(InstallError::io("inspect", path, error)),
    }
}

fn regular(path: &Path, meta: &Metadata) -> Result<(), InstallError> {
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(InstallError::File(path.to_owned()));
    }
    Ok(())
}
