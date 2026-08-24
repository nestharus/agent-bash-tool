use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::{CString, OsStr, OsString};
use std::fmt;
use std::fs::{self, DirBuilder, File, Metadata, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use std::os::unix::process::ExitStatusExt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::state::{
    self, CallerChainEntry, DeliveryHelperInterpreterProvenance, DeliveryHelperProvenance,
    DeliveryLifecycle, DeliveryMeta, DeliveryMode, Meta, StatePaths,
};

const CONSUMER_GRACE_MS_ENV: &str = "AGENT_BASH_CONSUMER_GRACE_MS";
const MAX_CONSUMER_GRACE_MS: u64 = 10_000;
const CONSUMER_GRACE_POLL_MS: u64 = 25;
const OWNER_LOOKUP_TIMEOUT: Duration = Duration::from_secs(60);
const OWNER_LOOKUP_POLL: Duration = Duration::from_millis(10);
const DELIVERY_HELPER_SCHEMA_VERSION: u8 = 4;
const DELIVERY_HELPER_ENV_ALLOWLIST_ENV: &str = "AGENT_BASH_DELIVERY_HELPER_ENV_ALLOWLIST";
const COMPLETION_REGISTRATION_AUTHORITY_ENV: &str = "OULIPOLY_COMPLETION_REGISTRATION_AUTHORITY";
const BASE_DELIVERY_HELPER_ENVIRONMENT: &[&str] = &[
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LOGNAME",
    "OULIPOLY_DATA_DIR",
    "PATH",
    "SHELL",
    "TMPDIR",
    "TZ",
    "USER",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_RUNTIME_DIR",
];
const MAX_DELIVERY_HELPER_ENVIRONMENT_VARIABLES: usize = 64;
const MAX_DELIVERY_HELPER_ENVIRONMENT_BYTES: usize = 64 * 1024;
const DELIVERY_HELPER_CACHE_DIR: &str = ".delivery-helpers";
const DELIVERY_HELPER_LEGACY_UNSUPPORTED: &str = "delivery_helper_legacy_unsupported";
const DELIVERY_HELPER_UNAVAILABLE: &str = "delivery_helper_unavailable";
const DELIVERY_HELPER_INVALID: &str = "delivery_helper_provenance_invalid";
const DELIVERY_HELPER_CHANGED: &str = "delivery_helper_changed";

#[derive(Debug)]
struct ConfiguredDeliveryHelper {
    provenance: DeliveryHelperProvenance,
    executable: File,
    interpreter: Option<File>,
}

#[derive(Debug)]
struct HandleBoundDeliveryHelper {
    provenance: DeliveryHelperProvenance,
    executable: File,
    interpreter: Option<File>,
}

pub(crate) struct DeliveryRegistrationCandidate {
    helper: ConfiguredDeliveryHelper,
}

impl DeliveryRegistrationCandidate {
    pub(crate) fn resolve_owner_binding(
        &self,
        caller_chain: &[CallerChainEntry],
        expected_invocation_uuid: &str,
    ) -> io::Result<Option<(String, String)>> {
        resolve_owner_binding(caller_chain, Some(expected_invocation_uuid), || {
            self.helper.owner_lookup_command()
        })
    }

    pub(crate) fn bind_to_handle(self, paths: &StatePaths) -> io::Result<DeliveryRegistration> {
        let helper = self.helper.pin_to_handle(paths).map_err(io::Error::other)?;
        Ok(DeliveryRegistration { helper })
    }
}

pub(crate) struct DeliveryRegistration {
    helper: HandleBoundDeliveryHelper,
}

struct DeliveryLockGuard {
    _file: File,
}

impl DeliveryLockGuard {
    fn acquire(paths: &StatePaths) -> io::Result<Self> {
        Ok(Self {
            _file: state::lock_delivery(paths)?,
        })
    }
}

impl DeliveryRegistration {
    pub(crate) fn provenance(&self) -> DeliveryHelperProvenance {
        self.helper.provenance.clone()
    }
}

#[derive(Debug)]
struct DeliveryHelperError {
    code: &'static str,
    detail: String,
    retryable: bool,
}

impl DeliveryHelperError {
    fn unavailable(detail: impl Into<String>) -> Self {
        Self {
            code: DELIVERY_HELPER_UNAVAILABLE,
            detail: detail.into(),
            retryable: true,
        }
    }

    fn invalid(detail: impl Into<String>) -> Self {
        Self {
            code: DELIVERY_HELPER_INVALID,
            detail: detail.into(),
            retryable: false,
        }
    }

    fn changed(detail: impl Into<String>) -> Self {
        Self {
            code: DELIVERY_HELPER_CHANGED,
            detail: detail.into(),
            retryable: true,
        }
    }

    fn legacy(detail: impl Into<String>) -> Self {
        Self {
            code: DELIVERY_HELPER_LEGACY_UNSUPPORTED,
            detail: detail.into(),
            retryable: false,
        }
    }
}

impl fmt::Display for DeliveryHelperError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for DeliveryHelperError {}

impl ConfiguredDeliveryHelper {
    fn from_environment() -> Result<Self, DeliveryHelperError> {
        let configured =
            env::var_os("AGENT_BASH_AGENT_RUNNER_BIN").unwrap_or_else(|| OsString::from("agents"));
        if configured.is_empty() {
            return Err(DeliveryHelperError::invalid(
                "AGENT_BASH_AGENT_RUNNER_BIN is empty",
            ));
        }
        if configured.as_os_str().as_bytes().contains(&b'/') {
            return Self::from_configured_path(Path::new(&configured));
        }
        Self::from_search_path(&configured)
    }

    fn from_configured_path(path: &Path) -> Result<Self, DeliveryHelperError> {
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            env::current_dir()
                .map_err(|err| {
                    DeliveryHelperError::unavailable(format!(
                        "cannot resolve configured delivery helper {}: {err}",
                        path.display()
                    ))
                })?
                .join(path)
        };
        let canonical = fs::canonicalize(&absolute).map_err(|err| {
            DeliveryHelperError::unavailable(format!(
                "cannot resolve configured delivery helper {}: {err}",
                absolute.display()
            ))
        })?;
        Self::from_resolved_path(&canonical)
    }

    fn from_search_path(name: &OsStr) -> Result<Self, DeliveryHelperError> {
        let Some(search_path) = env::var_os("PATH") else {
            return Err(DeliveryHelperError::unavailable(format!(
                "cannot find delivery helper {:?}: PATH is not set",
                name
            )));
        };
        for directory in env::split_paths(&search_path) {
            let candidate = directory.join(name);
            let Ok(canonical) = fs::canonicalize(&candidate) else {
                continue;
            };
            if let Ok(helper) = Self::from_resolved_path(&canonical) {
                return Ok(helper);
            }
        }
        Err(DeliveryHelperError::unavailable(format!(
            "cannot find executable delivery helper {:?} in PATH",
            name
        )))
    }

    fn from_resolved_path(path: &Path) -> Result<Self, DeliveryHelperError> {
        if !path.is_absolute() {
            return Err(DeliveryHelperError::invalid(
                "resolved delivery helper path is not absolute",
            ));
        }
        let path_text = path.to_str().ok_or_else(|| {
            DeliveryHelperError::invalid("delivery helper path is not valid UTF-8")
        })?;
        let source = open_delivery_helper(path).map_err(|err| {
            DeliveryHelperError::unavailable(format!(
                "cannot open delivery helper {}: {err}",
                path.display()
            ))
        })?;
        let metadata = source.metadata().map_err(|err| {
            DeliveryHelperError::unavailable(format!(
                "cannot inspect delivery helper {}: {err}",
                path.display()
            ))
        })?;
        validate_delivery_helper_metadata(path, &metadata).map_err(DeliveryHelperError::invalid)?;
        let interpreter = configured_interpreter(&source)?;
        let interpreter_provenance =
            interpreter
                .as_ref()
                .map(|(path, _, sha256)| DeliveryHelperInterpreterProvenance {
                    path: path.to_string_lossy().into_owned(),
                    sha256: sha256.clone(),
                });
        let (executable, sha256) = sealed_execution_image(&source).map_err(|err| {
            DeliveryHelperError::unavailable(format!(
                "cannot snapshot delivery helper {}: {err}",
                path.display()
            ))
        })?;
        let environment = capture_delivery_helper_environment()?;
        Ok(Self {
            provenance: provenance_from_metadata(
                path_text.to_string(),
                &metadata,
                sha256,
                environment,
                interpreter_provenance,
            ),
            executable,
            interpreter: interpreter.map(|(_, executable, _)| executable),
        })
    }

    fn pin_to_handle(
        self,
        paths: &StatePaths,
    ) -> Result<HandleBoundDeliveryHelper, DeliveryHelperError> {
        let cache_dir = paths.root.join(DELIVERY_HELPER_CACHE_DIR);
        create_helper_cache_dir(&cache_dir).map_err(|err| {
            DeliveryHelperError::unavailable(format!(
                "cannot create delivery helper cache {}: {err}",
                cache_dir.display()
            ))
        })?;
        let cached = cache_dir.join(&self.provenance.sha256);
        let validated_cache = validate_cached_helper(&cached, &self.provenance.sha256).ok();
        let cache_lock = lock_helper_cache(&cache_dir).map_err(|err| {
            DeliveryHelperError::unavailable(format!(
                "cannot lock delivery helper cache {}: {err}",
                cache_dir.display()
            ))
        })?;
        let cache_unchanged = validated_cache.as_ref().is_some_and(|validated| {
            fs::metadata(&cached)
                .map(|current| same_file_version(validated, &current))
                .unwrap_or(false)
        });
        if !cache_unchanged {
            install_cached_helper(
                &cached,
                &self.executable,
                &self.provenance.sha256,
                &paths.handle,
            )
            .map_err(|err| {
                DeliveryHelperError::unavailable(format!(
                    "cannot cache delivery helper for {}: {err}",
                    paths.handle
                ))
            })?;
        }
        if let (Some(interpreter), Some(provenance)) =
            (&self.interpreter, &self.provenance.interpreter)
        {
            let cached_interpreter = cache_dir.join(&provenance.sha256);
            install_cached_helper(
                &cached_interpreter,
                interpreter,
                &provenance.sha256,
                &paths.handle,
            )
            .map_err(|err| {
                DeliveryHelperError::unavailable(format!(
                    "cannot cache delivery helper interpreter for {}: {err}",
                    paths.handle
                ))
            })?;
            fs::hard_link(&cached_interpreter, &paths.delivery_helper_interpreter).map_err(
                |err| {
                    DeliveryHelperError::unavailable(format!(
                        "cannot pin delivery helper interpreter for {}: {err}",
                        paths.handle
                    ))
                },
            )?;
        }
        fs::hard_link(&cached, &paths.delivery_helper).map_err(|err| {
            DeliveryHelperError::unavailable(format!(
                "cannot pin delivery helper for {}: {err}",
                paths.handle
            ))
        })?;
        cleanup_unreferenced_helper_snapshots(&cache_dir);
        File::open(&paths.state_dir)
            .and_then(|directory| directory.sync_all())
            .map_err(|err| {
                DeliveryHelperError::unavailable(format!(
                    "cannot persist delivery helper binding for {}: {err}",
                    paths.handle
                ))
            })?;
        drop(cache_lock);
        let snapshot_path = fs::canonicalize(&paths.delivery_helper).map_err(|err| {
            DeliveryHelperError::unavailable(format!(
                "cannot resolve pinned delivery helper for {}: {err}",
                paths.handle
            ))
        })?;
        let metadata = fs::metadata(&snapshot_path).map_err(|err| {
            DeliveryHelperError::unavailable(format!(
                "cannot inspect pinned delivery helper for {}: {err}",
                paths.handle
            ))
        })?;
        let interpreter_provenance = match self.provenance.interpreter {
            Some(mut provenance) => {
                provenance.path = fs::canonicalize(&paths.delivery_helper_interpreter)
                    .map_err(|err| {
                        DeliveryHelperError::unavailable(format!(
                            "cannot resolve pinned delivery helper interpreter for {}: {err}",
                            paths.handle
                        ))
                    })?
                    .to_string_lossy()
                    .into_owned();
                Some(provenance)
            }
            None => None,
        };
        let provenance = provenance_from_metadata(
            snapshot_path.to_string_lossy().into_owned(),
            &metadata,
            self.provenance.sha256,
            self.provenance.environment,
            interpreter_provenance,
        );
        Ok(HandleBoundDeliveryHelper {
            provenance,
            executable: self.executable,
            interpreter: self.interpreter,
        })
    }

    fn owner_lookup_command(&self) -> Command {
        delivery_helper_command(
            &self.provenance,
            &self.executable,
            self.interpreter.as_ref(),
        )
    }
}

impl HandleBoundDeliveryHelper {
    fn from_provenance(
        provenance: Option<&DeliveryHelperProvenance>,
        paths: &StatePaths,
    ) -> Result<Self, DeliveryHelperError> {
        let provenance = provenance.ok_or_else(|| {
            DeliveryHelperError::legacy(format!(
                "registered delivery helper snapshot is missing for {}",
                paths.handle
            ))
        })?;
        if provenance.schema_version != DELIVERY_HELPER_SCHEMA_VERSION {
            return Err(DeliveryHelperError::legacy(format!(
                "registered delivery helper for {} has unsupported schema version {}",
                paths.handle, provenance.schema_version
            )));
        }
        validate_delivery_helper_environment(&provenance.environment)?;
        let path = PathBuf::from(&provenance.path);
        if !path.is_absolute() {
            return Err(DeliveryHelperError::invalid(format!(
                "registered delivery helper path for {} is not absolute",
                paths.handle
            )));
        }
        let expected_parent = fs::canonicalize(&paths.state_dir).map_err(|err| {
            DeliveryHelperError::unavailable(format!(
                "registered delivery helper state for {} is unavailable: {err}",
                paths.handle
            ))
        })?;
        let expected_path = expected_parent.join("delivery-helper");
        if path != expected_path {
            return Err(DeliveryHelperError::changed(format!(
                "registered delivery helper binding changed for {}",
                paths.handle
            )));
        }
        let executable = open_delivery_helper(&path).map_err(|err| {
            if err.kind() == io::ErrorKind::NotFound {
                DeliveryHelperError::unavailable(format!(
                    "registered delivery helper {} for {} is unavailable: {err}",
                    path.display(),
                    paths.handle
                ))
            } else {
                DeliveryHelperError::changed(format!(
                    "registered delivery helper {} for {} cannot be opened safely: {err}",
                    path.display(),
                    paths.handle
                ))
            }
        })?;
        let metadata = executable.metadata().map_err(|err| {
            DeliveryHelperError::unavailable(format!(
                "cannot inspect registered delivery helper {} for {}: {err}",
                path.display(),
                paths.handle
            ))
        })?;
        validate_delivery_helper_metadata(&path, &metadata).map_err(|detail| {
            DeliveryHelperError::changed(format!("{detail} for {}", paths.handle))
        })?;
        if !provenance_matches(provenance, &metadata) {
            return Err(DeliveryHelperError::changed(format!(
                "registered delivery helper identity changed for {} at {}",
                paths.handle,
                path.display()
            )));
        }
        let (executable, sha256) = sealed_execution_image(&executable).map_err(|err| {
            DeliveryHelperError::unavailable(format!(
                "cannot load registered delivery helper for {}: {err}",
                paths.handle
            ))
        })?;
        if sha256 != provenance.sha256 {
            return Err(DeliveryHelperError::changed(format!(
                "registered delivery helper contents changed for {}",
                paths.handle
            )));
        }
        let interpreter = match &provenance.interpreter {
            Some(interpreter) => Some(load_bound_interpreter(interpreter, paths)?),
            None => None,
        };
        Ok(Self {
            provenance: provenance.clone(),
            executable,
            interpreter,
        })
    }

    fn operation_command(&self) -> Command {
        delivery_helper_command(
            &self.provenance,
            &self.executable,
            self.interpreter.as_ref(),
        )
    }
}

fn delivery_helper_command(
    provenance: &DeliveryHelperProvenance,
    executable: &File,
    interpreter: Option<&File>,
) -> Command {
    let fd = executable.as_raw_fd();
    let interpreter_fd = interpreter.map(AsRawFd::as_raw_fd);
    debug_assert_eq!(provenance.interpreter.is_some(), interpreter_fd.is_some());
    let mut command = if let Some(interpreter_fd) = interpreter_fd {
        let mut command = Command::new(format!("/proc/self/fd/{interpreter_fd}"));
        command.arg(format!("/proc/self/fd/{fd}"));
        command
    } else {
        Command::new(format!("/proc/self/fd/{fd}"))
    };
    command
        .env_clear()
        .envs(&provenance.environment)
        .current_dir("/");
    unsafe {
        command.pre_exec(move || {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            if flags < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                return Err(io::Error::last_os_error());
            }
            if let Some(interpreter_fd) = interpreter_fd {
                let flags = libc::fcntl(interpreter_fd, libc::F_GETFD);
                if flags < 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::fcntl(interpreter_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    command
}

fn open_delivery_helper(path: &Path) -> io::Result<File> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "helper path contains NUL"))?;
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn validate_delivery_helper_metadata(path: &Path, metadata: &Metadata) -> Result<(), String> {
    if !metadata.is_file() {
        return Err(format!(
            "delivery helper {} is not a regular file",
            path.display()
        ));
    }
    if metadata.mode() & 0o111 == 0 {
        return Err(format!(
            "delivery helper {} is not executable",
            path.display()
        ));
    }
    Ok(())
}

fn configured_interpreter(
    source: &File,
) -> Result<Option<(PathBuf, File, String)>, DeliveryHelperError> {
    let mut reader = source.try_clone().map_err(|err| {
        DeliveryHelperError::unavailable(format!("cannot inspect delivery helper: {err}"))
    })?;
    reader.seek(SeekFrom::Start(0)).map_err(|err| {
        DeliveryHelperError::unavailable(format!("cannot inspect delivery helper: {err}"))
    })?;
    let mut prefix = [0_u8; 4096];
    let read = reader.read(&mut prefix).map_err(|err| {
        DeliveryHelperError::unavailable(format!("cannot inspect delivery helper: {err}"))
    })?;
    if !prefix[..read].starts_with(b"#!") {
        return Ok(None);
    }
    let line = prefix[2..read]
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    let line = std::str::from_utf8(line)
        .map_err(|_| DeliveryHelperError::invalid("delivery helper shebang is not valid UTF-8"))?
        .trim();
    let mut parts = line.split_whitespace();
    let path = parts
        .next()
        .ok_or_else(|| DeliveryHelperError::invalid("delivery helper shebang is empty"))?;
    if parts.next().is_some() {
        return Err(DeliveryHelperError::invalid(
            "delivery helper shebang arguments are unsupported",
        ));
    }
    let path = Path::new(path);
    if !path.is_absolute() {
        return Err(DeliveryHelperError::invalid(
            "delivery helper interpreter path is not absolute",
        ));
    }
    let path = fs::canonicalize(path).map_err(|err| {
        DeliveryHelperError::unavailable(format!(
            "cannot resolve delivery helper interpreter {}: {err}",
            path.display()
        ))
    })?;
    let source = open_delivery_helper(&path).map_err(|err| {
        DeliveryHelperError::unavailable(format!(
            "cannot open delivery helper interpreter {}: {err}",
            path.display()
        ))
    })?;
    let metadata = source.metadata().map_err(|err| {
        DeliveryHelperError::unavailable(format!(
            "cannot inspect delivery helper interpreter {}: {err}",
            path.display()
        ))
    })?;
    validate_delivery_helper_metadata(&path, &metadata).map_err(DeliveryHelperError::invalid)?;
    let (executable, sha256) = sealed_execution_image(&source).map_err(|err| {
        DeliveryHelperError::unavailable(format!(
            "cannot snapshot delivery helper interpreter {}: {err}",
            path.display()
        ))
    })?;
    if execution_image_is_script(&executable)? {
        return Err(DeliveryHelperError::invalid(
            "delivery helper interpreter must be a native executable",
        ));
    }
    Ok(Some((path, executable, sha256)))
}

fn execution_image_is_script(executable: &File) -> Result<bool, DeliveryHelperError> {
    let mut reader = executable.try_clone().map_err(|err| {
        DeliveryHelperError::unavailable(format!("cannot inspect execution image: {err}"))
    })?;
    reader.seek(SeekFrom::Start(0)).map_err(|err| {
        DeliveryHelperError::unavailable(format!("cannot inspect execution image: {err}"))
    })?;
    let mut prefix = [0_u8; 2];
    let read = reader.read(&mut prefix).map_err(|err| {
        DeliveryHelperError::unavailable(format!("cannot inspect execution image: {err}"))
    })?;
    Ok(read == prefix.len() && prefix == *b"#!")
}

fn load_bound_interpreter(
    provenance: &DeliveryHelperInterpreterProvenance,
    paths: &StatePaths,
) -> Result<File, DeliveryHelperError> {
    let expected_path = fs::canonicalize(&paths.state_dir)
        .map_err(|err| {
            DeliveryHelperError::unavailable(format!(
                "registered delivery helper state for {} is unavailable: {err}",
                paths.handle
            ))
        })?
        .join("delivery-helper-interpreter");
    if Path::new(&provenance.path) != expected_path {
        return Err(DeliveryHelperError::changed(format!(
            "registered delivery helper interpreter binding changed for {}",
            paths.handle
        )));
    }
    let source = open_delivery_helper(&expected_path).map_err(|err| {
        DeliveryHelperError::unavailable(format!(
            "registered delivery helper interpreter for {} is unavailable: {err}",
            paths.handle
        ))
    })?;
    let (executable, sha256) = sealed_execution_image(&source).map_err(|err| {
        DeliveryHelperError::unavailable(format!(
            "cannot load registered delivery helper interpreter for {}: {err}",
            paths.handle
        ))
    })?;
    if sha256 != provenance.sha256 {
        return Err(DeliveryHelperError::changed(format!(
            "registered delivery helper interpreter contents changed for {}",
            paths.handle
        )));
    }
    if execution_image_is_script(&executable)? {
        return Err(DeliveryHelperError::changed(format!(
            "registered delivery helper interpreter for {} is not native",
            paths.handle
        )));
    }
    Ok(executable)
}

fn provenance_from_metadata(
    path: String,
    metadata: &Metadata,
    sha256: String,
    environment: BTreeMap<String, String>,
    interpreter: Option<DeliveryHelperInterpreterProvenance>,
) -> DeliveryHelperProvenance {
    DeliveryHelperProvenance {
        schema_version: DELIVERY_HELPER_SCHEMA_VERSION,
        path,
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.size(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        mode: metadata.mode(),
        sha256,
        environment,
        interpreter,
    }
}

fn capture_delivery_helper_environment() -> Result<BTreeMap<String, String>, DeliveryHelperError> {
    let mut names = BASE_DELIVERY_HELPER_ENVIRONMENT
        .iter()
        .map(|name| (*name).to_string())
        .collect::<BTreeSet<_>>();
    if let Some(configured) = env::var_os(DELIVERY_HELPER_ENV_ALLOWLIST_ENV) {
        let configured = configured.into_string().map_err(|_| {
            DeliveryHelperError::invalid(format!(
                "{DELIVERY_HELPER_ENV_ALLOWLIST_ENV} is not valid UTF-8"
            ))
        })?;
        for name in configured
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
        {
            validate_delivery_helper_environment_name(name)?;
            names.insert(name.to_string());
        }
    }
    if names.len() > MAX_DELIVERY_HELPER_ENVIRONMENT_VARIABLES {
        return Err(DeliveryHelperError::invalid(format!(
            "delivery helper environment names exceed {MAX_DELIVERY_HELPER_ENVIRONMENT_VARIABLES}"
        )));
    }

    let mut environment = BTreeMap::new();
    for name in names {
        let Some(value) = env::var_os(&name) else {
            continue;
        };
        let value = value.into_string().map_err(|_| {
            DeliveryHelperError::invalid(format!(
                "delivery helper environment variable {name} is not valid UTF-8"
            ))
        })?;
        environment.insert(name, value);
    }
    validate_delivery_helper_environment(&environment)?;
    Ok(environment)
}

fn validate_delivery_helper_environment(
    environment: &BTreeMap<String, String>,
) -> Result<(), DeliveryHelperError> {
    if environment.len() > MAX_DELIVERY_HELPER_ENVIRONMENT_VARIABLES {
        return Err(DeliveryHelperError::invalid(format!(
            "registered delivery helper environment exceeds {MAX_DELIVERY_HELPER_ENVIRONMENT_VARIABLES} variables"
        )));
    }
    let mut bytes = 0_usize;
    for (name, value) in environment {
        validate_delivery_helper_environment_name(name)?;
        if value.as_bytes().contains(&0) {
            return Err(DeliveryHelperError::invalid(format!(
                "registered delivery helper environment variable {name} contains NUL"
            )));
        }
        bytes = bytes.saturating_add(name.len()).saturating_add(value.len());
    }
    if bytes > MAX_DELIVERY_HELPER_ENVIRONMENT_BYTES {
        return Err(DeliveryHelperError::invalid(format!(
            "registered delivery helper environment exceeds {MAX_DELIVERY_HELPER_ENVIRONMENT_BYTES} bytes"
        )));
    }
    Ok(())
}

fn validate_delivery_helper_environment_name(name: &str) -> Result<(), DeliveryHelperError> {
    let valid = !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric());
    if !valid {
        return Err(DeliveryHelperError::invalid(format!(
            "delivery helper environment variable name {name:?} is invalid"
        )));
    }
    if matches!(
        name,
        COMPLETION_REGISTRATION_AUTHORITY_ENV
            | DELIVERY_HELPER_ENV_ALLOWLIST_ENV
            | "AGENT_BASH_AGENT_RUNNER_BIN"
    ) {
        return Err(DeliveryHelperError::invalid(format!(
            "delivery helper environment variable {name} is reserved"
        )));
    }
    Ok(())
}

fn sealed_execution_image(source: &File) -> io::Result<(File, String)> {
    let name = CString::new("agent-bash-delivery-helper").expect("static memfd name");
    let fd = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            name.as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut image = unsafe { File::from_raw_fd(i32::try_from(fd).map_err(io::Error::other)?) };
    let mut reader = source.try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        image.write_all(&buffer[..read])?;
    }
    image.set_permissions(fs::Permissions::from_mode(0o500))?;
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    if unsafe { libc::fcntl(image.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
        return Err(io::Error::last_os_error());
    }
    image.seek(SeekFrom::Start(0))?;
    Ok((image, format!("{:x}", digest.finalize())))
}

fn create_helper_cache_dir(path: &Path) -> io::Result<()> {
    match DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(err) => Err(err),
    }
}

fn cleanup_unreferenced_helper_snapshots(cache_dir: &Path) {
    let Ok(entries) = fs::read_dir(cache_dir) else {
        return;
    };
    for entry in entries.filter_map(Result::ok).take(128) {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.len() != 64 || !name.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            continue;
        }
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if metadata.is_file() && metadata.nlink() == 1 {
            let _ = fs::remove_file(entry.path());
        }
    }
}

fn lock_helper_cache(cache_dir: &Path) -> io::Result<File> {
    let lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .open(cache_dir.join("cache.lock"))?;
    loop {
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } == 0 {
            return Ok(lock);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

fn install_cached_helper(
    cached: &Path,
    image: &File,
    expected_sha256: &str,
    handle: &str,
) -> io::Result<()> {
    if cached.exists() {
        return validate_cached_helper(cached, expected_sha256).map(|_| ());
    }
    let temp = cached.with_file_name(format!(".{}.{}.tmp", expected_sha256, handle));
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o500)
        .open(&temp)?;
    let mut input = image.try_clone()?;
    input.seek(SeekFrom::Start(0))?;
    io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    drop(output);
    match fs::hard_link(&temp, cached) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
        Err(err) => {
            let _ = fs::remove_file(&temp);
            return Err(err);
        }
    }
    fs::remove_file(&temp)?;
    validate_cached_helper(cached, expected_sha256).map(|_| ())
}

fn validate_cached_helper(path: &Path, expected_sha256: &str) -> io::Result<Metadata> {
    let file = open_delivery_helper(path)?;
    let metadata = file.metadata()?;
    validate_delivery_helper_metadata(path, &metadata)
        .map_err(|detail| io::Error::new(io::ErrorKind::InvalidData, detail))?;
    let (_, observed_sha256) = sealed_execution_image(&file)?;
    if observed_sha256 == expected_sha256 {
        Ok(metadata)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cached delivery helper digest mismatch",
        ))
    }
}

fn same_file_version(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.size() == right.size()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.mode() == right.mode()
}

fn provenance_matches(provenance: &DeliveryHelperProvenance, metadata: &Metadata) -> bool {
    provenance.device == metadata.dev()
        && provenance.inode == metadata.ino()
        && provenance.size == metadata.size()
        && provenance.modified_seconds == metadata.mtime()
        && provenance.modified_nanoseconds == metadata.mtime_nsec()
        && provenance.mode == metadata.mode()
}

#[derive(Debug, Serialize)]
pub(crate) struct DetachOutcome {
    handle: String,
    delivery_mode: DeliveryMode,
    state: String,
    transitioned: bool,
    #[serde(rename = "notification_attempted")]
    terminal_activation_requests_notification: bool,
}

#[derive(Debug, Deserialize)]
struct PidSessionResponse {
    found: bool,
    invocation_uuid: Option<String>,
    session_id: Option<String>,
}

fn resolve_owner_binding(
    caller_chain: &[CallerChainEntry],
    expected_invocation_uuid: Option<&str>,
    mut owner_lookup_command: impl FnMut() -> Command,
) -> io::Result<Option<(String, String)>> {
    for entry in caller_chain
        .iter()
        .filter(|entry| state::process_identity_is_live(entry))
    {
        if let Some(owner) =
            resolve_owner_for_pid(owner_lookup_command(), entry.pid, expected_invocation_uuid)?
        {
            return Ok(Some(owner));
        }
    }
    Ok(None)
}

fn resolve_owner_for_pid(
    mut command: Command,
    pid: libc::pid_t,
    expected_invocation_uuid: Option<&str>,
) -> io::Result<Option<(String, String)>> {
    let mut child = command
        .args(["session", "of-pid", &pid.to_string(), "--json"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let deadline = Instant::now() + OWNER_LOOKUP_TIMEOUT;
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("agents session of-pid {pid} timed out"),
            ));
        }
        thread::sleep(OWNER_LOOKUP_POLL);
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        if output.status.code() == Some(1)
            && serde_json::from_slice::<PidSessionResponse>(&output.stdout)
                .is_ok_and(|response| !response.found)
        {
            return Ok(None);
        }
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let fallback = String::from_utf8_lossy(&output.stdout).trim().to_string();
        return Err(io::Error::other(format!(
            "agents session of-pid {pid} exited with {}{}",
            output.status,
            if !detail.is_empty() {
                format!(": {detail}")
            } else if !fallback.is_empty() {
                format!(": {fallback}")
            } else {
                String::new()
            }
        )));
    }
    let response: PidSessionResponse = serde_json::from_slice(&output.stdout).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("agents session of-pid {pid} returned invalid JSON: {err}"),
        )
    })?;
    if !response.found
        || expected_invocation_uuid
            .is_some_and(|expected| response.invocation_uuid.as_deref() != Some(expected))
    {
        return Ok(None);
    }
    let Some(session_id) = response.session_id.filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let Some(invocation_uuid) = response.invocation_uuid else {
        return Ok(None);
    };
    Ok(Some((session_id, invocation_uuid)))
}

pub(crate) fn resolve_handle_owner_binding(
    paths: &StatePaths,
    provenance: Option<&DeliveryHelperProvenance>,
    caller_chain: &[CallerChainEntry],
) -> io::Result<Option<(String, String)>> {
    let helper =
        HandleBoundDeliveryHelper::from_provenance(provenance, paths).map_err(io::Error::other)?;
    resolve_owner_binding(caller_chain, None, || helper.operation_command())
}

pub(crate) fn prepare_registration() -> io::Result<DeliveryRegistrationCandidate> {
    let helper = ConfiguredDeliveryHelper::from_environment().map_err(io::Error::other)?;
    Ok(DeliveryRegistrationCandidate { helper })
}

pub(crate) fn register(
    paths: &StatePaths,
    meta: &Meta,
    registration: DeliveryRegistration,
) -> std::io::Result<()> {
    run_required_delivery_helper_command(&register_request(meta, paths, registration.helper))
}

pub(crate) fn reconcile_completion_delivery(
    paths: &StatePaths,
    meta: &mut Meta,
) -> std::io::Result<()> {
    let delivery_lock = DeliveryLockGuard::acquire(paths)?;
    let mut persisted = state::read_meta(paths)?;
    let mode = state::read_delivery_mode(paths)?;
    persisted.delivery_mode = mode;
    let lifecycle = persisted.delivery.lifecycle();
    if !lifecycle.permits_attempt() {
        *meta = persisted;
        return Ok(());
    }
    let retry_count = persisted.delivery.retry_count.saturating_add(u8::from(
        lifecycle == DeliveryLifecycle::RetryablePreAdmissionFailure,
    ));
    let request = match completion_request(
        persisted.caller_ppid,
        &persisted.handle,
        paths,
        consumed_before_delivery(paths),
        persisted.delivery_helper.as_ref(),
    ) {
        Ok(request) => request,
        Err(err) => {
            persisted.delivery = delivery_meta_from_helper_error(err, retry_count);
            persisted.touch();
            state::write_meta_atomic(paths, &persisted)?;
            *meta = persisted;
            return Ok(());
        }
    };
    let owner_result = run_delivery_owner_child_process_holding_lock(&delivery_lock, || {
        persisted.delivery = provisional_delivery_transfer_meta();
        persisted.touch();
        state::write_meta_atomic(paths, &persisted)?;
        persisted.delivery = match run_delivery_helper_command(&request) {
            Ok(status) => delivery_meta_from_status(status),
            Err(DeliveryHelperCommandError::NotStarted(err)) => {
                delivery_meta_from_launch_error(err, retry_count)
            }
            Err(DeliveryHelperCommandError::Admitted(err)) => delivery_meta_from_error(err),
        };
        persisted.touch();
        state::write_meta_atomic(paths, &persisted)
    });
    let mut observed = state::read_meta(paths)?;
    if let Err(err) = owner_result {
        observed.delivery = match observed.delivery.lifecycle() {
            DeliveryLifecycle::Unclaimed => delivery_meta_from_owner_launch_error(err, retry_count),
            DeliveryLifecycle::ProvisionalTransfer => {
                delivery_meta_from_unknown_transfer(err, retry_count)
            }
            _ => {
                *meta = observed;
                return Err(err);
            }
        };
        observed.touch();
        state::write_meta_atomic(paths, &observed)?;
    }
    *meta = observed;
    Ok(())
}

fn delivery_meta_from_unknown_transfer(err: io::Error, retry_count: u8) -> DeliveryMeta {
    DeliveryMeta {
        attempted: true,
        exit_code: None,
        error: Some(format!("delivery helper outcome is unknown: {err}")),
        error_code: Some("transfer_outcome_unknown".to_string()),
        retryable: Some(false),
        retry_count,
        skipped: None,
    }
}

pub(crate) fn detach(paths: &StatePaths) -> std::io::Result<DetachOutcome> {
    let delivery_lock = DeliveryLockGuard::acquire(paths)?;
    let mode = state::read_delivery_mode(paths)?;
    if mode == DeliveryMode::Async {
        require_settled_activation(paths)?;
        let meta = repair_delivery_mode_mirror(paths, DeliveryMode::Async)?;
        drop(delivery_lock);
        return Ok(detach_outcome(&meta, false, false));
    }

    let meta = state::read_meta(paths)?;
    let request = activate_request(&meta, paths).map_err(io::Error::other)?;
    let owner_result = run_delivery_owner_child_process_holding_lock(&delivery_lock, || {
        let claimed = state::record_activation_attempt(paths)?;
        if let Err(err) = state::write_delivery_mode_atomic(paths, DeliveryMode::Async) {
            if claimed {
                let _ = state::rollback_activation_attempt(paths);
            }
            return Err(err);
        }
        let result = if claimed {
            if let Err(err) = state::write_activation_outcome(paths, "pending\n") {
                state::rollback_activation_attempt(paths)?;
                state::remove_activation_outcome(paths)?;
                state::write_delivery_mode_atomic(paths, DeliveryMode::Sync)?;
                repair_delivery_mode_mirror(paths, DeliveryMode::Sync)?;
                return Err(err);
            }
            run_required_delivery_helper_command_detailed(&request)
        } else {
            require_settled_activation(paths)?;
            Ok(())
        };
        match result {
            Err(DeliveryHelperCommandError::NotStarted(err)) => {
                state::rollback_activation_attempt(paths)?;
                state::remove_activation_outcome(paths)?;
                state::write_delivery_mode_atomic(paths, DeliveryMode::Sync)?;
                repair_delivery_mode_mirror(paths, DeliveryMode::Sync)?;
                Err(err)
            }
            Err(DeliveryHelperCommandError::Admitted(err)) => {
                state::write_activation_outcome(paths, &format!("failed: {err}\n"))?;
                repair_delivery_mode_mirror(paths, DeliveryMode::Async)?;
                Err(err)
            }
            Ok(()) => {
                state::write_activation_outcome(paths, "succeeded\n")?;
                repair_delivery_mode_mirror(paths, DeliveryMode::Async)?;
                Ok(())
            }
        }
    });
    require_settled_activation(paths).and(owner_result)?;
    let meta = state::read_meta(paths)?;
    drop(delivery_lock);
    let terminal_activation_requests_notification = state::terminal(&meta);
    Ok(detach_outcome(
        &meta,
        true,
        terminal_activation_requests_notification,
    ))
}

pub(crate) fn require_settled_activation(paths: &StatePaths) -> io::Result<()> {
    match state::read_activation_outcome(paths)?.as_deref() {
        None if !paths.activation_attempted.exists() => Ok(()),
        None => Err(io::Error::other("delivery activation outcome is unknown")),
        Some("succeeded\n") => Ok(()),
        Some("pending\n") => Err(io::Error::other("delivery activation outcome is unknown")),
        Some(outcome) => Err(io::Error::other(outcome.trim().to_string())),
    }
}

pub(crate) fn settled_delivery_mode(paths: &StatePaths) -> io::Result<DeliveryMode> {
    let _delivery_lock = DeliveryLockGuard::acquire(paths)?;
    let mode = state::read_delivery_mode(paths)?;
    if mode == DeliveryMode::Async {
        require_settled_activation(paths)?;
    }
    Ok(mode)
}

// The operation runs only in the forked child. Durable files are its sole
// handback channel; mutations to captured values are not visible to the parent.
fn run_delivery_owner_child_process_holding_lock(
    _delivery_lock: &DeliveryLockGuard,
    child_operation: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        let code = if child_operation().is_ok() { 0 } else { 70 };
        unsafe { libc::_exit(code) };
    }
    wait_for_delivery_owner(pid)
}

fn wait_for_delivery_owner(pid: libc::pid_t) -> io::Result<()> {
    loop {
        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        if waited == pid {
            if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
                return Ok(());
            }
            return Err(io::Error::other("delivery owner failed"));
        }
        if waited < 0 {
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
    }
}

fn repair_delivery_mode_mirror(paths: &StatePaths, mode: DeliveryMode) -> io::Result<Meta> {
    let _completion_lock = state::lock_completion(paths)?;
    let mut meta = state::read_meta(paths)?;
    if meta.delivery_mode != mode {
        meta.delivery_mode = mode;
        meta.touch();
        state::write_meta_atomic(paths, &meta)?;
    }
    Ok(meta)
}

fn detach_outcome(
    meta: &Meta,
    transitioned: bool,
    terminal_activation_requests_notification: bool,
) -> DetachOutcome {
    DetachOutcome {
        handle: meta.handle.clone(),
        delivery_mode: meta.delivery_mode,
        state: meta.state.clone(),
        transitioned,
        terminal_activation_requests_notification,
    }
}

fn consumed_before_delivery(paths: &StatePaths) -> bool {
    if paths.consumed.exists() {
        return true;
    }
    let grace = consumer_grace();
    if grace.is_zero() {
        return false;
    }
    wait_for_consumed_marker(paths, grace)
}

fn consumer_grace() -> Duration {
    let millis = std::env::var(CONSUMER_GRACE_MS_ENV)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0)
        .min(MAX_CONSUMER_GRACE_MS);
    Duration::from_millis(millis)
}

fn wait_for_consumed_marker(paths: &StatePaths, grace: Duration) -> bool {
    let deadline = Instant::now() + grace;
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(CONSUMER_GRACE_POLL_MS));
        if paths.consumed.exists() {
            return true;
        }
    }
    false
}

struct DeliveryHelperRequest {
    helper: HandleBoundDeliveryHelper,
    args: Vec<OsString>,
    transient_environment: Vec<(OsString, OsString)>,
}

impl DeliveryHelperRequest {
    fn command(&self) -> Command {
        let mut command = self.helper.operation_command();
        command.args(&self.args).envs(
            self.transient_environment
                .iter()
                .map(|(name, value)| (name, value)),
        );
        command
    }
}

fn register_request(
    meta: &Meta,
    paths: &StatePaths,
    helper: HandleBoundDeliveryHelper,
) -> DeliveryHelperRequest {
    DeliveryHelperRequest {
        helper,
        args: register_args(meta, paths),
        transient_environment: env::var_os(COMPLETION_REGISTRATION_AUTHORITY_ENV)
            .map(|value| vec![(OsString::from(COMPLETION_REGISTRATION_AUTHORITY_ENV), value)])
            .unwrap_or_default(),
    }
}

fn activate_request(
    meta: &Meta,
    paths: &StatePaths,
) -> Result<DeliveryHelperRequest, DeliveryHelperError> {
    Ok(DeliveryHelperRequest {
        helper: HandleBoundDeliveryHelper::from_provenance(meta.delivery_helper.as_ref(), paths)?,
        args: activate_args(&meta.handle),
        transient_environment: Vec::new(),
    })
}

fn completion_request(
    caller_ppid: libc::pid_t,
    handle: &str,
    paths: &StatePaths,
    consumed: bool,
    provenance: Option<&DeliveryHelperProvenance>,
) -> Result<DeliveryHelperRequest, DeliveryHelperError> {
    Ok(DeliveryHelperRequest {
        helper: HandleBoundDeliveryHelper::from_provenance(provenance, paths)?,
        args: completion_args(caller_ppid, handle, paths, consumed),
        transient_environment: Vec::new(),
    })
}

fn register_args(meta: &Meta, paths: &StatePaths) -> Vec<OsString> {
    vec![
        OsString::from("notify"),
        OsString::from("agent-bash-register"),
        OsString::from("--handle"),
        OsString::from(&meta.handle),
        OsString::from("--delivery-mode"),
        OsString::from(meta.delivery_mode.as_str()),
        OsString::from("--state-dir"),
        path_arg(&paths.state_dir),
        OsString::from("--meta"),
        path_arg(&paths.meta),
        OsString::from("--log"),
        path_arg(&paths.log),
        OsString::from("--rc"),
        path_arg(&paths.rc),
    ]
}

fn activate_args(handle: &str) -> Vec<OsString> {
    vec![
        OsString::from("notify"),
        OsString::from("agent-bash-activate"),
        OsString::from("--handle"),
        OsString::from(handle),
    ]
}

fn completion_args(
    caller_ppid: libc::pid_t,
    handle: &str,
    paths: &StatePaths,
    consumed: bool,
) -> Vec<OsString> {
    let mut args = vec![
        OsString::from("notify"),
        OsString::from("agent-bash-complete"),
        OsString::from("--caller-ppid"),
        OsString::from(caller_ppid.to_string()),
        OsString::from("--handle"),
        OsString::from(handle),
        OsString::from("--state-dir"),
        path_arg(&paths.state_dir),
        OsString::from("--meta"),
        path_arg(&paths.meta),
        OsString::from("--log"),
        path_arg(&paths.log),
        OsString::from("--rc"),
        path_arg(&paths.rc),
    ];
    if consumed {
        args.push(OsString::from("--consumed"));
    }
    args
}

fn path_arg(path: &Path) -> OsString {
    path.as_os_str().to_os_string()
}

enum DeliveryHelperCommandError {
    NotStarted(io::Error),
    Admitted(io::Error),
}

impl DeliveryHelperCommandError {
    fn into_io_error(self) -> io::Error {
        match self {
            Self::NotStarted(err) | Self::Admitted(err) => err,
        }
    }
}

fn run_delivery_helper_command(
    request: &DeliveryHelperRequest,
) -> Result<ExitStatus, DeliveryHelperCommandError> {
    let mut child = request
        .command()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(DeliveryHelperCommandError::NotStarted)?;
    child.wait().map_err(DeliveryHelperCommandError::Admitted)
}

fn run_required_delivery_helper_command(request: &DeliveryHelperRequest) -> std::io::Result<()> {
    run_required_delivery_helper_command_detailed(request)
        .map_err(DeliveryHelperCommandError::into_io_error)
}

fn run_required_delivery_helper_command_detailed(
    request: &DeliveryHelperRequest,
) -> Result<(), DeliveryHelperCommandError> {
    let child = request
        .command()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(DeliveryHelperCommandError::NotStarted)?;
    let output = child
        .wait_with_output()
        .map_err(DeliveryHelperCommandError::Admitted)?;
    if output.status.success() {
        return Ok(());
    }
    let detail = command_failure_detail(&output.stderr, &output.stdout);
    Err(DeliveryHelperCommandError::Admitted(std::io::Error::other(
        format!(
            "delivery helper exited with {}{}",
            output
                .status
                .code()
                .map_or_else(|| "no exit code".to_string(), |code| code.to_string()),
            detail
                .as_deref()
                .map_or_else(String::new, |detail| format!(": {detail}"))
        ),
    )))
}

fn command_failure_detail(stderr: &[u8], stdout: &[u8]) -> Option<String> {
    [stderr, stdout].into_iter().find_map(|bytes| {
        let detail = String::from_utf8_lossy(bytes).trim().to_string();
        (!detail.is_empty()).then_some(detail)
    })
}

fn delivery_meta_from_status(status: ExitStatus) -> DeliveryMeta {
    let mut meta = admitted_delivery_meta();
    if let Some(code) = status.code() {
        meta.exit_code = Some(code);
        return meta;
    }
    meta.error = Some(delivery_signal_error(status));
    meta
}

fn delivery_meta_from_error(err: std::io::Error) -> DeliveryMeta {
    let mut meta = admitted_delivery_meta();
    meta.error = Some(err.to_string());
    meta
}

fn delivery_meta_from_launch_error(err: io::Error, retry_count: u8) -> DeliveryMeta {
    DeliveryMeta {
        attempted: false,
        exit_code: None,
        error: Some(err.to_string()),
        error_code: Some("delivery_helper_launch_failed".to_string()),
        retryable: Some(retry_count == 0),
        retry_count,
        skipped: None,
    }
}

fn delivery_meta_from_owner_launch_error(err: io::Error, retry_count: u8) -> DeliveryMeta {
    DeliveryMeta {
        attempted: false,
        exit_code: None,
        error: Some(err.to_string()),
        error_code: Some("delivery_owner_launch_failed".to_string()),
        retryable: Some(retry_count == 0),
        retry_count,
        skipped: None,
    }
}

fn delivery_meta_from_helper_error(err: DeliveryHelperError, retry_count: u8) -> DeliveryMeta {
    DeliveryMeta {
        attempted: false,
        exit_code: None,
        error: Some(err.to_string()),
        error_code: Some(err.code.to_string()),
        retryable: Some(err.retryable && retry_count == 0),
        retry_count,
        skipped: None,
    }
}

fn admitted_delivery_meta() -> DeliveryMeta {
    DeliveryMeta {
        attempted: true,
        exit_code: None,
        error: None,
        error_code: None,
        retryable: None,
        retry_count: 0,
        skipped: None,
    }
}

fn provisional_delivery_transfer_meta() -> DeliveryMeta {
    DeliveryMeta {
        attempted: true,
        exit_code: None,
        error: Some(
            "delivery helper outcome is unknown until the admitted attempt exits".to_string(),
        ),
        error_code: Some(state::DELIVERY_ATTEMPT_IN_PROGRESS.to_string()),
        retryable: Some(false),
        retry_count: 0,
        skipped: None,
    }
}

pub(crate) fn completion_delivery_pending(meta: &Meta) -> bool {
    state::terminal(meta) && meta.delivery.lifecycle().needs_progress()
}

fn delivery_signal_error(status: ExitStatus) -> String {
    if let Some(signal) = status.signal() {
        return format!("terminated by signal {signal}");
    }
    "terminated without exit status".to_string()
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;

    #[test]
    fn changed_registered_helper_is_rejected_before_execution() {
        let temp = tempfile::tempdir().expect("tempdir");
        let helper_path = temp.path().join("helper");
        fs::write(&helper_path, "#!/bin/sh\nexit 0\n").expect("write helper");
        let mut permissions = fs::metadata(&helper_path)
            .expect("helper metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&helper_path, permissions).expect("make helper executable");
        let retained = temp.path().join("retained-helper");
        fs::rename(&helper_path, &retained).expect("retain original helper");
        fs::write(&helper_path, "#!/bin/sh\nexit 99\n").expect("write replacement helper");
        let mut permissions = fs::metadata(&helper_path)
            .expect("replacement metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&helper_path, permissions).expect("make replacement executable");

        let paths = StatePaths::new(temp.path().to_path_buf(), "ab_helper_change".to_string());
        state::create_handle_state(&paths).expect("create state");
        fs::hard_link(&retained, &paths.delivery_helper).expect("pin retained helper");
        let snapshot = fs::canonicalize(&paths.delivery_helper).expect("snapshot path");
        let snapshot_metadata = fs::metadata(&snapshot).expect("snapshot metadata");
        let (_, sha256) = sealed_execution_image(&File::open(&snapshot).expect("open snapshot"))
            .expect("snapshot digest");
        let provenance = provenance_from_metadata(
            snapshot.to_string_lossy().into_owned(),
            &snapshot_metadata,
            sha256,
            BTreeMap::new(),
            None,
        );
        let mut permissions = fs::metadata(&paths.delivery_helper)
            .expect("snapshot metadata")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&paths.delivery_helper, permissions).expect("make snapshot writable");
        fs::write(&paths.delivery_helper, "#!/bin/sh\nexit 9\n").expect("change snapshot");
        let mut permissions = fs::metadata(&paths.delivery_helper)
            .expect("changed snapshot metadata")
            .permissions();
        permissions.set_mode(provenance.mode & 0o7777);
        fs::set_permissions(&paths.delivery_helper, permissions).expect("restore snapshot mode");
        let modified = UNIX_EPOCH
            + Duration::new(
                u64::try_from(provenance.modified_seconds).expect("nonnegative mtime"),
                u32::try_from(provenance.modified_nanoseconds).expect("mtime nanos"),
            );
        File::options()
            .write(true)
            .open(&paths.delivery_helper)
            .expect("open changed snapshot")
            .set_times(fs::FileTimes::new().set_modified(modified))
            .expect("restore snapshot mtime");

        let err = HandleBoundDeliveryHelper::from_provenance(Some(&provenance), &paths)
            .expect_err("replacement must fail closed");
        assert_eq!(err.code, DELIVERY_HELPER_CHANGED);
        assert!(err.detail.contains("contents changed"), "{}", err.detail);
    }
}
