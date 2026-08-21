use std::env;
use std::ffi::OsStr;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

const SCHEMA_VERSION: u8 = 1;
const DEFAULT_STATE_TTL_SECS: u64 = 48 * 60 * 60;
const DEFAULT_REAP_MAX_DIRS: usize = 128;
const DEFAULT_REAP_MAX_SCAN: usize = 4096;
const DEFAULT_REAP_SHARDS: usize = 16;
const PENDING_DELIVERY_GRACE_MULTIPLIER: u64 = 7;
const REAP_SHARD_CURSOR_FILE: &str = ".reap-shard";
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub(crate) struct StatePaths {
    pub(crate) root: PathBuf,
    pub(crate) handle: String,
    pub(crate) state_dir: PathBuf,
    pub(crate) log: PathBuf,
    pub(crate) rc: PathBuf,
    pub(crate) meta: PathBuf,
    pub(crate) owner: PathBuf,
    pub(crate) consumed: PathBuf,
    pub(crate) delivery_mode: PathBuf,
    pub(crate) delivery_lock: PathBuf,
    pub(crate) cancel_requested: PathBuf,
    pub(crate) completion_lock: PathBuf,
    pub(crate) reconciliation_lock: PathBuf,
}

impl StatePaths {
    pub(crate) fn new(root: PathBuf, handle: String) -> Self {
        let state_dir = root.join(&handle);
        Self {
            root,
            handle,
            log: state_dir.join("log"),
            rc: state_dir.join("rc"),
            meta: state_dir.join("meta.json"),
            owner: state_dir.join("owner.json"),
            consumed: state_dir.join("consumed"),
            delivery_mode: state_dir.join("delivery-mode"),
            delivery_lock: state_dir.join("delivery.lock"),
            cancel_requested: state_dir.join("cancel-requested"),
            completion_lock: state_dir.join("completion.lock"),
            reconciliation_lock: state_dir.join("reconciliation.lock"),
            state_dir,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DeliveryMode {
    Sync,
    #[default]
    Async,
}

impl DeliveryMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Sync => "sync",
            Self::Async => "async",
        }
    }

    fn parse(value: &str) -> io::Result<Self> {
        match value.trim() {
            "sync" => Ok(Self::Sync),
            "async" => Ok(Self::Async),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid delivery mode",
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DeliveryHelperProvenance {
    pub(crate) schema_version: u8,
    pub(crate) path: String,
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) size: u64,
    pub(crate) modified_seconds: i64,
    pub(crate) modified_nanoseconds: i64,
    pub(crate) mode: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CallerChainEntry {
    pub(crate) pid: libc::pid_t,
    pub(crate) starttime_ticks: u64,
    pub(crate) boot_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OwnerMeta {
    pub(crate) owner_session_id: Option<String>,
    pub(crate) owner_invocation_uuid: Option<String>,
}

impl OwnerMeta {
    pub(crate) fn from_meta(meta: &Meta) -> Self {
        Self {
            owner_session_id: meta.owner_session_id.clone(),
            owner_invocation_uuid: meta.owner_invocation_uuid.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct DeliveryMeta {
    pub(crate) attempted: bool,
    pub(crate) exit_code: Option<i32>,
    pub(crate) error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) retryable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) skipped: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CgroupMeta {
    pub(crate) mode: String,
    pub(crate) path: Option<String>,
    pub(crate) delegated: bool,
    pub(crate) events_watch: bool,
    pub(crate) degraded_reason: Option<String>,
}

impl CgroupMeta {
    pub(crate) fn subreaper_only() -> Self {
        Self {
            mode: "subreaper-only".to_string(),
            path: None,
            delegated: false,
            events_watch: false,
            degraded_reason: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Meta {
    pub(crate) schema_version: u8,
    pub(crate) handle: String,
    pub(crate) created_at_unix_ms: u64,
    pub(crate) updated_at_unix_ms: u64,
    pub(crate) state: String,
    pub(crate) completion_reason: Option<String>,
    pub(crate) caller_ppid: libc::pid_t,
    pub(crate) caller_chain: Vec<CallerChainEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cancel_owner: Option<CallerChainEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) owner_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) owner_invocation_uuid: Option<String>,
    pub(crate) launcher_pid: libc::pid_t,
    pub(crate) supervisor_pid: Option<libc::pid_t>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) supervisor_pid_starttime_ticks: Option<u64>,
    pub(crate) workload_pid: Option<libc::pid_t>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) workload_pid_starttime_ticks: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) process_boot_id: Option<String>,
    pub(crate) workload_pgid: Option<libc::pid_t>,
    pub(crate) workload_pidfd: bool,
    pub(crate) argv: Vec<String>,
    pub(crate) cwd: String,
    pub(crate) mode: String,
    #[serde(default)]
    pub(crate) delivery_mode: DeliveryMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) delivery_helper: Option<DeliveryHelperProvenance>,
    pub(crate) ready_sentinel: Option<String>,
    pub(crate) ready_at_unix_ms: Option<u64>,
    pub(crate) completed_at_unix_ms: Option<u64>,
    pub(crate) rc: Option<i32>,
    pub(crate) signal: Option<i32>,
    pub(crate) workload_rc: Option<i32>,
    pub(crate) workload_signal: Option<i32>,
    pub(crate) delivery: DeliveryMeta,
    pub(crate) cgroup: CgroupMeta,
    pub(crate) error: Option<String>,
}

impl Meta {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        handle: String,
        caller_ppid: libc::pid_t,
        launcher_pid: libc::pid_t,
        argv: Vec<String>,
        cwd: PathBuf,
        mode: &str,
        delivery_mode: DeliveryMode,
        ready_sentinel: Option<String>,
        caller_chain: Vec<CallerChainEntry>,
        cancel_owner: Option<CallerChainEntry>,
    ) -> Self {
        let now = unix_ms();
        Self {
            schema_version: SCHEMA_VERSION,
            handle,
            created_at_unix_ms: now,
            updated_at_unix_ms: now,
            state: "RUNNING".to_string(),
            completion_reason: None,
            caller_ppid,
            caller_chain,
            cancel_owner,
            owner_session_id: None,
            owner_invocation_uuid: None,
            launcher_pid,
            supervisor_pid: None,
            supervisor_pid_starttime_ticks: None,
            workload_pid: None,
            workload_pid_starttime_ticks: None,
            process_boot_id: None,
            workload_pgid: None,
            workload_pidfd: false,
            argv,
            cwd: cwd.display().to_string(),
            mode: mode.to_string(),
            delivery_mode,
            delivery_helper: None,
            ready_sentinel,
            ready_at_unix_ms: None,
            completed_at_unix_ms: None,
            rc: None,
            signal: None,
            workload_rc: None,
            workload_signal: None,
            delivery: DeliveryMeta::default(),
            cgroup: CgroupMeta::subreaper_only(),
            error: None,
        }
    }

    pub(crate) fn touch(&mut self) {
        self.updated_at_unix_ms = unix_ms();
    }

    pub(crate) fn with_owner_context(
        mut self,
        session_id: Option<String>,
        invocation_uuid: Option<String>,
    ) -> Self {
        self.owner_session_id = session_id;
        self.owner_invocation_uuid = invocation_uuid;
        self
    }

    pub(crate) fn with_delivery_helper(mut self, helper: DeliveryHelperProvenance) -> Self {
        self.delivery_helper = Some(helper);
        self
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct RunOutput {
    schema_version: u8,
    handle: String,
    state_dir: PathBuf,
    log: PathBuf,
    rc: PathBuf,
    meta: PathBuf,
    caller_ppid: libc::pid_t,
    mode: String,
    delivery_mode: DeliveryMode,
    ready_sentinel: Option<String>,
}

impl RunOutput {
    pub(crate) fn new(
        paths: StatePaths,
        caller_ppid: libc::pid_t,
        mode: &str,
        delivery_mode: DeliveryMode,
        ready_sentinel: Option<String>,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            handle: paths.handle,
            state_dir: paths.state_dir,
            log: paths.log,
            rc: paths.rc,
            meta: paths.meta,
            caller_ppid,
            mode: mode.to_string(),
            delivery_mode,
            ready_sentinel,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct ListSummary {
    pub(crate) handle: String,
    pub(crate) state: String,
    pub(crate) rc: Option<i32>,
    pub(crate) mode: String,
    pub(crate) delivery_mode: DeliveryMode,
    pub(crate) created_at_unix_ms: u64,
    pub(crate) state_dir: PathBuf,
}

impl ListSummary {
    pub(crate) fn from_meta(meta: &Meta, state_dir: PathBuf) -> Self {
        Self {
            handle: meta.handle.clone(),
            state: meta.state.clone(),
            rc: meta.rc,
            mode: meta.mode.clone(),
            delivery_mode: meta.delivery_mode,
            created_at_unix_ms: meta.created_at_unix_ms,
            state_dir,
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum StateError {
    #[error("HOME is not set and XDG_STATE_HOME is not set")]
    MissingHome,
    #[error("getrandom failed: {0}")]
    GetRandom(io::Error),
}

enum StateRootEnv<'a> {
    Xdg(&'a OsStr),
    Home(&'a OsStr),
}

pub(crate) fn unix_ms() -> u64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    u64::try_from(millis).unwrap_or(u64::MAX)
}

pub(crate) fn state_root() -> Result<PathBuf, StateError> {
    state_root_from_env_values(env::var_os("XDG_STATE_HOME"), env::var_os("HOME"))
}

pub(crate) fn state_root_from_env_values(
    xdg_state_home: Option<impl AsRef<OsStr>>,
    home: Option<impl AsRef<OsStr>>,
) -> Result<PathBuf, StateError> {
    let xdg = xdg_state_home.as_ref().map(|value| value.as_ref());
    let home = home.as_ref().map(|value| value.as_ref());
    let selected = select_state_root_env(xdg, home)?;
    Ok(state_root_path(selected))
}

fn select_state_root_env<'a>(
    xdg_state_home: Option<&'a OsStr>,
    home: Option<&'a OsStr>,
) -> Result<StateRootEnv<'a>, StateError> {
    if let Some(xdg) = non_empty_env_value(xdg_state_home) {
        return Ok(StateRootEnv::Xdg(xdg));
    }
    if let Some(home) = non_empty_env_value(home) {
        return Ok(StateRootEnv::Home(home));
    }
    Err(StateError::MissingHome)
}

fn non_empty_env_value(value: Option<&OsStr>) -> Option<&OsStr> {
    value.filter(|value| !value.is_empty())
}

fn state_root_path(env: StateRootEnv<'_>) -> PathBuf {
    match env {
        StateRootEnv::Xdg(xdg) => PathBuf::from(xdg).join("agent-bash"),
        StateRootEnv::Home(home) => PathBuf::from(home).join(".local/state/agent-bash"),
    }
}

pub(crate) fn generate_handle() -> Result<String, StateError> {
    let mut random = [0_u8; 8];
    fill_getrandom(&mut random)?;
    let random = u64::from_ne_bytes(random);
    Ok(format!(
        "ab_{:x}_{}_{:016x}",
        unix_ms(),
        unsafe { libc::getpid() },
        random
    ))
}

fn fill_getrandom(buf: &mut [u8]) -> Result<(), StateError> {
    let mut filled = 0;
    while filled < buf.len() {
        let rc = unsafe {
            libc::getrandom(
                buf[filled..].as_mut_ptr().cast::<libc::c_void>(),
                buf.len() - filled,
                0,
            )
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(StateError::GetRandom(err));
        }
        filled += usize::try_from(rc).unwrap_or(0);
    }
    Ok(())
}

pub(crate) fn create_handle_state(paths: &StatePaths) -> io::Result<()> {
    fs::create_dir_all(&paths.root)?;
    fs::set_permissions(&paths.root, fs::Permissions::from_mode(0o700))?;
    DirBuilder::new().mode(0o700).create(&paths.state_dir)
}

pub(crate) fn create_log(paths: &StatePaths) -> io::Result<File> {
    OpenOptions::new()
        .create_new(true)
        .append(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .mode(0o600)
        .open(&paths.log)
}

pub(crate) fn open_log_append(paths: &StatePaths) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .mode(0o600)
        .open(&paths.log)
}

pub(crate) fn lock_reconciliation(paths: &StatePaths) -> io::Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .mode(0o600)
        .open(&paths.reconciliation_lock)?;
    lock_file_exclusive(&file)?;
    Ok(file)
}

pub(crate) fn lock_delivery(paths: &StatePaths) -> io::Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .mode(0o600)
        .open(&paths.delivery_lock)?;
    lock_file_exclusive(&file)?;
    Ok(file)
}

pub(crate) fn lock_completion(paths: &StatePaths) -> io::Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .mode(0o600)
        .open(&paths.completion_lock)?;
    lock_file_exclusive(&file)?;
    Ok(file)
}

pub(crate) fn create_cancel_request(paths: &StatePaths) -> io::Result<bool> {
    match OpenOptions::new()
        .create_new(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .mode(0o600)
        .open(&paths.cancel_requested)
    {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(err) => Err(err),
    }
}

pub(crate) fn remove_cancel_request(paths: &StatePaths) -> io::Result<()> {
    match fs::remove_file(&paths.cancel_requested) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

fn lock_file_exclusive(file: &File) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    loop {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ReapConfig {
    ttl_secs: u64,
    max_dirs: usize,
    max_scan: usize,
    shards: usize,
    now_unix_ms: u64,
}

impl ReapConfig {
    pub(crate) fn from_env() -> Self {
        Self {
            ttl_secs: env_u64("AGENT_BASH_STATE_TTL_SECS", DEFAULT_STATE_TTL_SECS),
            max_dirs: env_usize("AGENT_BASH_STATE_REAP_MAX_DIRS", DEFAULT_REAP_MAX_DIRS),
            max_scan: env_usize("AGENT_BASH_STATE_REAP_MAX_SCAN", DEFAULT_REAP_MAX_SCAN),
            shards: env_usize("AGENT_BASH_STATE_REAP_SHARDS", DEFAULT_REAP_SHARDS).max(1),
            now_unix_ms: unix_ms(),
        }
    }

    fn ttl_ms(self) -> u64 {
        secs_to_ms(self.ttl_secs)
    }

    fn pending_delivery_moot_ms(self) -> u64 {
        secs_to_ms(
            self.ttl_secs
                .saturating_mul(PENDING_DELIVERY_GRACE_MULTIPLIER),
        )
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct ReapStats {
    pub(crate) scanned: usize,
    pub(crate) reaped: usize,
    pub(crate) errors: usize,
}

pub(crate) fn reap_state_dirs(root: &Path, config: ReapConfig) -> ReapStats {
    let mut stats = ReapStats::default();
    if config.max_dirs == 0 || config.max_scan == 0 {
        return stats;
    }
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return stats,
        Err(_) => {
            stats.errors += 1;
            return stats;
        }
    };
    let shard = next_reap_shard(root, config.shards);
    let boot_id = read_boot_id();
    for entry in entries {
        if reap_limits_reached(&stats, config) {
            break;
        }
        let Ok(entry) = entry else {
            stats.errors += 1;
            continue;
        };
        if !reap_entry_is_handle_dir(&entry)
            || handle_reap_shard(&entry.file_name(), config.shards) != shard
        {
            continue;
        }
        stats.scanned += 1;
        reap_state_entry(root, entry, config, &boot_id, &mut stats);
    }
    stats
}

fn next_reap_shard(root: &Path, shards: usize) -> usize {
    if shards <= 1 {
        return 0;
    }
    let path = root.join(REAP_SHARD_CURSOR_FILE);
    let current = fs::read_to_string(&path)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0)
        % shards;
    let _ = fs::write(path, format!("{}\n", (current + 1) % shards));
    current
}

fn handle_reap_shard(name: &OsStr, shards: usize) -> usize {
    name.as_encoded_bytes()
        .iter()
        .fold(2_166_136_261_usize, |hash, byte| {
            hash.wrapping_mul(16_777_619) ^ usize::from(*byte)
        })
        % shards.max(1)
}

fn reap_limits_reached(stats: &ReapStats, config: ReapConfig) -> bool {
    stats.scanned >= config.max_scan || stats.reaped >= config.max_dirs
}

fn reap_state_entry(
    root: &Path,
    entry: fs::DirEntry,
    config: ReapConfig,
    boot_id: &str,
    stats: &mut ReapStats,
) {
    let paths = StatePaths::new(
        root.to_path_buf(),
        entry.file_name().to_string_lossy().into_owned(),
    );
    if !state_dir_reap_eligible(&paths, config, boot_id) {
        return;
    }
    match fs::remove_dir_all(&paths.state_dir) {
        Ok(()) => stats.reaped += 1,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(_) => stats.errors += 1,
    }
}

fn reap_entry_is_handle_dir(entry: &fs::DirEntry) -> bool {
    entry.file_type().map(|ty| ty.is_dir()).unwrap_or(false)
        && entry.file_name().to_string_lossy().starts_with("ab_")
}

fn state_dir_reap_eligible(paths: &StatePaths, config: ReapConfig, boot_id: &str) -> bool {
    let Ok(meta) = read_meta(paths) else {
        return false;
    };
    let age_ms = state_dir_reap_age_ms(paths, &meta, config.now_unix_ms);
    if age_ms < config.ttl_ms() {
        return false;
    }
    if meta_is_reap_terminal(&meta, boot_id) {
        return delivery_is_settled(paths, &meta) || age_ms >= config.pending_delivery_moot_ms();
    }
    meta.state == "RUNNING" && meta_processes_are_gone_or_reused(&meta, boot_id)
}

fn delivery_is_settled(paths: &StatePaths, meta: &Meta) -> bool {
    paths.consumed.exists()
        || (meta.delivery.attempted && meta.delivery.exit_code == Some(0))
        || meta.delivery.skipped.as_deref() == Some("sync_in_band")
}

fn meta_is_reap_terminal(meta: &Meta, boot_id: &str) -> bool {
    matches!(meta.state.as_str(), "DONE" | "ERROR")
        && meta.completed_at_unix_ms.is_some()
        && !ready_sentinel_workload_may_be_running(meta, boot_id)
}

fn ready_sentinel_workload_may_be_running(meta: &Meta, boot_id: &str) -> bool {
    if meta.completion_reason.as_deref() != Some("ready-sentinel")
        || meta.workload_rc.is_some()
        || meta.workload_signal.is_some()
    {
        return false;
    }
    !matches!(
        inspect_process_identity(
            meta.workload_pid,
            meta.workload_pid_starttime_ticks,
            meta.process_boot_id.as_deref(),
            boot_id,
        ),
        ProcessIdentityEvidence::Gone | ProcessIdentityEvidence::Mismatch
    )
}

fn meta_processes_are_gone_or_reused(meta: &Meta, boot_id: &str) -> bool {
    process_is_gone_or_reused(
        meta.supervisor_pid,
        meta.supervisor_pid_starttime_ticks,
        meta.process_boot_id.as_deref(),
        boot_id,
    ) && process_is_gone_or_reused(
        meta.workload_pid,
        meta.workload_pid_starttime_ticks,
        meta.process_boot_id.as_deref(),
        boot_id,
    )
}

fn process_is_gone_or_reused(
    pid: Option<libc::pid_t>,
    starttime_ticks: Option<u64>,
    process_boot_id: Option<&str>,
    current_boot_id: &str,
) -> bool {
    matches!(
        inspect_process_identity(pid, starttime_ticks, process_boot_id, current_boot_id),
        ProcessIdentityEvidence::Gone | ProcessIdentityEvidence::Mismatch
    )
}

fn state_dir_reap_age_ms(paths: &StatePaths, meta: &Meta, now_unix_ms: u64) -> u64 {
    let reference = meta
        .completed_at_unix_ms
        .unwrap_or(0)
        .max(meta.updated_at_unix_ms);
    if reference > 0 {
        return now_unix_ms.saturating_sub(reference);
    }
    dir_mtime_unix_ms(&paths.state_dir)
        .map(|mtime| now_unix_ms.saturating_sub(mtime))
        .unwrap_or(0)
}

fn dir_mtime_unix_ms(path: &Path) -> Option<u64> {
    let modified = fs::metadata(path).ok()?.modified().ok()?;
    let millis = modified.duration_since(UNIX_EPOCH).ok()?.as_millis();
    u64::try_from(millis).ok()
}

fn secs_to_ms(secs: u64) -> u64 {
    secs.saturating_mul(1000)
}

fn env_u64(name: &str, default: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default)
}

fn env_usize(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}

pub(crate) fn open_read_no_follow(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

pub(crate) fn write_meta_atomic(paths: &StatePaths, meta: &Meta) -> io::Result<()> {
    let mut persisted = meta.clone();
    if let Ok(delivery_mode) = read_delivery_mode(paths) {
        persisted.delivery_mode = delivery_mode;
    }
    let bytes = format_meta_bytes(&persisted)?;
    atomic_write(&paths.meta, &bytes)
}

pub(crate) fn write_owner_atomic(paths: &StatePaths, owner: &OwnerMeta) -> io::Result<()> {
    let mut bytes = serde_json::to_vec_pretty(owner).map_err(io::Error::other)?;
    bytes.push(b'\n');
    atomic_write(&paths.owner, &bytes)
}

pub(crate) fn read_owner(paths: &StatePaths) -> io::Result<OwnerMeta> {
    let bytes = read_file_bytes(&paths.owner)?;
    serde_json::from_slice(&bytes).map_err(io::Error::other)
}

pub(crate) fn write_delivery_mode_atomic(
    paths: &StatePaths,
    delivery_mode: DeliveryMode,
) -> io::Result<()> {
    atomic_write(&paths.delivery_mode, delivery_mode.as_str().as_bytes())
}

pub(crate) fn read_delivery_mode(paths: &StatePaths) -> io::Result<DeliveryMode> {
    match read_file_text(&paths.delivery_mode) {
        Ok(value) => DeliveryMode::parse(&value),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(DeliveryMode::Async),
        Err(err) => Err(err),
    }
}

pub(crate) fn read_meta(paths: &StatePaths) -> io::Result<Meta> {
    let bytes = read_meta_bytes(paths)?;
    parse_meta_bytes(&bytes)
}

pub(crate) fn write_rc_atomic(paths: &StatePaths, rc: i32) -> io::Result<()> {
    let bytes = format_rc_bytes(rc);
    atomic_write(&paths.rc, &bytes)
}

pub(crate) fn read_rc(paths: &StatePaths) -> io::Result<i32> {
    let contents = read_rc_text(paths)?;
    parse_rc_text(&contents)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = atomic_parent(path)?;
    let file_name = atomic_file_name(path)?;
    let tmp = atomic_temp_path(parent, file_name);
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn format_meta_bytes(meta: &Meta) -> io::Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(meta).map_err(io::Error::other)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn read_meta_bytes(paths: &StatePaths) -> io::Result<Vec<u8>> {
    read_file_bytes(&paths.meta)
}

fn parse_meta_bytes(bytes: &[u8]) -> io::Result<Meta> {
    serde_json::from_slice(bytes).map_err(io::Error::other)
}

fn format_rc_bytes(rc: i32) -> Vec<u8> {
    format!("{rc}\n").into_bytes()
}

fn read_rc_text(paths: &StatePaths) -> io::Result<String> {
    read_file_text(&paths.rc)
}

fn parse_rc_text(contents: &str) -> io::Result<i32> {
    contents
        .trim_end_matches('\n')
        .parse::<i32>()
        .map_err(io::Error::other)
}

fn read_file_bytes(path: &Path) -> io::Result<Vec<u8>> {
    let mut file = open_read_no_follow(path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn read_file_text(path: &Path) -> io::Result<String> {
    let mut file = open_read_no_follow(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

fn atomic_parent(path: &Path) -> io::Result<&Path> {
    path.parent()
        .ok_or_else(|| io::Error::other("path has no parent"))
}

fn atomic_file_name(path: &Path) -> io::Result<&OsStr> {
    path.file_name()
        .ok_or_else(|| io::Error::other("path has no file name"))
}

fn atomic_temp_path(parent: &Path, file_name: &OsStr) -> PathBuf {
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    parent.join(format!(
        ".{}.tmp.{}.{}",
        file_name.to_string_lossy(),
        unsafe { libc::getpid() },
        counter
    ))
}

#[derive(Debug)]
struct ProcStat {
    ppid: libc::pid_t,
    starttime_ticks: u64,
}

pub(crate) fn capture_caller_chain(start_pid: libc::pid_t) -> Vec<CallerChainEntry> {
    let boot_id = read_boot_id();
    let mut chain = Vec::new();
    let mut pid = start_pid;
    for _ in 0..128 {
        if invalid_caller_chain_pid(pid) {
            break;
        }
        let Some(stat) = read_proc_stat(pid) else {
            break;
        };
        chain.push(caller_chain_entry_from_proc_stat(pid, &stat, &boot_id));
        if terminal_caller_chain_pid(pid) {
            break;
        }
        pid = stat.ppid;
    }
    chain
}

fn invalid_caller_chain_pid(pid: libc::pid_t) -> bool {
    pid <= 0
}

fn terminal_caller_chain_pid(pid: libc::pid_t) -> bool {
    pid == 1
}

fn read_proc_stat(pid: libc::pid_t) -> Option<ProcStat> {
    read_proc_stat_result(pid).ok()
}

fn read_proc_stat_result(pid: libc::pid_t) -> io::Result<ProcStat> {
    let contents = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    parse_proc_stat(&contents)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid /proc stat"))
}

fn read_boot_id() -> String {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|value| value.trim().to_string())
        .unwrap_or_default()
}

pub(crate) fn current_boot_id() -> String {
    read_boot_id()
}

pub(crate) fn process_starttime_ticks(pid: libc::pid_t) -> Option<u64> {
    read_proc_stat(pid).map(|stat| stat.starttime_ticks)
}

pub(crate) fn process_parent_pid(pid: libc::pid_t) -> Option<libc::pid_t> {
    read_proc_stat(pid).map(|stat| stat.ppid)
}

pub(crate) fn process_identity_is_live(identity: &CallerChainEntry) -> bool {
    let current_boot_id = read_boot_id();
    matches!(
        inspect_process_identity(
            Some(identity.pid),
            Some(identity.starttime_ticks),
            Some(identity.boot_id.as_str()),
            &current_boot_id,
        ),
        ProcessIdentityEvidence::Live
    )
}

pub(crate) fn running_exit_mode(meta: &Meta) -> bool {
    meta.state == "RUNNING" && meta.mode == "exit"
}

pub(crate) fn terminal(meta: &Meta) -> bool {
    matches!(meta.state.as_str(), "DONE" | "ERROR") && meta.completed_at_unix_ms.is_some()
}

pub(crate) fn exact_supervisor_and_workload_are_gone(meta: &Meta) -> bool {
    if !running_exit_mode(meta) {
        return false;
    }
    let current_boot_id = read_boot_id();
    if current_boot_id.is_empty() {
        return false;
    }
    matches!(
        inspect_process_identity(
            meta.supervisor_pid,
            meta.supervisor_pid_starttime_ticks,
            meta.process_boot_id.as_deref(),
            &current_boot_id,
        ),
        ProcessIdentityEvidence::Gone
    ) && matches!(
        inspect_process_identity(
            meta.workload_pid,
            meta.workload_pid_starttime_ticks,
            meta.process_boot_id.as_deref(),
            &current_boot_id,
        ),
        ProcessIdentityEvidence::Gone
    )
}

enum ProcessIdentityEvidence {
    Live,
    Gone,
    Mismatch,
    Unavailable,
}

fn inspect_process_identity(
    pid: Option<libc::pid_t>,
    expected_starttime_ticks: Option<u64>,
    expected_boot_id: Option<&str>,
    current_boot_id: &str,
) -> ProcessIdentityEvidence {
    let (Some(pid), Some(expected_starttime_ticks), Some(expected_boot_id)) =
        (pid, expected_starttime_ticks, expected_boot_id)
    else {
        return ProcessIdentityEvidence::Unavailable;
    };
    if pid <= 1 || expected_starttime_ticks == 0 || expected_boot_id.is_empty() {
        return ProcessIdentityEvidence::Unavailable;
    }
    if expected_boot_id != current_boot_id {
        return ProcessIdentityEvidence::Mismatch;
    }
    match read_proc_stat_result(pid) {
        Ok(actual) if actual.starttime_ticks == expected_starttime_ticks => {
            ProcessIdentityEvidence::Live
        }
        Ok(_) => ProcessIdentityEvidence::Mismatch,
        Err(err) if err.kind() == io::ErrorKind::NotFound => ProcessIdentityEvidence::Gone,
        Err(_) => ProcessIdentityEvidence::Unavailable,
    }
}

fn caller_chain_entry_from_proc_stat(
    pid: libc::pid_t,
    stat: &ProcStat,
    boot_id: &str,
) -> CallerChainEntry {
    CallerChainEntry {
        pid,
        starttime_ticks: stat.starttime_ticks,
        boot_id: boot_id.to_string(),
    }
}

fn parse_proc_stat(contents: &str) -> Option<ProcStat> {
    let end_comm = contents.rfind(") ")?;
    let fields: Vec<&str> = contents[end_comm + 2..].split_whitespace().collect();
    let ppid = fields.get(1)?.parse::<libc::pid_t>().ok()?;
    let starttime_ticks = fields.get(19)?.parse::<u64>().ok()?;
    Some(ProcStat {
        ppid,
        starttime_ticks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_reap_config(now_unix_ms: u64, ttl_secs: u64, max_dirs: usize) -> ReapConfig {
        ReapConfig {
            ttl_secs,
            max_dirs,
            max_scan: 100,
            shards: 1,
            now_unix_ms,
        }
    }

    fn write_reap_state(
        root: &Path,
        handle: &str,
        state_name: &str,
        updated_at_unix_ms: u64,
        consumed: bool,
    ) -> StatePaths {
        write_reap_state_with_completion(
            root,
            handle,
            state_name,
            updated_at_unix_ms,
            consumed,
            "exit",
            Some(0),
        )
    }

    fn write_reap_state_with_completion(
        root: &Path,
        handle: &str,
        state_name: &str,
        updated_at_unix_ms: u64,
        consumed: bool,
        completion_reason: &str,
        workload_rc: Option<i32>,
    ) -> StatePaths {
        let paths = StatePaths::new(root.to_path_buf(), handle.to_string());
        create_handle_state(&paths).expect("create state");
        let mut meta = reap_state_meta(handle, state_name, updated_at_unix_ms);
        if reap_state_name_is_terminal(state_name) {
            apply_reap_state_completion(
                &mut meta,
                updated_at_unix_ms,
                completion_reason,
                workload_rc,
            );
        }
        write_meta_atomic(&paths, &meta).expect("write meta");
        if consumed {
            write_reap_state_consumed_marker(&paths);
        }
        paths
    }

    fn reap_state_meta(handle: &str, state_name: &str, updated_at_unix_ms: u64) -> Meta {
        let mut meta = Meta::new(
            handle.to_string(),
            123,
            456,
            vec!["sh".to_string()],
            PathBuf::from("/tmp"),
            "exit",
            DeliveryMode::Async,
            None,
            Vec::new(),
            None,
        );
        meta.state = state_name.to_string();
        meta.updated_at_unix_ms = updated_at_unix_ms;
        meta
    }

    fn reap_state_name_is_terminal(state_name: &str) -> bool {
        matches!(state_name, "DONE" | "ERROR")
    }

    fn apply_reap_state_completion(
        meta: &mut Meta,
        updated_at_unix_ms: u64,
        completion_reason: &str,
        workload_rc: Option<i32>,
    ) {
        meta.completed_at_unix_ms = Some(updated_at_unix_ms);
        meta.completion_reason = Some(completion_reason.to_string());
        meta.rc = Some(0);
        meta.workload_rc = workload_rc;
    }

    fn write_reap_state_consumed_marker(paths: &StatePaths) {
        fs::write(&paths.consumed, b"").expect("write consumed");
    }

    fn existing_handle_dirs(root: &Path) -> usize {
        fs::read_dir(root)
            .expect("read root")
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("ab_"))
            .count()
    }

    #[test]
    fn state_root_uses_xdg_state_home() {
        let root = state_root_from_env_values(Some("/tmp/example-state"), Some("/home/alice"))
            .expect("state root");
        assert_eq!(root, PathBuf::from("/tmp/example-state/agent-bash"));
    }

    #[test]
    fn state_root_falls_back_to_home_local_state() {
        let root =
            state_root_from_env_values(None::<&str>, Some("/home/alice")).expect("state root");
        assert_eq!(root, PathBuf::from("/home/alice/.local/state/agent-bash"));
    }

    #[test]
    fn handle_format_is_parseable_and_unique() {
        let first = generate_handle().expect("first handle");
        let second = generate_handle().expect("second handle");
        assert_ne!(first, second);
        for handle in [first, second] {
            let parts: Vec<_> = handle.split('_').collect();
            assert_eq!(parts.len(), 4);
            assert_eq!(parts[0], "ab");
            assert!(u64::from_str_radix(parts[1], 16).is_ok());
            assert!(parts[2].parse::<u32>().is_ok());
            assert_eq!(parts[3].len(), 16);
            assert!(u64::from_str_radix(parts[3], 16).is_ok());
        }
    }

    #[test]
    fn atomic_meta_round_trip() {
        let temp = tempfile::tempdir().expect("tempdir");
        let paths = StatePaths::new(temp.path().to_path_buf(), "ab_test".to_string());
        create_handle_state(&paths).expect("create state");
        let meta = Meta::new(
            paths.handle.clone(),
            123,
            456,
            vec!["sh".to_string()],
            PathBuf::from("/tmp"),
            "exit",
            DeliveryMode::Async,
            None,
            vec![CallerChainEntry {
                pid: 123,
                starttime_ticks: 99,
                boot_id: "boot".to_string(),
            }],
            None,
        )
        .with_owner_context(
            Some("ses_test".to_string()),
            Some("11111111-1111-4111-8111-111111111111".to_string()),
        );
        write_meta_atomic(&paths, &meta).expect("write meta");
        let read = read_meta(&paths).expect("read meta");
        assert_eq!(read.schema_version, 1);
        assert_eq!(read.owner_session_id.as_deref(), Some("ses_test"));
        assert_eq!(
            read.owner_invocation_uuid.as_deref(),
            Some("11111111-1111-4111-8111-111111111111")
        );
        assert_eq!(read.handle, paths.handle);
        assert_eq!(read.caller_chain[0].pid, 123);
    }

    #[test]
    fn delivery_mode_round_trip_and_legacy_default() {
        let temp = tempfile::tempdir().expect("tempdir");
        let paths = StatePaths::new(temp.path().to_path_buf(), "ab_test".to_string());
        create_handle_state(&paths).expect("create state");

        assert_eq!(
            read_delivery_mode(&paths).expect("legacy mode"),
            DeliveryMode::Async
        );
        write_delivery_mode_atomic(&paths, DeliveryMode::Sync).expect("write mode");
        assert_eq!(
            read_delivery_mode(&paths).expect("sync mode"),
            DeliveryMode::Sync
        );
    }

    #[test]
    fn rc_write_is_atomic_single_line() {
        let temp = tempfile::tempdir().expect("tempdir");
        let paths = StatePaths::new(temp.path().to_path_buf(), "ab_test".to_string());
        create_handle_state(&paths).expect("create state");
        write_rc_atomic(&paths, 7).expect("write rc");
        assert_eq!(fs::read_to_string(&paths.rc).expect("rc"), "7\n");
        assert_eq!(read_rc(&paths).expect("read rc"), 7);
    }

    #[test]
    fn reaper_removes_done_old_consumed_state_dir() {
        let temp = tempfile::tempdir().expect("tempdir");
        let now = 100_000;
        let paths = write_reap_state(temp.path(), "ab_done_old", "DONE", now - 20_000, true);

        let stats = reap_state_dirs(temp.path(), test_reap_config(now, 10, 10));

        assert_eq!(stats.reaped, 1);
        assert!(!paths.state_dir.exists());
    }

    #[test]
    fn reaper_keeps_running_state_without_exact_process_identities() {
        let temp = tempfile::tempdir().expect("tempdir");
        let now = 100_000;
        let paths = write_reap_state(temp.path(), "ab_running", "RUNNING", now - 20_000, true);

        let stats = reap_state_dirs(temp.path(), test_reap_config(now, 10, 10));

        assert_eq!(stats.reaped, 0);
        assert!(paths.state_dir.exists());
    }

    #[test]
    fn reaper_removes_old_running_state_after_pid_reuse() {
        let temp = tempfile::tempdir().expect("tempdir");
        let now = 100_000;
        let paths = write_reap_state(
            temp.path(),
            "ab_running_reused",
            "RUNNING",
            now - 20_000,
            true,
        );
        let mut meta = read_meta(&paths).expect("read meta");
        let pid = i32::try_from(std::process::id()).expect("pid");
        let actual = process_starttime_ticks(pid).expect("process start time");
        meta.supervisor_pid = Some(pid);
        meta.supervisor_pid_starttime_ticks = Some(actual.saturating_add(1));
        meta.workload_pid = Some(pid);
        meta.workload_pid_starttime_ticks = Some(actual.saturating_add(1));
        meta.process_boot_id = Some(current_boot_id());
        write_meta_atomic(&paths, &meta).expect("write reused identity");

        let stats = reap_state_dirs(temp.path(), test_reap_config(now, 10, 10));

        assert_eq!(stats.reaped, 1);
        assert!(!paths.state_dir.exists());
    }

    #[test]
    fn reaper_keeps_recent_done_state_dir_within_ttl() {
        let temp = tempfile::tempdir().expect("tempdir");
        let now = 100_000;
        let paths = write_reap_state(temp.path(), "ab_recent", "DONE", now - 5_000, true);

        let stats = reap_state_dirs(temp.path(), test_reap_config(now, 10, 10));

        assert_eq!(stats.reaped, 0);
        assert!(paths.state_dir.exists());
    }

    #[test]
    fn reaper_removes_completed_error_state_under_normal_retention() {
        let temp = tempfile::tempdir().expect("tempdir");
        let now = 100_000;
        let paths = write_reap_state(temp.path(), "ab_error", "ERROR", now - 20_000, true);

        let stats = reap_state_dirs(temp.path(), test_reap_config(now, 10, 10));

        assert_eq!(stats.reaped, 1);
        assert!(!paths.state_dir.exists());
    }

    #[test]
    fn reaper_keeps_pending_undelivered_state_dir_until_moot() {
        let temp = tempfile::tempdir().expect("tempdir");
        let now = 100_000;
        let paths = write_reap_state(temp.path(), "ab_pending", "DONE", now - 20_000, false);

        let stats = reap_state_dirs(temp.path(), test_reap_config(now, 10, 10));

        assert_eq!(stats.reaped, 0);
        assert!(paths.state_dir.exists());
    }

    #[test]
    fn reaper_keeps_retryable_failed_delivery_until_moot() {
        let temp = tempfile::tempdir().expect("tempdir");
        let now = 100_000;
        let paths = write_reap_state(temp.path(), "ab_retryable", "DONE", now - 20_000, false);
        let mut meta = read_meta(&paths).expect("read meta");
        meta.delivery.attempted = false;
        meta.delivery.error = Some("registered delivery helper is unavailable".to_string());
        meta.delivery.error_code = Some("delivery_helper_unavailable".to_string());
        meta.delivery.retryable = Some(true);
        write_meta_atomic(&paths, &meta).expect("write retryable delivery metadata");

        let stats = reap_state_dirs(temp.path(), test_reap_config(now, 10, 10));

        assert_eq!(stats.reaped, 0);
        assert!(paths.state_dir.exists());
    }

    #[test]
    fn reaper_removes_old_sync_in_band_state_without_consumed_marker() {
        let temp = tempfile::tempdir().expect("tempdir");
        let now = 100_000;
        let paths = write_reap_state(temp.path(), "ab_sync", "DONE", now - 20_000, false);
        let mut meta = read_meta(&paths).expect("read meta");
        meta.delivery.skipped = Some("sync_in_band".to_string());
        write_meta_atomic(&paths, &meta).expect("write settled meta");

        let stats = reap_state_dirs(temp.path(), test_reap_config(now, 10, 10));

        assert_eq!(stats.reaped, 1);
        assert!(!paths.state_dir.exists());
    }

    #[test]
    fn reaper_keeps_ready_sentinel_done_with_running_workload() {
        let temp = tempfile::tempdir().expect("tempdir");
        let now = 100_000;
        let paths = write_reap_state_with_completion(
            temp.path(),
            "ab_sentinel_running",
            "DONE",
            now - 20_000,
            true,
            "ready-sentinel",
            None,
        );
        let mut meta = read_meta(&paths).expect("read meta");
        let pid = i32::try_from(std::process::id()).expect("pid");
        meta.workload_pid = Some(pid);
        meta.workload_pid_starttime_ticks = process_starttime_ticks(pid);
        meta.process_boot_id = Some(current_boot_id());
        write_meta_atomic(&paths, &meta).expect("write live workload identity");

        let stats = reap_state_dirs(temp.path(), test_reap_config(now, 10, 10));

        assert_eq!(stats.reaped, 0);
        assert!(paths.state_dir.exists());
    }

    #[test]
    fn reaper_respects_max_dirs_cap() {
        let temp = tempfile::tempdir().expect("tempdir");
        let now = 100_000;
        for index in 0..3 {
            write_reap_state(
                temp.path(),
                &format!("ab_done_old_{index}"),
                "DONE",
                now - 20_000,
                true,
            );
        }

        let stats = reap_state_dirs(temp.path(), test_reap_config(now, 10, 2));

        assert_eq!(stats.reaped, 2);
        assert_eq!(existing_handle_dirs(temp.path()), 1);
    }

    #[test]
    fn reaper_rotates_across_all_configured_shards() {
        let temp = tempfile::tempdir().expect("tempdir");
        let now = 100_000;
        for index in 0..40 {
            write_reap_state(
                temp.path(),
                &format!("ab_sharded_{index}"),
                "DONE",
                now - 20_000,
                true,
            );
        }
        let config = ReapConfig {
            ttl_secs: 10,
            max_dirs: 100,
            max_scan: 100,
            shards: 4,
            now_unix_ms: now,
        };

        for _ in 0..4 {
            reap_state_dirs(temp.path(), config);
        }

        assert_eq!(existing_handle_dirs(temp.path()), 0);
    }

    #[test]
    fn reaper_is_best_effort_when_removal_fails() {
        let temp = tempfile::tempdir().expect("tempdir");
        let now = 100_000;
        let paths = write_reap_state(temp.path(), "ab_locked", "DONE", now - 20_000, true);
        let mut perms = fs::metadata(temp.path()).expect("metadata").permissions();
        perms.set_mode(0o500);
        fs::set_permissions(temp.path(), perms).expect("chmod root readonly");

        let stats = reap_state_dirs(temp.path(), test_reap_config(now, 10, 10));

        let mut perms = fs::metadata(temp.path()).expect("metadata").permissions();
        perms.set_mode(0o700);
        fs::set_permissions(temp.path(), perms).expect("restore perms");
        assert_eq!(stats.reaped, 0);
        assert_eq!(stats.errors, 1);
        assert!(paths.state_dir.exists());
    }

    #[test]
    fn open_read_no_follow_rejects_symlink() {
        let temp = tempfile::tempdir().expect("tempdir");
        let target = temp.path().join("target");
        let link = temp.path().join("link");
        fs::write(&target, "secret").expect("target");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        let err = open_read_no_follow(&link).expect_err("symlink rejected");
        assert_eq!(err.raw_os_error(), Some(libc::ELOOP));
    }

    #[test]
    fn proc_stat_parser_reads_ppid_and_starttime() {
        let stat =
            parse_proc_stat("42 (name with ) paren) S 7 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 12345 0")
                .expect("stat");
        assert_eq!(stat.ppid, 7);
        assert_eq!(stat.starttime_ticks, 12345);
    }
}
