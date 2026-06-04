use std::env;
use std::ffi::OsStr;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

const SCHEMA_VERSION: u8 = 1;
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub(crate) struct StatePaths {
    pub(crate) root: PathBuf,
    pub(crate) handle: String,
    pub(crate) state_dir: PathBuf,
    pub(crate) log: PathBuf,
    pub(crate) rc: PathBuf,
    pub(crate) meta: PathBuf,
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
            state_dir,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CallerChainEntry {
    pub(crate) pid: libc::pid_t,
    pub(crate) starttime_ticks: u64,
    pub(crate) boot_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct DeliveryMeta {
    pub(crate) attempted: bool,
    pub(crate) exit_code: Option<i32>,
    pub(crate) error: Option<String>,
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
    pub(crate) launcher_pid: libc::pid_t,
    pub(crate) supervisor_pid: Option<libc::pid_t>,
    pub(crate) workload_pid: Option<libc::pid_t>,
    pub(crate) workload_pgid: Option<libc::pid_t>,
    pub(crate) workload_pidfd: bool,
    pub(crate) argv: Vec<String>,
    pub(crate) cwd: String,
    pub(crate) mode: String,
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
        ready_sentinel: Option<String>,
        caller_chain: Vec<CallerChainEntry>,
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
            launcher_pid,
            supervisor_pid: None,
            workload_pid: None,
            workload_pgid: None,
            workload_pidfd: false,
            argv,
            cwd: cwd.display().to_string(),
            mode: mode.to_string(),
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
    ready_sentinel: Option<String>,
}

impl RunOutput {
    pub(crate) fn new(
        paths: StatePaths,
        caller_ppid: libc::pid_t,
        mode: &str,
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
    if let Some(xdg) = xdg_state_home
        && !xdg.as_ref().is_empty()
    {
        return Ok(PathBuf::from(xdg.as_ref()).join("agent-bash"));
    }
    if let Some(home) = home
        && !home.as_ref().is_empty()
    {
        return Ok(PathBuf::from(home.as_ref()).join(".local/state/agent-bash"));
    }
    Err(StateError::MissingHome)
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
        .mode(0o600)
        .open(&paths.log)
}

pub(crate) fn open_log_append(paths: &StatePaths) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&paths.log)
}

pub(crate) fn write_meta_atomic(paths: &StatePaths, meta: &Meta) -> io::Result<()> {
    let mut bytes = serde_json::to_vec_pretty(meta).map_err(io::Error::other)?;
    bytes.push(b'\n');
    atomic_write(&paths.meta, &bytes)
}

pub(crate) fn read_meta(paths: &StatePaths) -> io::Result<Meta> {
    let bytes = fs::read(&paths.meta)?;
    serde_json::from_slice(&bytes).map_err(io::Error::other)
}

pub(crate) fn write_rc_atomic(paths: &StatePaths, rc: i32) -> io::Result<()> {
    atomic_write(&paths.rc, format!("{rc}\n").as_bytes())
}

pub(crate) fn read_rc(paths: &StatePaths) -> io::Result<i32> {
    let contents = fs::read_to_string(&paths.rc)?;
    contents
        .trim_end_matches('\n')
        .parse::<i32>()
        .map_err(io::Error::other)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("path has no parent"))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::other("path has no file name"))?
        .to_string_lossy();
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = parent.join(format!(
        ".{file_name}.tmp.{}.{}",
        unsafe { libc::getpid() },
        counter
    ));
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

#[derive(Debug)]
struct ProcStat {
    ppid: libc::pid_t,
    starttime_ticks: u64,
}

pub(crate) fn capture_caller_chain(start_pid: libc::pid_t) -> Vec<CallerChainEntry> {
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|value| value.trim().to_string())
        .unwrap_or_default();
    let mut chain = Vec::new();
    let mut pid = start_pid;
    for _ in 0..128 {
        if pid <= 0 {
            break;
        }
        let Some(stat) = read_proc_stat(pid) else {
            break;
        };
        chain.push(CallerChainEntry {
            pid,
            starttime_ticks: stat.starttime_ticks,
            boot_id: boot_id.clone(),
        });
        if pid == 1 {
            break;
        }
        pid = stat.ppid;
    }
    chain
}

fn read_proc_stat(pid: libc::pid_t) -> Option<ProcStat> {
    parse_proc_stat(&fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
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
            None,
            vec![CallerChainEntry {
                pid: 123,
                starttime_ticks: 99,
                boot_id: "boot".to_string(),
            }],
        );
        write_meta_atomic(&paths, &meta).expect("write meta");
        let read = read_meta(&paths).expect("read meta");
        assert_eq!(read.schema_version, 1);
        assert_eq!(read.handle, paths.handle);
        assert_eq!(read.caller_chain[0].pid, 123);
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
    fn proc_stat_parser_reads_ppid_and_starttime() {
        let stat =
            parse_proc_stat("42 (name with ) paren) S 7 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 12345 0")
                .expect("stat");
        assert_eq!(stat.ppid, 7);
        assert_eq!(stat.starttime_ticks, 12345);
    }
}
