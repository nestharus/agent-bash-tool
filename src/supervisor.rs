use std::collections::HashMap;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::RawFd;
use std::time::{Duration, Instant};

use regex::bytes::Regex;

use crate::cgroup::{self, ActiveCgroup};
use crate::delivery;
use crate::state::{self, Meta, StatePaths};

const EX_SOFTWARE: i32 = 70;
const ONE_MIB: usize = 1024 * 1024;
const CANCEL_GRACE: Duration = Duration::from_secs(2);
const CANCEL_POLL: Duration = Duration::from_millis(100);
const OWNER_POLL: Duration = Duration::from_millis(250);
const SUPERVISOR_RECOVERY_POLL: Duration = Duration::from_millis(100);
const LOG_MAX_BYTES_ENV: &str = "AGENT_BASH_LOG_MAX_BYTES";
const DEFAULT_LOG_MAX_BYTES: u64 = 16 * 1024 * 1024;
const MIN_LOG_MAX_BYTES: u64 = 64 * 1024;
const MAX_LOG_MAX_BYTES: u64 = 1024 * 1024 * 1024;
const LOG_TRUNCATED_MARKER: &[u8] = b"\n[agent-bash log truncated; retaining newest output]\n";

#[derive(Clone)]
pub(crate) struct SupervisorConfig {
    pub(crate) paths: StatePaths,
    pub(crate) meta: Meta,
    pub(crate) argv: Vec<String>,
    pub(crate) completion_scope: CompletionScope,
    pub(crate) ready_sentinel: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompletionScope {
    Tree,
    Root,
}

pub(crate) fn validate_argv(argv: &[String]) -> Result<(), String> {
    if argv.is_empty() {
        return Err("agent-bash: missing workload command".to_string());
    }
    for arg in argv {
        if CString::new(arg.as_str()).is_err() {
            return Err("agent-bash: workload argv contains NUL byte".to_string());
        }
    }
    Ok(())
}

pub(crate) fn fork_supervisor(config: SupervisorConfig) -> io::Result<()> {
    match unsafe { libc::fork() } {
        -1 => Err(io::Error::last_os_error()),
        0 => unsafe { daemonization_child(config) },
        _ => Ok(()),
    }
}

pub(crate) fn request_cancel(paths: &StatePaths) -> io::Result<bool> {
    let meta = wait_for_supervisor_metadata(paths)?;
    let supervisor = meta
        .supervisor_pid
        .zip(meta.supervisor_pid_starttime_ticks)
        .zip(meta.process_boot_id.as_deref());
    let Some(((pid, starttime_ticks), boot_id)) = supervisor else {
        reconcile_lost_supervisor(paths)?;
        return Ok(false);
    };
    let identity = state::CallerChainEntry {
        pid,
        starttime_ticks,
        boot_id: boot_id.to_string(),
    };
    if !state::process_identity_is_live(&identity) {
        reconcile_lost_supervisor(paths)?;
        return Ok(false);
    }
    let rc = unsafe { libc::kill(pid, libc::SIGUSR1) };
    if rc == 0 {
        Ok(true)
    } else {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            reconcile_lost_supervisor(paths)?;
            Ok(false)
        } else {
            Err(err)
        }
    }
}

fn wait_for_supervisor_metadata(paths: &StatePaths) -> io::Result<Meta> {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let meta = state::read_meta(paths)?;
        if meta.supervisor_pid.is_some() || state::terminal(&meta) || Instant::now() >= deadline {
            return Ok(meta);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

unsafe fn daemonization_child(config: SupervisorConfig) -> ! {
    redirect_stdio_to_devnull();
    if unsafe { libc::setsid() } < 0 {
        unsafe { libc::_exit(EX_SOFTWARE) };
    }
    let guardian_paths = config.paths.clone();
    match unsafe { libc::fork() } {
        -1 => unsafe { libc::_exit(EX_SOFTWARE) },
        0 => {
            let code = run_supervisor(config);
            unsafe { libc::_exit(code) };
        }
        supervisor_pid => {
            let code = guard_supervisor_exit(&guardian_paths, supervisor_pid);
            unsafe { libc::_exit(code) };
        }
    }
}

fn guard_supervisor_exit(paths: &StatePaths, supervisor_pid: libc::pid_t) -> i32 {
    let status = match wait_for_exact_child(supervisor_pid) {
        Ok(status) => status,
        Err(_) => return EX_SOFTWARE,
    };
    if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
        return 0;
    }

    loop {
        match reconcile_lost_supervisor(paths) {
            Ok(meta) if state::terminal(&meta) => return 0,
            Ok(meta) if !state::running_exit_mode(&meta) => return 0,
            Ok(_) => std::thread::sleep(SUPERVISOR_RECOVERY_POLL),
            Err(_) => return EX_SOFTWARE,
        }
    }
}

fn wait_for_exact_child(pid: libc::pid_t) -> io::Result<i32> {
    loop {
        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        if waited == pid {
            return Ok(status);
        }
        if waited < 0 {
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
    }
}

fn redirect_stdio_to_devnull() {
    let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd >= 0 {
        unsafe {
            libc::dup2(fd, libc::STDIN_FILENO);
            libc::dup2(fd, libc::STDOUT_FILENO);
            libc::dup2(fd, libc::STDERR_FILENO);
            libc::close(fd);
        }
    }
}

fn run_supervisor(config: SupervisorConfig) -> i32 {
    set_private_umask();
    let mut meta = supervisor_meta(config.meta);

    let mut log = match open_supervisor_log(&config.paths) {
        Ok(file) => file,
        Err(err) => {
            let _ = record_supervisor_error(
                &config.paths,
                &mut meta,
                open_log_failed_message(err),
                None,
            );
            return EX_SOFTWARE;
        }
    };

    if let Err(err) = set_subreaper() {
        let _ = record_supervisor_error(
            &config.paths,
            &mut meta,
            subreaper_failed_message(err),
            Some(&mut log),
        );
        return EX_SOFTWARE;
    }

    let sigchld = match Sigchld::new() {
        Ok(sigchld) => sigchld,
        Err(err) => {
            let _ = record_supervisor_error(
                &config.paths,
                &mut meta,
                signalfd_failed_message(err),
                Some(&mut log),
            );
            return EX_SOFTWARE;
        }
    };

    let cgroup_setup = cgroup::setup(&meta.handle);
    apply_cgroup_setup_meta(&mut meta, cgroup_setup.meta.clone());
    persist_supervisor_meta_best_effort(&config.paths, &meta);

    let c_argv = match argv_to_cstrings(&config.argv) {
        Ok(argv) => argv,
        Err(err) => {
            let _ = record_supervisor_error(&config.paths, &mut meta, err, Some(&mut log));
            return EX_SOFTWARE;
        }
    };
    let spawn = match spawn_workload(
        &c_argv,
        cgroup_setup.active.as_ref().map(ActiveCgroup::procs_fd),
    ) {
        Ok(spawn) => spawn,
        Err(err) => {
            let _ = record_supervisor_error(
                &config.paths,
                &mut meta,
                spawn_failed_message(err),
                Some(&mut log),
            );
            return EX_SOFTWARE;
        }
    };

    let root_pidfd = pidfd_open(spawn.pid);
    let owner_pidfd = owner_pidfd(&meta);
    apply_spawn_metadata(&mut meta, &spawn, root_pidfd);
    persist_supervisor_meta_best_effort(&config.paths, &meta);

    let sentinel = match sentinel_matcher(config.ready_sentinel.as_deref()) {
        Ok(sentinel) => sentinel,
        Err(err) => {
            let _ = record_supervisor_error(
                &config.paths,
                &mut meta,
                invalid_sentinel_after_fork_message(err),
                Some(&mut log),
            );
            return EX_SOFTWARE;
        }
    };

    let loop_state = event_loop_state(EventLoopSeed {
        paths: config.paths,
        meta,
        log,
        sigchld,
        cgroup: cgroup_setup.active,
        spawn,
        root_pidfd,
        owner_pidfd,
        completion_scope: config.completion_scope,
        sentinel,
    });
    event_loop_exit_code(event_loop(loop_state))
}

fn set_private_umask() {
    unsafe {
        libc::umask(0o077);
    }
}

fn supervisor_meta(mut meta: Meta) -> Meta {
    let pid = current_pid();
    meta.supervisor_pid = Some(pid);
    meta.supervisor_pid_starttime_ticks = state::process_starttime_ticks(pid);
    let boot_id = state::current_boot_id();
    meta.process_boot_id = (!boot_id.is_empty()).then_some(boot_id);
    meta.touch();
    meta
}

fn open_supervisor_log(paths: &StatePaths) -> io::Result<BoundedLog> {
    BoundedLog::new(state::open_log_append(paths)?, log_max_bytes())
}

fn log_max_bytes() -> u64 {
    std::env::var(LOG_MAX_BYTES_ENV)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_LOG_MAX_BYTES)
        .clamp(MIN_LOG_MAX_BYTES, MAX_LOG_MAX_BYTES)
}

struct BoundedLog {
    file: File,
    max_bytes: u64,
    len: u64,
}

impl BoundedLog {
    fn new(file: File, max_bytes: u64) -> io::Result<Self> {
        let len = file.metadata()?.len();
        let mut log = Self {
            file,
            max_bytes: max_bytes.max(1),
            len,
        };
        if len > log.max_bytes {
            log.reset_with_tail(&[])?;
        }
        Ok(log)
    }

    fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self
            .len
            .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
            > self.max_bytes
        {
            return self.reset_with_tail(bytes);
        }
        self.file.write_all(bytes)?;
        self.len = self
            .len
            .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        Ok(())
    }

    fn reset_with_tail(&mut self, bytes: &[u8]) -> io::Result<()> {
        let marker = retained_suffix(LOG_TRUNCATED_MARKER, self.max_bytes);
        let payload_budget = self
            .max_bytes
            .saturating_sub(u64::try_from(marker.len()).unwrap_or(self.max_bytes));
        let new_tail = retained_suffix(bytes, payload_budget);
        let old_budget =
            payload_budget.saturating_sub(u64::try_from(new_tail.len()).unwrap_or(payload_budget));
        let old_tail = self.read_tail(old_budget)?;

        self.file.set_len(0)?;
        self.file.write_all(marker)?;
        self.file.write_all(&old_tail)?;
        self.file.write_all(new_tail)?;
        self.len =
            u64::try_from(marker.len() + old_tail.len() + new_tail.len()).unwrap_or(self.max_bytes);
        Ok(())
    }

    fn read_tail(&mut self, max_bytes: u64) -> io::Result<Vec<u8>> {
        let keep = self.len.min(max_bytes);
        if keep == 0 {
            return Ok(Vec::new());
        }
        self.file
            .seek(SeekFrom::End(-i64::try_from(keep).unwrap_or(i64::MAX)))?;
        let mut tail = vec![0; usize::try_from(keep).unwrap_or(usize::MAX)];
        self.file.read_exact(&mut tail)?;
        Ok(tail)
    }

    fn sync_all(&self) -> io::Result<()> {
        self.file.sync_all()
    }
}

fn retained_suffix(bytes: &[u8], max_bytes: u64) -> &[u8] {
    let keep = usize::try_from(max_bytes)
        .unwrap_or(usize::MAX)
        .min(bytes.len());
    &bytes[bytes.len().saturating_sub(keep)..]
}

fn open_log_failed_message(err: io::Error) -> String {
    format!("open log failed: {err}")
}

fn subreaper_failed_message(err: io::Error) -> String {
    format!("PR_SET_CHILD_SUBREAPER failed: {err}")
}

fn signalfd_failed_message(err: io::Error) -> String {
    format!("signalfd failed: {err}")
}

fn spawn_failed_message(err: io::Error) -> String {
    format!("spawn failed: {err}")
}

fn invalid_sentinel_after_fork_message(err: regex::Error) -> String {
    format!("invalid ready sentinel after fork: {err}")
}

fn apply_cgroup_setup_meta(meta: &mut Meta, cgroup_meta: state::CgroupMeta) {
    meta.cgroup = cgroup_meta;
    meta.touch();
}

fn persist_supervisor_meta_best_effort(paths: &StatePaths, meta: &Meta) {
    let _ = state::write_meta_atomic(paths, meta);
}

fn apply_spawn_metadata(meta: &mut Meta, spawn: &WorkloadSpawn, root_pidfd: Option<RawFd>) {
    meta.workload_pid = Some(spawn.pid);
    meta.workload_pid_starttime_ticks = state::process_starttime_ticks(spawn.pid);
    meta.workload_pgid = Some(spawn.pid);
    meta.workload_pidfd = root_pidfd.is_some();
    meta.touch();
}

fn sentinel_matcher(pattern: Option<&str>) -> Result<Option<SentinelMatcher>, regex::Error> {
    let Some(pattern) = pattern else {
        return Ok(None);
    };
    let regex = parse_sentinel_regex(pattern)?;
    Ok(Some(map_sentinel_matcher(regex, pattern)))
}

fn parse_sentinel_regex(pattern: &str) -> Result<Regex, regex::Error> {
    Regex::new(pattern)
}

fn map_sentinel_matcher(regex: Regex, pattern: &str) -> SentinelMatcher {
    SentinelMatcher::new(regex, pattern.len())
}

struct EventLoopSeed {
    paths: StatePaths,
    meta: Meta,
    log: BoundedLog,
    sigchld: Sigchld,
    cgroup: Option<ActiveCgroup>,
    spawn: WorkloadSpawn,
    root_pidfd: Option<RawFd>,
    owner_pidfd: Option<RawFd>,
    completion_scope: CompletionScope,
    sentinel: Option<SentinelMatcher>,
}

fn event_loop_state(seed: EventLoopSeed) -> EventLoop {
    EventLoop {
        paths: seed.paths,
        meta: seed.meta,
        log: seed.log,
        sigchld: seed.sigchld,
        cgroup: seed.cgroup,
        root_pid: seed.spawn.pid,
        root_pidfd: seed.root_pidfd,
        owner_pidfd: seed.owner_pidfd,
        completion_scope: seed.completion_scope,
        stdout_fd: Some(seed.spawn.stdout_fd),
        stderr_fd: Some(seed.spawn.stderr_fd),
        exec_err_fd: Some(seed.spawn.exec_err_fd),
        root_status: None,
        tree_empty: false,
        completion_recorded: false,
        sentinel: seed.sentinel,
        spawn_error: None,
        cancellation: None,
    }
}

fn owner_pidfd(meta: &Meta) -> Option<RawFd> {
    let owner = meta.cancel_owner.as_ref()?;
    if !state::process_identity_is_live(owner) {
        return None;
    }
    let fd = pidfd_open(owner.pid)?;
    if state::process_identity_is_live(owner) {
        Some(fd)
    } else {
        close_fd(fd);
        None
    }
}

fn event_loop_exit_code(result: io::Result<()>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(_) => EX_SOFTWARE,
    }
}

fn set_subreaper() -> io::Result<()> {
    let rc = unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn argv_to_cstrings(argv: &[String]) -> Result<Vec<CString>, String> {
    validate_cstring_argv(argv)?;
    Ok(map_argv_to_cstrings(argv))
}

fn validate_cstring_argv(argv: &[String]) -> Result<(), String> {
    for arg in argv {
        if CString::new(arg.as_str()).is_err() {
            return Err("workload argv contains NUL byte".to_string());
        }
    }
    Ok(())
}

fn map_argv_to_cstrings(argv: &[String]) -> Vec<CString> {
    argv.iter()
        .map(String::as_str)
        .map(validated_arg_to_cstring)
        .collect()
}

fn validated_arg_to_cstring(arg: &str) -> CString {
    CString::new(arg).expect("argv was validated")
}

struct WorkloadSpawn {
    pid: libc::pid_t,
    stdout_fd: RawFd,
    stderr_fd: RawFd,
    exec_err_fd: RawFd,
}

fn spawn_workload(c_argv: &[CString], cgroup_procs_fd: Option<RawFd>) -> io::Result<WorkloadSpawn> {
    let mut stdout_pipe = make_pipe()?;
    let mut stderr_pipe = make_pipe()?;
    let mut exec_err_pipe = make_pipe()?;
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        unsafe {
            workload_child(
                c_argv,
                &mut stdout_pipe,
                &mut stderr_pipe,
                &mut exec_err_pipe,
                cgroup_procs_fd,
            )
        };
    }
    close_fd(stdout_pipe.write);
    close_fd(stderr_pipe.write);
    close_fd(exec_err_pipe.write);
    set_nonblocking(stdout_pipe.read)?;
    set_nonblocking(stderr_pipe.read)?;
    set_nonblocking(exec_err_pipe.read)?;
    Ok(workload_spawn(
        pid,
        stdout_pipe.read,
        stderr_pipe.read,
        exec_err_pipe.read,
    ))
}

fn workload_spawn(
    pid: libc::pid_t,
    stdout_fd: RawFd,
    stderr_fd: RawFd,
    exec_err_fd: RawFd,
) -> WorkloadSpawn {
    WorkloadSpawn {
        pid,
        stdout_fd,
        stderr_fd,
        exec_err_fd,
    }
}

unsafe fn workload_child(
    c_argv: &[CString],
    stdout_pipe: &mut Pipe,
    stderr_pipe: &mut Pipe,
    exec_err_pipe: &mut Pipe,
    cgroup_procs_fd: Option<RawFd>,
) -> ! {
    unblock_supervisor_signals();
    set_workload_process_group();
    enroll_workload_in_cgroup(cgroup_procs_fd, exec_err_pipe.write);
    redirect_workload_output(stdout_pipe, stderr_pipe, exec_err_pipe);
    redirect_workload_stdin();
    close_workload_output_writes(stdout_pipe, stderr_pipe);
    let pointers = argv_pointers(c_argv);
    exec_workload(&pointers);
    write_errno_and_exit(exec_err_pipe.write, 127);
}

fn set_workload_process_group() {
    unsafe {
        libc::setpgid(0, 0);
    }
}

fn enroll_workload_in_cgroup(cgroup_procs_fd: Option<RawFd>, exec_error_fd: RawFd) {
    let Some(fd) = cgroup_procs_fd else {
        return;
    };
    if cgroup::write_pid_to_procs_fd(fd, current_pid()) != 0 {
        write_errno_and_exit(exec_error_fd, 126);
    }
}

fn current_pid() -> libc::pid_t {
    unsafe { libc::getpid() }
}

fn signal_descendants(root_pid: libc::pid_t, signal: i32) {
    for pid in descendant_pids(root_pid) {
        unsafe {
            libc::kill(pid, signal);
        }
    }
}

fn descendant_pids(root_pid: libc::pid_t) -> Vec<libc::pid_t> {
    let parents = proc_parent_map();
    let mut descendants: Vec<_> = parents
        .keys()
        .filter_map(|pid| descendant_depth(*pid, root_pid, &parents).map(|depth| (*pid, depth)))
        .collect();
    descendants.sort_unstable_by_key(|(_, depth)| std::cmp::Reverse(*depth));
    descendants.into_iter().map(|(pid, _)| pid).collect()
}

fn proc_parent_map() -> HashMap<libc::pid_t, libc::pid_t> {
    let Ok(entries) = fs::read_dir("/proc") else {
        return HashMap::new();
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_str()?.parse::<libc::pid_t>().ok())
        .filter_map(|pid| state::process_parent_pid(pid).map(|ppid| (pid, ppid)))
        .collect()
}

fn descendant_depth(
    pid: libc::pid_t,
    root_pid: libc::pid_t,
    parents: &HashMap<libc::pid_t, libc::pid_t>,
) -> Option<usize> {
    let mut current = pid;
    for depth in 1..=parents.len() {
        let parent = *parents.get(&current)?;
        if parent == root_pid {
            return Some(depth);
        }
        if parent <= 1 || parent == current {
            return None;
        }
        current = parent;
    }
    None
}

fn redirect_workload_output(
    stdout_pipe: &mut Pipe,
    stderr_pipe: &mut Pipe,
    exec_err_pipe: &mut Pipe,
) {
    unsafe {
        libc::close(stdout_pipe.read);
        libc::close(stderr_pipe.read);
        libc::close(exec_err_pipe.read);
        libc::dup2(stdout_pipe.write, libc::STDOUT_FILENO);
        libc::dup2(stderr_pipe.write, libc::STDERR_FILENO);
    }
}

fn redirect_workload_stdin() {
    let devnull = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if devnull < 0 {
        return;
    }
    unsafe {
        libc::dup2(devnull, libc::STDIN_FILENO);
        libc::close(devnull);
    }
}

fn close_workload_output_writes(stdout_pipe: &Pipe, stderr_pipe: &Pipe) {
    unsafe {
        libc::close(stdout_pipe.write);
        libc::close(stderr_pipe.write);
    }
}

fn argv_pointers(c_argv: &[CString]) -> Vec<*const libc::c_char> {
    let mut pointers: Vec<*const libc::c_char> = c_argv.iter().map(|arg| arg.as_ptr()).collect();
    pointers.push(std::ptr::null());
    pointers
}

fn exec_workload(pointers: &[*const libc::c_char]) {
    unsafe {
        libc::execvp(pointers[0], pointers.as_ptr());
    }
}

fn unblock_supervisor_signals() {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGCHLD);
        libc::sigaddset(&mut set, libc::SIGUSR1);
        libc::sigprocmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
    }
}

fn write_errno_and_exit(fd: RawFd, code: i32) -> ! {
    let errno = last_errno();
    let bytes = errno_bytes(errno);
    write_error_bytes_and_exit(fd, code, &bytes)
}

fn last_errno() -> i32 {
    io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

fn errno_bytes(errno: i32) -> [u8; 4] {
    errno.to_ne_bytes()
}

fn write_error_bytes_and_exit(fd: RawFd, code: i32, bytes: &[u8]) -> ! {
    unsafe {
        libc::write(fd, bytes.as_ptr().cast::<libc::c_void>(), bytes.len());
        libc::_exit(code);
    }
}

#[derive(Clone, Copy)]
struct Pipe {
    read: RawFd,
    write: RawFd,
}

fn make_pipe() -> io::Result<Pipe> {
    let mut fds = [0; 2];
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(Pipe {
            read: fds[0],
            write: fds[1],
        })
    }
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn close_fd(fd: RawFd) {
    unsafe {
        libc::close(fd);
    }
}

struct Sigchld {
    fd: RawFd,
}

impl Sigchld {
    fn new() -> io::Result<Self> {
        unsafe {
            let mut mask: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut mask);
            libc::sigaddset(&mut mask, libc::SIGCHLD);
            libc::sigaddset(&mut mask, libc::SIGUSR1);
            if libc::sigprocmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut()) < 0 {
                return Err(io::Error::last_os_error());
            }
            let fd = libc::signalfd(-1, &mask, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK);
            if fd < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(Self { fd })
            }
        }
    }

    fn drain(&self) -> SignalEvents {
        let mut events = SignalEvents::default();
        let mut info = unsafe { std::mem::zeroed::<libc::signalfd_siginfo>() };
        loop {
            let n = unsafe {
                libc::read(
                    self.fd,
                    (&mut info as *mut libc::signalfd_siginfo).cast::<libc::c_void>(),
                    std::mem::size_of::<libc::signalfd_siginfo>(),
                )
            };
            if n > 0 {
                if info.ssi_signo == libc::SIGUSR1 as u32 {
                    events.cancel_requested = true;
                }
                continue;
            }
            if n == 0 {
                break;
            }
            let err = io::Error::last_os_error();
            if matches!(err.raw_os_error(), Some(libc::EAGAIN)) {
                break;
            }
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        events
    }
}

#[derive(Default)]
struct SignalEvents {
    cancel_requested: bool,
}

impl Drop for Sigchld {
    fn drop(&mut self) {
        close_fd(self.fd);
    }
}

fn pidfd_open(pid: libc::pid_t) -> Option<RawFd> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd >= 0 {
        Some(i32::try_from(fd).ok()?)
    } else {
        None
    }
}

#[derive(Clone, Copy)]
struct RootStatus {
    rc: i32,
    signal: Option<i32>,
}

struct SentinelMatcher {
    regex: Regex,
    buffer: Vec<u8>,
    limit: usize,
}

impl SentinelMatcher {
    fn new(regex: Regex, pattern_len: usize) -> Self {
        Self {
            regex,
            buffer: Vec::new(),
            limit: ONE_MIB.max(pattern_len.saturating_mul(4)),
        }
    }

    fn push_stdout(&mut self, bytes: &[u8]) -> bool {
        self.append_stdout(bytes);
        self.trim_buffer();
        self.matches()
    }

    fn append_stdout(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    fn trim_buffer(&mut self) {
        if self.buffer.len() > self.limit {
            let excess = self.buffer.len() - self.limit;
            self.buffer.drain(..excess);
        }
    }

    fn matches(&self) -> bool {
        self.regex.is_match(&self.buffer)
    }
}

struct EventLoop {
    paths: StatePaths,
    meta: Meta,
    log: BoundedLog,
    sigchld: Sigchld,
    cgroup: Option<ActiveCgroup>,
    root_pid: libc::pid_t,
    root_pidfd: Option<RawFd>,
    owner_pidfd: Option<RawFd>,
    completion_scope: CompletionScope,
    stdout_fd: Option<RawFd>,
    stderr_fd: Option<RawFd>,
    exec_err_fd: Option<RawFd>,
    root_status: Option<RootStatus>,
    tree_empty: bool,
    completion_recorded: bool,
    sentinel: Option<SentinelMatcher>,
    spawn_error: Option<String>,
    cancellation: Option<Cancellation>,
}

struct Cancellation {
    reason: &'static str,
    started_at: Instant,
}

#[derive(Clone, Copy)]
enum PollKey {
    Stdout,
    Stderr,
    ExecErr,
    Sigchld,
    Pidfd,
    OwnerPidfd,
    Cgroup,
}

struct PollEntry {
    fd: RawFd,
    events: libc::c_short,
    key: PollKey,
}

fn event_loop(mut loop_state: EventLoop) -> io::Result<()> {
    loop {
        loop_state.check_polled_owner();
        loop_state.drive_cancellation();
        loop_state.maybe_finish()?;
        if loop_state.should_exit() {
            return Ok(());
        }

        let entries = poll_entries(&loop_state);
        let mut pollfds = pollfds_for_entries(&entries);
        poll_until_ready(&mut pollfds, loop_state.poll_timeout())?;
        dispatch_ready_pollfds(&mut loop_state, &entries, &pollfds)?;
    }
}

fn poll_entries(loop_state: &EventLoop) -> Vec<PollEntry> {
    let mut entries = Vec::new();
    push_optional_poll_entry(&mut entries, loop_state.stdout_fd, PollKey::Stdout);
    push_optional_poll_entry(&mut entries, loop_state.stderr_fd, PollKey::Stderr);
    push_optional_poll_entry(&mut entries, loop_state.exec_err_fd, PollKey::ExecErr);
    entries.push(poll_entry(
        loop_state.sigchld.fd,
        libc::POLLIN,
        PollKey::Sigchld,
    ));
    push_optional_poll_entry(&mut entries, loop_state.root_pidfd, PollKey::Pidfd);
    push_optional_poll_entry(&mut entries, loop_state.owner_pidfd, PollKey::OwnerPidfd);
    push_optional_poll_entry(&mut entries, cgroup_inotify_fd(loop_state), PollKey::Cgroup);
    entries
}

fn push_optional_poll_entry(entries: &mut Vec<PollEntry>, fd: Option<RawFd>, key: PollKey) {
    let Some(fd) = fd else {
        return;
    };
    entries.push(poll_entry(fd, readable_events(), key));
}

fn poll_entry(fd: RawFd, events: libc::c_short, key: PollKey) -> PollEntry {
    PollEntry { fd, events, key }
}

fn readable_events() -> libc::c_short {
    libc::POLLIN | libc::POLLHUP | libc::POLLERR
}

fn cgroup_inotify_fd(loop_state: &EventLoop) -> Option<RawFd> {
    loop_state
        .cgroup
        .as_ref()
        .and_then(ActiveCgroup::inotify_fd)
}

fn pollfds_for_entries(entries: &[PollEntry]) -> Vec<libc::pollfd> {
    entries
        .iter()
        .map(|entry| libc::pollfd {
            fd: entry.fd,
            events: entry.events,
            revents: 0,
        })
        .collect()
}

fn poll_until_ready(pollfds: &mut [libc::pollfd], timeout: Option<Duration>) -> io::Result<()> {
    let timeout_ms = timeout
        .map(|duration| i32::try_from(duration.as_millis()).unwrap_or(i32::MAX))
        .unwrap_or(-1);
    loop {
        let rc = unsafe {
            libc::poll(
                pollfds.as_mut_ptr(),
                pollfds.len() as libc::nfds_t,
                timeout_ms,
            )
        };
        if rc >= 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

fn dispatch_ready_pollfds(
    loop_state: &mut EventLoop,
    entries: &[PollEntry],
    pollfds: &[libc::pollfd],
) -> io::Result<()> {
    for (entry, pollfd) in entries.iter().zip(pollfds) {
        if pollfd.revents == 0 {
            continue;
        }
        loop_state.dispatch_poll_key(entry.key)?;
    }
    Ok(())
}

impl EventLoop {
    fn dispatch_poll_key(&mut self, key: PollKey) -> io::Result<()> {
        match key {
            PollKey::Stdout => self.read_stdout(),
            PollKey::Stderr => self.read_stderr(),
            PollKey::ExecErr => {
                self.read_exec_error();
                Ok(())
            }
            PollKey::Sigchld => self.handle_sigchld(),
            PollKey::Pidfd => self.reap_children(),
            PollKey::OwnerPidfd => {
                self.close_owner_pidfd();
                self.request_cancellation("owner-exit");
                Ok(())
            }
            PollKey::Cgroup => {
                self.handle_cgroup_event();
                Ok(())
            }
        }
    }

    fn handle_sigchld(&mut self) -> io::Result<()> {
        let signals = self.sigchld.drain();
        if signals.cancel_requested {
            self.request_cancellation("cancel-request");
        }
        self.reap_children()
    }

    fn poll_timeout(&self) -> Option<Duration> {
        if self.cancellation.is_some() {
            Some(CANCEL_POLL)
        } else if self.meta.cancel_owner.is_some() && self.owner_pidfd.is_none() {
            Some(OWNER_POLL)
        } else {
            None
        }
    }

    fn check_polled_owner(&mut self) {
        if self.owner_pidfd.is_some() || self.cancellation.is_some() {
            return;
        }
        let Some(owner) = self.meta.cancel_owner.as_ref() else {
            return;
        };
        if !state::process_identity_is_live(owner) {
            self.request_cancellation("owner-exit");
        }
    }

    fn close_owner_pidfd(&mut self) {
        if let Some(fd) = self.owner_pidfd.take() {
            close_fd(fd);
        }
    }

    fn request_cancellation(&mut self, reason: &'static str) {
        if self.cancellation.is_none() {
            self.cancellation = Some(Cancellation {
                reason,
                started_at: Instant::now(),
            });
        }
        self.drive_cancellation();
    }

    fn drive_cancellation(&mut self) {
        let Some(cancellation) = self.cancellation.as_mut() else {
            return;
        };
        let signal = if cancellation.started_at.elapsed() >= CANCEL_GRACE {
            libc::SIGKILL
        } else {
            libc::SIGTERM
        };
        signal_descendants(current_pid(), signal);
    }

    fn handle_cgroup_event(&self) {
        let Some(cgroup) = &self.cgroup else {
            return;
        };
        cgroup.drain_inotify();
        let _ = cgroup.populated();
        let _ = cgroup.live_pids();
    }

    fn read_stdout(&mut self) -> io::Result<()> {
        let Some(fd) = self.stdout_fd else {
            return Ok(());
        };
        let available = read_available(fd)?;
        self.handle_stdout_chunks(&available.chunks)?;
        self.close_stdout_if_closed(fd, available.closed);
        Ok(())
    }

    fn handle_stdout_chunks(&mut self, chunks: &[Vec<u8>]) -> io::Result<()> {
        for bytes in chunks {
            self.handle_stdout_bytes(bytes)?;
        }
        Ok(())
    }

    fn handle_stdout_bytes(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.log.write_all(bytes)?;
        if self.stdout_reaches_sentinel(bytes) {
            self.record_ready_sentinel()?;
        }
        Ok(())
    }

    fn stdout_reaches_sentinel(&mut self, bytes: &[u8]) -> bool {
        let Some(matcher) = &mut self.sentinel else {
            return false;
        };
        !self.completion_recorded && matcher.push_stdout(bytes)
    }

    fn close_stdout_if_closed(&mut self, fd: RawFd, closed: bool) {
        if !closed {
            return;
        }
        close_fd(fd);
        self.stdout_fd = None;
    }

    fn read_stderr(&mut self) -> io::Result<()> {
        let Some(fd) = self.stderr_fd else {
            return Ok(());
        };
        let available = read_available(fd)?;
        self.write_stderr_chunks(&available.chunks)?;
        self.close_stderr_if_closed(fd, available.closed);
        Ok(())
    }

    fn write_stderr_chunks(&mut self, chunks: &[Vec<u8>]) -> io::Result<()> {
        for bytes in chunks {
            self.log.write_all(bytes)?;
        }
        Ok(())
    }

    fn close_stderr_if_closed(&mut self, fd: RawFd, closed: bool) {
        if !closed {
            return;
        }
        close_fd(fd);
        self.stderr_fd = None;
    }

    fn read_exec_error(&mut self) {
        let Some(fd) = self.exec_err_fd else {
            return;
        };
        match read_available(fd) {
            Ok(available) => self.handle_exec_error_read(fd, available),
            Err(err) => self.record_exec_error_read_failure(fd, err),
        }
    }

    fn handle_exec_error_read(&mut self, fd: RawFd, available: AvailableRead) {
        self.record_exec_error_chunks(&available.chunks);
        self.close_exec_error_if_closed(fd, available.closed);
    }

    fn record_exec_error_chunks(&mut self, chunks: &[Vec<u8>]) {
        for bytes in chunks {
            self.spawn_error = Some(exec_error_message(bytes));
        }
    }

    fn close_exec_error_if_closed(&mut self, fd: RawFd, closed: bool) {
        if !closed {
            return;
        }
        close_fd(fd);
        self.exec_err_fd = None;
    }

    fn record_exec_error_read_failure(&mut self, fd: RawFd, err: io::Error) {
        self.spawn_error = Some(err.to_string());
        close_fd(fd);
        self.exec_err_fd = None;
    }

    fn reap_children(&mut self) -> io::Result<()> {
        loop {
            let mut status = 0;
            let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
            if pid > 0 {
                if pid == self.root_pid {
                    self.record_root_status(status)?;
                }
                continue;
            }
            if pid == 0 {
                self.tree_empty = false;
                return Ok(());
            }
            let err = io::Error::last_os_error();
            if matches!(err.raw_os_error(), Some(libc::ECHILD)) {
                self.tree_empty = true;
                return Ok(());
            }
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
    }

    fn record_root_status(&mut self, status: i32) -> io::Result<()> {
        let root_status = status_to_root_status(status);
        self.root_status = Some(root_status);
        apply_root_status_metadata(&mut self.meta, root_status);
        state::write_meta_atomic(&self.paths, &self.meta)?;
        self.close_root_pidfd();
        Ok(())
    }

    fn close_root_pidfd(&mut self) {
        let Some(fd) = self.root_pidfd.take() else {
            return;
        };
        close_fd(fd);
    }

    fn maybe_finish(&mut self) -> io::Result<()> {
        match finish_decision(self) {
            FinishDecision::None => Ok(()),
            FinishDecision::SpawnError(message) => self.record_supervisor_error_in_loop(message),
            FinishDecision::Exit {
                root_status,
                reason,
            } => self.record_exit_completion(root_status, reason),
        }
    }

    fn apply_ready_sentinel_metadata(&mut self, now: u64) {
        apply_ready_sentinel_metadata(&mut self.meta, now);
    }

    fn apply_exit_completion_metadata(&mut self, root_status: RootStatus, reason: &str) {
        apply_exit_completion_metadata(&mut self.meta, root_status, reason);
    }

    fn apply_supervisor_error_metadata(&mut self, message: String) {
        apply_supervisor_error_metadata(&mut self.meta, message);
    }

    fn persist_completion_and_delivery(&mut self) -> io::Result<()> {
        state::write_meta_atomic(&self.paths, &self.meta)?;
        delivery::complete(&self.paths, &mut self.meta)?;
        self.completion_recorded = true;
        Ok(())
    }

    fn output_closed(&self) -> bool {
        self.stdout_fd.is_none() && self.stderr_fd.is_none() && self.exec_err_fd.is_none()
    }

    fn should_exit(&self) -> bool {
        self.completion_recorded
            && self.root_status.is_some()
            && self.completion_scope.is_complete(self.tree_empty)
            && self.output_closed()
    }

    fn record_ready_sentinel(&mut self) -> io::Result<()> {
        let now = state::unix_ms();
        self.log.sync_all()?;
        state::write_rc_atomic(&self.paths, 0)?;
        self.apply_ready_sentinel_metadata(now);
        self.persist_completion_and_delivery()
    }

    fn record_exit_completion(&mut self, root_status: RootStatus, reason: &str) -> io::Result<()> {
        self.log.sync_all()?;
        state::write_rc_atomic(&self.paths, root_status.rc)?;
        self.apply_exit_completion_metadata(root_status, reason);
        self.persist_completion_and_delivery()
    }

    fn record_supervisor_error_in_loop(&mut self, message: String) -> io::Result<()> {
        self.log.sync_all()?;
        state::write_rc_atomic(&self.paths, EX_SOFTWARE)?;
        self.apply_supervisor_error_metadata(message);
        self.persist_completion_and_delivery()
    }
}

struct AvailableRead {
    chunks: Vec<Vec<u8>>,
    closed: bool,
}

enum FdRead {
    Bytes(Vec<u8>),
    Closed,
    Pending,
}

fn read_available(fd: RawFd) -> io::Result<AvailableRead> {
    let mut chunks = Vec::new();
    let mut buf = [0_u8; 8192];
    loop {
        match read_fd_chunk(fd, &mut buf)? {
            FdRead::Bytes(bytes) => chunks.push(bytes),
            FdRead::Closed => return Ok(available_read(chunks, true)),
            FdRead::Pending => return Ok(available_read(chunks, false)),
        }
    }
}

fn read_fd_chunk(fd: RawFd, buf: &mut [u8]) -> io::Result<FdRead> {
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
    if n > 0 {
        return Ok(FdRead::Bytes(
            buf[..usize::try_from(n).unwrap_or(0)].to_vec(),
        ));
    }
    if n == 0 {
        return Ok(FdRead::Closed);
    }
    let err = io::Error::last_os_error();
    if matches!(err.raw_os_error(), Some(libc::EAGAIN)) {
        return Ok(FdRead::Pending);
    }
    if err.kind() == io::ErrorKind::Interrupted {
        return Ok(FdRead::Pending);
    }
    Err(err)
}

fn available_read(chunks: Vec<Vec<u8>>, closed: bool) -> AvailableRead {
    AvailableRead { chunks, closed }
}

fn exec_error_message(bytes: &[u8]) -> String {
    match exec_error_errno(bytes) {
        Some(errno) => io::Error::from_raw_os_error(errno).to_string(),
        None => "exec setup failed".to_string(),
    }
}

fn exec_error_errno(bytes: &[u8]) -> Option<i32> {
    let bytes: [u8; 4] = bytes.try_into().ok()?;
    Some(i32::from_ne_bytes(bytes))
}

enum FinishDecision {
    None,
    SpawnError(String),
    Exit {
        root_status: RootStatus,
        reason: &'static str,
    },
}

fn finish_decision(loop_state: &EventLoop) -> FinishDecision {
    if loop_state.completion_recorded {
        return FinishDecision::None;
    }
    if spawn_error_complete(loop_state) {
        return FinishDecision::SpawnError(spawn_error_message_for_completion(loop_state));
    }
    let Some(root_status) = loop_state.root_status else {
        return FinishDecision::None;
    };
    if !exit_completion_ready(loop_state) {
        return FinishDecision::None;
    }
    FinishDecision::Exit {
        root_status,
        reason: exit_completion_reason(loop_state),
    }
}

fn spawn_error_complete(loop_state: &EventLoop) -> bool {
    loop_state.spawn_error.is_some()
        && loop_state.root_status.is_some()
        && loop_state.tree_empty
        && loop_state.output_closed()
}

fn spawn_error_message_for_completion(loop_state: &EventLoop) -> String {
    let message = loop_state.spawn_error.clone().unwrap_or_default();
    format!("workload spawn failed: {message}")
}

fn exit_completion_ready(loop_state: &EventLoop) -> bool {
    loop_state
        .completion_scope
        .is_complete(loop_state.tree_empty)
        && loop_state.output_closed()
}

impl CompletionScope {
    fn is_complete(self, tree_empty: bool) -> bool {
        self == Self::Root || tree_empty
    }
}

fn exit_completion_reason(loop_state: &EventLoop) -> &'static str {
    if let Some(cancellation) = &loop_state.cancellation {
        cancellation.reason
    } else if loop_state.sentinel.is_some() {
        "exit-before-ready"
    } else {
        "exit"
    }
}

fn apply_root_status_metadata(meta: &mut Meta, root_status: RootStatus) {
    meta.workload_rc = Some(root_status.rc);
    meta.workload_signal = root_status.signal;
    meta.touch();
}

fn apply_ready_sentinel_metadata(meta: &mut Meta, now: u64) {
    meta.state = "DONE".to_string();
    meta.completion_reason = Some("ready-sentinel".to_string());
    meta.rc = Some(0);
    meta.signal = None;
    meta.ready_at_unix_ms = Some(now);
    meta.completed_at_unix_ms = Some(now);
    meta.touch();
}

fn apply_exit_completion_metadata(meta: &mut Meta, root_status: RootStatus, reason: &str) {
    meta.state = "DONE".to_string();
    meta.completion_reason = Some(reason.to_string());
    meta.rc = Some(root_status.rc);
    meta.signal = root_status.signal;
    meta.completed_at_unix_ms = Some(state::unix_ms());
    meta.touch();
}

fn apply_supervisor_error_metadata(meta: &mut Meta, message: String) {
    meta.state = "ERROR".to_string();
    meta.completion_reason = Some("supervisor-error".to_string());
    meta.rc = Some(EX_SOFTWARE);
    meta.error = Some(message);
    meta.completed_at_unix_ms = Some(state::unix_ms());
    meta.touch();
}

fn status_to_root_status(status: i32) -> RootStatus {
    if libc::WIFEXITED(status) {
        RootStatus {
            rc: libc::WEXITSTATUS(status),
            signal: None,
        }
    } else if libc::WIFSIGNALED(status) {
        let signal = libc::WTERMSIG(status);
        RootStatus {
            rc: signal_to_shell_rc(signal),
            signal: Some(signal),
        }
    } else {
        RootStatus {
            rc: EX_SOFTWARE,
            signal: None,
        }
    }
}

pub(crate) fn signal_to_shell_rc(signal: i32) -> i32 {
    128 + signal
}

fn record_supervisor_error(
    paths: &StatePaths,
    meta: &mut Meta,
    message: String,
    log: Option<&mut BoundedLog>,
) -> io::Result<()> {
    sync_optional_log(log)?;
    state::write_rc_atomic(paths, EX_SOFTWARE)?;
    apply_supervisor_error_metadata(meta, message);
    persist_meta_with_delivery(paths, meta)
}

fn sync_optional_log(log: Option<&mut BoundedLog>) -> io::Result<()> {
    let Some(log) = log else {
        return Ok(());
    };
    log.sync_all()
}

fn persist_meta_with_delivery(paths: &StatePaths, meta: &mut Meta) -> io::Result<()> {
    state::write_meta_atomic(paths, meta)?;
    delivery::complete(paths, meta)
}

pub(crate) fn reconcile_lost_supervisor(paths: &StatePaths) -> io::Result<Meta> {
    reconcile_lost_supervisor_with_delivery(paths, true)
}

pub(crate) fn reconcile_lost_supervisor_without_delivery(paths: &StatePaths) -> io::Result<Meta> {
    reconcile_lost_supervisor_with_delivery(paths, false)
}

fn reconcile_lost_supervisor_with_delivery(paths: &StatePaths, deliver: bool) -> io::Result<Meta> {
    let _lock = state::lock_reconciliation(paths)?;
    let mut meta = state::read_meta(paths)?;
    if state::terminal(&meta) {
        if deliver {
            delivery::complete(paths, &mut meta)?;
        }
        return Ok(meta);
    }
    if !state::exact_supervisor_and_workload_are_gone(&meta) {
        return Ok(meta);
    }

    state::write_rc_atomic(paths, EX_SOFTWARE)?;
    apply_lost_supervisor_metadata(&mut meta);
    if deliver {
        persist_meta_with_delivery(paths, &mut meta)?;
    } else {
        state::write_meta_atomic(paths, &meta)?;
    }
    Ok(meta)
}

fn apply_lost_supervisor_metadata(meta: &mut Meta) {
    meta.state = "ERROR".to_string();
    meta.completion_reason = Some("supervisor-lost".to_string());
    meta.rc = Some(EX_SOFTWARE);
    meta.signal = None;
    meta.completed_at_unix_ms = Some(state::unix_ms());
    meta.error = Some("supervisor and workload process identities are gone".to_string());
    meta.touch();
}

impl Drop for EventLoop {
    fn drop(&mut self) {
        if let Some(fd) = self.stdout_fd.take() {
            close_fd(fd);
        }
        if let Some(fd) = self.stderr_fd.take() {
            close_fd(fd);
        }
        if let Some(fd) = self.exec_err_fd.take() {
            close_fd(fd);
        }
        if let Some(fd) = self.root_pidfd.take() {
            close_fd(fd);
        }
        self.close_owner_pidfd();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sentinel_matches_stdout_only() {
        let regex = Regex::new("READY:[0-9]+").expect("regex");
        let mut matcher = SentinelMatcher::new(regex, "READY:[0-9]+".len());
        assert!(!matcher.push_stdout(b"READY"));
        assert!(matcher.push_stdout(b":123"));

        let regex = Regex::new("ERRREADY").expect("regex");
        let matcher = SentinelMatcher::new(regex, "ERRREADY".len());
        assert!(!matcher.regex.is_match(b"stderr is not passed here"));
    }

    #[test]
    fn signal_to_shell_rc_maps_signal() {
        assert_eq!(signal_to_shell_rc(15), 143);
    }

    #[test]
    fn bounded_log_discards_old_output_and_retains_newest_bytes() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("log");
        let file = std::fs::OpenOptions::new()
            .create_new(true)
            .append(true)
            .read(true)
            .open(&path)
            .expect("create log");
        let mut log = BoundedLog::new(file, 128).expect("bounded log");

        log.write_all(&[b'a'; 100]).expect("write old output");
        log.write_all(&[b'b'; 100]).expect("write new output");
        log.sync_all().expect("sync log");

        let retained = std::fs::read(path).expect("read retained log");
        assert_eq!(retained.len(), 128);
        assert!(retained.starts_with(LOG_TRUNCATED_MARKER));
        assert!(
            retained[LOG_TRUNCATED_MARKER.len()..]
                .iter()
                .all(|byte| *byte == b'b')
        );
    }

    #[test]
    fn bounded_log_caps_a_single_oversized_chunk() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("log");
        let file = std::fs::OpenOptions::new()
            .create_new(true)
            .append(true)
            .read(true)
            .open(&path)
            .expect("create log");
        let mut log = BoundedLog::new(file, 96).expect("bounded log");

        log.write_all(&[b'x'; 4096]).expect("write large output");

        let retained = std::fs::read(path).expect("read retained log");
        assert_eq!(retained.len(), 96);
        assert!(retained.starts_with(LOG_TRUNCATED_MARKER));
        assert!(
            retained[LOG_TRUNCATED_MARKER.len()..]
                .iter()
                .all(|byte| *byte == b'x')
        );
    }
}
