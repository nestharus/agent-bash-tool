use std::ffi::CString;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::RawFd;

use regex::bytes::Regex;

use crate::cgroup::{self, ActiveCgroup};
use crate::delivery;
use crate::state::{self, Meta, StatePaths};

const EX_SOFTWARE: i32 = 70;
const ONE_MIB: usize = 1024 * 1024;

#[derive(Clone)]
pub(crate) struct SupervisorConfig {
    pub(crate) paths: StatePaths,
    pub(crate) meta: Meta,
    pub(crate) argv: Vec<String>,
    pub(crate) ready_sentinel: Option<String>,
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

unsafe fn daemonization_child(config: SupervisorConfig) -> ! {
    redirect_stdio_to_devnull();
    if unsafe { libc::setsid() } < 0 {
        unsafe { libc::_exit(EX_SOFTWARE) };
    }
    match unsafe { libc::fork() } {
        -1 => unsafe { libc::_exit(EX_SOFTWARE) },
        0 => {
            let code = run_supervisor(config);
            unsafe { libc::_exit(code) };
        }
        _ => unsafe { libc::_exit(0) },
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
    unsafe {
        libc::umask(0o077);
    }
    let mut meta = config.meta;
    meta.supervisor_pid = Some(unsafe { libc::getpid() });
    meta.touch();

    let mut log = match state::open_log_append(&config.paths) {
        Ok(file) => file,
        Err(err) => {
            let _ = record_supervisor_error(
                &config.paths,
                &mut meta,
                format!("open log failed: {err}"),
                None,
            );
            return EX_SOFTWARE;
        }
    };

    if let Err(err) = set_subreaper() {
        let _ = record_supervisor_error(
            &config.paths,
            &mut meta,
            format!("PR_SET_CHILD_SUBREAPER failed: {err}"),
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
                format!("signalfd failed: {err}"),
                Some(&mut log),
            );
            return EX_SOFTWARE;
        }
    };

    let cgroup_setup = cgroup::setup(&meta.handle);
    meta.cgroup = cgroup_setup.meta;
    meta.touch();
    let _ = state::write_meta_atomic(&config.paths, &meta);

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
                format!("spawn failed: {err}"),
                Some(&mut log),
            );
            return EX_SOFTWARE;
        }
    };

    meta.workload_pid = Some(spawn.pid);
    meta.workload_pgid = Some(spawn.pid);
    let root_pidfd = pidfd_open(spawn.pid);
    meta.workload_pidfd = root_pidfd.is_some();
    meta.touch();
    let _ = state::write_meta_atomic(&config.paths, &meta);

    let sentinel = match config.ready_sentinel.as_ref() {
        Some(pattern) => match Regex::new(pattern) {
            Ok(regex) => Some(SentinelMatcher::new(regex, pattern.len())),
            Err(err) => {
                let _ = record_supervisor_error(
                    &config.paths,
                    &mut meta,
                    format!("invalid ready sentinel after fork: {err}"),
                    Some(&mut log),
                );
                return EX_SOFTWARE;
            }
        },
        None => None,
    };

    let result = event_loop(EventLoop {
        paths: config.paths.clone(),
        meta,
        log,
        sigchld,
        cgroup: cgroup_setup.active,
        root_pid: spawn.pid,
        root_pidfd,
        stdout_fd: Some(spawn.stdout_fd),
        stderr_fd: Some(spawn.stderr_fd),
        exec_err_fd: Some(spawn.exec_err_fd),
        root_status: None,
        tree_empty: false,
        completion_recorded: false,
        sentinel,
        spawn_error: None,
    });
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
    argv.iter()
        .map(|arg| {
            CString::new(arg.as_str()).map_err(|_| "workload argv contains NUL byte".to_string())
        })
        .collect()
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
    Ok(WorkloadSpawn {
        pid,
        stdout_fd: stdout_pipe.read,
        stderr_fd: stderr_pipe.read,
        exec_err_fd: exec_err_pipe.read,
    })
}

unsafe fn workload_child(
    c_argv: &[CString],
    stdout_pipe: &mut Pipe,
    stderr_pipe: &mut Pipe,
    exec_err_pipe: &mut Pipe,
    cgroup_procs_fd: Option<RawFd>,
) -> ! {
    unblock_sigchld();
    unsafe {
        libc::setpgid(0, 0);
    }
    if let Some(fd) = cgroup_procs_fd {
        let pid = unsafe { libc::getpid() };
        if cgroup::write_pid_to_procs_fd(fd, pid) != 0 {
            write_errno_and_exit(exec_err_pipe.write, 126);
        }
    }
    unsafe {
        libc::close(stdout_pipe.read);
        libc::close(stderr_pipe.read);
        libc::close(exec_err_pipe.read);
        libc::dup2(stdout_pipe.write, libc::STDOUT_FILENO);
        libc::dup2(stderr_pipe.write, libc::STDERR_FILENO);
    }
    let devnull = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if devnull >= 0 {
        unsafe {
            libc::dup2(devnull, libc::STDIN_FILENO);
            libc::close(devnull);
        }
    }
    unsafe {
        libc::close(stdout_pipe.write);
        libc::close(stderr_pipe.write);
    }
    let mut pointers: Vec<*const libc::c_char> = c_argv.iter().map(|arg| arg.as_ptr()).collect();
    pointers.push(std::ptr::null());
    unsafe {
        libc::execvp(pointers[0], pointers.as_ptr());
    }
    write_errno_and_exit(exec_err_pipe.write, 127);
}

fn unblock_sigchld() {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGCHLD);
        libc::sigprocmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
    }
}

fn write_errno_and_exit(fd: RawFd, code: i32) -> ! {
    let errno = io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO);
    let bytes = errno.to_ne_bytes();
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

    fn drain(&self) {
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
    }
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
        self.buffer.extend_from_slice(bytes);
        if self.buffer.len() > self.limit {
            let excess = self.buffer.len() - self.limit;
            self.buffer.drain(..excess);
        }
        self.regex.is_match(&self.buffer)
    }
}

struct EventLoop {
    paths: StatePaths,
    meta: Meta,
    log: File,
    sigchld: Sigchld,
    cgroup: Option<ActiveCgroup>,
    root_pid: libc::pid_t,
    root_pidfd: Option<RawFd>,
    stdout_fd: Option<RawFd>,
    stderr_fd: Option<RawFd>,
    exec_err_fd: Option<RawFd>,
    root_status: Option<RootStatus>,
    tree_empty: bool,
    completion_recorded: bool,
    sentinel: Option<SentinelMatcher>,
    spawn_error: Option<String>,
}

#[derive(Clone, Copy)]
enum PollKey {
    Stdout,
    Stderr,
    ExecErr,
    Sigchld,
    Pidfd,
    Cgroup,
}

fn event_loop(mut loop_state: EventLoop) -> io::Result<()> {
    loop {
        loop_state.maybe_finish()?;
        if loop_state.should_exit() {
            return Ok(());
        }

        let mut entries = Vec::new();
        if let Some(fd) = loop_state.stdout_fd {
            entries.push((
                fd,
                libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                PollKey::Stdout,
            ));
        }
        if let Some(fd) = loop_state.stderr_fd {
            entries.push((
                fd,
                libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                PollKey::Stderr,
            ));
        }
        if let Some(fd) = loop_state.exec_err_fd {
            entries.push((
                fd,
                libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                PollKey::ExecErr,
            ));
        }
        entries.push((loop_state.sigchld.fd, libc::POLLIN, PollKey::Sigchld));
        if let Some(fd) = loop_state.root_pidfd {
            entries.push((
                fd,
                libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                PollKey::Pidfd,
            ));
        }
        if let Some(fd) = loop_state
            .cgroup
            .as_ref()
            .and_then(ActiveCgroup::inotify_fd)
        {
            entries.push((fd, libc::POLLIN, PollKey::Cgroup));
        }

        let mut pollfds: Vec<libc::pollfd> = entries
            .iter()
            .map(|(fd, events, _)| libc::pollfd {
                fd: *fd,
                events: *events,
                revents: 0,
            })
            .collect();
        let rc = unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, -1) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        for (index, pollfd) in pollfds.iter().enumerate() {
            if pollfd.revents == 0 {
                continue;
            }
            match entries[index].2 {
                PollKey::Stdout => loop_state.read_stdout()?,
                PollKey::Stderr => loop_state.read_stderr()?,
                PollKey::ExecErr => loop_state.read_exec_error(),
                PollKey::Sigchld => {
                    loop_state.sigchld.drain();
                    loop_state.reap_children()?;
                }
                PollKey::Pidfd => {
                    loop_state.reap_children()?;
                }
                PollKey::Cgroup => {
                    if let Some(cgroup) = &loop_state.cgroup {
                        cgroup.drain_inotify();
                        let _ = cgroup.populated();
                        let _ = cgroup.live_pids();
                    }
                }
            }
        }
    }
}

impl EventLoop {
    fn read_stdout(&mut self) -> io::Result<()> {
        let Some(fd) = self.stdout_fd else {
            return Ok(());
        };
        let mut closed = false;
        read_available(
            fd,
            |bytes| {
                self.log.write_all(bytes)?;
                if !self.completion_recorded
                    && let Some(matcher) = &mut self.sentinel
                    && matcher.push_stdout(bytes)
                {
                    self.record_ready_sentinel()?;
                }
                Ok(())
            },
            &mut closed,
        )?;
        if closed {
            close_fd(fd);
            self.stdout_fd = None;
        }
        Ok(())
    }

    fn read_stderr(&mut self) -> io::Result<()> {
        let Some(fd) = self.stderr_fd else {
            return Ok(());
        };
        let mut closed = false;
        read_available(
            fd,
            |bytes| {
                self.log.write_all(bytes)?;
                Ok(())
            },
            &mut closed,
        )?;
        if closed {
            close_fd(fd);
            self.stderr_fd = None;
        }
        Ok(())
    }

    fn read_exec_error(&mut self) {
        let Some(fd) = self.exec_err_fd else {
            return;
        };
        let mut buf = [0_u8; 4];
        loop {
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
            if n > 0 {
                if usize::try_from(n).unwrap_or(0) == buf.len() {
                    let errno = i32::from_ne_bytes(buf);
                    self.spawn_error = Some(io::Error::from_raw_os_error(errno).to_string());
                } else {
                    self.spawn_error = Some("exec setup failed".to_string());
                }
                continue;
            }
            if n == 0 {
                close_fd(fd);
                self.exec_err_fd = None;
                break;
            }
            let err = io::Error::last_os_error();
            if matches!(err.raw_os_error(), Some(libc::EAGAIN)) {
                break;
            }
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            self.spawn_error = Some(err.to_string());
            close_fd(fd);
            self.exec_err_fd = None;
            break;
        }
    }

    fn reap_children(&mut self) -> io::Result<()> {
        loop {
            let mut status = 0;
            let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
            if pid > 0 {
                if pid == self.root_pid {
                    let root_status = status_to_root_status(status);
                    self.root_status = Some(root_status);
                    self.meta.workload_rc = Some(root_status.rc);
                    self.meta.workload_signal = root_status.signal;
                    self.meta.touch();
                    state::write_meta_atomic(&self.paths, &self.meta)?;
                    if let Some(fd) = self.root_pidfd.take() {
                        close_fd(fd);
                    }
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

    fn maybe_finish(&mut self) -> io::Result<()> {
        if self.completion_recorded {
            return Ok(());
        }
        if self.spawn_error.is_some()
            && self.root_status.is_some()
            && self.tree_empty
            && self.output_closed()
        {
            let message = self.spawn_error.clone().unwrap_or_default();
            self.record_supervisor_error_in_loop(format!("workload spawn failed: {message}"))?;
            return Ok(());
        }
        if let Some(root_status) = self.root_status
            && self.tree_empty
            && self.output_closed()
        {
            if self.sentinel.is_some() {
                self.record_exit_completion(root_status, "exit-before-ready")?;
            } else {
                self.record_exit_completion(root_status, "exit")?;
            }
        }
        Ok(())
    }

    fn output_closed(&self) -> bool {
        self.stdout_fd.is_none() && self.stderr_fd.is_none() && self.exec_err_fd.is_none()
    }

    fn should_exit(&self) -> bool {
        self.completion_recorded
            && self.root_status.is_some()
            && self.tree_empty
            && self.output_closed()
    }

    fn record_ready_sentinel(&mut self) -> io::Result<()> {
        let now = state::unix_ms();
        self.log.sync_all()?;
        state::write_rc_atomic(&self.paths, 0)?;
        self.meta.state = "DONE".to_string();
        self.meta.completion_reason = Some("ready-sentinel".to_string());
        self.meta.rc = Some(0);
        self.meta.signal = None;
        self.meta.ready_at_unix_ms = Some(now);
        self.meta.completed_at_unix_ms = Some(now);
        self.meta.touch();
        state::write_meta_atomic(&self.paths, &self.meta)?;
        self.meta.delivery =
            delivery::notify(self.meta.caller_ppid, &self.meta.handle, &self.paths);
        self.meta.touch();
        state::write_meta_atomic(&self.paths, &self.meta)?;
        self.completion_recorded = true;
        Ok(())
    }

    fn record_exit_completion(&mut self, root_status: RootStatus, reason: &str) -> io::Result<()> {
        self.log.sync_all()?;
        state::write_rc_atomic(&self.paths, root_status.rc)?;
        self.meta.state = "DONE".to_string();
        self.meta.completion_reason = Some(reason.to_string());
        self.meta.rc = Some(root_status.rc);
        self.meta.signal = root_status.signal;
        self.meta.completed_at_unix_ms = Some(state::unix_ms());
        self.meta.touch();
        state::write_meta_atomic(&self.paths, &self.meta)?;
        self.meta.delivery =
            delivery::notify(self.meta.caller_ppid, &self.meta.handle, &self.paths);
        self.meta.touch();
        state::write_meta_atomic(&self.paths, &self.meta)?;
        self.completion_recorded = true;
        Ok(())
    }

    fn record_supervisor_error_in_loop(&mut self, message: String) -> io::Result<()> {
        self.log.sync_all()?;
        state::write_rc_atomic(&self.paths, EX_SOFTWARE)?;
        self.meta.state = "ERROR".to_string();
        self.meta.completion_reason = Some("supervisor-error".to_string());
        self.meta.rc = Some(EX_SOFTWARE);
        self.meta.error = Some(message);
        self.meta.completed_at_unix_ms = Some(state::unix_ms());
        self.meta.touch();
        state::write_meta_atomic(&self.paths, &self.meta)?;
        self.meta.delivery =
            delivery::notify(self.meta.caller_ppid, &self.meta.handle, &self.paths);
        self.meta.touch();
        state::write_meta_atomic(&self.paths, &self.meta)?;
        self.completion_recorded = true;
        Ok(())
    }
}

fn read_available(
    fd: RawFd,
    mut on_bytes: impl FnMut(&[u8]) -> io::Result<()>,
    closed: &mut bool,
) -> io::Result<()> {
    let mut buf = [0_u8; 8192];
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
        if n > 0 {
            on_bytes(&buf[..usize::try_from(n).unwrap_or(0)])?;
            continue;
        }
        if n == 0 {
            *closed = true;
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if matches!(err.raw_os_error(), Some(libc::EAGAIN)) {
            return Ok(());
        }
        if err.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        *closed = true;
        return Err(err);
    }
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
    log: Option<&mut File>,
) -> io::Result<()> {
    if let Some(log) = log {
        log.sync_all()?;
    }
    state::write_rc_atomic(paths, EX_SOFTWARE)?;
    meta.state = "ERROR".to_string();
    meta.completion_reason = Some("supervisor-error".to_string());
    meta.rc = Some(EX_SOFTWARE);
    meta.error = Some(message);
    meta.completed_at_unix_ms = Some(state::unix_ms());
    meta.touch();
    state::write_meta_atomic(paths, meta)?;
    meta.delivery = delivery::notify(meta.caller_ppid, &meta.handle, paths);
    meta.touch();
    state::write_meta_atomic(paths, meta)
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
}
