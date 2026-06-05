use std::fs;
use std::io;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::state::CgroupMeta;

pub(crate) struct CgroupSetup {
    pub(crate) meta: CgroupMeta,
    pub(crate) active: Option<ActiveCgroup>,
}

pub(crate) struct ActiveCgroup {
    path: PathBuf,
    procs_fd: RawFd,
    events_watch_fd: Option<RawFd>,
    inotify_fd: Option<RawFd>,
    watch_descriptor: Option<i32>,
}

impl ActiveCgroup {
    pub(crate) fn procs_fd(&self) -> RawFd {
        self.procs_fd
    }

    pub(crate) fn inotify_fd(&self) -> Option<RawFd> {
        self.inotify_fd
    }

    pub(crate) fn drain_inotify(&self) {
        if let Some(fd) = self.inotify_fd {
            let mut buf = [0_u8; 4096];
            loop {
                let n =
                    unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
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

    pub(crate) fn populated(&self) -> Option<bool> {
        let contents = read_cgroup_events(&self.path)?;
        parse_cgroup_events_populated(&contents)
    }

    pub(crate) fn live_pids(&self) -> io::Result<Vec<libc::pid_t>> {
        let contents = read_cgroup_procs(&self.path)?;
        Ok(parse_cgroup_pid_lines(&contents))
    }
}

impl Drop for ActiveCgroup {
    fn drop(&mut self) {
        if let (Some(inotify_fd), Some(wd)) = (self.inotify_fd, self.watch_descriptor) {
            unsafe {
                libc::inotify_rm_watch(inotify_fd, wd);
            }
        }
        if let Some(fd) = self.events_watch_fd.take() {
            unsafe {
                libc::close(fd);
            }
        }
        if let Some(fd) = self.inotify_fd.take() {
            unsafe {
                libc::close(fd);
            }
        }
        unsafe {
            libc::close(self.procs_fd);
        }
        let _ = fs::remove_dir(&self.path);
    }
}

pub(crate) fn setup(handle: &str) -> CgroupSetup {
    if cgroup_disabled() {
        return subreaper_only_setup();
    }
    try_setup(handle).unwrap_or_else(subreaper_only_setup)
}

fn try_setup(handle: &str) -> Option<CgroupSetup> {
    let mountinfo = read_mountinfo_text()?;
    let mount = parse_mountinfo_cgroup2_mount(&mountinfo)?;
    let cgroup = read_self_cgroup_text()?;
    let relative = parse_proc_self_cgroup_v2_entry(&cgroup)?;
    let current = current_cgroup_path(mount, &relative);
    let child = child_cgroup_path(&current, handle);
    fs::create_dir(&child).ok()?;
    match open_cgroup_procs(&child) {
        Ok(procs_fd) => {
            let events_fd = match open_cgroup_events(&child) {
                Ok(fd) => fd,
                Err(_) => {
                    close_fd(procs_fd);
                    remove_child_cgroup(&child);
                    return None;
                }
            };
            let (inotify_fd, watch_descriptor) = match setup_inotify(&cgroup_events_path(&child)) {
                Ok(watch) => watch,
                Err(_) => {
                    close_fd(events_fd);
                    close_fd(procs_fd);
                    remove_child_cgroup(&child);
                    return None;
                }
            };
            let active = active_cgroup(
                child.clone(),
                procs_fd,
                events_fd,
                inotify_fd,
                watch_descriptor,
            );
            Some(CgroupSetup {
                meta: cgroup_v2_meta(&child),
                active: Some(active),
            })
        }
        Err(_) => {
            remove_child_cgroup(&child);
            None
        }
    }
}

fn open_raw(path: &Path, flags: libc::c_int) -> io::Result<RawFd> {
    let c_path = path_cstring(path)?;
    open_raw_cstring(&c_path, flags)
}

fn open_raw_cstring(c_path: &std::ffi::CString, flags: libc::c_int) -> io::Result<RawFd> {
    let fd = unsafe { libc::open(c_path.as_ptr(), flags) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd)
    }
}

fn setup_inotify(events_path: &Path) -> io::Result<(Option<RawFd>, Option<i32>)> {
    let fd = create_inotify_fd()?;
    let c_path = path_cstring(events_path)?;
    let wd = add_inotify_watch(fd, &c_path);
    if wd < 0 {
        let err = io::Error::last_os_error();
        close_fd(fd);
        return Err(err);
    }
    Ok((Some(fd), Some(wd)))
}

pub(crate) fn write_pid_to_procs_fd(fd: RawFd, pid: libc::pid_t) -> libc::c_int {
    let Some(bytes) = format_pid_line(pid) else {
        return -1;
    };
    if write_fd_all(fd, &bytes) { 0 } else { -1 }
}

fn read_cgroup_events(path: &Path) -> Option<String> {
    fs::read_to_string(cgroup_events_path(path)).ok()
}

fn read_cgroup_procs(path: &Path) -> io::Result<String> {
    fs::read_to_string(cgroup_procs_path(path))
}

fn parse_cgroup_pid_lines(contents: &str) -> Vec<libc::pid_t> {
    contents.lines().filter_map(parse_cgroup_pid_line).collect()
}

fn parse_cgroup_pid_line(line: &str) -> Option<libc::pid_t> {
    line.trim().parse::<libc::pid_t>().ok()
}

fn cgroup_disabled() -> bool {
    std::env::var_os("AGENT_BASH_DISABLE_CGROUP").is_some()
}

fn subreaper_only_setup() -> CgroupSetup {
    CgroupSetup {
        meta: CgroupMeta::subreaper_only(),
        active: None,
    }
}

fn read_mountinfo_text() -> Option<String> {
    fs::read_to_string("/proc/self/mountinfo").ok()
}

fn read_self_cgroup_text() -> Option<String> {
    fs::read_to_string("/proc/self/cgroup").ok()
}

fn current_cgroup_path(mount: PathBuf, relative: &str) -> PathBuf {
    if relative == "/" {
        return mount;
    }
    mount.join(relative.trim_start_matches('/'))
}

fn child_cgroup_path(current: &Path, handle: &str) -> PathBuf {
    current.join(format!("agent-bash-{handle}"))
}

fn cgroup_procs_path(path: &Path) -> PathBuf {
    path.join("cgroup.procs")
}

fn cgroup_events_path(path: &Path) -> PathBuf {
    path.join("cgroup.events")
}

fn open_cgroup_procs(child: &Path) -> io::Result<RawFd> {
    open_raw(&cgroup_procs_path(child), libc::O_WRONLY | libc::O_CLOEXEC)
}

fn open_cgroup_events(child: &Path) -> io::Result<RawFd> {
    open_raw(&cgroup_events_path(child), libc::O_RDONLY | libc::O_CLOEXEC)
}

fn active_cgroup(
    path: PathBuf,
    procs_fd: RawFd,
    events_fd: RawFd,
    inotify_fd: Option<RawFd>,
    watch_descriptor: Option<i32>,
) -> ActiveCgroup {
    ActiveCgroup {
        path,
        procs_fd,
        events_watch_fd: Some(events_fd),
        inotify_fd,
        watch_descriptor,
    }
}

fn cgroup_v2_meta(path: &Path) -> CgroupMeta {
    CgroupMeta {
        mode: "v2".to_string(),
        path: Some(path_display_string(path)),
        delegated: true,
        events_watch: true,
        degraded_reason: None,
    }
}

fn path_display_string(path: &Path) -> String {
    path.display().to_string()
}

fn remove_child_cgroup(path: &Path) {
    let _ = fs::remove_dir(path);
}

fn close_fd(fd: RawFd) {
    unsafe {
        libc::close(fd);
    }
}

fn path_cstring(path: &Path) -> io::Result<std::ffi::CString> {
    std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
}

fn create_inotify_fd() -> io::Result<RawFd> {
    let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd)
    }
}

fn add_inotify_watch(fd: RawFd, c_path: &std::ffi::CString) -> i32 {
    unsafe { libc::inotify_add_watch(fd, c_path.as_ptr(), libc::IN_MODIFY) }
}

fn format_pid_line(pid: libc::pid_t) -> Option<Vec<u8>> {
    let pid = validate_nonnegative_pid(pid)?;
    Some(format_valid_pid_line(pid))
}

fn validate_nonnegative_pid(pid: libc::pid_t) -> Option<libc::pid_t> {
    if pid < 0 { None } else { Some(pid) }
}

fn format_valid_pid_line(pid: libc::pid_t) -> Vec<u8> {
    format!("{pid}\n").into_bytes()
}

fn write_fd_all(fd: RawFd, bytes: &[u8]) -> bool {
    let written = unsafe { libc::write(fd, bytes.as_ptr().cast::<libc::c_void>(), bytes.len()) };
    written == isize::try_from(bytes.len()).unwrap_or(-1)
}

pub(crate) fn parse_proc_self_cgroup_v2_entry(contents: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        let mut parts = line.splitn(3, ':');
        let hierarchy = parts.next()?;
        let controllers = parts.next()?;
        let path = parts.next()?;
        if hierarchy == "0" && controllers.is_empty() {
            Some(path.to_string())
        } else {
            None
        }
    })
}

pub(crate) fn parse_mountinfo_cgroup2_mount(contents: &str) -> Option<PathBuf> {
    contents.lines().find_map(|line| {
        let (before, after) = line.split_once(" - ")?;
        let mut after_fields = after.split_whitespace();
        if after_fields.next()? != "cgroup2" {
            return None;
        }
        let mountpoint = before.split_whitespace().nth(4)?;
        Some(PathBuf::from(unescape_mountinfo(mountpoint)))
    })
}

fn unescape_mountinfo(value: &str) -> String {
    value
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

pub(crate) fn parse_cgroup_events_populated(contents: &str) -> Option<bool> {
    contents.lines().find_map(|line| {
        let value = line.strip_prefix("populated ")?;
        match value.trim() {
            "0" => Some(false),
            "1" => Some(true),
            _ => None,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_proc_self_cgroup_v2_entry() {
        let contents = "11:memory:/user.slice\n0::/user.slice/user-1000.slice/session.scope\n";
        assert_eq!(
            super::parse_proc_self_cgroup_v2_entry(contents).as_deref(),
            Some("/user.slice/user-1000.slice/session.scope")
        );
    }

    #[test]
    fn parse_mountinfo_cgroup2_mount() {
        let contents =
            "25 23 0:21 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw\n";
        assert_eq!(
            super::parse_mountinfo_cgroup2_mount(contents).as_deref(),
            Some(Path::new("/sys/fs/cgroup"))
        );
    }

    #[test]
    fn parse_cgroup_events_populated() {
        assert_eq!(
            super::parse_cgroup_events_populated("populated 0\nfrozen 0\n"),
            Some(false)
        );
        assert_eq!(
            super::parse_cgroup_events_populated("populated 1\nfrozen 0\n"),
            Some(true)
        );
    }

    #[test]
    fn subreaper_only_when_no_mount_or_unwritable() {
        assert!(super::parse_mountinfo_cgroup2_mount("no cgroup here").is_none());
        let setup = CgroupSetup {
            meta: CgroupMeta::subreaper_only(),
            active: None,
        };
        assert_eq!(setup.meta.mode, "subreaper-only");
        assert!(setup.active.is_none());
    }
}
