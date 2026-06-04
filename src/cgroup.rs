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
        fs::read_to_string(self.path.join("cgroup.events"))
            .ok()
            .and_then(|contents| parse_cgroup_events_populated(&contents))
    }

    pub(crate) fn live_pids(&self) -> io::Result<Vec<libc::pid_t>> {
        let contents = fs::read_to_string(self.path.join("cgroup.procs"))?;
        Ok(contents
            .lines()
            .filter_map(|line| line.trim().parse::<libc::pid_t>().ok())
            .collect())
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
    if std::env::var_os("AGENT_BASH_DISABLE_CGROUP").is_some() {
        return CgroupSetup {
            meta: CgroupMeta::subreaper_only(),
            active: None,
        };
    }
    try_setup(handle).unwrap_or_else(|| CgroupSetup {
        meta: CgroupMeta::subreaper_only(),
        active: None,
    })
}

fn try_setup(handle: &str) -> Option<CgroupSetup> {
    let mountinfo = fs::read_to_string("/proc/self/mountinfo").ok()?;
    let mount = parse_mountinfo_cgroup2_mount(&mountinfo)?;
    let cgroup = fs::read_to_string("/proc/self/cgroup").ok()?;
    let relative = parse_proc_self_cgroup_v2_entry(&cgroup)?;
    let current = if relative == "/" {
        mount
    } else {
        mount.join(relative.trim_start_matches('/'))
    };
    let child = current.join(format!("agent-bash-{handle}"));
    fs::create_dir(&child).ok()?;
    match open_raw(
        &child.join("cgroup.procs"),
        libc::O_WRONLY | libc::O_CLOEXEC,
    ) {
        Ok(procs_fd) => {
            let events_fd = match open_raw(
                &child.join("cgroup.events"),
                libc::O_RDONLY | libc::O_CLOEXEC,
            ) {
                Ok(fd) => fd,
                Err(_) => {
                    unsafe {
                        libc::close(procs_fd);
                    }
                    let _ = fs::remove_dir(&child);
                    return None;
                }
            };
            let (inotify_fd, watch_descriptor) = match setup_inotify(&child.join("cgroup.events")) {
                Ok(watch) => watch,
                Err(_) => {
                    unsafe {
                        libc::close(events_fd);
                        libc::close(procs_fd);
                    }
                    let _ = fs::remove_dir(&child);
                    return None;
                }
            };
            let active = ActiveCgroup {
                path: child.clone(),
                procs_fd,
                events_watch_fd: Some(events_fd),
                inotify_fd,
                watch_descriptor,
            };
            Some(CgroupSetup {
                meta: CgroupMeta {
                    mode: "v2".to_string(),
                    path: Some(child.display().to_string()),
                    delegated: true,
                    events_watch: true,
                    degraded_reason: None,
                },
                active: Some(active),
            })
        }
        Err(_) => {
            let _ = fs::remove_dir(&child);
            None
        }
    }
}

fn open_raw(path: &Path, flags: libc::c_int) -> io::Result<RawFd> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let fd = unsafe { libc::open(c_path.as_ptr(), flags) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd)
    }
}

fn setup_inotify(events_path: &Path) -> io::Result<(Option<RawFd>, Option<i32>)> {
    let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let c_path = std::ffi::CString::new(events_path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let wd = unsafe { libc::inotify_add_watch(fd, c_path.as_ptr(), libc::IN_MODIFY) };
    if wd < 0 {
        let err = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }
    Ok((Some(fd), Some(wd)))
}

pub(crate) fn write_pid_to_procs_fd(fd: RawFd, pid: libc::pid_t) -> libc::c_int {
    let mut buf = [0_u8; 32];
    let mut value = pid as i64;
    if value < 0 {
        return -1;
    }
    let mut digits = [0_u8; 20];
    let mut len = 0;
    if value == 0 {
        digits[0] = b'0';
        len = 1;
    } else {
        while value > 0 {
            digits[len] = b'0' + u8::try_from(value % 10).unwrap_or(0);
            value /= 10;
            len += 1;
        }
    }
    for index in 0..len {
        buf[index] = digits[len - index - 1];
    }
    buf[len] = b'\n';
    let total = len + 1;
    let written = unsafe { libc::write(fd, buf.as_ptr().cast::<libc::c_void>(), total) };
    if written == isize::try_from(total).unwrap_or(-1) {
        0
    } else {
        -1
    }
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
