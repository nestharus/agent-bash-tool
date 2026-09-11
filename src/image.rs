//! Tree-local immutable image custody. No helper commands or delivery authority cross this API.
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const SEALS: i32 = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
const REQUEST_SIZE: usize = 72;
const INTERNAL: &str = "--internal-image-custodian-v1";

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[derive(Clone, Copy)]
struct Limits {
    bytes: u64,
    count: usize,
    deadline: Duration,
}
impl Limits {
    fn from_env() -> io::Result<Self> {
        Ok(Self {
            bytes: setting("BYTES", 256 * 1024 * 1024, 1, 1024 * 1024 * 1024)?,
            count: setting("COUNT", 8, 1, 64)? as usize,
            deadline: Duration::from_millis(setting("DEADLINE_MS", 10_000, 1, 60_000)?),
        })
    }
}
fn setting(name: &str, default: u64, min: u64, max: u64) -> io::Result<u64> {
    let key = format!("AGENT_BASH_IMAGE_{name}");
    let value = match std::env::var(&key) {
        Ok(v) => v.parse().map_err(|_| invalid(format!("invalid {key}")))?,
        Err(std::env::VarError::NotPresent) => default,
        Err(_) => return Err(invalid(format!("invalid {key}"))),
    };
    if !(min..=max).contains(&value) {
        return Err(invalid(format!("{key} must be {min}..={max}")));
    }
    Ok(value)
}
fn check_time(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "image acquisition deadline",
        ))
    } else {
        Ok(())
    }
}

/// Positional reads never change a shared open-file-description offset.
pub(crate) fn read_at(file: &File, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
    loop {
        match file.read_at(buffer, offset) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            result => return result,
        }
    }
}
pub(crate) fn read_prefix(file: &File, buffer: &mut [u8]) -> io::Result<usize> {
    let mut offset = 0;
    while offset < buffer.len() {
        let n = read_at(file, &mut buffer[offset..], offset as u64)?;
        if n == 0 {
            break;
        }
        offset += n;
    }
    Ok(offset)
}
fn source_size(source: &File, limit: u64) -> io::Result<u64> {
    let m = source.metadata()?;
    if !m.is_file() || m.mode() & 0o111 == 0 || m.len() > limit {
        return Err(invalid(
            "image must be executable regular file within byte budget",
        ));
    }
    Ok(m.len())
}
fn stream(
    source: &File,
    len: u64,
    deadline: Instant,
    mut consume: impl FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<String> {
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut offset = 0;
    while offset < len {
        check_time(deadline)?;
        let want = (len - offset).min(buffer.len() as u64) as usize;
        let n = read_at(source, &mut buffer[..want], offset)?;
        if n == 0 {
            return Err(invalid("image shortened during read"));
        }
        consume(&buffer[..n])?;
        digest.update(&buffer[..n]);
        offset += n as u64;
    }
    if read_at(source, &mut buffer[..1], len)? != 0 || source.metadata()?.len() != len {
        return Err(invalid("image grew during read"));
    }
    check_time(deadline)?;
    Ok(format!("{:x}", digest.finalize()))
}
pub(crate) fn digest(source: &File) -> io::Result<String> {
    let limits = Limits::from_env()?;
    stream(
        source,
        source_size(source, limits.bytes)?,
        Instant::now() + limits.deadline,
        |_| Ok(()),
    )
}
pub(crate) fn copy(source: &File, output: &mut File) -> io::Result<()> {
    let limits = Limits::from_env()?;
    stream(
        source,
        source_size(source, limits.bytes)?,
        Instant::now() + limits.deadline,
        |b| output.write_all(b),
    )?;
    Ok(())
}
fn readonly(image: &File) -> io::Result<File> {
    let alias = File::open(format!("/proc/self/fd/{}", image.as_raw_fd()))?;
    let a = alias.metadata()?;
    let b = image.metadata()?;
    if a.dev() != b.dev() || a.ino() != b.ino() {
        return Err(invalid("image alias identity mismatch"));
    }
    Ok(alias)
}
fn verify(image: &File, len: u64, expected: &str, deadline: Instant) -> io::Result<()> {
    if source_size(image, len)? != len {
        return Err(invalid("image length mismatch"));
    }
    let seals = unsafe { libc::fcntl(image.as_raw_fd(), libc::F_GET_SEALS) };
    if seals < 0 || seals & SEALS != SEALS {
        return Err(invalid("image required seals missing"));
    }
    if stream(image, len, deadline, |_| Ok(()))? != expected {
        return Err(invalid("image digest mismatch"));
    }
    Ok(())
}
fn materialize(source: &File, len: u64, expected: &str, deadline: Instant) -> io::Result<File> {
    if source_size(source, len)? != len {
        return Err(invalid("source length mismatch"));
    }
    let name = CString::new("agent-bash-delivery-helper").unwrap();
    let raw =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut image = unsafe { File::from_raw_fd(raw) };
    if stream(source, len, deadline, |b| image.write_all(b))? != expected {
        return Err(invalid("source digest changed before publication"));
    }
    image.set_permissions(fs::Permissions::from_mode(0o500))?;
    if unsafe { libc::fcntl(raw, libc::F_ADD_SEALS, SEALS) } < 0 {
        return Err(io::Error::other(format!(
            "image F_ADD_SEALS size={len}: {}",
            io::Error::last_os_error()
        )));
    }
    readonly(&image)
}

fn socket() -> io::Result<File> {
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        let socket = unsafe { File::from_raw_fd(fd) };
        let size: libc::c_int = 4096;
        for option in [libc::SO_RCVBUF, libc::SO_SNDBUF] {
            if unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    option,
                    (&size as *const libc::c_int).cast(),
                    std::mem::size_of_val(&size) as _,
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(socket)
    }
}
fn address(pid: i32, start: u64) -> (libc::sockaddr_un, libc::socklen_t) {
    let name = format!("agent-bash-image-v1-{}-{pid}-{start}", unsafe {
        libc::geteuid()
    });
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as _;
    for (target, byte) in addr.sun_path[1..].iter_mut().zip(name.bytes()) {
        *target = byte as _;
    }
    let len = std::mem::offset_of!(libc::sockaddr_un, sun_path) + 1 + name.len();
    (addr, len as _)
}
fn connect(pid: i32, start: u64) -> io::Result<File> {
    let socket = socket()?;
    let (addr, len) = address(pid, start);
    if unsafe {
        libc::connect(
            socket.as_raw_fd(),
            (&addr as *const libc::sockaddr_un).cast(),
            len,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(socket)
}
fn tree_endpoint() -> io::Result<Option<File>> {
    // Search outermost first. No caller-supplied socket or ambient routing identity.
    let chain = crate::state::capture_caller_chain(unsafe { libc::getpid() });
    for entry in chain.iter().rev() {
        match connect(entry.pid, entry.starttime_ticks) {
            Ok(s) => return Ok(Some(s)),
            Err(e) if matches!(e.raw_os_error(), Some(libc::ECONNREFUSED | libc::ENOENT)) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(None)
}
fn ready(fd: RawFd, event: i16, deadline: Instant) -> io::Result<()> {
    loop {
        check_time(deadline)?;
        let millis = deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .max(1)
            .min(i32::MAX as u128) as i32;
        let mut p = libc::pollfd {
            fd,
            events: event,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut p, 1, millis) };
        if rc > 0 {
            return Ok(());
        }
        if rc < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(io::Error::last_os_error());
        }
    }
}
fn send(fd: RawFd, bytes: &[u8], file: Option<&File>, deadline: Instant) -> io::Result<()> {
    let mut control = [0usize; 8];
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr() as _,
        iov_len: bytes.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    if let Some(file) = file {
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = unsafe { libc::CMSG_SPACE(4) } as usize;
        unsafe {
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN(4) as usize;
            std::ptr::write_unaligned(libc::CMSG_DATA(c).cast::<i32>(), file.as_raw_fd());
        }
    }
    loop {
        ready(fd, libc::POLLOUT, deadline)?;
        let n = unsafe { libc::sendmsg(fd, &msg, libc::MSG_NOSIGNAL) };
        if n == bytes.len() as isize {
            return Ok(());
        }
        if n >= 0 {
            return Err(invalid("short image packet send"));
        }
        let e = io::Error::last_os_error();
        if !matches!(
            e.kind(),
            io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
        ) {
            return Err(e);
        }
    }
}
fn receive(fd: RawFd, deadline: Instant) -> io::Result<(Vec<u8>, Vec<File>)> {
    loop {
        ready(fd, libc::POLLIN, deadline)?;
        let mut bytes = [0u8; 512];
        let mut control = [0usize; 4];
        let mut iov = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = std::mem::size_of_val(&control);
        let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_CMSG_CLOEXEC) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if matches!(
                e.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(e);
        }
        let mut files = Vec::new();
        let mut malformed = false;
        let mut headers = 0;
        unsafe {
            let mut c = libc::CMSG_FIRSTHDR(&msg);
            while !c.is_null() {
                headers += 1;
                let base = libc::CMSG_LEN(0) as usize;
                if (*c).cmsg_len < base {
                    malformed = true;
                    break;
                }
                let size = (*c).cmsg_len - base;
                if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                    for i in 0..size / 4 {
                        files.push(File::from_raw_fd(std::ptr::read_unaligned(
                            libc::CMSG_DATA(c).add(i * 4).cast::<i32>(),
                        )));
                    }
                    malformed |= !size.is_multiple_of(4);
                } else {
                    malformed = true;
                }
                c = libc::CMSG_NXTHDR(&msg, c);
            }
        }
        if n == 0
            || msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
            || malformed
            || headers > 1
            || files.len() > 1
        {
            return Err(invalid("malformed image packet/ancillary data"));
        }
        return Ok((bytes[..n as usize].to_vec(), files));
    }
}

pub(crate) fn acquire(source: &File) -> io::Result<(File, String)> {
    let limits = Limits::from_env()?;
    let deadline = Instant::now() + limits.deadline;
    let len = source_size(source, limits.bytes)?;
    let digest = stream(source, len, deadline, |_| Ok(()))?;
    let Some(socket) = tree_endpoint()? else {
        return Ok((materialize(source, len, &digest, deadline)?, digest));
    };
    let image = request(&socket, source, len, &digest, deadline)?;
    Ok((image, digest))
}
fn request(
    socket: &File,
    source: &File,
    len: u64,
    digest: &str,
    deadline: Instant,
) -> io::Result<File> {
    let mut request = len.to_le_bytes().to_vec();
    request.extend_from_slice(digest.as_bytes());
    send(socket.as_raw_fd(), &request, Some(source), deadline)?;
    let (reply, mut files) = receive(socket.as_raw_fd(), deadline)?;
    if reply != b"I1" || files.len() != 1 {
        return Err(invalid(format!(
            "image custodian rejected acquisition: {}",
            String::from_utf8_lossy(&reply)
        )));
    }
    let image = files.pop().unwrap();
    verify(&image, len, digest, deadline)?;
    readonly(&image)
}

struct Store {
    images: HashMap<(u64, String), File>,
    bytes: u64,
    limits: Limits,
}
impl Store {
    fn serve(&mut self, socket: &File, deadline: Instant) -> io::Result<()> {
        let (request, mut files) = receive(socket.as_raw_fd(), deadline)?;
        if request.len() != REQUEST_SIZE || files.len() != 1 {
            return Err(invalid("invalid image request"));
        }
        let len = u64::from_le_bytes(request[..8].try_into().unwrap());
        let digest = std::str::from_utf8(&request[8..])
            .map_err(|_| invalid("invalid digest"))?
            .to_owned();
        if !digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid("invalid digest"));
        }
        if source_size(&files[0], self.limits.bytes)? != len {
            return Err(invalid("request source length mismatch"));
        }
        let key = (len, digest);
        if !self.images.contains_key(&key) {
            if self.images.len() >= self.limits.count
                || len > self.limits.bytes.saturating_sub(self.bytes)
            {
                return Err(invalid("image epoch capacity exhausted (no eviction)"));
            }
            let image = materialize(&files.pop().unwrap(), len, &key.1, deadline)?;
            self.images.insert(key.clone(), image);
            self.bytes += len;
        }
        send(socket.as_raw_fd(), b"I1", self.images.get(&key), deadline)
    }
}
fn authorized(socket: &File, owner: i32, start: u64) -> bool {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of_val(&cred) as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut size,
        )
    };
    rc == 0
        && cred.uid == unsafe { libc::geteuid() }
        && crate::state::capture_caller_chain(cred.pid)
            .iter()
            .any(|p| p.pid == owner && p.starttime_ticks == start)
}
fn server(listener: File, owner: i32, start: u64, limits: Limits) -> io::Result<()> {
    let mut store = Store {
        images: HashMap::new(),
        bytes: 0,
        limits,
    };
    loop {
        // No age limit: kernel parent-death custody and Owner::drop end service.
        // A periodic poll timeout is only an idle wait, never epoch retirement.
        match ready(
            listener.as_raw_fd(),
            libc::POLLIN,
            Instant::now() + limits.deadline,
        ) {
            Err(e) if e.kind() == io::ErrorKind::TimedOut => continue,
            result => result?,
        }
        let raw = unsafe {
            libc::accept4(
                listener.as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            )
        };
        if raw < 0 {
            continue;
        }
        let client = unsafe { File::from_raw_fd(raw) };
        if !authorized(&client, owner, start) {
            continue;
        }
        let deadline = Instant::now() + limits.deadline;
        if let Err(e) = store.serve(&client, deadline) {
            let text = e.to_string();
            let _ = send(raw, &text.as_bytes()[..text.len().min(512)], None, deadline);
        }
    }
}

/// Called before guard/CLI/environment capture. This clean exec has only fd 3 and null stdio.
pub(crate) fn internal_main() -> Option<i32> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.get(1).and_then(|a| a.to_str()) != Some(INTERNAL) {
        return None;
    }
    let run = || -> io::Result<()> {
        if args.len() != 7 {
            return Err(invalid("invalid custodian bootstrap"));
        }
        let number = |i: usize| -> io::Result<u64> {
            args[i]
                .to_str()
                .ok_or_else(|| invalid("bootstrap utf8"))?
                .parse()
                .map_err(|_| invalid("bootstrap integer"))
        };
        let owner = i32::try_from(number(2)?).map_err(|_| invalid("owner pid"))?;
        let start = number(3)?;
        if unsafe { libc::getppid() } != owner
            || crate::state::process_starttime_ticks(owner) != Some(start)
        {
            return Err(invalid("custodian parent changed"));
        }
        let limits = Limits {
            bytes: number(4)?,
            count: number(5)? as usize,
            deadline: Duration::from_millis(number(6)?),
        };
        if limits.bytes == 0
            || limits.bytes > 1024 * 1024 * 1024
            || limits.count == 0
            || limits.count > 64
            || limits.deadline.is_zero()
            || limits.deadline > Duration::from_secs(60)
        {
            return Err(invalid("invalid custodian limits"));
        }
        if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } < 0
            || unsafe { libc::getppid() } != owner
        {
            return Err(invalid("custodian owner lost"));
        }
        server(unsafe { File::from_raw_fd(3) }, owner, start, limits)
    };
    Some(if run().is_ok() { 0 } else { 70 })
}

pub(crate) struct Owner {
    child: Option<Child>,
    // Keep the same queue/namespace through recovery: clients never fall back locally.
    listener: Option<File>,
    limits: Limits,
    recovery: Recovery,
}

/// Rate limit spawn attempts, not session lifetime. Saturation never disables recovery.
struct Recovery {
    next: Instant,
    delay: Duration,
    launched: Instant,
}
impl Recovery {
    fn new(now: Instant) -> Self {
        Self {
            next: now,
            delay: Duration::from_secs(1),
            launched: now,
        }
    }
    fn lost(&mut self, now: Instant) {
        if now.saturating_duration_since(self.launched) >= Duration::from_secs(60) {
            self.delay = Duration::from_secs(1);
        }
        self.next = now + self.delay;
    }
    fn attempted(&mut self, now: Instant) {
        self.launched = now;
        self.next = now + self.delay;
        self.delay = (self.delay * 2).min(Duration::from_secs(30));
    }
}
impl Owner {
    pub(crate) fn start() -> io::Result<Self> {
        if tree_endpoint()?.is_some() {
            return Ok(Self {
                child: None,
                listener: None,
                limits: Limits::from_env()?,
                recovery: Recovery::new(Instant::now()),
            });
        }
        Self::launch()
    }
    fn launch() -> io::Result<Self> {
        let limits = Limits::from_env()?;
        let owner = unsafe { libc::getpid() };
        let start = crate::state::process_starttime_ticks(owner)
            .ok_or_else(|| invalid("missing owner identity"))?;
        let listener = socket()?;
        let (addr, len) = address(owner, start);
        if unsafe {
            libc::bind(
                listener.as_raw_fd(),
                (&addr as *const libc::sockaddr_un).cast(),
                len,
            )
        } < 0
            || unsafe { libc::listen(listener.as_raw_fd(), 16) } < 0
        {
            return Err(io::Error::last_os_error());
        }
        let child = Self::spawn(&listener, limits)?;
        Ok(Self {
            child: Some(child),
            listener: Some(listener),
            limits,
            recovery: Recovery::new(Instant::now()),
        })
    }
    fn spawn(listener: &File, limits: Limits) -> io::Result<Child> {
        let owner = unsafe { libc::getpid() };
        let start = crate::state::process_starttime_ticks(owner)
            .ok_or_else(|| invalid("missing owner identity"))?;
        let fd = listener.as_raw_fd();
        // Exec the exact running agent-bash image, not a replaceable installation path.
        let mut command = Command::new("/proc/self/exe");
        command.args([
            INTERNAL.to_owned(),
            owner.to_string(),
            start.to_string(),
            limits.bytes.to_string(),
            limits.count.to_string(),
            limits.deadline.as_millis().to_string(),
        ]);
        command
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0
                    || libc::getppid() != owner
                {
                    return Err(io::Error::other("custodian owner lost"));
                }
                if fd != 3 && libc::dup2(fd, 3) < 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                // CLOEXEC rather than close: preserve Rust's exec-error pipe until exec.
                if libc::syscall(
                    libc::SYS_close_range,
                    4u32,
                    u32::MAX,
                    libc::CLOSE_RANGE_CLOEXEC,
                ) < 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        command.spawn()
    }
    /// Sole supervisor event-loop caller; never spawn until the previous child was reaped.
    /// No request or helper command is retried here. Pending connections keep their deadlines.
    pub(crate) fn recover(&mut self) -> io::Result<()> {
        if self.child.is_some() || Instant::now() < self.recovery.next {
            return Ok(());
        }
        let Some(listener) = &self.listener else {
            return Ok(());
        };
        self.recovery.attempted(Instant::now());
        self.child = Some(Self::spawn(listener, self.limits)?);
        Ok(())
    }
    pub(crate) fn pid(&self) -> Option<i32> {
        self.child.as_ref().map(|c| c.id() as i32)
    }
    pub(crate) fn reaped(&mut self, pid: i32) {
        if self.child.as_ref().is_some_and(|c| c.id() as i32 == pid) {
            self.child = None;
            self.recovery.lost(Instant::now());
        }
    }
    /// Only this exact unreaped clean-exec child is infrastructure, never its descendants.
    pub(crate) fn only_child(&self) -> bool {
        let Some(child) = &self.child else {
            return false;
        };
        let pid = unsafe { libc::getpid() };
        let Ok(children) = fs::read_to_string(format!("/proc/self/task/{pid}/children")) else {
            return false;
        };
        let expected = child.id().to_string();
        let pids: Vec<_> = children.split_whitespace().collect();
        pids == [expected.as_str()]
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom};

    fn source(bytes: &[u8]) -> File {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(bytes).unwrap();
        file.set_permissions(fs::Permissions::from_mode(0o500))
            .unwrap();
        file
    }
    fn until() -> Instant {
        Instant::now() + Duration::from_secs(2)
    }
    fn sealed(bytes: &[u8]) -> File {
        materialize(
            &source(bytes),
            bytes.len() as u64,
            &format!("{:x}", Sha256::digest(bytes)),
            until(),
        )
        .unwrap()
    }
    #[test]
    fn recovery_backoff_saturates_without_poison_and_resets_after_stability() {
        let mut now = Instant::now();
        let mut recovery = Recovery::new(now);
        for expected in [1, 2, 4, 8, 16, 30, 30, 30] {
            recovery.lost(now);
            assert_eq!(recovery.next - now, Duration::from_secs(expected));
            now = recovery.next;
            recovery.attempted(now);
        }
        // Days of uptime are stability, not exhaustion of a lifetime allowance.
        now += Duration::from_secs(86400 * 365);
        recovery.lost(now);
        assert_eq!(recovery.next - now, Duration::from_secs(1));
        recovery.attempted(recovery.next);
        assert_eq!(recovery.delay, Duration::from_secs(2));
    }

    #[test]
    fn failed_spawn_attempts_remain_rate_limited_without_a_terminal_count() {
        let mut now = Instant::now();
        let mut recovery = Recovery::new(now);
        for seconds in [1, 2, 4, 8, 16, 30, 30, 30] {
            // A failed spawn has no child to reap: only attempted advances its retry gate.
            recovery.attempted(now);
            assert_eq!(recovery.next - now, Duration::from_secs(seconds));
            now = recovery.next;
        }
        assert_eq!(recovery.delay, Duration::from_secs(30));
    }

    #[test]
    fn live_child_is_not_replaced_even_after_former_maximum_age() {
        let now = Instant::now();
        let child = Command::new("/bin/sleep").arg("10").spawn().unwrap();
        let pid = child.id();
        let mut owner = Owner {
            child: Some(child),
            listener: Some(socket().unwrap()),
            limits: Limits {
                bytes: 4,
                count: 1,
                deadline: Duration::from_millis(20),
            },
            recovery: Recovery::new(now - Duration::from_secs(86400 * 365)),
        };
        owner.recover().unwrap();
        assert_eq!(owner.pid(), Some(pid as i32));
        assert!(owner.child.as_mut().unwrap().try_wait().unwrap().is_none());
        // Owner::drop terminates and reaps this private fixture child.
    }

    #[test]
    fn positional_copy_and_independent_readonly_aliases() {
        let bytes = b"#!/bin/sh\necho positional\n";
        let mut image = sealed(bytes);
        let mut other = readonly(&image).unwrap();
        image.seek(SeekFrom::End(0)).unwrap();
        let mut out = tempfile::tempfile().unwrap();
        copy(&image, &mut out).unwrap();
        out.seek(SeekFrom::Start(0)).unwrap();
        let mut actual = Vec::new();
        out.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, bytes);
        let mut prefix = [0; 2];
        other.read_exact(&mut prefix).unwrap();
        assert_eq!(&prefix, b"#!");
        assert_eq!(image.stream_position().unwrap(), bytes.len() as u64);
        assert!(image.write_all(b"x").is_err());
        assert_eq!(
            unsafe { libc::fcntl(image.as_raw_fd(), libc::F_GETFL) } & libc::O_ACCMODE,
            libc::O_RDONLY
        );
    }
    #[test]
    fn required_seals_digest_type_size_and_source_mutation_fail_closed() {
        let bytes = b"tiny image";
        let hash = format!("{:x}", Sha256::digest(bytes));
        for missing in [
            libc::F_SEAL_SEAL,
            libc::F_SEAL_SHRINK,
            libc::F_SEAL_GROW,
            libc::F_SEAL_WRITE,
        ] {
            let raw = unsafe {
                libc::memfd_create(
                    c"test".as_ptr(),
                    libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
                )
            };
            let mut f = unsafe { File::from_raw_fd(raw) };
            f.write_all(bytes).unwrap();
            f.set_permissions(fs::Permissions::from_mode(0o500))
                .unwrap();
            assert_eq!(
                unsafe { libc::fcntl(raw, libc::F_ADD_SEALS, SEALS & !missing) },
                0
            );
            assert!(verify(&f, bytes.len() as u64, &hash, until()).is_err());
        }
        let f = sealed(bytes);
        assert!(verify(&f, bytes.len() as u64 + 1, &hash, until()).is_err());
        assert!(verify(&f, bytes.len() as u64, &"0".repeat(64), until()).is_err());
        assert!(verify(&File::open("/dev/null").unwrap(), 0, &hash, until()).is_err());
        assert!(materialize(&source(b"mutated!!!"), bytes.len() as u64, &hash, until()).is_err());
        assert!(
            materialize(
                &source(b"growing-image"),
                bytes.len() as u64,
                &hash,
                until()
            )
            .is_err()
        );
    }
    #[test]
    fn writable_mapping_sealing_failure_is_unpublished() {
        let raw = unsafe {
            libc::memfd_create(
                c"test".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        let f = unsafe { File::from_raw_fd(raw) };
        f.set_len(4096).unwrap();
        let map = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                raw,
                0,
            )
        };
        assert_ne!(map, libc::MAP_FAILED);
        assert_eq!(unsafe { libc::fcntl(raw, libc::F_ADD_SEALS, SEALS) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBUSY));
        assert!(verify(&f, 4096, &"0".repeat(64), until()).is_err());
        assert_eq!(unsafe { libc::munmap(map, 4096) }, 0);
    }
    fn pair() -> (File, File) {
        let mut fds = [0; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                    0,
                    fds.as_mut_ptr(),
                )
            },
            0
        );
        unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) }
    }
    #[test]
    fn fd_transfer_cloexec_and_truncated_packet_rejection() {
        let (a, b) = pair();
        let f = sealed(b"x");
        send(a.as_raw_fd(), b"I1", Some(&f), until()).unwrap();
        let (_, files) = receive(b.as_raw_fd(), until()).unwrap();
        assert_eq!(files.len(), 1);
        assert_ne!(
            unsafe { libc::fcntl(files[0].as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        send(a.as_raw_fd(), &[1; 513], Some(&f), until()).unwrap();
        assert!(receive(b.as_raw_fd(), until()).is_err());
        assert!(receive(b.as_raw_fd(), Instant::now()).is_err());
    }
    #[test]
    fn false_custodian_cannot_supply_unsealed_or_wrong_bytes() {
        for wrong in [source(b"tiny"), sealed(b"evil")] {
            let (a, b) = pair();
            let responder = std::thread::spawn(move || {
                let _request = receive(b.as_raw_fd(), until()).unwrap();
                send(b.as_raw_fd(), b"I1", Some(&wrong), until()).unwrap();
            });
            let hash = format!("{:x}", Sha256::digest(b"tiny"));
            assert!(request(&a, &source(b"tiny"), 4, &hash, until()).is_err());
            responder.join().unwrap();
        }
    }

    #[test]
    fn single_publication_no_eviction_and_compound_budget_failure() {
        let limits = Limits {
            bytes: 4,
            count: 1,
            deadline: Duration::from_secs(2),
        };
        let mut store = Store {
            images: HashMap::new(),
            bytes: 0,
            limits,
        };
        let (a, b) = pair();
        let f = source(b"tiny");
        let hash = format!("{:x}", Sha256::digest(b"tiny"));
        let mut packet = 4u64.to_le_bytes().to_vec();
        packet.extend_from_slice(hash.as_bytes());
        let mut inodes = Vec::new();
        for _ in 0..3 {
            send(a.as_raw_fd(), &packet, Some(&f), until()).unwrap();
            store.serve(&b, until()).unwrap();
            let (_, files) = receive(a.as_raw_fd(), until()).unwrap();
            inodes.push(files[0].metadata().unwrap().ino());
        }
        assert!(inodes.iter().all(|i| *i == inodes[0]));
        assert_eq!(store.bytes, 4);
        assert_eq!(store.images.len(), 1);
        let other = source(b"else");
        let hash = format!("{:x}", Sha256::digest(b"else"));
        packet[8..].copy_from_slice(hash.as_bytes());
        send(a.as_raw_fd(), &packet, Some(&other), until()).unwrap();
        assert!(
            store
                .serve(&b, until())
                .unwrap_err()
                .to_string()
                .contains("capacity")
        );
        assert_eq!(store.bytes, 4);
    }
}
