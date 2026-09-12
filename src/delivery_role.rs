//! One completion-execution subreaper, shared by the supervisor and guardian.
//! The slot is published before execution and retired BEFORE its PID is reaped.
//! It is not a discovered PID registry: the only producer is the forking owner.
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicI32, AtomicPtr, Ordering};

static SLOT: AtomicPtr<AtomicI32> = AtomicPtr::new(std::ptr::null_mut());
const UNKNOWN: i32 = -1;

// Called in the single-threaded daemon before the guardian/supervisor fork.
pub(crate) fn initialize() -> io::Result<()> {
    let memory = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            std::mem::size_of::<AtomicI32>(),
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if memory == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    let slot = memory.cast::<AtomicI32>();
    unsafe {
        slot.write(AtomicI32::new(0));
    }
    SLOT.store(slot, Ordering::SeqCst);
    Ok(())
}

fn slot() -> Option<&'static AtomicI32> {
    unsafe { SLOT.load(Ordering::SeqCst).as_ref() }
}

pub(crate) fn enabled() -> bool {
    slot().is_some()
}

pub(crate) fn pending() -> bool {
    slot().is_some_and(|slot| slot.load(Ordering::SeqCst) != 0)
}

pub(crate) fn publish(pid: i32) -> io::Result<()> {
    slot()
        .ok_or_else(|| io::Error::other("delivery role unavailable"))?
        .compare_exchange(0, pid, Ordering::SeqCst, Ordering::SeqCst)
        .map(|_| ())
        .map_err(|_| io::Error::other("delivery role still owns responsibility"))
}

// Only the role custodian calls this, after waitpid has proved ECHILD.
pub(crate) fn drained() {
    if let Some(slot) = slot() {
        let pid = unsafe { libc::getpid() };
        let _ = slot.compare_exchange(pid, -pid, Ordering::SeqCst, Ordering::SeqCst);
    }
}

// All adopting reapers call this while the exact child is still waitable.
// Abnormal custodian loss cannot turn into a stale numeric exemption.
pub(crate) fn before_reap(pid: i32) {
    if let Some(slot) = slot() {
        let value = slot.load(Ordering::SeqCst);
        let retired = retired_slot(value, pid);
        if retired != value {
            // Reaping unrelated workload must not overwrite a concurrent drain
            // certificate published by the still-running role custodian.
            let _ = slot.compare_exchange(value, retired, Ordering::SeqCst, Ordering::SeqCst);
        }
    }
}

fn retired_slot(value: i32, pid: i32) -> i32 {
    if value == pid {
        UNKNOWN
    } else if value == -pid {
        0
    } else {
        value
    }
}

pub(crate) fn exclusion() -> io::Result<Option<(i32, OwnedFd)>> {
    let Some(slot) = slot() else {
        return Ok(None);
    };
    let value = slot.load(Ordering::SeqCst);
    if value == 0 {
        return Ok(None);
    }
    if value == UNKNOWN {
        return Err(io::Error::other("delivery custodian lost; role unknown"));
    }
    if value < UNKNOWN {
        return Ok(None);
    } // unreaped, ECHILD-certified custodian
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, value, 0) } as i32;
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut event = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    if unsafe { libc::poll(&mut event, 1, 0) } != 0 {
        return Err(io::Error::other(
            "delivery custodian not live; retain role responsibility",
        ));
    }
    Ok(Some((value, fd)))
}

// Waitable observation and slot retirement precede freeing any PID. Single
// reaper per process; guardian does not adopt/reap until its supervisor is gone.
pub(crate) fn reap_one(options: i32) -> io::Result<Option<(i32, i32)>> {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::waitid(
            libc::P_ALL,
            0,
            &mut info,
            libc::WEXITED | libc::WNOWAIT | options,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let pid = unsafe { info.si_pid() };
    if pid == 0 {
        return Ok(None);
    }
    before_reap(pid);
    let mut status = 0;
    if unsafe { libc::waitpid(pid, &mut status, 0) } != pid {
        return Err(io::Error::last_os_error());
    }
    Ok(Some((pid, status)))
}

pub(crate) fn run_custodian(
    work: impl FnOnce() -> io::Result<()>,
    outcome: impl FnOnce(i32) -> io::Result<()>,
) -> ! {
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } < 0 {
        // No execution was admitted.
        drained();
        unsafe { libc::_exit(70) };
    }
    let worker = unsafe { libc::fork() };
    if worker == 0 {
        let result = work();
        unsafe { libc::_exit(if result.is_ok() { 0 } else { 70 }) };
    }
    if worker < 0 {
        drained();
        unsafe { libc::_exit(70) };
    }
    let mut code = 70;
    let mut outcome = Some(outcome);
    loop {
        let mut status = 0;
        let pid = unsafe { libc::waitpid(-1, &mut status, 0) };
        if pid == worker {
            code = if outcome.take().expect("sole worker outcome")(status).is_ok() {
                0
            } else {
                70
            };
        }
        if pid >= 0 {
            continue;
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if error.raw_os_error() == Some(libc::ECHILD) {
            drained();
            unsafe { libc::_exit(code) };
        }
        // Unknown never claims ECHILD or abandons its descendant role.
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_retirement_requires_exact_unreaped_custodian_and_drain_certificate() {
        assert_eq!(retired_slot(42, 41), 42);
        assert_eq!(retired_slot(-42, 41), -42);
        assert_eq!(retired_slot(42, 42), UNKNOWN);
        assert_eq!(retired_slot(-42, 42), 0);
        // Once unknown, reaping any later occupant cannot clear responsibility.
        assert_eq!(retired_slot(UNKNOWN, 42), UNKNOWN);
        assert_eq!(retired_slot(0, 42), 0);
    }
}
