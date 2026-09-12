//! One completion-execution subreaper, shared by the supervisor and guardian.
//! The slot is published before execution and retired BEFORE its PID is reaped.
//! It is not a discovered PID registry: the only producer is the forking owner.
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicI32, AtomicPtr, AtomicU64, Ordering};

struct Role {
    pid: AtomicI32,
    challenge: AtomicU64,
    acknowledged: AtomicU64,
}
static SLOT: AtomicPtr<Role> = AtomicPtr::new(std::ptr::null_mut());
const UNKNOWN: i32 = -1;

// Called in the single-threaded daemon before the guardian/supervisor fork.
pub(crate) fn initialize() -> io::Result<()> {
    let memory = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            std::mem::size_of::<Role>(),
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if memory == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    let slot = memory.cast::<Role>();
    unsafe {
        slot.write(Role {
            pid: AtomicI32::new(0),
            challenge: AtomicU64::new(0),
            acknowledged: AtomicU64::new(0),
        });
    }
    SLOT.store(slot, Ordering::SeqCst);
    Ok(())
}

fn role() -> Option<&'static Role> {
    unsafe { SLOT.load(Ordering::SeqCst).as_ref() }
}
fn slot() -> Option<&'static AtomicI32> {
    role().map(|role| &role.pid)
}

// Called AFTER all target ancestry observations. Only the single-threaded
// custodian answers, in userspace. A fresh response proves it had not begun
// irreversible kernel exit/reparenting at the time of those observations.
// Pidfd nonreadiness alone does NOT prove that (exit_state is published later).
pub(crate) fn confirm_containment(pid: i32) -> bool {
    let Some(role) = role() else { return false };
    confirm_role(role, pid)
}

fn confirm_role(role: &Role, pid: i32) -> bool {
    if role.pid.load(Ordering::SeqCst) != pid {
        return false;
    }
    let Ok(previous) = role
        .challenge
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
            value.checked_add(1)
        })
    else {
        return false; // Never reuse a challenge, including on overflow.
    };
    let challenge = previous + 1;
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(100);
    loop {
        if role.pid.load(Ordering::SeqCst) != pid {
            return false;
        }
        if role.acknowledged.load(Ordering::SeqCst) == challenge {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

fn acknowledge_containment() {
    if let Some(role) = role() {
        let challenge = role.challenge.load(Ordering::SeqCst);
        role.acknowledged.store(challenge, Ordering::SeqCst);
    }
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
        acknowledge_containment();
        let mut status = 0;
        let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if pid == 0 {
            std::thread::sleep(std::time::Duration::from_millis(10));
            continue;
        }
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
    fn containment_requires_fresh_post_observation_userspace_response() {
        let role = std::sync::Arc::new(Role {
            pid: AtomicI32::new(42),
            challenge: AtomicU64::new(7),
            acknowledged: AtomicU64::new(7),
        });
        // Model reparent-before-exit-readiness: the exact role still has its
        // published PID, but can no longer execute userspace. Old ACK is useless.
        assert!(!confirm_role(&role, 42));
        assert_eq!(role.challenge.load(Ordering::SeqCst), 8);
        let responder = role.clone();
        let thread = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while responder.challenge.load(Ordering::SeqCst) != 9 {
                assert!(
                    std::time::Instant::now() < deadline,
                    "challenge was not published"
                );
                std::thread::yield_now();
            }
            responder.acknowledged.store(9, Ordering::SeqCst);
        });
        assert!(confirm_role(&role, 42));
        thread.join().unwrap();
        role.challenge.store(u64::MAX, Ordering::SeqCst);
        assert!(!confirm_role(&role, 42));
        assert!(!confirm_role(&role, 43));
    }

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
