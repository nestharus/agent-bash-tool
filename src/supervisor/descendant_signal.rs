//! Numeric discovery is only a hint. Signal authority comes from a live,
//! pidfd-pinned ancestry chain terminating at this adopting reaper.
use std::collections::HashSet;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};

use super::{current_pid, open_pidfd, state};

type Pid = libc::pid_t;

trait Boundary {
    type Handle;
    fn capture(&mut self, pid: Pid) -> io::Result<Self::Handle>;
    fn parent(&mut self, pid: Pid) -> Option<Pid>;
    fn live(&mut self, handle: &Self::Handle) -> bool;
    fn send(&mut self, handle: &Self::Handle, signal: i32) -> io::Result<()>;
}

struct Kernel;
impl Boundary for Kernel {
    type Handle = OwnedFd;
    fn capture(&mut self, pid: Pid) -> io::Result<OwnedFd> {
        open_pidfd(pid)
    }
    fn parent(&mut self, pid: Pid) -> Option<Pid> {
        state::process_parent_pid(pid)
    }
    fn live(&mut self, handle: &OwnedFd) -> bool {
        let mut event = libc::pollfd {
            fd: handle.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // Unknown, exited and invalid descriptors all fail closed.
        unsafe { libc::poll(&mut event, 1, 0) == 0 && event.revents == 0 }
    }
    fn send(&mut self, handle: &OwnedFd, signal: i32) -> io::Result<()> {
        let rc = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                handle.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

pub(super) fn signal(pid: Pid, signal: i32, infrastructure: Option<Pid>) {
    // Failed capture/validation/send leaves the existing cancellation obligation
    // intact. Both reapers retry and escalate. The guardian requires ECHILD;
    // the live supervisor also has the non-spawning image-owner shortcut.
    let _ = signal_using(&mut Kernel, current_pid(), pid, signal, infrastructure);
}

struct Link<H> {
    pid: Pid,
    parent: Pid,
    handle: H,
}

fn signal_using<B: Boundary>(
    boundary: &mut B,
    root: Pid,
    pid: Pid,
    signal: i32,
    infrastructure: Option<Pid>,
) -> io::Result<bool> {
    let mut chain = Vec::new();
    let mut seen = HashSet::new();
    let mut cursor = pid;
    while cursor != root {
        if cursor <= 1 || infrastructure == Some(cursor) || !seen.insert(cursor) {
            return Ok(false);
        }
        // Pin BEFORE observing /proc, including every intermediate ancestor.
        let handle = boundary.capture(cursor)?;
        let Some(parent) = boundary.parent(cursor) else {
            return Ok(false);
        };
        chain.push(Link {
            pid: cursor,
            parent,
            handle,
        });
        cursor = parent;
    }
    let Some(target) = chain.first() else {
        return Ok(false);
    };
    // Re-read edges after every referenced ancestor has been captured. A parent
    // dying/reparenting during capture invalidates the pass (retry on next poll).
    // Then check ALL pins after ALL numeric reads: a live pidfd cannot refer to
    // an earlier occupant of any /proc slot observed above. Unlike start ticks,
    // this temporal proof does not depend on clock granularity or boot markers.
    if chain
        .iter()
        .any(|link| boundary.parent(link.pid) != Some(link.parent))
        || chain.iter().any(|link| !boundary.live(&link.handle))
    {
        return Ok(false);
    }
    // Root is this process, not a caller-supplied stale PID. Reparenting after
    // proof does not revoke ownership: the live supervisor/guardian is a
    // subreaper. Exit/reuse after proof cannot retarget this stable handle.
    boundary.send(&target.handle, signal)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct Injected {
        parents: HashMap<Pid, Pid>,
        reads: usize,
        change_on_read: Option<(usize, Pid, Option<Pid>)>,
        dead: HashSet<Pid>,
        capture_error: Option<Pid>,
        sent: Vec<Pid>,
    }
    impl Boundary for Injected {
        type Handle = Pid;
        fn capture(&mut self, pid: Pid) -> io::Result<Pid> {
            if self.capture_error == Some(pid) {
                return Err(io::Error::other("unavailable"));
            }
            Ok(pid)
        }
        fn parent(&mut self, pid: Pid) -> Option<Pid> {
            self.reads += 1;
            if let Some((at, changed, parent)) = self.change_on_read
                && at == self.reads
            {
                match parent {
                    Some(parent) => {
                        self.parents.insert(changed, parent);
                    }
                    None => {
                        self.parents.remove(&changed);
                    }
                }
            }
            self.parents.get(&pid).copied()
        }
        fn live(&mut self, handle: &Pid) -> bool {
            !self.dead.contains(handle)
        }
        fn send(&mut self, handle: &Pid, _: i32) -> io::Result<()> {
            self.sent.push(*handle);
            Ok(())
        }
    }
    fn tree() -> Injected {
        Injected {
            parents: [(30, 20), (20, 10)].into(),
            ..Default::default()
        }
    }
    fn attempt(b: &mut Injected) -> io::Result<bool> {
        signal_using(b, 10, 30, libc::SIGTERM, None)
    }
    #[test]
    fn exact_descendant_boundary_rejects_reused_target_or_ancestor() {
        for dead in [20, 30] {
            let mut b = tree();
            // Numeric ancestry can look identical after reuse; the captured
            // old identity's pidfd must nevertheless be dead.
            b.dead.insert(dead);
            assert!(!attempt(&mut b).unwrap());
            assert!(b.sent.is_empty());
        }
    }
    #[test]
    fn exact_descendant_boundary_retries_disappearance_and_reparenting() {
        for parent in [None, Some(10), Some(99)] {
            let mut b = tree();
            b.change_on_read = Some((3, 30, parent));
            assert!(!attempt(&mut b).unwrap());
            assert!(b.sent.is_empty());
            if parent == Some(10) {
                assert!(attempt(&mut b).unwrap());
                assert_eq!(b.sent, [30]);
            }
        }
    }
    #[test]
    fn exact_descendant_boundary_rejects_unknown_wrong_owner_and_infrastructure() {
        let mut b = tree();
        b.capture_error = Some(20);
        assert!(attempt(&mut b).is_err());
        assert!(b.sent.is_empty());
        let mut b = tree();
        b.parents.insert(20, 1);
        assert!(!attempt(&mut b).unwrap());
        assert!(b.sent.is_empty());
        let mut b = tree();
        assert!(!signal_using(&mut b, 10, 30, libc::SIGTERM, Some(20)).unwrap());
        assert!(b.sent.is_empty());
    }

    struct Child(std::process::Child);
    impl Child {
        fn new() -> Self {
            Self(
                std::process::Command::new("/bin/sleep")
                    .env_clear()
                    .arg("60")
                    .spawn()
                    .unwrap(),
            )
        }
        fn pid(&self) -> Pid {
            self.0.id() as Pid
        }
        fn stop(&mut self) {
            self.0.kill().unwrap();
            self.0.wait().unwrap();
        }
    }
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    // Injection is at the same capture/read/send boundary used by production.
    // Descriptors and signal syscall remain real, unlike the structural tests.
    struct ExitRace<'a> {
        target: &'a mut Child,
        replacement: Pid,
        at_send: bool,
        stopped: bool,
        sends: usize,
    }
    impl Boundary for ExitRace<'_> {
        type Handle = OwnedFd;
        fn capture(&mut self, pid: Pid) -> io::Result<OwnedFd> {
            Kernel.capture(pid)
        }
        fn parent(&mut self, pid: Pid) -> Option<Pid> {
            if !self.at_send && !self.stopped {
                self.target.stop();
                self.stopped = true;
            }
            // Deterministic logical slot reuse: numeric reads show a live
            // replacement with a plausible owned parent, while the fd is old.
            Kernel.parent(if self.stopped { self.replacement } else { pid })
        }
        fn live(&mut self, handle: &OwnedFd) -> bool {
            Kernel.live(handle)
        }
        fn send(&mut self, handle: &OwnedFd, signal: i32) -> io::Result<()> {
            self.sends += 1;
            self.target.stop();
            self.stopped = true;
            Kernel.send(handle, signal)
        }
    }

    #[test]
    fn exact_descendant_real_signal_and_wrong_root_noop() {
        let mut target = Child::new();
        let unrelated = Child::new();
        let sentinel = Kernel.capture(unrelated.pid()).unwrap();
        assert!(
            !signal_using(
                &mut Kernel,
                unrelated.pid(),
                target.pid(),
                libc::SIGKILL,
                None
            )
            .unwrap()
        );
        assert!(target.0.try_wait().unwrap().is_none());
        assert!(
            signal_using(
                &mut Kernel,
                current_pid(),
                target.pid(),
                libc::SIGKILL,
                None
            )
            .unwrap()
        );
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(target.0.wait().unwrap().signal(), Some(libc::SIGKILL));
        assert!(Kernel.live(&sentinel));
    }

    #[test]
    fn exact_descendant_real_pidfd_rejects_numeric_replacement_and_late_exit() {
        for at_send in [false, true] {
            let mut target = Child::new();
            let unrelated = Child::new();
            let sentinel = Kernel.capture(unrelated.pid()).unwrap();
            let pid = target.pid();
            let mut boundary = ExitRace {
                target: &mut target,
                replacement: unrelated.pid(),
                at_send,
                stopped: false,
                sends: 0,
            };
            let result = signal_using(&mut boundary, current_pid(), pid, libc::SIGKILL, None);
            if at_send {
                assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::ESRCH));
                assert_eq!(boundary.sends, 1);
            } else {
                assert!(!result.unwrap());
                assert_eq!(boundary.sends, 0);
            }
            assert!(
                Kernel.live(&sentinel),
                "replacement must not receive signal"
            );
        }
    }
}
