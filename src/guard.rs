use thiserror::Error;

use crate::state::{self, CallerChainEntry};

#[derive(Debug, Clone)]
pub(crate) struct AttachedGuard {
    local_parent_pid: libc::pid_t,
    observer_parent: Option<CallerChainEntry>,
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("attached subprocess required")]
pub(crate) struct GuardError;

impl AttachedGuard {
    pub(crate) fn capture() -> Self {
        let local_parent_pid = unsafe { libc::getppid() };
        Self {
            local_parent_pid,
            observer_parent: state::attached_parent_identity(local_parent_pid).ok(),
        }
    }

    pub(crate) fn observer_parent_pid(&self) -> Result<libc::pid_t, GuardError> {
        self.validate()?;
        Ok(self.observer_parent.as_ref().ok_or(GuardError)?.pid)
    }

    pub(crate) fn caller_chain(&self) -> Result<Vec<CallerChainEntry>, GuardError> {
        let pid = self.observer_parent_pid()?;
        let chain = state::capture_caller_chain(pid);
        if chain.first() != self.observer_parent.as_ref() {
            return Err(GuardError);
        }
        self.validate()?;
        Ok(chain)
    }

    pub(crate) fn validate(&self) -> Result<(), GuardError> {
        let current = unsafe { libc::getppid() };
        validate_parent_pair(self.local_parent_pid, current)?;
        if state::attached_parent_identity(current).ok().as_ref() != self.observer_parent.as_ref()
            || self.observer_parent.is_none()
        {
            return Err(GuardError);
        }
        Ok(())
    }
}

pub(crate) fn validate_parent_pair(
    expected: libc::pid_t,
    current: libc::pid_t,
) -> Result<(), GuardError> {
    if expected <= 1 || current != expected {
        Err(GuardError)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attached_guard_accepts_stable_parent() {
        let ppid = unsafe { libc::getppid() };
        assert!(validate_parent_pair(ppid, ppid).is_ok());
    }

    #[test]
    fn attached_guard_rejects_pid_one() {
        assert_eq!(validate_parent_pair(1, 1), Err(GuardError));
    }

    #[test]
    fn attached_guard_rejects_changed_parent() {
        assert_eq!(validate_parent_pair(42, 43), Err(GuardError));
    }

    #[test]
    fn attached_guard_rejects_wrong_local_parent_before_caller_lookup() {
        let mut guard = AttachedGuard::capture();
        assert!(guard.validate().is_ok());
        guard.local_parent_pid += 1;
        assert_eq!(guard.caller_chain(), Err(GuardError));
    }

    #[test]
    fn attached_guard_rejects_reused_observer_parent_incarnation() {
        let mut guard = AttachedGuard::capture();
        assert!(guard.validate().is_ok());
        guard.observer_parent.as_mut().unwrap().starttime_ticks += 1;
        assert_eq!(guard.caller_chain(), Err(GuardError));
    }

    #[test]
    fn attached_guard_rejects_wrong_observer_parent() {
        let mut guard = AttachedGuard::capture();
        assert!(guard.validate().is_ok());
        guard.observer_parent.as_mut().unwrap().pid += 1;
        assert_eq!(guard.caller_chain(), Err(GuardError));
    }

    #[test]
    fn attached_guard_rejects_reparented_source() {
        const STAGE: &str = "AGE319_GUARD_REPARENT_STAGE";
        if let Some(ready) = std::env::var_os(STAGE) {
            let guard = AttachedGuard::capture();
            assert!(guard.validate().is_ok());
            std::fs::write(ready, "ready").unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while unsafe { libc::getppid() } == guard.local_parent_pid {
                assert!(
                    std::time::Instant::now() < deadline,
                    "source never reparented"
                );
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            assert_eq!(guard.caller_chain(), Err(GuardError));
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let output = std::process::Command::new("timeout")
            .args(["--kill-after=2s", "10s", "sh", "-c"])
            .arg("\"$AGE319_TEST_EXE\" --exact guard::tests::attached_guard_rejects_reparented_source --nocapture & while [ ! -e \"$AGE319_READY\" ]; do sleep 0.01; done")
            .env("AGE319_TEST_EXE", std::env::current_exe().unwrap())
            .env("AGE319_READY", temp.path().join("ready"))
            .env(STAGE, temp.path().join("ready"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    }
}
