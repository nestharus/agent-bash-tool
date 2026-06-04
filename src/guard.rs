use thiserror::Error;

#[derive(Debug, Clone, Copy)]
pub(crate) struct AttachedGuard {
    startup_ppid: libc::pid_t,
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("attached subprocess required")]
pub(crate) struct GuardError;

impl AttachedGuard {
    pub(crate) fn capture() -> Self {
        Self {
            startup_ppid: unsafe { libc::getppid() },
        }
    }

    pub(crate) fn startup_ppid(self) -> libc::pid_t {
        self.startup_ppid
    }

    pub(crate) fn validate(self) -> Result<(), GuardError> {
        let current = unsafe { libc::getppid() };
        validate_parent_pair(self.startup_ppid, current)
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
}
