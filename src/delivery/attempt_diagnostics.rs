//! Opt-in lossy observations. No filesystem sink or diagnostic custody authority.
use super::*;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::time::{SystemTime, UNIX_EPOCH};

struct AttemptDiagnostics {
    socket: UnixDatagram,
    id: String,
    operation: String,
    source_id: String,
    started: Instant,
}

impl AttemptDiagnostics {
    fn create(paths: &StatePaths, operation: &'static str) -> Option<Self> {
        let name = std::env::var("AGENT_BASH_DIAGNOSTIC_SOCKET").ok()?;
        Self::connect(paths, operation, &name)
    }

    fn connect(paths: &StatePaths, operation: &'static str, name: &str) -> Option<Self> {
        if name.is_empty() || name.len() > 100 {
            return None;
        }
        // Abstract Linux address: no path lookup, filesystem creation or sync.
        let address = SocketAddr::from_abstract_name(name.as_bytes()).ok()?;
        let socket = UnixDatagram::unbound().ok()?;
        socket.set_nonblocking(true).ok()?;
        socket.connect_addr(&address).ok()?;
        let mut random = [0u8; 16];
        if unsafe {
            libc::getrandom(
                random.as_mut_ptr().cast(),
                random.len(),
                libc::GRND_NONBLOCK,
            )
        } != 16
        {
            return None;
        }
        let attempt = Self {
            socket,
            id: random.iter().map(|b| format!("{b:02x}")).collect(),
            operation: operation.into(),
            source_id: source_id(paths),
            started: Instant::now(),
        };
        attempt.record("started", serde_json::json!({}));
        Some(attempt)
    }

    #[cfg(test)]
    fn id(&self) -> &str {
        &self.id
    }

    fn record(&self, phase: &'static str, evidence: serde_json::Value) {
        let value = serde_json::json!({
            "schema": "owned-attempt-diagnostic-v3", "attempt_id": self.id,
            "source_id": self.source_id,
            "unix_time_us": SystemTime::now().duration_since(UNIX_EPOCH).ok().map(|d| d.as_micros()),
            "operation": self.operation, "phase": phase,
            "pid": unsafe { libc::getpid() },
            "elapsed_us": self.started.elapsed().as_micros(), "evidence": evidence,
        });
        if let Ok(bytes) = serde_json::to_vec(&value) {
            if bytes.len() <= 4096 {
                // One atomic datagram, no retry, blocking fallback or stderr write.
                let _ = self.socket.send(&bytes);
            }
        }
    }
}

// Observe the raw local spawn/wait result, before logical success conversion or
// custody cleanup. This socket is created in the executing worker, after its FD
// preparation; it is never carried across that close-range boundary.
pub(super) fn observe<T>(
    paths: &StatePaths,
    operation_name: &'static str,
    operation: impl FnOnce() -> Result<T, DeliveryHelperCommandError>,
    status: impl FnOnce(&T) -> ExitStatus,
) -> Result<T, DeliveryHelperCommandError> {
    let diagnostic = AttemptDiagnostics::create(paths, operation_name);
    let result = operation();
    if let Some(diagnostic) = diagnostic {
        match &result {
            Ok(value) => diagnostic.record(
                "wait_returned",
                serde_json::json!({"raw_status": status(value).into_raw()}),
            ),
            Err(DeliveryHelperCommandError::NotStarted(error)) => diagnostic.record(
                "spawn_error",
                serde_json::json!({"os_error": error.raw_os_error()}),
            ),
            Err(DeliveryHelperCommandError::Admitted(error)) => diagnostic.record(
                "wait_error",
                serde_json::json!({"os_error": error.raw_os_error()}),
            ),
        }
    }
    result
}

// Versioned, length-framed raw Unix bytes preserve the StatePaths identity domain
// without exporting paths/handles or ambiguously joining their components. No
// canonicalization or filesystem I/O: aliases are intentionally distinct inputs.
fn source_id(paths: &StatePaths) -> String {
    let mut digest = Sha256::new();
    digest.update(b"owned-attempt-source-v1\0");
    for part in [paths.root.as_os_str().as_bytes(), paths.handle.as_bytes()] {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    format!("{:x}", digest.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sources_operations_and_retries_have_joinable_identities() {
        if crate::test_support::private_case() {
            return;
        }
        let name = "age353-attribution";
        let receiver =
            UnixDatagram::bind_addr(&SocketAddr::from_abstract_name(name).unwrap()).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let paths = [
            StatePaths::new("/private/ab".into(), "c".into()),
            StatePaths::new("/private/a".into(), "bc".into()),
            StatePaths::new("/private/ab".into(), "bc".into()),
            StatePaths::new("/other/ab".into(), "c".into()),
        ];
        let mut ids = std::collections::HashSet::new();
        let mut sources = std::collections::HashSet::new();
        for paths in &paths {
            sources.insert(source_id(paths));
            for operation in ["register", "activate", "complete"] {
                for _retry in 0..3 {
                    let before = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_micros();
                    let attempt = AttemptDiagnostics::connect(paths, operation, name).unwrap();
                    let mut bytes = [0; 4096];
                    let size = receiver.recv(&mut bytes).unwrap();
                    let record: serde_json::Value = serde_json::from_slice(&bytes[..size]).unwrap();
                    let after = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_micros();
                    assert_eq!(record["source_id"], source_id(paths));
                    assert_eq!(record["operation"], operation);
                    assert_eq!(record["attempt_id"], attempt.id());
                    assert_eq!(attempt.id().len(), 32);
                    assert!(ids.insert(attempt.id().to_owned()));
                    let timestamp = record["unix_time_us"].as_u64().unwrap() as u128;
                    assert!((before..=after).contains(&timestamp));
                    assert!(
                        !std::str::from_utf8(&bytes[..size])
                            .unwrap()
                            .contains("/private")
                    );
                }
            }
        }
        assert_eq!(sources.len(), paths.len());
        assert_eq!(ids.len(), 36);
        // No UTF-8 replacement may collapse distinct Unix identity bytes.
        use std::os::unix::ffi::OsStringExt;
        let a = StatePaths::new(
            std::ffi::OsString::from_vec(vec![b'/', 0xfe]).into(),
            "c".into(),
        );
        let b = StatePaths::new(
            std::ffi::OsString::from_vec(vec![b'/', 0xff]).into(),
            "c".into(),
        );
        assert_ne!(source_id(&a), source_id(&b));
        assert!(AttemptDiagnostics::connect(&paths[0], "complete", "missing").is_none());
        assert!(AttemptDiagnostics::connect(&paths[0], "complete", "").is_none());
    }

    #[test]
    fn lazy_disabled_errors_and_bounded_overhead() {
        if crate::test_support::private_case() {
            return;
        }
        let paths = StatePaths::new("/not-created".into(), "source".into());
        unsafe {
            std::env::remove_var("AGENT_BASH_DIAGNOSTIC_SOCKET");
        }
        let result = observe(
            &paths,
            "complete",
            || Ok(7),
            |_| panic!("disabled evidence evaluated"),
        );
        assert_eq!(result.unwrap(), 7);
        let name = "age364-errors-overhead";
        let receiver =
            UnixDatagram::bind_addr(&SocketAddr::from_abstract_name(name).unwrap()).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        unsafe {
            std::env::set_var("AGENT_BASH_DIAGNOSTIC_SOCKET", name);
        }
        for admitted in [false, true] {
            let result: Result<(), _> = observe(
                &paths,
                "complete",
                || {
                    let error = io::Error::from_raw_os_error(libc::EIO);
                    Err(if admitted {
                        DeliveryHelperCommandError::Admitted(error)
                    } else {
                        DeliveryHelperCommandError::NotStarted(error)
                    })
                },
                |_| panic!("error has no exit status"),
            );
            assert!(matches!(result, Err(DeliveryHelperCommandError::Admitted(_))) == admitted);
            let mut bytes = [0; 4097];
            receiver.recv(&mut bytes).unwrap(); // started
            let size = receiver.recv(&mut bytes).unwrap();
            let record: serde_json::Value = serde_json::from_slice(&bytes[..size]).unwrap();
            assert_eq!(
                record["phase"],
                if admitted {
                    "wait_error"
                } else {
                    "spawn_error"
                }
            );
            assert_eq!(
                record["evidence"],
                serde_json::json!({"os_error": libc::EIO})
            );
        }
        // Isolated debug-build micro-measurement, not a latency/capacity SLO.
        // A full queue intentionally measures lossy, unconsumed emission cost.
        for enabled in [false, true] {
            unsafe {
                if enabled {
                    std::env::set_var("AGENT_BASH_DIAGNOSTIC_SOCKET", name);
                } else {
                    std::env::remove_var("AGENT_BASH_DIAGNOSTIC_SOCKET");
                }
            }
            let fd_before = fs::read_dir("/proc/self/fd").unwrap().count();
            let cpu_before = cpu_us();
            let start = Instant::now();
            for _ in 0..10_000 {
                observe(
                    &paths,
                    "complete",
                    || Ok(ExitStatus::from_raw(0)),
                    |status| *status,
                )
                .unwrap();
            }
            let wall = start.elapsed();
            let cpu = cpu_us() - cpu_before;
            assert_eq!(fs::read_dir("/proc/self/fd").unwrap().count(), fd_before);
            assert!(wall < Duration::from_secs(5));
            println!(
                "AGE-364 10000 immediate-result attempts enabled={enabled}: wall_us={} cpu_us={cpu} fd_delta=0; queue unconsumed",
                wall.as_micros()
            );
        }
    }

    fn cpu_us() -> i64 {
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
        assert_eq!(
            unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) },
            0
        );
        let usage = unsafe { usage.assume_init() };
        (usage.ru_utime.tv_sec + usage.ru_stime.tv_sec) * 1_000_000
            + usage.ru_utime.tv_usec
            + usage.ru_stime.tv_usec
    }

    #[test]
    fn full_or_failed_sink_never_waits() {
        let (sender, receiver) = UnixDatagram::pair().unwrap();
        sender.set_nonblocking(true).unwrap();
        let diagnostic = AttemptDiagnostics {
            socket: sender,
            id: "test".into(),
            operation: "complete".into(),
            source_id: "test-source".into(),
            started: Instant::now(),
        };
        let start = Instant::now();
        for _ in 0..10000 {
            diagnostic.record("wait_returned", serde_json::json!({"raw_status": 1792}));
        }
        assert!(start.elapsed() < Duration::from_secs(2));
        // Oversized serialization is dropped rather than truncated or retried.
        let (sender, oversized_receiver) = UnixDatagram::pair().unwrap();
        oversized_receiver.set_nonblocking(true).unwrap();
        let oversized = AttemptDiagnostics {
            socket: sender,
            id: "test".into(),
            operation: "complete".into(),
            source_id: "test-source".into(),
            started: Instant::now(),
        };
        oversized.record(
            "wait_error",
            serde_json::json!({"test_only": "x".repeat(8192)}),
        );
        assert_eq!(
            oversized_receiver.recv(&mut [0; 4097]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(receiver);
        diagnostic.record("wait_error", serde_json::json!({"os_error": 5}));
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}
