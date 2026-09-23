//! Test-only process and abstract-socket isolation. Never linked into the product.
use std::sync::atomic::{AtomicBool, Ordering};
use std::{env, fs, process::Command, process::Stdio, time::Duration};

const FIXTURE: &str = "AGENT_BASH_TEST_PRIVATE_CASE";
const PARENT_NET: &str = "AGENT_BASH_TEST_PARENT_NET";
const PID1_WRAPPER: &str = "AGENT_BASH_TEST_PID1_WRAPPER";

/// Returns true in the outer libtest worker after the exact private case finishes.
/// Other libtest workers remain concurrent. No inherited endpoint is contacted to
/// discover whether isolation is needed: Linux network namespaces isolate the
/// abstract AF_UNIX image-service address space, including all ancestor services.
/// A private PID namespace and procfs keep ancestor FD inspection within the
/// fixture's user namespace. Fail closed if unprivileged namespaces are unavailable.
#[track_caller]
pub(crate) fn private_case() -> bool {
    let thread = std::thread::current();
    let name = thread.name().expect("named libtest worker");
    if env::var_os(PID1_WRAPPER).is_some() {
        assert_eq!(std::process::id(), 1, "fixture wrapper must be PID 1");
        // Keep PID 1 alive while the actual test runs as its child. The
        // private procfs then contains the complete visible ancestor chain,
        // with no inaccessible parent outside the new user namespace.
        let child = Command::new(env::current_exe().expect("test executable"))
            .args(["--exact", name, "--nocapture"])
            .env_remove(PID1_WRAPPER)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("execute private case below PID 1");
        let child_pid = child.id() as libc::pid_t;
        let done = AtomicBool::new(false);
        let output = std::thread::scope(|scope| {
            // Orphaned grandchildren belong to fixture PID 1. Reap only those
            // children; the test process remains owned by Child::wait_with_output.
            let reaper = scope.spawn(|| {
                while !done.load(Ordering::Relaxed) {
                    if let Ok(children) = fs::read_to_string("/proc/1/task/1/children") {
                        for word in children.split_whitespace() {
                            if let Ok(pid) = word.parse::<libc::pid_t>() {
                                if pid != child_pid {
                                    unsafe {
                                        libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG)
                                    };
                                }
                            }
                        }
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            });
            let output = child.wait_with_output();
            done.store(true, Ordering::Relaxed);
            reaper.join().expect("fixture PID 1 reaper");
            output.expect("wait for private case")
        });
        assert!(
            output.status.success(),
            "private case={name} status={}\nstdout={}\nstderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        print!("{}", String::from_utf8_lossy(&output.stdout));
        return true;
    }
    let net = fs::read_link("/proc/self/ns/net").expect("read current network namespace");
    if env::var(FIXTURE).as_deref() == Ok(name) {
        let parent_net = env::var_os(PARENT_NET).expect("parent namespace evidence");
        assert_ne!(
            net.as_os_str(),
            parent_net,
            "fixture did not change network namespace"
        );
        assert!(std::process::id() > 1, "case must run below fixture PID 1");
        assert_eq!(
            fs::read_link("/proc/self").expect("read private procfs self link"),
            std::path::PathBuf::from(std::process::id().to_string()),
            "fixture procfs must observe its own PID namespace"
        );
        println!(
            "private case={name} net={} parent={}",
            net.display(),
            parent_net.to_string_lossy()
        );
        return false;
    }
    let temp = tempfile::tempdir().expect("private fixture homes");
    let mut command = Command::new("timeout");
    command
        .args([
            "--kill-after=5s",
            "300s",
            "unshare",
            "--user",
            "--map-current-user",
            "--net",
            "--pid",
            "--fork",
            "--mount-proc",
            "--",
        ])
        .arg(env::current_exe().expect("test executable"))
        .args(["--exact", name, "--nocapture"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", temp.path())
        .env("XDG_CONFIG_HOME", temp.path().join("config"))
        .env("XDG_STATE_HOME", temp.path().join("state"))
        .env(FIXTURE, name)
        .env(PID1_WRAPPER, "1")
        .env(PARENT_NET, &net);
    // Preserve only the adapter runtime executable, not the ambient home,
    // endpoint identities or image settings. BUN is the suite's existing override.
    if let Some(bun) = bun_executable() {
        command.env("BUN", bun);
    }
    if let Some(tmp) = env::var_os("TMPDIR") {
        command.env("TMPDIR", tmp);
    }
    let output = command.output().expect("execute private namespace fixture");
    assert!(
        output.status.success(),
        "private case={name} status={}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // Preserve namespace evidence when the caller selects --nocapture.
    print!("{}", String::from_utf8_lossy(&output.stdout));
    true
}

fn bun_executable() -> Option<std::path::PathBuf> {
    let requested = env::var_os("BUN").unwrap_or_else(|| "bun".into());
    let requested = std::path::PathBuf::from(requested);
    if requested.components().count() > 1 {
        return Some(fs::canonicalize(&requested).unwrap_or(requested));
    }
    env::split_paths(&env::var_os("PATH").unwrap_or_default())
        .map(|directory| directory.join(&requested))
        .find(|candidate| candidate.is_file())
        .map(|candidate| fs::canonicalize(&candidate).unwrap_or(candidate))
}
