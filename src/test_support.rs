//! Test-only process and abstract-socket isolation. Never linked into the product.
use std::{env, fs, process::Command};

const FIXTURE: &str = "AGENT_BASH_TEST_PRIVATE_CASE";
const PARENT_NET: &str = "AGENT_BASH_TEST_PARENT_NET";

/// Returns true in the outer libtest worker after the exact private case finishes.
/// Other libtest workers remain concurrent. No inherited endpoint is contacted to
/// discover whether isolation is needed: Linux network namespaces isolate the
/// abstract AF_UNIX image-service address space, including all ancestor services.
/// Fail closed on hosts without unprivileged user/network namespaces or unshare.
#[track_caller]
pub(crate) fn private_case() -> bool {
    let thread = std::thread::current();
    let name = thread.name().expect("named libtest worker");
    let net = fs::read_link("/proc/self/ns/net").expect("read current network namespace");
    if env::var(FIXTURE).as_deref() == Ok(name) {
        let parent_net = env::var_os(PARENT_NET).expect("parent namespace evidence");
        assert_ne!(
            net.as_os_str(),
            parent_net,
            "fixture did not change network namespace"
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
