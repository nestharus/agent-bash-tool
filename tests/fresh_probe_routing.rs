#![cfg(all(target_os = "linux", not(feature = "private-v30-admission")))]

use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn featureless_probe_precedes_legacy_config_and_c() {
    const STAGE: &str = "AGE319_FEATURELESS_PROBE_PRIVATE_STAGE";
    if std::env::var_os(STAGE).is_none() {
        let output = Command::new("unshare")
            .args(["-Ur", "--"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "featureless_probe_precedes_legacy_config_and_c",
                "--nocapture",
            ])
            .env(STAGE, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    assert_eq!(unsafe { libc::geteuid() }, 0);
    assert!(
        fs::read_to_string("/proc/self/uid_map")
            .unwrap()
            .split_ascii_whitespace()
            .nth(2)
            == Some("1")
    );

    run_probe_case(
        concat!(
            "fresh-bash-parent {",
            "\"root_id\":\"11111111-1111-4111-8111-111111111111\",",
            "\"root_invocation_uuid\":\"22222222-2222-4222-8222-222222222222\",",
            "\"root_session_id\":\"v30:root\",",
            "\"parent_work_grant_id\":\"33333333-3333-4333-8333-333333333333\",",
            "\"parent_work_id\":\"work\"}\n"
        ),
        true,
        69,
        "unavailable before K",
    );
    run_probe_case("fresh-bash-parent {}\n", false, 74, "parent probe invalid");
    run_probe_case(
        "error consumed causal parent work grant absent\n",
        false,
        74,
        "parent probe refused",
    );
    run_probe_case(
        "error Bash child is outside a released root\n",
        false,
        73,
        "state root unavailable",
    );
}

fn run_probe_case(response: &'static str, root_scope: bool, expected_code: i32, reason: &str) {
    let temp = tempfile::tempdir().unwrap();
    let binary = temp.path().join("agent-bash");
    fs::copy(env!("CARGO_BIN_EXE_agent-bash"), &binary).unwrap();
    // The successful probe must select the fresh path before this is read.
    fs::write(temp.path().join("agent-bash.toml"), "state_root = [").unwrap();
    let socket = temp.path().join("v30.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "Bash did not probe fixture peer");
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("fixture accept: {error}"),
            }
        };
        let challenge = [0x5a; 16];
        stream.write_all(&challenge).unwrap();
        let mut frame = [0; 17];
        stream.read_exact(&mut frame).unwrap();
        assert_eq!(frame[0], 0x90);
        assert_eq!(&frame[1..], &challenge);
        stream.write_all(response.as_bytes()).unwrap();
        drop(stream);
        let deadline = Instant::now() + Duration::from_millis(200);
        while Instant::now() < deadline {
            match listener.accept() {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Ok(_) => panic!("Bash submitted C after an unproved or unsupported parent"),
                Err(error) => panic!("fixture second accept: {error}"),
            }
        }
    });
    let effect = temp.path().join("effect");
    let mut command = Command::new(&binary);
    command.arg("run");
    if root_scope {
        command.args(["--completion-scope", "root"]);
    }
    let output = command
        .args(["--", "/usr/bin/touch"])
        .arg(&effect)
        .env(
            "OULIPOLY_KERNEL_BROKER_FIXTURE_SOCKET_V1",
            temp.path().join("control.sock"),
        )
        .output()
        .unwrap();
    server.join().unwrap();
    assert_eq!(output.status.code(), Some(expected_code), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(reason),
        "{output:?}"
    );
    assert!(!effect.exists());
    assert!(fs::read_dir(temp.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("ab_")
    }));
}
