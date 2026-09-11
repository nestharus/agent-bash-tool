use std::process::Command;

#[test]
fn tiny_private_tree_custody_and_delivery_processes() {
    let output = Command::new("timeout")
        .args([
            "45",
            "python3",
            "tests/fixtures/image_custody.py",
            "suite",
            env!("CARGO_BIN_EXE_agent-bash"),
        ])
        .output()
        .expect("run private image fixture");
    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    println!("{}", String::from_utf8_lossy(&output.stdout));
}
