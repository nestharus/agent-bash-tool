//! Cooperative capture ownership is separate from completion/I/O and hashing.
//! The exclusive nonblocking lease covers open descriptors through durable body
//! publication, and loss inventory through durable missing publication.
use super::*;

pub(super) fn lock(paths: &StatePaths) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(paths.state_dir.join("source-capture.lock"))?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
}

fn selected_file(paths: &StatePaths, selection: &Value) -> io::Result<File> {
    let length = selection["byte_len"]
        .as_u64()
        .filter(|n| *n <= MAX_OUTPUT)
        .ok_or_else(|| error("original output selection missing"))?;
    let directory = fs::metadata(&paths.state_dir)?;
    if selection["directory"]["device"] != directory.dev()
        || selection["directory"]["inode"] != directory.ino()
    {
        return Err(error("original source directory changed"));
    }
    // Enumerated names are only candidates. Open without following links and
    // validate the actual descriptor against the original storage and boundary.
    for entry in fs::read_dir(&paths.state_dir)? {
        let entry = entry?;
        let meta = fs::symlink_metadata(entry.path())?;
        if selection["device"] != meta.dev() || selection["inode"] != meta.ino() {
            continue;
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(entry.path())?;
        let meta = file.metadata()?;
        if meta.is_file()
            && selection["device"] == meta.dev()
            && selection["inode"] == meta.ino()
            && meta.len() >= length
        {
            return Ok(file);
        }
    }
    Err(error(
        "no complete original selected inode in managed storage",
    ))
}

// Receipt name is derived only from a producer-generated local temporary name.
fn receipt_name(name: &str) -> String {
    format!("output-copy-{name}.json")
}
fn candidate(name: &str) -> bool {
    name.starts_with(".completion-output-") && name.ends_with(".tmp")
}
fn receipt(
    paths: &StatePaths,
    name: &str,
    meta: &fs::Metadata,
    selection: &Value,
) -> io::Result<Value> {
    let record = value(&paths.state_dir.join(receipt_name(name)))?;
    if !meta.is_file()
        || record["device"] != meta.dev()
        || record["inode"] != meta.ino()
        || record["selection_sha256"] != digest(&bytes(selection)?)
        || record["byte_len"] != selection["byte_len"]
    {
        return Err(error("interrupted copy identity conflict"));
    }
    Ok(record)
}

fn recover_copy(paths: &StatePaths, selection: &Value) -> io::Result<bool> {
    for entry in fs::read_dir(&paths.state_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !candidate(&name) {
            continue;
        }
        let meta = fs::symlink_metadata(entry.path())?;
        // Unknown/old copies are not evidence of completion or grounds to delete.
        let Ok(record) = receipt(paths, &name, &meta, selection) else {
            continue;
        };
        if record["complete"] != true || record["byte_len"] != meta.len() {
            continue;
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(entry.path())?;
        let actual = file.metadata()?;
        receipt(paths, &name, &actual, selection)?;
        if actual.len() != meta.len() {
            return Err(error("completed copy changed"));
        }
        file.sync_all()?;
        fs::hard_link(entry.path(), paths.state_dir.join(OUTPUT))?;
        File::open(&paths.state_dir)?.sync_all()?;
        return Ok(true);
    }
    Ok(false)
}

/// Only a proven dead writer's exact, short, non-finalized copy can cease to
/// inhibit loss inventory. Preserve its bytes and receipt for inspection.
pub(super) fn incomplete_dead_copy(
    paths: &StatePaths,
    name: &str,
    meta: &fs::Metadata,
    selection: &Value,
) -> bool {
    let check = || -> io::Result<bool> {
        if !candidate(name) {
            return Ok(false);
        }
        let record = receipt(paths, name, meta, selection)?;
        let writer: CallerChainEntry = serde_json::from_value(record["writer"].clone())?;
        Ok(record["complete"] == false
            && meta.len() < selection["byte_len"].as_u64().unwrap_or(0)
            && matches!(
                state::process_identity_evidence(&writer),
                state::ProcessIdentityEvidence::Gone | state::ProcessIdentityEvidence::Mismatch
            ))
    };
    check().unwrap_or(false)
}

/// Caller owns source-capture.lock, never a whole-body hashing lock.
pub(super) fn freeze(paths: &StatePaths) -> io::Result<()> {
    let destination = paths.state_dir.join(OUTPUT);
    if destination.try_exists()? {
        return Ok(());
    }
    if paths
        .state_dir
        .join("missing-output-observation-v2.json")
        .try_exists()?
    {
        return Err(error("original output already adjudicated missing"));
    }
    let selection = value(&paths.state_dir.join(SELECTION))?;
    let directory = fs::metadata(&paths.state_dir)?;
    if selection["directory"]["device"] != directory.dev()
        || selection["directory"]["inode"] != directory.ino()
    {
        return Err(error("original source directory changed"));
    }
    if recover_copy(paths, &selection)? {
        return Ok(());
    }
    let source = selected_file(paths, &selection)?;
    let length = selection["byte_len"]
        .as_u64()
        .ok_or_else(|| error("missing selected boundary"))?;
    stop_barrier(paths, "capture-open")?;
    let name = format!(
        ".completion-output-{}.tmp",
        state::generate_handle().map_err(io::Error::other)?
    );
    let temp = paths.state_dir.join(&name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temp)?;
    let meta = file.metadata()?;
    let mut record = json!({"device": meta.dev(), "inode": meta.ino(),
        "selection_sha256": digest(&bytes(&selection)?), "byte_len": length,
        "writer": identity(unsafe { libc::getpid() })?, "complete": false});
    save(paths, &receipt_name(&name), &record)?;
    // A fault build can stop after an actual partial write with a real receipt.
    let mut source = source.take(length);
    let first = io::copy(&mut source.by_ref().take(length.min(4096)), &mut file)?;
    stop_barrier(paths, "capture-partial")?;
    if first + io::copy(&mut source, &mut file)? != length {
        return Err(error("original output selection was lost during copy"));
    }
    file.sync_all()?;
    record["complete"] = json!(true);
    save(paths, &receipt_name(&name), &record)?;
    stop_barrier(paths, "capture-complete")?;
    fs::hard_link(&temp, &destination)?;
    File::open(&paths.state_dir)?.sync_all()?;
    fs::remove_file(temp)?;
    Ok(())
}

#[cfg(feature = "source-fault-tests")]
fn stop_barrier(paths: &StatePaths, name: &str) -> io::Result<()> {
    let configured = std::env::var("AGENT_BASH_SOURCE_FAULT").unwrap_or_default();
    if configured == name || configured == format!("guardian-{name}") {
        immutable(
            paths,
            &format!("fault-{name}.reached.json"),
            &bytes(&json!(identity(unsafe { libc::getpid() })?))?,
        )?;
        unsafe {
            libc::raise(libc::SIGSTOP);
        }
    }
    Ok(())
}
#[cfg(not(feature = "source-fault-tests"))]
fn stop_barrier(_paths: &StatePaths, _name: &str) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (tempfile::TempDir, StatePaths, Value) {
        let (temp, paths, _) = super::super::tests::source();
        fs::write(&paths.log, b"original selected bytes").unwrap();
        select_output(&paths).unwrap();
        let selected = value(&paths.state_dir.join(SELECTION)).unwrap();
        (temp, paths, selected)
    }
    #[test]
    fn capture_lease_is_nonblocking_and_independent_of_completion() {
        let (_temp, paths, _) = fixture();
        let lease = lock(&paths).unwrap();
        assert_eq!(lock(&paths).unwrap_err().kind(), io::ErrorKind::WouldBlock);
        assert!(state::try_lock_completion(&paths).unwrap().is_some());
        drop(lease);
        assert!(lock(&paths).is_ok());
    }
    #[test]
    fn managed_alias_recovers_exact_prefix_without_path_restoration() {
        let (_temp, paths, _) = fixture();
        fs::rename(
            paths.state_dir.join(SELECTED_LOG),
            paths.state_dir.join("alias"),
        )
        .unwrap();
        fs::remove_file(&paths.log).unwrap();
        fs::write(&paths.log, b"later log").unwrap();
        freeze_output(&paths).unwrap();
        assert_eq!(
            fs::read(paths.state_dir.join(OUTPUT)).unwrap(),
            b"original selected bytes"
        );
        assert!(!paths.state_dir.join(SELECTED_LOG).exists());
    }
    #[test]
    fn unvalidated_full_copy_is_not_adopted_by_length_or_filename() {
        let (_temp, paths, selection) = fixture();
        fs::write(
            paths.state_dir.join(".completion-output-unknown.tmp"),
            b"original selected bytes",
        )
        .unwrap();
        assert!(!recover_copy(&paths, &selection).unwrap());
        assert!(!paths.state_dir.join(OUTPUT).exists());
    }
    #[test]
    fn copy_receipt_must_bind_exact_storage_selection_and_completion() {
        let (_temp, paths, selection) = fixture();
        let name = ".completion-output-fixture.tmp";
        let temp = paths.state_dir.join(name);
        fs::write(&temp, b"original selected bytes").unwrap();
        let meta = fs::metadata(&temp).unwrap();
        let record = json!({"device": meta.dev(), "inode": meta.ino(),
            "selection_sha256": digest(&bytes(&selection).unwrap()),
            "byte_len": meta.len(), "complete": true});
        for field in [
            "device",
            "inode",
            "selection_sha256",
            "byte_len",
            "complete",
        ] {
            let mut invalid = record.clone();
            invalid[field] = Value::Null;
            save(&paths, &receipt_name(name), &invalid).unwrap();
            assert!(
                !recover_copy(&paths, &selection).unwrap(),
                "accepted bad {field}"
            );
        }
        save(&paths, &receipt_name(name), &record).unwrap();
        assert!(recover_copy(&paths, &selection).unwrap());
        assert_eq!(
            fs::read(paths.state_dir.join(OUTPUT)).unwrap(),
            b"original selected bytes"
        );
    }
}
