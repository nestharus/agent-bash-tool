//! Cooperative capture ownership is separate from completion/I/O and hashing.
//! The exclusive nonblocking lease covers open descriptors through durable body
//! publication, and loss inventory through durable missing publication.
use super::*;
use std::path::PathBuf;

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

/// Caller holds source-capture.lock through loss inventory. Validated receipts
/// were introduced with that lease: no cooperating writer can still be copying
/// this short fragment. Process liveness is not operation ownership. Unknown or
/// legacy provenance and full uncompleted copies remain uncertainty.
pub(super) fn inactive_short_copy(
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
        let _writer: CallerChainEntry = serde_json::from_value(record["writer"].clone())?;
        Ok(record["complete"] == false && meta.len() < selection["byte_len"].as_u64().unwrap_or(0))
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
    // One slot per selection bounds even repeated cleanup failures. Existing
    // slots are crash/cleanup uncertainty, not permission to overwrite evidence.
    let name = format!(".completion-output-{}.tmp", digest(&bytes(&selection)?));
    let mut attempt = Attempt::new(paths, &name);
    let result = attempt.capture(source, length, &selection);
    // Only this call's created inodes, under the capture lease, are disposable.
    // Once linked publicly they may have another custodian: never roll them back.
    if !destination.try_exists().unwrap_or(true) {
        if attempt.disposable(&selection) {
            attempt.cleanup();
        }
    } else if result.is_ok() {
        fs::remove_file(paths.state_dir.join(&name))?;
    }
    result
}

/// In-memory operation ownership, not a retained authority ledger. A crash drops
/// this knowledge; a later caller must use receipts or retain uncertainty.
struct Attempt<'a> {
    paths: &'a StatePaths,
    name: &'a str,
    owned: Vec<(PathBuf, u64, u64)>,
}
impl<'a> Attempt<'a> {
    fn new(paths: &'a StatePaths, name: &'a str) -> Self {
        Self {
            paths,
            name,
            owned: Vec::new(),
        }
    }
    fn create(&mut self, path: PathBuf) -> io::Result<File> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)?;
        let meta = file.metadata()?;
        self.owned.push((path, meta.dev(), meta.ino()));
        Ok(file)
    }
    fn save_receipt(&mut self, record: &Value) -> io::Result<()> {
        let path = self.paths.state_dir.join(receipt_name(self.name));
        let temp = path.with_extension("pending");
        let mut file = self.create(temp.clone())?;
        if record["complete"] == true {
            returning_fault(self.paths, "receipt-write", &file)?;
        }
        file.write_all(&bytes(record)?)?;
        if record["complete"] == true {
            returning_fault(self.paths, "receipt-fsync", &file)?;
        }
        file.sync_all()?;
        fs::rename(&temp, &path)?;
        self.owned.last_mut().expect("created receipt").0 = path;
        File::open(&self.paths.state_dir)?.sync_all()
    }
    fn capture(&mut self, source: File, length: u64, selection: &Value) -> io::Result<()> {
        // Do not overwrite a receipt or receipt staging file whose ownership was
        // lost, even if its body pathname is absent.
        let receipt = self.paths.state_dir.join(receipt_name(self.name));
        if receipt.try_exists()? || receipt.with_extension("pending").try_exists()? {
            return Err(error("retained capture slot requires recovery"));
        }
        let temp = self.paths.state_dir.join(self.name);
        let mut file = self.create(temp.clone())?;
        let meta = file.metadata()?;
        let mut record = json!({"device": meta.dev(), "inode": meta.ino(),
            "selection_sha256": digest(&bytes(selection)?), "byte_len": length,
            "writer": identity(unsafe { libc::getpid() })?, "complete": false});
        self.save_receipt(&record)?;
        let mut source = source.take(length);
        let first = io::copy(&mut source.by_ref().take(length.min(4096)), &mut file)?;
        stop_barrier(self.paths, "capture-partial")?;
        returning_fault(self.paths, "copy", &file)?;
        if first + io::copy(&mut source, &mut file)? != length {
            return Err(error("original output selection was lost during copy"));
        }
        returning_fault(self.paths, "fsync", &file)?;
        file.sync_all()?;
        record["complete"] = json!(true);
        self.save_receipt(&record)?;
        stop_barrier(self.paths, "capture-complete")?;
        returning_fault(self.paths, "publish", &file)?;
        fs::hard_link(&temp, self.paths.state_dir.join(OUTPUT))?;
        File::open(&self.paths.state_dir)?.sync_all()
    }
    fn disposable(&self, selection: &Value) -> bool {
        let path = self.paths.state_dir.join(self.name);
        let Ok(meta) = fs::symlink_metadata(path) else {
            return false;
        };
        // A completed receipt is retained recovery custody, even when final
        // linking or directory synchronization returns an error to this writer.
        if receipt(self.paths, self.name, &meta, selection)
            .is_ok_and(|r| r["complete"] == true && r["byte_len"] == meta.len())
        {
            return false;
        }
        // Do not destroy a possibly sole full copy after original-path loss.
        // With no completion receipt that remains uncertain, not missing/ready.
        meta.len() < selection["byte_len"].as_u64().unwrap_or(0)
            || selected_file(self.paths, selection).is_ok()
    }
    fn cleanup(&self) {
        for (path, device, inode) in self.owned.iter().rev() {
            if let Ok(meta) = fs::symlink_metadata(path)
                && meta.is_file()
                && meta.dev() == *device
                && meta.ino() == *inode
            {
                // Failure leaves the fixed slot occupied, not a fresh allocation
                // on every retry. Never remove a replaced or unknown pathname.
                let _ = fs::remove_file(path);
            }
        }
    }
}

// Unit controls use real failing kernel operations on private descriptors. No
// fixture writes a copy receipt, completed body, or missing-output proof.
#[cfg(test)]
fn returning_fault(paths: &StatePaths, edge: &str, file: &File) -> io::Result<()> {
    let configured =
        fs::read_to_string(paths.state_dir.join("test-returning-error")).unwrap_or_default();
    if configured != edge {
        return Ok(());
    }
    if edge == "publish" {
        use std::os::unix::fs::PermissionsExt;
        return fs::set_permissions(&paths.state_dir, fs::Permissions::from_mode(0o500));
    }
    let target = if edge.ends_with("fsync") {
        "/dev/null"
    } else {
        "/dev/full"
    };
    let failed = OpenOptions::new().write(true).open(target)?;
    // Substitute only this operation's private descriptor. The subsequent
    // production copy/write/fsync syscall returns the real kernel error.
    if unsafe { libc::dup2(failed.as_raw_fd(), file.as_raw_fd()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
#[cfg(not(test))]
fn returning_fault(_paths: &StatePaths, _edge: &str, _file: &File) -> io::Result<()> {
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
    use std::os::unix::fs::PermissionsExt;
    fn fixture() -> (tempfile::TempDir, StatePaths, Value) {
        let (temp, paths, _) = super::super::tests::source();
        fs::write(&paths.log, b"original selected bytes").unwrap();
        select_output(&paths).unwrap();
        let selected = value(&paths.state_dir.join(SELECTION)).unwrap();
        (temp, paths, selected)
    }
    #[test]
    fn returning_errors_retry_without_scratch_amplification() {
        if crate::test_support::private_case() {
            return;
        }
        for edge in ["copy", "fsync", "receipt-write", "receipt-fsync"] {
            let (_temp, paths, _) = super::super::tests::source();
            let original = vec![b'a'; 32768];
            fs::write(&paths.log, &original).unwrap();
            select_output(&paths).unwrap();
            let selection = fs::read(paths.state_dir.join(SELECTION)).unwrap();
            fs::remove_file(&paths.log).unwrap();
            fs::write(&paths.log, b"later unrelated output").unwrap();
            fs::write(paths.state_dir.join("test-returning-error"), edge).unwrap();
            for attempt in 0..12 {
                let failure = freeze_output(&paths).unwrap_err();
                assert!(
                    failure.raw_os_error().is_some(),
                    "real syscall failure: {failure}"
                );
                let scratch: Vec<_> = fs::read_dir(&paths.state_dir)
                    .unwrap()
                    .map(|e| e.unwrap().path())
                    .filter(|p| {
                        p.file_name()
                            .unwrap()
                            .to_string_lossy()
                            .contains("completion-output-")
                    })
                    .collect();
                let size: u64 = scratch.iter().map(|p| fs::metadata(p).unwrap().len()).sum();
                println!(
                    "edge={edge} attempt={attempt} errno={:?} scratch_files={} scratch_bytes={size}",
                    failure.raw_os_error(),
                    scratch.len()
                );
                assert!(
                    scratch.is_empty(),
                    "returned private fragments retained: {scratch:?}"
                );
                assert!(!paths.state_dir.join(OUTPUT).exists());
                assert!(
                    !paths
                        .state_dir
                        .join("missing-output-observation-v2.json")
                        .exists()
                );
                assert_eq!(
                    fs::read(paths.state_dir.join(SELECTION)).unwrap(),
                    selection
                );
                assert!(
                    lock(&paths).is_ok(),
                    "returned writer no longer owns capture"
                );
            }
            fs::remove_file(paths.state_dir.join("test-returning-error")).unwrap();
            freeze_output(&paths).unwrap();
            assert_eq!(fs::read(paths.state_dir.join(OUTPUT)).unwrap(), original);
            assert_eq!(
                fs::read(paths.state_dir.join(SELECTION)).unwrap(),
                selection
            );
            println!("edge={edge} recovered_original=true writer_still_alive=true");
        }
    }
    #[test]
    fn returned_link_failure_retains_completed_copy_for_another_owner() {
        if crate::test_support::private_case() {
            return;
        }
        let (_temp, paths, selection) = fixture();
        fs::write(paths.state_dir.join("test-returning-error"), "publish").unwrap();
        let failure = freeze_output(&paths).unwrap_err();
        assert_eq!(failure.kind(), io::ErrorKind::PermissionDenied);
        fs::set_permissions(&paths.state_dir, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(!paths.state_dir.join(OUTPUT).exists());
        let name = format!(
            ".completion-output-{}.tmp",
            digest(&bytes(&selection).unwrap())
        );
        let meta = fs::metadata(paths.state_dir.join(&name)).unwrap();
        assert_eq!(
            receipt(&paths, &name, &meta, &selection).unwrap()["complete"],
            true
        );
        fs::remove_file(paths.state_dir.join(SELECTED_LOG)).unwrap();
        fs::remove_file(&paths.log).unwrap();
        fs::remove_file(paths.state_dir.join("test-returning-error")).unwrap();
        freeze_output(&paths).unwrap();
        assert_eq!(
            fs::read(paths.state_dir.join(OUTPUT)).unwrap(),
            b"original selected bytes"
        );
        println!(
            "actual_link_error={failure}; completed_receipt_retained=true original_pin_absent=true recovered_original=true writer_alive=true"
        );
    }
    #[test]
    fn returned_short_copy_is_inactive_even_when_cleanup_fails_and_writer_lives() {
        if crate::test_support::private_case() {
            return;
        }
        let (_temp, paths, _) = super::super::tests::source();
        fs::write(&paths.log, vec![b'a'; 32768]).unwrap();
        select_output(&paths).unwrap();
        let selection = value(&paths.state_dir.join(SELECTION)).unwrap();
        let lease = lock(&paths).unwrap();
        let name = format!(
            ".completion-output-{}.tmp",
            digest(&bytes(&selection).unwrap())
        );
        let mut attempt = Attempt::new(&paths, &name);
        fs::write(paths.state_dir.join("test-returning-error"), "copy").unwrap();
        let failure = attempt
            .capture(
                selected_file(&paths, &selection).unwrap(),
                32768,
                &selection,
            )
            .unwrap_err();
        assert_eq!(failure.raw_os_error(), Some(libc::ENOSPC));
        fs::set_permissions(&paths.state_dir, fs::Permissions::from_mode(0o500)).unwrap();
        attempt.cleanup();
        let meta = fs::metadata(paths.state_dir.join(&name)).unwrap();
        assert_eq!(meta.len(), 4096);
        assert!(inactive_short_copy(&paths, &name, &meta, &selection));
        assert!(lock(&paths).is_err(), "inventory still owns exclusion");
        fs::set_permissions(&paths.state_dir, fs::Permissions::from_mode(0o700)).unwrap();
        attempt.cleanup();
        drop(lease);
        println!(
            "actual_copy_errno=ENOSPC actual_cleanup_denied=true retained_bytes=4096 capture_lease_owned=true writer_alive=true short_copy_inactive=true"
        );
    }
    #[test]
    fn unknown_fixed_slot_is_bounded_and_never_overwritten() {
        if crate::test_support::private_case() {
            return;
        }
        let (_temp, paths, selection) = fixture();
        let name = format!(
            ".completion-output-{}.tmp",
            digest(&bytes(&selection).unwrap())
        );
        let unknown = paths.state_dir.join(name);
        fs::write(&unknown, b"uncertain crash evidence").unwrap();
        for _ in 0..12 {
            assert!(freeze_output(&paths).is_err());
            assert_eq!(fs::read(&unknown).unwrap(), b"uncertain crash evidence");
            assert!(!paths.state_dir.join(OUTPUT).exists());
        }
        assert_eq!(
            fs::read_dir(&paths.state_dir)
                .unwrap()
                .filter(|e| candidate(&e.as_ref().unwrap().file_name().to_string_lossy()))
                .count(),
            1
        );
    }
    #[test]
    fn cleanup_failure_and_replaced_names_never_authorize_fresh_scratch() {
        if crate::test_support::private_case() {
            return;
        }
        let (_temp, paths, selection) = fixture();
        let name = format!(
            ".completion-output-{}.tmp",
            digest(&bytes(&selection).unwrap())
        );
        let path = paths.state_dir.join(&name);
        let mut attempt = Attempt::new(&paths, &name);
        let mut file = attempt.create(path.clone()).unwrap();
        file.write_all(b"private partial").unwrap();
        fs::set_permissions(&paths.state_dir, fs::Permissions::from_mode(0o500)).unwrap();
        attempt.cleanup();
        assert!(path.exists(), "actual unlink permission failure required");
        fs::set_permissions(&paths.state_dir, fs::Permissions::from_mode(0o700)).unwrap();
        // The returned invocation still has positive ownership, so it can retry
        // cleanup; a new capture call has no such authority and cannot allocate.
        for _ in 0..12 {
            assert!(freeze_output(&paths).is_err());
        }
        attempt.cleanup();
        assert!(!path.exists());
        freeze_output(&paths).unwrap();
        assert_eq!(
            fs::read(paths.state_dir.join(OUTPUT)).unwrap(),
            b"original selected bytes"
        );

        let other = paths.state_dir.join("private-test-slot");
        let mut attempt = Attempt::new(&paths, "private-test-slot");
        let original = attempt.create(other.clone()).unwrap();
        fs::remove_file(&other).unwrap();
        fs::write(&other, b"another owner's evidence").unwrap();
        attempt.cleanup();
        assert_eq!(fs::read(other).unwrap(), b"another owner's evidence");
        drop(original); // Keep old inode allocated during the substitution check.
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
