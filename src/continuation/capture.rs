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
    // Keep retained slot evidence intact. A validated original source permits
    // an anonymous retry, whose private allocation dies with its descriptor.
    let name = format!(".completion-output-{}.tmp", digest(&bytes(&selection)?));
    if occupied_slot(paths, &name)? {
        return capture_anonymous(paths, source, length);
    }
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

// Occupancy is not ownership, including dangling symlinks and orphan receipts.
fn occupied_slot(paths: &StatePaths, name: &str) -> io::Result<bool> {
    let receipt = paths.state_dir.join(receipt_name(name));
    for path in [
        paths.state_dir.join(name),
        receipt.with_extension("pending"),
        receipt,
    ] {
        match fs::symlink_metadata(path) {
            Ok(_) => return Ok(true),
            Err(err) if err.kind() == io::ErrorKind::NotFound => (),
            Err(err) => return Err(err),
        }
    }
    Ok(false)
}

/// Source-proven escape from retained-slot uncertainty. The capture lease bounds
/// live allocation to one private inode. O_TMPFILE needs no unlink or persisted
/// cleanup authority, even across returned errors or process death. Never fall
/// back to random named scratch on unsupported filesystems. Existing receipts,
/// fragments and original pins are not changed. As with initial capture, original
/// managed storage must survive interruption for retry: this is not protection
/// against external deletion of all original and completed storage.
fn capture_anonymous(paths: &StatePaths, source: File, length: u64) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_TMPFILE | libc::O_CLOEXEC)
        .open(&paths.state_dir)?;
    copy_selected(paths, source, &mut file, length)?;
    stop_barrier(paths, "capture-complete")?;
    returning_fault(paths, "publish", &file)?;
    link_anonymous(&file, &paths.state_dir.join(OUTPUT))?;
    File::open(&paths.state_dir)?.sync_all()
}

// /proc/self/fd + AT_SYMLINK_FOLLOW is Linux's unprivileged O_TMPFILE
// publication path (AT_EMPTY_PATH requires CAP_DAC_READ_SEARCH). linkat never
// replaces a public destination. The descriptor remains owned until after link.
fn link_anonymous(file: &File, destination: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let source = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
    let destination = CString::new(destination.as_os_str().as_bytes())?;
    let result = unsafe {
        libc::linkat(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::AT_SYMLINK_FOLLOW,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn copy_selected(paths: &StatePaths, source: File, file: &mut File, length: u64) -> io::Result<()> {
    let mut source = source.take(length);
    let first = io::copy(&mut source.by_ref().take(length.min(4096)), file)?;
    stop_barrier(paths, "capture-partial")?;
    returning_fault(paths, "copy", file)?;
    if first + io::copy(&mut source, file)? != length {
        return Err(error("original output selection was lost during copy"));
    }
    returning_fault(paths, "fsync", file)?;
    file.sync_all()
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
            "writer": identity()?, "complete": false});
        self.save_receipt(&record)?;
        copy_selected(self.paths, source, &mut file, length)?;
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
    if configured.strip_suffix("-cleanup").unwrap_or(&configured) != edge {
        return Ok(());
    }
    if configured.ends_with("-cleanup") {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&paths.state_dir, fs::Permissions::from_mode(0o500))?;
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
            &bytes(&json!(identity()?))?,
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
    // Re-exec the unit image, not a retained Attempt or inherited capture FD.
    fn capture_process(paths: &StatePaths) -> std::process::Command {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "continuation::capture::tests::capture_process_worker",
                "--nocapture",
            ])
            .env("AGE360_CAPTURE_ROOT", &paths.root)
            .env("AGE360_CAPTURE_HANDLE", &paths.handle);
        command
    }
    #[test]
    fn capture_process_worker() {
        let Some(root) = std::env::var_os("AGE360_CAPTURE_ROOT") else {
            return;
        };
        let paths = StatePaths::new(root.into(), std::env::var("AGE360_CAPTURE_HANDLE").unwrap());
        let result = freeze_output(&paths);
        if let Ok(expected) = std::env::var("AGE360_CAPTURE_ERRNO") {
            let failure = result.unwrap_err();
            assert_eq!(failure.raw_os_error(), Some(expected.parse().unwrap()));
            println!("fresh_pid={} actual_errno={failure}", std::process::id());
        } else {
            result.unwrap();
            println!("fresh_pid={} recovered=true", std::process::id());
        }
    }
    fn run_capture_process(paths: &StatePaths, errno: Option<i32>) {
        let mut command = capture_process(paths);
        if let Some(errno) = errno {
            command.env("AGE360_CAPTURE_ERRNO", errno.to_string());
        }
        let output = command.output().unwrap();
        assert!(output.status.success(), "{output:?}");
        print!("{}", String::from_utf8_lossy(&output.stdout));
    }
    fn scratch_evidence(paths: &StatePaths) -> Vec<(PathBuf, Vec<u8>)> {
        let mut result: Vec<_> = fs::read_dir(&paths.state_dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .contains("completion-output-")
                    && p.file_name().unwrap() != OUTPUT
            })
            .map(|p| {
                let data = fs::read(&p).unwrap();
                (p, data)
            })
            .collect();
        result.sort();
        result
    }
    #[test]
    fn cleanup_errors_then_fresh_process_retries_retain_evidence_and_recover() {
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
            fs::write(&paths.log, b"unrelated replacement log").unwrap();
            fs::write(
                paths.state_dir.join("test-returning-error"),
                format!("{edge}-cleanup"),
            )
            .unwrap();
            let errno = if edge.ends_with("fsync") {
                libc::EINVAL
            } else {
                libc::ENOSPC
            };
            run_capture_process(&paths, Some(errno));
            let evidence = scratch_evidence(&paths);
            assert!(!evidence.is_empty());
            // Fresh processes cannot unlink with this directory's actual mode.
            for _ in 0..3 {
                run_capture_process(&paths, Some(libc::EACCES));
                assert_eq!(scratch_evidence(&paths), evidence);
                assert!(lock(&paths).is_ok());
            }
            // Anonymous copy errors must not append fresh named slots, even
            // when each operation returns with cleanup permission denied again.
            for attempt in 0..12 {
                fs::set_permissions(&paths.state_dir, fs::Permissions::from_mode(0o700)).unwrap();
                fs::write(paths.state_dir.join("test-returning-error"), "copy-cleanup").unwrap();
                run_capture_process(&paths, Some(libc::ENOSPC));
                assert_eq!(scratch_evidence(&paths), evidence);
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
                assert!(lock(&paths).is_ok());
                println!(
                    "initial_edge={edge} retry={attempt} retained_files={} retained_bytes={}",
                    evidence.len(),
                    evidence.iter().map(|(_, b)| b.len()).sum::<usize>()
                );
            }
            fs::set_permissions(&paths.state_dir, fs::Permissions::from_mode(0o700)).unwrap();
            fs::remove_file(paths.state_dir.join("test-returning-error")).unwrap();
            run_capture_process(&paths, None);
            assert_eq!(scratch_evidence(&paths), evidence);
            assert_eq!(fs::read(paths.state_dir.join(OUTPUT)).unwrap(), original);
            assert_eq!(
                fs::read(paths.state_dir.join(SELECTION)).unwrap(),
                selection
            );
        }
    }
    #[test]
    #[cfg(feature = "source-fault-tests")]
    fn interrupted_occupied_slot_retry_releases_allocation_and_recovers_original() {
        if crate::test_support::private_case() {
            return;
        }
        for edge in ["capture-partial", "capture-complete"] {
            let (_temp, paths, _) = super::super::tests::source();
            let original = vec![b'a'; 32768];
            fs::write(&paths.log, &original).unwrap();
            select_output(&paths).unwrap();
            let selection = fs::read(paths.state_dir.join(SELECTION)).unwrap();
            let name = format!(".completion-output-{}.tmp", digest(&selection));
            fs::write(paths.state_dir.join(name), b"unknown retained evidence").unwrap();
            fs::remove_file(&paths.log).unwrap();
            fs::write(&paths.log, b"replacement live log").unwrap();
            let evidence = scratch_evidence(&paths);
            let mut child = capture_process(&paths)
                .env("AGENT_BASH_SOURCE_FAULT", edge)
                .spawn()
                .unwrap();
            let mut status = 0;
            assert_eq!(
                unsafe { libc::waitpid(child.id() as i32, &mut status, libc::WUNTRACED) },
                child.id() as i32
            );
            assert!(libc::WIFSTOPPED(status));
            assert!(
                paths
                    .state_dir
                    .join(format!("fault-{edge}.reached.json"))
                    .exists()
            );
            assert!(
                lock(&paths).is_err(),
                "stopped capture still excludes loss inventory"
            );
            assert!(freeze_output(&paths).is_err());
            assert!(!paths.state_dir.join(OUTPUT).exists());
            assert!(
                !paths
                    .state_dir
                    .join("missing-output-observation-v2.json")
                    .exists()
            );
            assert_eq!(scratch_evidence(&paths), evidence);
            // Prove the stopped copier holds an anonymous inode, not a new name.
            let anonymous: Vec<_> = fs::read_dir(format!("/proc/{}/fd", child.id()))
                .unwrap()
                .filter_map(|e| fs::read_link(e.ok()?.path()).ok())
                .filter(|p| {
                    p.to_string_lossy().contains("(deleted)") && p.starts_with(&paths.state_dir)
                })
                .collect();
            assert_eq!(anonymous.len(), 1, "{anonymous:?}");
            child.kill().unwrap();
            assert!(!child.wait().unwrap().success());
            assert!(lock(&paths).is_ok());
            run_capture_process(&paths, None);
            assert_eq!(scratch_evidence(&paths), evidence);
            assert_eq!(fs::read(paths.state_dir.join(OUTPUT)).unwrap(), original);
            assert_eq!(
                fs::read(paths.state_dir.join(SELECTION)).unwrap(),
                selection
            );
            println!(
                "interruption={edge} anonymous_fds=1 reaped=true original_recovered=true unknown_unchanged=true"
            );
        }
    }
    #[test]
    fn occupied_slot_anonymous_fsync_and_link_errors_retry_without_named_growth() {
        if crate::test_support::private_case() {
            return;
        }
        for edge in ["fsync", "publish"] {
            let (_temp, paths, selection) = fixture();
            let name = format!(
                ".completion-output-{}.tmp",
                digest(&bytes(&selection).unwrap())
            );
            fs::write(paths.state_dir.join(name), b"unknown evidence").unwrap();
            let evidence = scratch_evidence(&paths);
            fs::remove_file(&paths.log).unwrap();
            fs::write(&paths.log, b"replacement log").unwrap();
            fs::write(paths.state_dir.join("test-returning-error"), edge).unwrap();
            for _ in 0..12 {
                run_capture_process(
                    &paths,
                    Some(if edge == "fsync" {
                        libc::EINVAL
                    } else {
                        libc::EACCES
                    }),
                );
                assert_eq!(scratch_evidence(&paths), evidence);
                assert!(!paths.state_dir.join(OUTPUT).exists());
                fs::set_permissions(&paths.state_dir, fs::Permissions::from_mode(0o700)).unwrap();
            }
            fs::remove_file(paths.state_dir.join("test-returning-error")).unwrap();
            run_capture_process(&paths, None);
            assert_eq!(scratch_evidence(&paths), evidence);
            assert_eq!(
                fs::read(paths.state_dir.join(OUTPUT)).unwrap(),
                b"original selected bytes"
            );
        }
    }
    #[test]
    #[cfg(feature = "source-fault-tests")]
    fn interrupted_named_attempt_with_intact_pin_recovers_in_fresh_process() {
        if crate::test_support::private_case() {
            return;
        }
        for edge in ["capture-partial", "capture-complete"] {
            let (_temp, paths, _) = super::super::tests::source();
            let original = vec![b'a'; 32768];
            fs::write(&paths.log, &original).unwrap();
            select_output(&paths).unwrap();
            let selection = fs::read(paths.state_dir.join(SELECTION)).unwrap();
            fs::remove_file(&paths.log).unwrap();
            fs::write(&paths.log, b"replacement live log").unwrap();
            let mut child = capture_process(&paths)
                .env("AGENT_BASH_SOURCE_FAULT", edge)
                .spawn()
                .unwrap();
            let mut status = 0;
            assert_eq!(
                unsafe { libc::waitpid(child.id() as i32, &mut status, libc::WUNTRACED) },
                child.id() as i32
            );
            assert!(libc::WIFSTOPPED(status));
            assert!(
                paths
                    .state_dir
                    .join(format!("fault-{edge}.reached.json"))
                    .exists()
            );
            assert!(lock(&paths).is_err());
            let evidence = scratch_evidence(&paths);
            assert_eq!(evidence.len(), 2, "actual named body plus product receipt");
            child.kill().unwrap();
            assert!(!child.wait().unwrap().success());
            run_capture_process(&paths, None);
            assert_eq!(scratch_evidence(&paths), evidence);
            assert_eq!(fs::read(paths.state_dir.join(OUTPUT)).unwrap(), original);
            assert_eq!(
                fs::read(paths.state_dir.join(SELECTION)).unwrap(),
                selection
            );
            println!(
                "named_interruption={edge} retained_evidence_unchanged=true fresh_process_original_recovery=true"
            );
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
    fn unknown_fixed_slot_recovers_original_without_overwriting_evidence() {
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
        fs::remove_file(&paths.log).unwrap();
        fs::write(&paths.log, b"replacement live log").unwrap();
        let committed = fs::read(paths.state_dir.join(SELECTION)).unwrap();
        freeze_output(&paths).unwrap();
        assert_eq!(fs::read(&unknown).unwrap(), b"uncertain crash evidence");
        assert_eq!(
            fs::read(paths.state_dir.join(OUTPUT)).unwrap(),
            b"original selected bytes"
        );
        assert_eq!(
            fs::read(paths.state_dir.join(SELECTION)).unwrap(),
            committed
        );
        assert_eq!(
            fs::read_dir(&paths.state_dir)
                .unwrap()
                .filter(|e| candidate(&e.as_ref().unwrap().file_name().to_string_lossy()))
                .count(),
            1
        );
    }
    #[test]
    fn orphan_receipts_and_dangling_slots_preserve_evidence_and_selected_prefix() {
        if crate::test_support::private_case() {
            return;
        }
        for kind in ["receipt", "pending", "dangling"] {
            let (_temp, paths, selection) = fixture();
            let name = format!(
                ".completion-output-{}.tmp",
                digest(&bytes(&selection).unwrap())
            );
            let receipt = paths.state_dir.join(receipt_name(&name));
            let occupied = match kind {
                "receipt" => receipt,
                "pending" => receipt.with_extension("pending"),
                _ => paths.state_dir.join(&name),
            };
            if kind == "dangling" {
                std::os::unix::fs::symlink("absent-unknown-target", &occupied).unwrap();
            } else {
                fs::write(&occupied, b"unknown receipt evidence").unwrap();
            }
            let before = fs::symlink_metadata(&occupied).unwrap();
            // Same selected inode can grow: the committed prefix is the output.
            OpenOptions::new()
                .append(true)
                .open(paths.state_dir.join(SELECTED_LOG))
                .unwrap()
                .write_all(b"later bytes beyond selected boundary")
                .unwrap();
            fs::remove_file(&paths.log).unwrap();
            fs::write(&paths.log, b"replacement live log").unwrap();
            run_capture_process(&paths, None);
            let after = fs::symlink_metadata(&occupied).unwrap();
            assert_eq!(
                (before.dev(), before.ino(), before.len()),
                (after.dev(), after.ino(), after.len())
            );
            if kind == "dangling" {
                assert_eq!(
                    fs::read_link(&occupied).unwrap(),
                    Path::new("absent-unknown-target")
                );
            } else {
                assert_eq!(fs::read(&occupied).unwrap(), b"unknown receipt evidence");
            }
            assert_eq!(
                fs::read(paths.state_dir.join(OUTPUT)).unwrap(),
                b"original selected bytes"
            );
        }
    }
    #[test]
    fn occupied_unknown_slot_without_original_remains_uncertain() {
        let (_temp, paths, selection) = fixture();
        let name = format!(
            ".completion-output-{}.tmp",
            digest(&bytes(&selection).unwrap())
        );
        let unknown = paths.state_dir.join(name);
        fs::write(&unknown, b"possibly sole original bytes").unwrap();
        fs::remove_file(paths.state_dir.join(SELECTED_LOG)).unwrap();
        fs::remove_file(&paths.log).unwrap();
        fs::write(&paths.log, b"replacement live log").unwrap();
        assert!(freeze_output(&paths).is_err());
        assert_eq!(fs::read(&unknown).unwrap(), b"possibly sole original bytes");
        assert!(!paths.state_dir.join(OUTPUT).exists());
        assert!(
            !paths
                .state_dir
                .join("missing-output-observation-v2.json")
                .exists()
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
        drop(attempt); // Production cannot carry in-memory cleanup ownership.
        freeze_output(&paths).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"private partial");
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
