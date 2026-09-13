//! Exact local acceptance of a bounded prefix of the existing retained source.
//! No receipt grants authority, pins state, or proves that producers stopped.
use std::io::{self, Read};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::state::{Meta, StatePaths};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Identity {
    version: u8,
    handle: String,
    created_at_unix_ms: u64,
    bytes: u64,
    sha256: String,
    encoding: String,
}

pub(crate) struct Snapshot {
    pub(crate) identity: Identity,
    pub(crate) output: String,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

// Freeze the bound at open, not EOF: terminal sentinel/root output can append.
// A short read is not a successful acquisition of the requested representation.
fn read_prefix(paths: &StatePaths, bytes: Option<u64>) -> io::Result<Vec<u8>> {
    let file = crate::state::open_read_no_follow(&paths.log)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(invalid("retained source is not a regular file"));
    }
    let length = metadata.len();
    let bytes = bytes.unwrap_or(length);
    if bytes > length {
        return Err(invalid("retained source shorter than requested prefix"));
    }
    read_bounded(file, bytes)
}

fn read_bounded(reader: impl Read, bytes: u64) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    reader.take(bytes).read_to_end(&mut output)?;
    if output.len() as u64 != bytes {
        return Err(invalid("incomplete retained source read"));
    }
    Ok(output)
}

fn identity(meta: &Meta, output: &[u8]) -> Identity {
    Identity {
        version: 1,
        handle: meta.handle.clone(),
        created_at_unix_ms: meta.created_at_unix_ms,
        bytes: output.len() as u64,
        sha256: format!("{:x}", Sha256::digest(output)),
        encoding: "hex".into(),
    }
}

pub(crate) fn acquire(paths: &StatePaths, meta: &Meta, bytes: Option<u64>) -> io::Result<Snapshot> {
    let output = read_prefix(paths, bytes)?;
    Ok(Snapshot {
        identity: identity(meta, &output),
        output: output.iter().map(|byte| format!("{byte:02x}")).collect(),
    })
}

pub(crate) fn validate(paths: &StatePaths, meta: &Meta, expected: &Identity) -> io::Result<()> {
    if expected.version != 1
        || expected.handle != meta.handle
        || expected.created_at_unix_ms != meta.created_at_unix_ms
        || expected.encoding != "hex"
    {
        return Err(invalid("snapshot source identity mismatch"));
    }
    let output = read_prefix(paths, Some(expected.bytes))?;
    if identity(meta, &output) != *expected {
        return Err(invalid("snapshot bytes do not match retained source"));
    }
    Ok(())
}

// Caller holds output.lock through source revalidation and this publication.
// The sole visible record is replaceable, never rolled back on a sync error.
// A visible record is publication intent, not proof that a success reply arrived.
pub(crate) fn record_receipt(paths: &StatePaths, identity: &Identity) -> io::Result<bool> {
    reject_legacy(paths)?;
    publish_receipt(&paths.state_dir, identity, |_, file| file.sync_all())
}

fn reject_legacy(paths: &StatePaths) -> io::Result<()> {
    match std::fs::symlink_metadata(&paths.consumed) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(invalid(
            "legacy-state: consumed entry exists; previous suppression cannot be reversed locally",
        )),
    }
}

fn publication_error(phase: &str, error: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!(
        "local-receipt {phase}: {error}; acceptance unconfirmed"
    ))
}

fn publish_receipt(
    directory: &std::path::Path,
    identity: &Identity,
    sync: impl Fn(&str, &std::fs::File) -> io::Result<()>,
) -> io::Result<bool> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let destination = directory.join("output-receipt.json");
    let encoded = serde_json::to_vec(identity)?;
    crate::state::durable_marker_exists(&destination).map_err(|e| publication_error("read", e))?;
    let existing = match crate::state::open_read_no_follow(&destination) {
        Ok(file) => Some(file),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(publication_error("read", error)),
    };
    if let Some(mut file) = existing {
        let mut bytes = Vec::new();
        (&mut file)
            .take(encoded.len() as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes == encoded {
            sync("duplicate-file-sync", &file)
                .map_err(|e| publication_error("duplicate-file-sync", e))?;
            sync_receipt_directory(directory, &sync)?;
            return Ok(false);
        }
    }
    // One reusable staging slot, ignored by readers. An interrupted write is
    // overwritten on retry. Never remove/retract the published destination.
    let staging = directory.join("output-receipt.pending");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&staging)
        .map_err(|e| publication_error("prepare", e))?;
    file.write_all(&encoded)
        .map_err(|e| publication_error("write", e))?;
    sync("prepare-file-sync", &file).map_err(|e| publication_error("prepare-file-sync", e))?;
    std::fs::rename(staging, destination).map_err(|e| publication_error("publish", e))?;
    sync_receipt_directory(directory, &sync)?;
    Ok(true)
}

fn sync_receipt_directory(
    directory: &std::path::Path,
    sync: &impl Fn(&str, &std::fs::File) -> io::Result<()>,
) -> io::Result<()> {
    let file =
        std::fs::File::open(directory).map_err(|e| publication_error("directory-open", e))?;
    sync("published-directory-sync", &file)
        .map_err(|e| publication_error("published-directory-sync", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_identity(bytes: u64) -> Identity {
        Identity {
            version: 1,
            handle: "ab_test".into(),
            created_at_unix_ms: 1,
            bytes,
            sha256: "test-only".into(),
            encoding: "hex".into(),
        }
    }

    #[test]
    fn publication_failure_is_irrevocable_and_duplicate_retry_syncs() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path();
        let id = test_identity(3);
        let destination = dir.join("output-receipt.json");
        let error = publish_receipt(dir, &id, |phase, file| {
            if phase == "published-directory-sync" {
                // Observer sees complete identity even when publisher returns error.
                assert_eq!(
                    std::fs::read(&destination).unwrap(),
                    serde_json::to_vec(&id).unwrap()
                );
                return Err(io::Error::other("injected"));
            }
            file.sync_all()
        })
        .unwrap_err();
        assert!(error.to_string().contains("published-directory-sync"));
        assert!(destination.exists());
        let error = publish_receipt(dir, &id, |phase, _| {
            assert_eq!(phase, "duplicate-file-sync");
            Err(io::Error::other("injected retry failure"))
        })
        .unwrap_err();
        assert!(error.to_string().contains("duplicate-file-sync"));
        assert!(destination.exists());
        let phases = std::cell::RefCell::new(Vec::new());
        assert!(
            !publish_receipt(dir, &id, |phase, file| {
                phases.borrow_mut().push(phase.to_owned());
                file.sync_all()
            })
            .unwrap()
        );
        assert_eq!(
            *phases.borrow(),
            ["duplicate-file-sync", "published-directory-sync"]
        );
        assert!(!dir.join("consumed").exists());
    }

    #[test]
    fn prepublication_failure_keeps_previous_receipt_and_retry_replaces_only_latest() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path();
        let old = test_identity(0);
        let new = test_identity(7);
        assert!(publish_receipt(dir, &old, |_, f| f.sync_all()).unwrap());
        let error = publish_receipt(dir, &new, |phase, _| {
            assert_eq!(phase, "prepare-file-sync");
            Err(io::Error::other("interrupted before publication"))
        })
        .unwrap_err();
        assert!(error.to_string().contains("prepare-file-sync"));
        assert_eq!(
            std::fs::read(dir.join("output-receipt.json")).unwrap(),
            serde_json::to_vec(&old).unwrap()
        );
        assert!(publish_receipt(dir, &new, |_, f| f.sync_all()).unwrap());
        assert_eq!(
            std::fs::read(dir.join("output-receipt.json")).unwrap(),
            serde_json::to_vec(&new).unwrap()
        );
        assert_eq!(std::fs::read_dir(dir).unwrap().count(), 1);
        // Publication failure is separate from file or directory sync failure.
        std::fs::remove_file(dir.join("output-receipt.json")).unwrap();
        let error = publish_receipt(dir, &old, |_, f| {
            f.sync_all()?;
            std::fs::create_dir(dir.join("output-receipt.json"))?;
            Ok(())
        })
        .unwrap_err();
        assert!(error.to_string().contains("local-receipt publish:"));
    }

    #[test]
    fn bounded_read_excludes_later_bytes_and_rejects_short_acquisition() {
        assert_eq!(read_bounded(&b"prefixlater"[..], 6).unwrap(), b"prefix");
        assert_eq!(read_bounded(&b""[..], 0).unwrap(), b"");
        assert_eq!(
            read_bounded(&b"short"[..], 6).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn partial_then_error_is_not_successful_acquisition() {
        struct FailedRead;
        impl Read for FailedRead {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("source failed after prefix"))
            }
        }
        let source = (&b"prefix"[..]).chain(FailedRead);
        assert!(read_bounded(source, 12).is_err());
    }
}
