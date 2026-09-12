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

#[cfg(test)]
mod tests {
    use super::*;

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
