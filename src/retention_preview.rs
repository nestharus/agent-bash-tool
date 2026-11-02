//! Explicit-root, read-only inspection of the legacy state reaper's gates.
//! This deliberately cannot authorize removal: fresh source release validation
//! hashes body bytes and the reaper's locks are mutating operations.

use std::collections::HashMap;
use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};

use crate::state;

const TTL_FLOOR_SECS: u64 = 24 * 60 * 60;
const MAX_HANDLES: usize = 128;
const MAX_VISITS: usize = 100_000;
const JSON_LIMIT: u64 = 1024 * 1024;

#[derive(Serialize)]
pub(crate) struct DiscoveryPreview {
    root_stamp: String,
    root_metadata_unchanged: bool,
    root_entries_visited: usize,
    total_entries_visited: usize,
    iteration_exhausted: bool,
    next_directory_offset: Option<i64>,
    checkpoint_note: &'static str,
    preview: Preview,
}

fn root_stamp(meta: &std::fs::Metadata) -> String {
    format!(
        "{}:{}:{}:{}:{}:{}:{}:{}",
        meta.dev(),
        meta.ino(),
        meta.mtime(),
        meta.mtime_nsec(),
        meta.ctime(),
        meta.ctime_nsec(),
        meta.len(),
        meta.nlink()
    )
}

/// Bounded handle discovery; the directory cookie is valid only while the
/// supplied root stamp still matches. No shard cursor or state file is written.
pub(crate) fn discover(
    root: &Path,
    max_entries: usize,
    max_handles: usize,
    resume_offset: Option<i64>,
    expected_stamp: Option<&str>,
    configured_ttl_secs: u64,
) -> io::Result<DiscoveryPreview> {
    if !(2..=MAX_VISITS).contains(&max_entries)
        || !(1..=MAX_HANDLES).contains(&max_handles)
        || resume_offset.is_some() != expected_stamp.is_some()
        || resume_offset.is_some_and(|n| n < 0)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid discovery limits or checkpoint pair",
        ));
    }
    let root_fd = open_absolute_dir_nofollow(root)?;
    let stamp = root_stamp(&root_fd.metadata()?);
    if expected_stamp.is_some_and(|expected| expected != stamp) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "root namespace changed; checkpoint rejected",
        ));
    }
    let duplicate = unsafe { libc::dup(root_fd.as_raw_fd()) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        unsafe {
            libc::close(duplicate);
        }
        return Err(io::Error::last_os_error());
    }
    struct Directory(*mut libc::DIR);
    impl Drop for Directory {
        fn drop(&mut self) {
            unsafe {
                libc::closedir(self.0);
            }
        }
    }
    let stream = Directory(stream);
    if let Some(offset) = resume_offset {
        unsafe {
            libc::seekdir(stream.0, offset as libc::c_long);
        }
    }
    let mut names = Vec::new();
    let mut offsets = Vec::new();
    let mut visited = 0;
    let mut eof = false;
    // Leave at least half the budget for selected handle inspection.
    while visited < max_entries / 2 && names.len() < max_handles {
        let before = unsafe { libc::telldir(stream.0) };
        if before < 0 {
            return Err(io::Error::last_os_error());
        }
        unsafe {
            *libc::__errno_location() = 0;
        }
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let errno = unsafe { *libc::__errno_location() };
            if errno != 0 {
                return Err(io::Error::from_raw_os_error(errno));
            }
            eof = true;
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        visited += 1;
        if let Ok(name) = name.to_str() {
            if valid_handle(name) {
                names.push(name.to_owned());
                offsets.push(before as i64);
            }
        }
    }
    let after = unsafe { libc::telldir(stream.0) };
    if after < 0 {
        return Err(io::Error::last_os_error());
    }
    let preview = if names.is_empty() {
        empty_preview(
            &root_fd.metadata()?,
            max_entries - visited,
            configured_ttl_secs,
        )
    } else {
        inspect_directory(&root_fd, &names, max_entries - visited, configured_ttl_secs)?
    };
    let pending = preview.next_handle_index.map(|index| offsets[index]);
    let stable = root_stamp(&root_fd.metadata()?) == stamp;
    Ok(DiscoveryPreview {
        root_stamp: stamp,
        root_metadata_unchanged: stable,
        root_entries_visited: visited,
        total_entries_visited: visited + preview.visited_entries,
        iteration_exhausted: stable && eof && pending.is_none(),
        next_directory_offset: if stable {
            pending.or_else(|| (!eof).then_some(after as i64))
        } else {
            None
        },
        checkpoint_note: "Resume with this offset and root stamp only; observed root metadata changes reject it. Directory cookies and timestamps do not prove a frozen namespace. Nested allocations remain unmeasured. No removal authority is issued.",
        preview,
    })
}

fn empty_preview(meta: &std::fs::Metadata, max_entries: usize, ttl_secs: u64) -> Preview {
    Preview {
        schema: "agent-bash-retention-preview-v1",
        root_device: meta.dev(),
        root_inode: meta.ino(),
        effective_ttl_secs: ttl_secs.max(TTL_FLOOR_SECS),
        visited_entries: 0,
        max_entries,
        next_handle_index: None,
        checkpoint_note: None,
        observed_unique_allocated_bytes: 0,
        observed_unique_inodes: 0,
        external_or_unseen_hardlinks: 0,
        allocation_note: "Unique observed inode blocks only; nested contents and unvisited entries are excluded. This is not a reclaim estimate.",
        apply_supported: false,
        apply_blocker: "Existing removal requires separate current lock, generation, source-release and ownership checks; this preview cannot authorize deletion.",
        members: Vec::new(),
    }
}

#[derive(Serialize)]
pub(crate) struct Preview {
    schema: &'static str,
    root_device: u64,
    root_inode: u64,
    effective_ttl_secs: u64,
    visited_entries: usize,
    max_entries: usize,
    next_handle_index: Option<usize>,
    checkpoint_note: Option<&'static str>,
    observed_unique_allocated_bytes: u64,
    observed_unique_inodes: usize,
    external_or_unseen_hardlinks: usize,
    allocation_note: &'static str,
    apply_supported: bool,
    apply_blocker: &'static str,
    members: Vec<Member>,
}

#[derive(Serialize)]
struct Member {
    handle: String,
    recorded_owner_session_id: Option<String>,
    recorded_owner_invocation_uuid: Option<String>,
    recorded_root_id: Option<String>,
    disposition: &'static str,
    reasons: Vec<&'static str>,
    reference_unix_ms: Option<u64>,
    age_secs: Option<u64>,
    directory_device: Option<u64>,
    directory_inode: Option<u64>,
    listed_entries: usize,
    allocation_complete: bool,
}

// Ignore command/environment/unknown fields instead of materializing a full
// Meta or arbitrary JSON Value when only retention headers are needed.
#[derive(Deserialize)]
struct RetentionMeta {
    handle: String,
    state: String,
    #[serde(default)]
    completed_at_unix_ms: Option<u64>,
    #[serde(default)]
    updated_at_unix_ms: u64,
    #[serde(default)]
    completion_reason: Option<String>,
    #[serde(default)]
    workload_rc: Option<i32>,
    #[serde(default)]
    workload_signal: Option<i32>,
    #[serde(default)]
    supervisor_pid: Option<i32>,
    #[serde(default)]
    owner_session_id: Option<String>,
    #[serde(default)]
    owner_invocation_uuid: Option<String>,
    #[serde(default)]
    delivery: state::CompletionDeliveryMeta,
}

#[derive(Deserialize)]
struct Acceptance {
    protocol: String,
    work_id: String,
    root_id: String,
    registration: Registration,
}

#[derive(Deserialize)]
struct Registration {
    kind: String,
    #[serde(default)]
    parent_work_id: Option<String>,
}

#[derive(Deserialize)]
struct RootResult {
    protocol: String,
    work_id: String,
    root_id: String,
    result_nonce: String,
    outcome: String,
    physical_tree_drained: bool,
}

pub(crate) fn inspect(
    root: &Path,
    handles: &[String],
    max_entries: usize,
    configured_ttl_secs: u64,
) -> io::Result<Preview> {
    let root_fd = open_absolute_dir_nofollow(root)?;
    inspect_directory(&root_fd, handles, max_entries, configured_ttl_secs)
}

fn inspect_directory(
    root_fd: &File,
    handles: &[String],
    max_entries: usize,
    configured_ttl_secs: u64,
) -> io::Result<Preview> {
    if handles.is_empty()
        || handles.len() > MAX_HANDLES
        || max_entries == 0
        || max_entries > MAX_VISITS
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "require 1..128 handles and 1..100000 visited entries",
        ));
    }
    for handle in handles {
        if !valid_handle(handle) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid handle; expected a single ab_ ASCII component",
            ));
        }
    }
    if handles
        .iter()
        .collect::<std::collections::HashSet<_>>()
        .len()
        != handles.len()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "duplicate handles",
        ));
    }
    let root_meta = root_fd.metadata()?;
    let ttl_secs = configured_ttl_secs.max(TTL_FLOOR_SECS);
    let now = state::unix_ms();
    let mut preview = Preview {
        schema: "agent-bash-retention-preview-v1",
        root_device: root_meta.dev(),
        root_inode: root_meta.ino(),
        effective_ttl_secs: ttl_secs,
        visited_entries: 0,
        max_entries,
        next_handle_index: None,
        checkpoint_note: None,
        observed_unique_allocated_bytes: 0,
        observed_unique_inodes: 0,
        external_or_unseen_hardlinks: 0,
        allocation_note: "Unique observed inode blocks only; nested contents and unvisited entries are excluded. This is not a reclaim estimate.",
        apply_supported: false,
        apply_blocker: "The current reaper requires mutating locks and fresh-v2 release validation hashes source bodies; there is no inode-bound exact-plan apply protocol.",
        members: Vec::new(),
    };
    let mut inodes: HashMap<(u64, u64), (u64, u64, u64)> = HashMap::new();
    for (index, handle) in handles.iter().enumerate() {
        if preview.visited_entries == max_entries {
            preview.next_handle_index = Some(index);
            preview.checkpoint_note = Some(
                "Resume at this handle index with the same explicit handle list; recheck root identity and all members.",
            );
            break;
        }
        preview.visited_entries += 1;
        let mut member = Member {
            handle: handle.clone(),
            recorded_owner_session_id: None,
            recorded_owner_invocation_uuid: None,
            recorded_root_id: None,
            disposition: "unresolved",
            reasons: Vec::new(),
            reference_unix_ms: None,
            age_secs: None,
            directory_device: None,
            directory_inode: None,
            listed_entries: 0,
            allocation_complete: false,
        };
        let directory = match open_child_dir(&root_fd, handle) {
            Ok(dir) => dir,
            Err(err) => {
                member
                    .reasons
                    .push(if err.kind() == io::ErrorKind::NotFound {
                        "handle_missing"
                    } else {
                        "handle_not_safe_directory"
                    });
                preview.members.push(member);
                continue;
            }
        };
        let directory_meta = directory.metadata()?;
        member.directory_device = Some(directory_meta.dev());
        member.directory_inode = Some(directory_meta.ino());
        count_inode(&mut inodes, &directory_meta);
        check_gates(&root_fd, &directory, handle, now, ttl_secs, &mut member);
        match scan_direct_entries(
            &directory,
            &mut preview.visited_entries,
            max_entries,
            &mut inodes,
            &mut member,
        ) {
            Ok(complete) => {
                member.allocation_complete = complete
                    && !member.reasons.iter().any(|r| {
                        matches!(
                            *r,
                            "nested_directory_allocation_unknown" | "entry_metadata_unknown"
                        )
                    });
                if !complete {
                    member
                        .reasons
                        .push("entry_limit_reached_allocation_unknown");
                    preview.next_handle_index = Some(index);
                    preview.checkpoint_note = Some(
                        "This directory was partial; retry this handle with a larger limit. Directory order is not a stable offset.",
                    );
                }
            }
            Err(_) => member.reasons.push("directory_enumeration_failed"),
        }
        member.disposition = if member.reasons.iter().any(|reason| is_hold(reason)) {
            "held"
        } else {
            "unresolved"
        };
        preview.members.push(member);
        if preview.next_handle_index.is_some() {
            break;
        }
    }
    preview.observed_unique_inodes = inodes.len();
    for (_key, (blocks, nlink, observed_links)) in &inodes {
        preview.observed_unique_allocated_bytes = preview
            .observed_unique_allocated_bytes
            .saturating_add(blocks.saturating_mul(512));
        if *nlink > *observed_links {
            preview.external_or_unseen_hardlinks += 1;
        }
    }
    Ok(preview)
}

fn is_hold(reason: &str) -> bool {
    matches!(
        reason,
        "younger_than_effective_ttl"
            | "running_or_nonterminal"
            | "delivery_needs_progress"
            | "causal_parent_retains"
            | "root_result_pending"
            | "custody_marker_present"
            | "source_release_absent"
    )
}

fn valid_handle(handle: &str) -> bool {
    handle.starts_with("ab_")
        && handle.len() > 3
        && handle.len() <= 255
        && handle
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

fn uuid_locator(value: Option<&str>) -> Option<String> {
    value
        .filter(|s| {
            s.len() == 36
                && s.bytes().enumerate().all(|(i, b)| {
                    if matches!(i, 8 | 13 | 18 | 23) {
                        b == b'-'
                    } else {
                        b.is_ascii_hexdigit()
                    }
                })
        })
        .map(str::to_owned)
}

fn open_absolute_dir_nofollow(path: &Path) -> io::Result<File> {
    if !path.is_absolute()
        || path
            .as_os_str()
            .as_bytes()
            .split(|b| *b == b'/')
            .any(|c| c == b"." || c == b"..")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "root must be absolute without dot components",
        ));
    }
    let mut dir = File::open("/")?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => dir = open_dir_at(dir.as_raw_fd(), name)?,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "root must have no dot or parent components",
                ));
            }
        }
    }
    Ok(dir)
}

fn open_dir_at(parent: RawFd, name: &OsStr) -> io::Result<File> {
    let c_name = CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"))?;
    let fd = unsafe {
        libc::openat(
            parent,
            c_name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

fn open_child_dir(parent: &File, handle: &str) -> io::Result<File> {
    open_dir_at(parent.as_raw_fd(), OsStr::new(handle))
}

fn read_json_at<T: serde::de::DeserializeOwned>(dir: &File, name: &str) -> io::Result<Option<T>> {
    let c_name = CString::new(name).unwrap();
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c_name.as_ptr(),
            libc::O_RDONLY
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK
                | libc::O_NOATIME,
        )
    };
    if fd < 0 {
        let err = io::Error::last_os_error();
        return if err.kind() == io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(err)
        };
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let meta = file.metadata()?;
    if !meta.is_file() || meta.nlink() != 1 || meta.len() > JSON_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "metadata is not a bounded single-link regular file",
        ));
    }
    let result = serde_json::from_reader((&file).take(JSON_LIMIT + 1)).map_err(io::Error::other)?;
    let after = file.metadata()?;
    if (
        meta.dev(),
        meta.ino(),
        meta.len(),
        meta.mtime(),
        meta.mtime_nsec(),
        meta.ctime(),
        meta.ctime_nsec(),
    ) != (
        after.dev(),
        after.ino(),
        after.len(),
        after.mtime(),
        after.mtime_nsec(),
        after.ctime(),
        after.ctime_nsec(),
    ) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "metadata changed while reading",
        ));
    }
    Ok(Some(result))
}

fn exists_at(dir: &File, name: &str) -> io::Result<bool> {
    let c_name = CString::new(name).unwrap();
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let rc = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            c_name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc == 0 {
        Ok(true)
    } else {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::NotFound {
            Ok(false)
        } else {
            Err(err)
        }
    }
}

fn check_gates(
    root: &File,
    dir: &File,
    handle: &str,
    now: u64,
    ttl_secs: u64,
    member: &mut Member,
) {
    let meta = match read_json_at::<RetentionMeta>(dir, "meta.json").and_then(|value| {
        value.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "meta missing"))
    }) {
        Ok(meta) if meta.handle == handle => meta,
        _ => {
            member
                .reasons
                .push("metadata_missing_malformed_or_mismatched");
            return;
        }
    };
    let reference = meta
        .completed_at_unix_ms
        .unwrap_or(0)
        .max(meta.updated_at_unix_ms);
    member.recorded_owner_session_id = uuid_locator(meta.owner_session_id.as_deref());
    member.recorded_owner_invocation_uuid = uuid_locator(meta.owner_invocation_uuid.as_deref());
    if reference == 0 {
        member.reasons.push("retention_reference_unknown");
    } else {
        member.reference_unix_ms = Some(reference);
        let age = now.saturating_sub(reference) / 1000;
        member.age_secs = Some(age);
        if age < ttl_secs {
            member.reasons.push("younger_than_effective_ttl");
        }
    }
    if !matches!(meta.state.as_str(), "DONE" | "ERROR") || meta.completed_at_unix_ms.is_none() {
        member.reasons.push("running_or_nonterminal");
    } else if meta.completion_reason.as_deref() == Some("ready-sentinel")
        && meta.workload_rc.is_none()
        && meta.workload_signal.is_none()
    {
        member
            .reasons
            .push("ready_sentinel_live_identity_unchecked");
    }
    if meta.delivery.completion_lifecycle().needs_progress() {
        member.reasons.push("delivery_needs_progress");
    }
    if meta.supervisor_pid.is_some() {
        member.reasons.push("supervisor_live_identity_unchecked");
    }
    for marker in ["physical-custody", "external-transfer-custody"] {
        match exists_at(dir, marker) {
            Ok(true) => member.reasons.push("custody_marker_present"),
            Err(_) => member.reasons.push("custody_marker_unknown"),
            _ => {}
        }
    }
    match exists_at(dir, crate::continuation::REGISTRATION) {
        Ok(true) => match exists_at(dir, "broker-source-retention-release-v1.json") {
            Ok(false) => member.reasons.push("source_release_absent"),
            _ => member
                .reasons
                .push("source_release_requires_body_validation"),
        },
        Err(_) => member.reasons.push("source_registration_unknown"),
        _ => {}
    }
    match read_json_at::<Acceptance>(dir, crate::root_work::ACCEPTED_FILE) {
        Ok(Some(acceptance)) => {
            member.recorded_root_id = uuid_locator(Some(&acceptance.root_id));
            if acceptance.protocol != crate::root_work::PROTOCOL
                || acceptance.work_id != handle
                || acceptance.root_id.is_empty()
            {
                member.reasons.push("acceptance_unknown");
            } else {
                match acceptance.registration.kind.as_str() {
                    "root" => match read_json_at::<RootResult>(dir, "root-work-result-v1.json") {
                        Ok(Some(result))
                            if result.protocol == crate::root_work::PROTOCOL
                                && result.work_id == handle
                                && result.root_id == acceptance.root_id
                                && !result.result_nonce.is_empty()
                                && !result.outcome.is_empty()
                                && result.physical_tree_drained => {}
                        Ok(None) => member.reasons.push("root_result_pending"),
                        _ => member.reasons.push("root_result_unknown"),
                    },
                    "nested" => match acceptance.registration.parent_work_id.as_deref() {
                        Some(parent) if valid_handle(parent) => {
                            match open_child_dir(root, parent) {
                                Ok(_) => member.reasons.push("causal_parent_retains"),
                                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                                Err(_) => member.reasons.push("causal_parent_unknown"),
                            }
                        }
                        _ => member.reasons.push("causal_parent_unknown"),
                    },
                    _ => member.reasons.push("acceptance_unknown"),
                }
            }
        }
        Err(_) => member.reasons.push("acceptance_unknown"),
        _ => {}
    }
    member
        .reasons
        .push("apply_lock_and_generation_revalidation_required");
}

fn count_inode(inodes: &mut HashMap<(u64, u64), (u64, u64, u64)>, meta: &std::fs::Metadata) {
    let links = if meta.is_dir() { 1 } else { meta.nlink() };
    let entry = inodes
        .entry((meta.dev(), meta.ino()))
        .or_insert((meta.blocks(), links, 0));
    entry.2 = entry.2.saturating_add(1);
}

fn scan_direct_entries(
    dir: &File,
    visited: &mut usize,
    max: usize,
    inodes: &mut HashMap<(u64, u64), (u64, u64, u64)>,
    member: &mut Member,
) -> io::Result<bool> {
    let dup = unsafe { libc::dup(dir.as_raw_fd()) };
    if dup < 0 {
        return Err(io::Error::last_os_error());
    }
    let stream = unsafe { libc::fdopendir(dup) };
    if stream.is_null() {
        unsafe {
            libc::close(dup);
        }
        return Err(io::Error::last_os_error());
    }
    let mut complete = true;
    loop {
        if *visited == max {
            complete = false;
            break;
        }
        unsafe {
            *libc::__errno_location() = 0;
        }
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            let errno = unsafe { *libc::__errno_location() };
            if errno != 0 {
                unsafe {
                    libc::closedir(stream);
                }
                return Err(io::Error::from_raw_os_error(errno));
            }
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        *visited += 1;
        member.listed_entries += 1;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        let rc = unsafe {
            libc::fstatat(
                dir.as_raw_fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc < 0 {
            member.reasons.push("entry_metadata_unknown");
            continue;
        }
        let stat = unsafe { stat.assume_init() };
        if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
            member.reasons.push("nested_directory_allocation_unknown");
        }
        let key = (stat.st_dev as u64, stat.st_ino as u64);
        let links = if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
            1
        } else {
            stat.st_nlink as u64
        };
        let allocation = (stat.st_blocks.max(0) as u64, links);
        inodes
            .entry(key)
            .and_modify(|value| value.2 = value.2.saturating_add(1))
            .or_insert((allocation.0, allocation.1, 1));
    }
    unsafe {
        libc::closedir(stream);
    }
    Ok(complete)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use std::os::unix::fs::symlink;

    fn fixture(root: &Path, name: &str, age_secs: u64) -> std::path::PathBuf {
        let path = root.join(name);
        fs::create_dir(&path).unwrap();
        let reference = state::unix_ms() - age_secs * 1000;
        fs::write(path.join("meta.json"), serde_json::to_vec(&json!({
            "handle": name, "state": "DONE", "completed_at_unix_ms": reference,
            "updated_at_unix_ms": reference,
            "delivery": {"attempted": false, "exit_code": null, "error": null, "skipped": "sync"},
            "command": "sensitive command must not appear", "env": {"KEY": "sensitive value"},
            "unknown_output": "ignored embedded value"
        })).unwrap()).unwrap();
        path
    }

    fn one(root: &Path, name: &str) -> Preview {
        inspect(root, &[name.to_owned()], 4096, 48 * 3600).unwrap()
    }

    #[test]
    fn preview_preserves_files_and_omits_sensitive_metadata_fields() {
        let temp = tempfile::tempdir().unwrap();
        let path = fixture(temp.path(), "ab_old", 49 * 3600);
        let before = fs::read(path.join("meta.json")).unwrap();
        let root_before = fs::metadata(temp.path()).unwrap();
        let file_before = fs::metadata(path.join("meta.json")).unwrap();
        let fifo = CString::new(path.join("log").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let result = one(temp.path(), "ab_old");
        assert_eq!(before, fs::read(path.join("meta.json")).unwrap());
        let after = fs::metadata(path.join("meta.json")).unwrap();
        assert_eq!(
            (file_before.ino(), file_before.mtime(), file_before.ctime()),
            (after.ino(), after.mtime(), after.ctime())
        );
        let root_after = fs::metadata(temp.path()).unwrap();
        assert_eq!(
            (root_before.ino(), root_before.mtime(), root_before.ctime()),
            (root_after.ino(), root_after.mtime(), root_after.ctime())
        );
        assert!(!result.apply_supported);
        assert_eq!(result.members[0].disposition, "unresolved");
        let text = serde_json::to_string(&result).unwrap();
        for secret in [
            "sensitive command",
            "sensitive value",
            "ignored embedded value",
        ] {
            assert!(!text.contains(secret));
        }
        assert_eq!(fs::read_dir(path).unwrap().count(), 2);
    }

    #[test]
    fn applies_48_hour_default_and_24_hour_minimum() {
        let temp = tempfile::tempdir().unwrap();
        fixture(temp.path(), "ab_day", 25 * 3600);
        fixture(temp.path(), "ab_young", 23 * 3600);
        assert!(
            one(temp.path(), "ab_day").members[0]
                .reasons
                .contains(&"younger_than_effective_ttl")
        );
        let day = inspect(temp.path(), &["ab_day".into()], 4096, 1).unwrap();
        assert_eq!(day.effective_ttl_secs, 24 * 3600);
        assert!(
            !day.members[0]
                .reasons
                .contains(&"younger_than_effective_ttl")
        );
        assert!(
            inspect(temp.path(), &["ab_young".into()], 4096, 1)
                .unwrap()
                .members[0]
                .reasons
                .contains(&"younger_than_effective_ttl")
        );
    }

    #[test]
    fn running_and_required_source_remain_held() {
        let temp = tempfile::tempdir().unwrap();
        let path = fixture(temp.path(), "ab_running", 49 * 3600);
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(path.join("meta.json")).unwrap()).unwrap();
        value["state"] = json!("RUNNING");
        fs::write(path.join("meta.json"), serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(
            one(temp.path(), "ab_running").members[0].disposition,
            "held"
        );
        let path = fixture(temp.path(), "ab_required", 49 * 3600);
        fs::write(path.join(crate::continuation::REGISTRATION), b"{}").unwrap();
        let result = one(temp.path(), "ab_required");
        assert!(result.members[0].reasons.contains(&"source_release_absent"));
        assert!(!result.apply_supported);
    }

    #[test]
    fn parent_and_result_obligations_are_visible() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("ab_parent")).unwrap();
        let child = fixture(temp.path(), "ab_child", 49 * 3600);
        fs::write(
            child.join(crate::root_work::ACCEPTED_FILE),
            serde_json::to_vec(&json!({
                "protocol":crate::root_work::PROTOCOL,"root_id":"r","work_id":"ab_child",
                "registration":{"kind":"nested","parent_work_id":"ab_parent"}
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(
            one(temp.path(), "ab_child").members[0]
                .reasons
                .contains(&"causal_parent_retains")
        );
        let root = fixture(temp.path(), "ab_root", 49 * 3600);
        fs::write(
            root.join(crate::root_work::ACCEPTED_FILE),
            serde_json::to_vec(&json!({
                "protocol":crate::root_work::PROTOCOL,"root_id":"r","work_id":"ab_root",
                "registration":{"kind":"root"}
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(
            one(temp.path(), "ab_root").members[0]
                .reasons
                .contains(&"root_result_pending")
        );
    }

    #[test]
    fn rejects_symlink_roots_handles_and_metadata() {
        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), temp.path().join("alias")).unwrap();
        assert!(inspect(&temp.path().join("alias"), &["ab_old".into()], 10, 172800).is_err());
        symlink(outside.path(), temp.path().join("ab_alias")).unwrap();
        assert!(
            one(temp.path(), "ab_alias").members[0]
                .reasons
                .contains(&"handle_not_safe_directory")
        );
        let path = temp.path().join("ab_meta");
        fs::create_dir(&path).unwrap();
        fs::write(outside.path().join("private"), b"do not open").unwrap();
        symlink(outside.path().join("private"), path.join("meta.json")).unwrap();
        assert!(
            one(temp.path(), "ab_meta").members[0]
                .reasons
                .contains(&"metadata_missing_malformed_or_mismatched")
        );
    }

    #[test]
    fn unknown_and_malformed_metadata_cannot_be_eligible() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("ab_bad")).unwrap();
        fs::write(temp.path().join("ab_bad/meta.json"), b"not json").unwrap();
        let result = one(temp.path(), "ab_bad");
        assert_eq!(result.members[0].disposition, "unresolved");
        assert!(!result.apply_supported);
        assert!(inspect(temp.path(), &["../ab_bad".into()], 20, 172800).is_err());
        assert!(inspect(temp.path(), &["ab_bad".into(), "ab_bad".into()], 20, 172800).is_err());
    }

    #[test]
    fn recorded_owner_uuids_are_locators_not_arbitrary_metadata_text() {
        let temp = tempfile::tempdir().unwrap();
        let path = fixture(temp.path(), "ab_owner", 49 * 3600);
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(path.join("meta.json")).unwrap()).unwrap();
        value["owner_session_id"] = json!("01a0cc7d-0af9-75c3-91e3-4e48228aa8a4");
        value["owner_invocation_uuid"] = json!("untrusted sensitive metadata text");
        fs::write(path.join("meta.json"), serde_json::to_vec(&value).unwrap()).unwrap();
        let result = one(temp.path(), "ab_owner");
        assert_eq!(
            result.members[0].recorded_owner_session_id.as_deref(),
            Some("01a0cc7d-0af9-75c3-91e3-4e48228aa8a4")
        );
        assert!(result.members[0].recorded_owner_invocation_uuid.is_none());
        assert!(
            !serde_json::to_string(&result)
                .unwrap()
                .contains("untrusted sensitive")
        );
        assert!(!result.apply_supported);
    }

    #[test]
    fn counts_inode_allocation_once_and_marks_nested_unknowns() {
        let temp = tempfile::tempdir().unwrap();
        let path = fixture(temp.path(), "ab_links", 49 * 3600);
        fs::write(path.join("body"), vec![0u8; 16384]).unwrap();
        fs::hard_link(path.join("body"), path.join("selected-body")).unwrap();
        fs::create_dir(path.join("nested")).unwrap();
        let result = one(temp.path(), "ab_links");
        assert_eq!(result.observed_unique_inodes, 4);
        assert_eq!(result.external_or_unseen_hardlinks, 0);
        assert!(!result.members[0].allocation_complete);
    }

    #[test]
    fn discovery_is_bounded_and_checkpoint_rejects_namespace_drift() {
        let temp = tempfile::tempdir().unwrap();
        for name in ["ab_one", "ab_two", "ab_three"] {
            fixture(temp.path(), name, 49 * 3600);
        }
        let first = discover(temp.path(), 100, 1, None, None, 172800).unwrap();
        assert_eq!(first.preview.members.len(), 1);
        assert!(!first.iteration_exhausted);
        assert!(first.total_entries_visited <= 100);
        let offset = first.next_directory_offset.unwrap();
        let next = discover(
            temp.path(),
            100,
            1,
            Some(offset),
            Some(&first.root_stamp),
            172800,
        )
        .unwrap();
        assert_ne!(
            first.preview.members[0].handle,
            next.preview.members[0].handle
        );
        fs::create_dir(temp.path().join("new_entry")).unwrap();
        assert!(
            discover(
                temp.path(),
                100,
                1,
                Some(offset),
                Some(&first.root_stamp),
                172800
            )
            .is_err()
        );
    }

    #[test]
    fn entry_limits_preserve_partial_coverage() {
        let temp = tempfile::tempdir().unwrap();
        fixture(temp.path(), "ab_one", 49 * 3600);
        let result = one(temp.path(), "ab_one");
        assert!(result.members[0].allocation_complete);
        let partial = inspect(temp.path(), &["ab_one".into()], 1, 172800).unwrap();
        assert_eq!(partial.visited_entries, 1);
        assert_eq!(partial.next_handle_index, Some(0));
        assert!(!partial.members[0].allocation_complete);
        assert!(discover(temp.path(), 1, 1, None, None, 172800).is_err());
    }
}
