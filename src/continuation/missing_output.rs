//! Conservative revision5 producer. Only a completion-only successor with an
//! exact dead original observer may attest loss. Managed-storage enumeration,
//! not a failed pathname lookup, establishes absence. Unknown/legacy selections
//! and unvalidated copy candidates stay pending; nothing here drains or ACKs.
use super::*;

const PROOF: &str = "missing-output-observation-v2.json";

pub(super) fn observe(paths: &StatePaths) -> io::Result<Option<Value>> {
    if paths.state_dir.join(PROOF).try_exists()? {
        return value(&paths.state_dir.join(PROOF)).map(Some);
    }
    let staged = value(&paths.state_dir.join("source-observation-v2.json"))?;
    let Ok(observer) =
        serde_json::from_value::<CallerChainEntry>(staged["outcome"]["observer"].clone())
    else {
        return Ok(None);
    };
    if !matches!(
        state::process_identity_evidence(&observer),
        state::ProcessIdentityEvidence::Gone | state::ProcessIdentityEvidence::Mismatch
    ) {
        return Ok(None);
    }
    let selection = value(&paths.state_dir.join(SELECTION))?;
    let directory = fs::metadata(&paths.state_dir)?;
    if selection["directory"]["device"] != directory.dev()
        || selection["directory"]["inode"] != directory.ino()
    {
        return Ok(None);
    }
    let entries = inventory(paths)?;
    if entries.iter().any(|(name, meta)| {
        name == OUTPUT
            || (name.starts_with(".completion-output-")
                && !capture::incomplete_dead_copy(paths, name, meta, &selection))
    }) {
        return Ok(None);
    }
    let Some((reason, selected, observed)) = loss(&selection, &entries)? else {
        return Ok(None);
    };
    if reason == "selected_storage_short" {
        sync_short_selection(paths, &selected, &observed, &entries)?;
    }
    // Sync the inspected storage before retaining the causal observation. Any
    // storage error remains uncertainty, never proof of permanent loss.
    File::open(&paths.state_dir)?.sync_all()?;
    let outcome = &staged["outcome"];
    let proof = json!({
        "representation": "missing-original-output-v1", "capture_state": "irrecoverable",
        "reason": reason,
        "detail": "Exact original observer is gone. Original selection record and same source directory were inspected; no complete body or in-progress copy survives. Managed retained inode inventory establishes selection loss; later log bytes were not substituted.",
        "producer": identity(unsafe { libc::getpid() })?,
        "original_observer": observer, "completion_revision": outcome["completion_revision"],
        "outcome_sha256": digest(&bytes(outcome)?),
        "selection": selected, "observed_byte_len": observed
    });
    immutable(paths, PROOF, &bytes(&proof)?)?;
    Ok(Some(proof))
}

fn sync_short_selection(
    paths: &StatePaths,
    selected: &Value,
    observed: &Value,
    entries: &[(String, fs::Metadata)],
) -> io::Result<()> {
    let (name, _) = entries
        .iter()
        .find(|(_, m)| selected["device"] == m.dev() && selected["inode"] == m.ino())
        .ok_or_else(|| error("selected inode no longer present"))?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(paths.state_dir.join(name))?;
    file.sync_all()?;
    let meta = file.metadata()?;
    if selected["device"] != meta.dev()
        || selected["inode"] != meta.ino()
        || *observed != meta.len()
    {
        return Err(error("selected inode changed during loss observation"));
    }
    Ok(())
}

fn inventory(paths: &StatePaths) -> io::Result<Vec<(String, fs::Metadata)>> {
    fs::read_dir(&paths.state_dir)?
        .map(|entry| {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| error("non UTF-8 storage entry"))?;
            // Do not follow aliases or ignore unreadable/disappearing entries.
            let meta = fs::symlink_metadata(entry.path())?;
            if meta.file_type().is_symlink() {
                return Err(error("ambiguous source storage alias"));
            }
            Ok((name, meta))
        })
        .collect()
}

type Loss = (&'static str, Value, Value);
fn loss(selection: &Value, entries: &[(String, fs::Metadata)]) -> io::Result<Option<Loss>> {
    if selection["missing"].as_str().is_some() {
        // A pin made before failure can still preserve recoverable evidence.
        return Ok(
            (!entries.iter().any(|(name, _)| name == SELECTED_LOG)).then_some((
                "original_selection_not_retained",
                Value::Null,
                Value::Null,
            )),
        );
    }
    let (Some(device), Some(inode), Some(length)) = (
        selection["device"].as_u64(),
        selection["inode"].as_u64(),
        selection["byte_len"].as_u64(),
    ) else {
        return Ok(None);
    };
    if inode == 0 || length > MAX_OUTPUT || selection["link_count"] != 2 {
        return Ok(None);
    }
    let selected = json!({"device": device, "inode": inode, "byte_len": length});
    let aliases: Vec<_> = entries
        .iter()
        .filter(|(_, m)| m.dev() == device && m.ino() == inode)
        .collect();
    if aliases.is_empty() && entries.iter().any(|(name, _)| name == SELECTED_LOG) {
        // A replacement or mounted-over pin is ambiguous, not original loss.
        return Ok(None);
    }
    if aliases.is_empty() {
        // Successful enumeration of the original directory, with no original
        // inode at the pin, live-log alias, body or copy, is stronger than ENOENT.
        return Ok(Some(("selected_storage_lost", selected, Value::Null)));
    }
    let (_, meta) = aliases[0];
    if !meta.is_file() || meta.len() >= length || meta.nlink() != aliases.len() as u64 {
        return Ok(None);
    }
    Ok(Some((
        "selected_storage_short",
        selected,
        json!(meta.len()),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, StatePaths) {
        let (temp, paths, common) = super::super::tests::source();
        fs::write(&paths.log, b"original evidence").unwrap();
        select_output(&paths).unwrap();
        let mut observer = identity(unsafe { libc::getpid() }).unwrap();
        // Unit fixture only: exact identity mismatch, not a live-process loss test.
        observer.starttime_ticks += 1;
        let mut outcome = common;
        outcome["observer"] = json!(observer);
        outcome["completion_revision"] = json!(1);
        save(
            &paths,
            "source-observation-v2.json",
            &json!({"outcome": outcome}),
        )
        .unwrap();
        (temp, paths)
    }

    fn rollover(paths: &StatePaths) {
        fs::remove_file(&paths.log).unwrap();
        fs::write(&paths.log, b"later bytes").unwrap();
    }

    #[test]
    fn lost_pin_with_surviving_original_log_alias_is_not_permanent_loss() {
        let (_temp, paths) = fixture();
        fs::remove_file(paths.state_dir.join(SELECTED_LOG)).unwrap();
        assert!(observe(&paths).unwrap().is_none());
        assert!(!paths.state_dir.join(PROOF).exists());
    }

    #[test]
    fn intact_inode_or_live_original_observer_cannot_prove_loss() {
        let (_temp, paths) = fixture();
        assert!(observe(&paths).unwrap().is_none());
        rollover(&paths);
        fs::remove_file(paths.state_dir.join(SELECTED_LOG)).unwrap();
        let mut staged = value(&paths.state_dir.join("source-observation-v2.json")).unwrap();
        staged["outcome"]["observer"] = json!(identity(unsafe { libc::getpid() }).unwrap());
        save(&paths, "source-observation-v2.json", &staged).unwrap();
        assert!(observe(&paths).unwrap().is_none());
    }

    #[test]
    fn lost_managed_inode_retains_attributable_exact_observation_once() {
        let (_temp, paths) = fixture();
        rollover(&paths);
        fs::remove_file(paths.state_dir.join(SELECTED_LOG)).unwrap();
        let proof = observe(&paths).unwrap().unwrap();
        assert_eq!(proof["reason"], "selected_storage_lost");
        assert_eq!(
            proof["producer"],
            json!(identity(unsafe { libc::getpid() }).unwrap())
        );
        let staged = value(&paths.state_dir.join("source-observation-v2.json")).unwrap();
        assert_eq!(proof["original_observer"], staged["outcome"]["observer"]);
        assert_eq!(
            proof["outcome_sha256"],
            digest(&bytes(&staged["outcome"]).unwrap())
        );
        assert_eq!(proof, observe(&paths).unwrap().unwrap());
        assert!(
            !paths.state_dir.join(SNAPSHOT).exists(),
            "observation alone is not publication"
        );
    }

    #[test]
    fn short_same_inode_retains_actual_exclusive_prefix_and_observed_length() {
        let (_temp, paths) = fixture();
        rollover(&paths);
        fs::write(paths.state_dir.join(SELECTED_LOG), b"short").unwrap();
        let proof = observe(&paths).unwrap().unwrap();
        assert_eq!(proof["reason"], "selected_storage_short");
        assert_eq!(proof["observed_byte_len"], 5);
        assert_eq!(proof["selection"]["byte_len"], 17);
    }

    #[test]
    fn incomplete_body_or_unaccounted_alias_prevents_loss_attestation() {
        let (_temp, paths) = fixture();
        rollover(&paths);
        let pin = paths.state_dir.join(SELECTED_LOG);
        fs::hard_link(&pin, paths.root.join("outside-alias")).unwrap();
        fs::write(&pin, b"").unwrap();
        assert!(observe(&paths).unwrap().is_none());
        fs::remove_file(paths.root.join("outside-alias")).unwrap();
        fs::write(
            paths.state_dir.join(".completion-output-interrupted.tmp"),
            b"prefix",
        )
        .unwrap();
        assert!(observe(&paths).unwrap().is_none());
    }

    #[test]
    fn changed_source_directory_identity_prevents_loss_attestation() {
        let (_temp, paths) = fixture();
        rollover(&paths);
        fs::remove_file(paths.state_dir.join(SELECTED_LOG)).unwrap();
        let mut selection = value(&paths.state_dir.join(SELECTION)).unwrap();
        selection["directory"]["inode"] = json!(0);
        save(&paths, SELECTION, &selection).unwrap();
        assert!(observe(&paths).unwrap().is_none());
    }

    #[test]
    fn replacement_pin_is_ambiguous_not_missing_or_successful_output() {
        let (_temp, paths) = fixture();
        rollover(&paths);
        let pin = paths.state_dir.join(SELECTED_LOG);
        // Keep the original inode allocated outside the managed directory so
        // this cannot accidentally exercise inode reuse instead of replacement.
        fs::rename(&pin, paths.root.join("unmanaged-pin")).unwrap();
        fs::write(&pin, b"not the original output").unwrap();
        assert!(freeze_output(&paths).is_err());
        assert!(observe(&paths).unwrap().is_none());
    }

    #[test]
    fn unknown_initial_link_inventory_prevents_permanent_loss() {
        let (_temp, paths) = fixture();
        rollover(&paths);
        fs::remove_file(paths.state_dir.join(SELECTED_LOG)).unwrap();
        let mut selection = value(&paths.state_dir.join(SELECTION)).unwrap();
        selection["link_count"] = json!(3);
        save(&paths, SELECTION, &selection).unwrap();
        assert!(observe(&paths).unwrap().is_none());
    }

    #[test]
    fn revision5_import_preserves_canonical_transport_bytes() {
        let wire: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/age360/missing-output-wire.json"
        ))
        .unwrap();
        assert_eq!(wire["fixture_revision"], 5);
        let snapshot = wire["missing_output_snapshot_bytes_utf8"].as_str().unwrap();
        assert_eq!(
            digest(snapshot.as_bytes()),
            wire["missing_output_snapshot_sha256"]
        );
        let parsed: Value = serde_json::from_str(snapshot).unwrap();
        assert_eq!(
            parsed["output"]["outcome_sha256"],
            digest(wire["outcome_bytes_utf8"].as_str().unwrap().as_bytes())
        );
        assert_eq!(
            wire["missing_output_recovery_response"]["status"],
            "source_output_missing"
        );
    }

    #[test]
    fn missing_original_identity_remains_uncertainty() {
        let (_temp, paths) = fixture();
        save(
            &paths,
            "source-observation-v2.json",
            &json!({"outcome": null}),
        )
        .unwrap();
        assert!(observe(&paths).unwrap().is_none());
    }
}
