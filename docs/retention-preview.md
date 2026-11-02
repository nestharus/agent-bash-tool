# Retention preview

`retention-preview` reports bounded retention metadata for an explicitly selected
legacy state root. It does not create state, acquire creating locks, reconcile
delivery, advance the reaper cursor, accept output, issue a release or delete data.
It reads three bounded JSON metadata types and file metadata, without opening log
or source-output bodies. Command, environment and unknown JSON values are not
materialized into the retention views or included in the report.
Recorded owner/root identifiers are returned only when they have UUID syntax.
They are producer-recorded locators, not authenticated ownership or release.

Inspect known handles:

```sh
agent-bash retention-preview --root /absolute/selected/state --handle ab_example
```

Discover a bounded batch:

```sh
agent-bash retention-preview --root /absolute/selected/state --discover \
  --max-handles 128 --max-entries 4096
```

Discovery counts every root entry visited, including unrelated names, and shares
the entry budget with inspection. Continue with the returned
`next_directory_offset` using `--resume-offset` and the matching `--root-stamp`.
The checkpoint is rejected if the directory's device, inode, modification time,
change time, size or link count differs. An observed change during discovery
invalidates its checkpoint. These metadata checks and directory cookies do not
prove frozen membership: timestamps can have coarse resolution, and concurrent
changes can affect enumeration. `iteration_exhausted` describes this iterator,
not a consistent whole-store census.
Partial handle enumeration requires a larger entry budget; nested allocations
remain explicitly unmeasured. Ordinary filesystem access-time updates are not
suppressed for directory enumeration.

The preview applies the configured `AGENT_BASH_STATE_TTL_SECS`, normally 48 hours,
with a 24-hour minimum for its reported cutoff. This does not change the existing
automatic reaper's configuration or behavior. Age uses the later of recorded
completion and update times. Missing or malformed metadata stays unresolved;
running work, pending delivery, parent/result duties, custody and absent source
release remain visible holds or unknowns. Process identities and source-release
body validation are not performed by this read-only command.

Every report has `apply_supported: false`. An old terminal state, a small report,
or a matching checkpoint does not authorize deletion. Physical removal still
requires current owner authority and the existing reaper's complete lock,
identity, result, custody and exact source-release checks. In particular, fresh
completion-v2 release validation hashes original source bytes, so it cannot be
advertised as part of this body-free preview. Historical unknowns do not become
fresh registered sources, and native root-v1 stores are a separate lineage.

Allocation totals count observed inode blocks once. Unseen hard links and nested
contents are reported separately; these totals are not predicted reclaimed
space. No default store is selected, and this command grants no access to a
store that its owner has placed outside the caller's authorized scope.
