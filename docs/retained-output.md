# Retained output and exact local acceptance

`status --observe-only` reads without progressing completion. `snapshot HANDLE` additionally
returns a terminal log prefix in JSON, without trimming or lossy decoding:

- `snapshot`: `{version:1, handle, created_at_unix_ms, bytes, sha256, encoding:"hex"}`;
- `output`: lowercase hex, exactly `bytes * 2` characters, SHA-256 over decoded bytes;
- `status`: the terminal status header observed during acquisition.

The byte bound is captured from the open log's length. Reads stop there even if output appends.
A short read or missing source fails; it is not an empty successful snapshot. The hash identifies
acquired bytes, not a file's eventual size, a workload's physical cessation, or an atomic snapshot
of the log or all metadata. Terminal ready-sentinel/root-completion output may still grow. A rewritten source
can prevent future recovery/acceptance, even though bytes already acquired by a caller remain useful.
Normal supervisor capture only appends; it does not replace or truncate the live log. Producers
are not locked. External replacement or in-place rewrites can still
produce short or mixed reads. The hash identifies exactly the bytes actually acquired;
a later acceptance read may reject them. Acceptance likewise validates the
bytes it reads, not an immutable historical image. Sequential append/replacement/truncation tests
do not establish behavior under concurrent external replacement; that interleaving is not tested.

After validating the entire response, length, hash and identity, the consumer calls
`accept-output HANDLE --snapshot '<snapshot JSON>'`. This revalidates authority and exact
source bytes before publishing a separate `output-receipt.json`. Partial and zero-byte
prefixes represent only those acquired bytes, never an event or forever-final log.

Success returns `version:1`, exact `handle` and `snapshot`, `local_receipt:"durable"`,
boolean `receipt_updated`, `remote_ack:"unconfirmed"`, and `physical_drain:"unconfirmed"`.
`receipt_updated:false` means the same identity was already visible; **every success,
including duplicates, syncs the record and containing directory**. A lost reply is unconfirmed.
One latest identity per handle is retained, not bytes or unlimited history. Later acceptance
replaces it; no prior receipt lifetime or arbitrary new TTL is promised.

Publication uses one reusable, non-authoritative pending file, file sync, atomic rename,
and directory sync. Published content is never rolled back on a later synchronization error.
Visible content means publication intent, not confirmed durability or receipt of a response.
Errors identify preparation/file-sync/publication/directory-sync phases; a post-publication
error leaves the visible identity for a revalidated retry to sync. Readers must not infer
successful acceptance from file existence. Replacement intentionally supersedes prior records.
Shared activation-marker publication semantics are unchanged.

This operation never creates `consumed` or forwards an event-wide consumed hint. Normal
completion notification remains enabled; duplicate presentation is an accepted cost. Local
receipt does not imply remote ACK. Paired suppression/settlement remains deferred to separately
authorized AGE-360/361/363 work, not solved here.

Any existing `consumed` entry causes distinguishable `legacy-state` rejection, without modifying
it. Previous suppression/ACK cannot be reversed locally. The guarantee applies only without
legacy coarse state and with coordinated new CLI/adapter callers. Concurrent old binaries or
old writers are unsupported. There is no unsafe consume compatibility shim, live migration,
or automatic cleanup of old effects; keep acquired bytes on rejection.

## Authority and lifetime

Snapshot observation preserves existing account-local status read access. Knowledge of a handle or
snapshot does not grant control. Accept-output uses the existing live caller-chain/pinned-helper acting
session rule, or exact caller ancestry for sessionless handles. Same-session recovery in a new
invocation remains authorized; the historical owner's invocation UUID is not a new recovery gate.
No provenance/schema-7 shortcut or ambient owner-string override is introduced.

`output.lock` excludes reaping during acquisition and acceptance; reaping takes the existing delivery
lock, then the bounded custody lock, then tries the output lock without waiting. Output operations never acquire the delivery or
reconciliation locks. The lock does not exclude appenders or change TTL/delivery/physical-retention
eligibility. It is released after owned acquisition/validation/publication, before stdout transport; it does not pin a caller's unread source
between commands. A cleanup race can therefore yield explicit unavailable/unknown, never a recreated
source or fabricated acceptance. A caller must keep already acquired bytes when acceptance fails.

Restart recovery is limited to the **existing retained source-state lifetime** (configured state TTL
and existing physical/delivery vetoes). There is no new expiry, indefinite pin, separate snapshot
store, or guarantee after cleanup. To recover an earlier prefix, read `snapshot HANDLE --bytes N`
and compare the entire identity to the saved identity. Appended bytes do not invalidate that prefix;
external truncation/replacement may. If the prior identity was also lost, a new snapshot is a new observation,
not proof of recovering the former one. No adapter-memory persistence is claimed after process loss.

## OpenCode representation and failure behavior

The bundled adapter obtains and validates the whole snapshot before receipt/progression. Valid
UTF-8 is returned unchanged, including leading/trailing whitespace, BOM, NUL and newlines. Bytes that
cannot round-trip through UTF-8 are returned as explicitly labelled hex. The output block is last;
status, exact identity and local/remote uncertainty precede it. If a running textual status read races
terminal state and exact acquisition fails, that text is retained without exact-acceptance claims.

Receipt errors/rejection, malformed/stale/lost replies, timeout/abort and later progression failure
cannot replace acquired output. After post-acquisition abort in a synchronous call, the adapter
still invokes the existing cancellation path without the aborted signal and reports its actual
response (or explicitly unconfirmed failure) alongside the retained output. This preserves the
existing cancellation invocation responsibility; a request is not itself drain proof.
Terminal cancellation uses the merged AGE-362 same-boot physical-custody admission path,
independently of logical completion and delivery waits. The two post-acquisition abort regressions
(receipt and progression) now observe accepted cancellation, exact live-descendant exit and guardian
custody discharge while the adapter remains alive, with the acquired bytes retained exactly once.
These cases failed before that prerequisite; they do not establish all-topology cancellation success.
In particular, uncertified delivery-role custodian loss leaves UNKNOWN and can indefinitely withhold
workload signals until independent cessation. A request alone still proves neither drain nor remote
ACK. An explicit asynchronous poll does not acquire synchronous cancellation ownership.
The adapter's resolved return value retains the bytes while its process remains alive. A host
that discards results after abort may not display or persist them; actual host-aborted OpenCode UI
retention is unverified. Process death loses adapter memory; source recovery remains bounded by
the state lifetime and external replacement limitations above. Only a validated reply confirms a durable local receipt. Unknown
acceptance does not justify replaying the workload: observe retained state or retry the same bounded
identity using existing authority. A failed/partial snapshot response never authorizes a receipt.

Explicit running-handle polls retain the existing default tail read (65,536 bytes), not full-log
reads. Terminal acquisition alone reads the complete observed prefix. If a running read
races terminal state and exact acquisition fails, only the acquired tail text is retained.

Wire hex expands bytes 2x; acquisition/adapter memory is proportional to the acquired prefix, as with
the snapshot representation. `status` streams its frozen observed prefix in fixed
chunks, including `--full`; default running tails remain 65,536 bytes.
Persistent storage remains the existing log plus a small lock file and receipt record,
not a copy per read/acceptance. No aggregate capacity or universal reliability claim is made.


### Completion continuation: original-event selection

The v2 source selects the append-only log in the original live terminal-event turn:
`selected-log-v2.bin` pins its inode and `output-selection-v2.json` records the
exclusive byte boundary. Later appends are outside that selection. Delayed body
capture (including a successor after observer loss) copies only the retained
original prefix. If the observer dies without a selection, a successor records
unverified output as missing rather than calling a possibly partial log complete.
Neither the pin nor the
boundary is a recipient receipt. The public full-body representation is unchanged.

Recovery hashes retained bytes without `completion.lock`; original incremental
publication attempts that lock nonblockingly. A stopped recovery has no whole-body
critical section on the live observer's I/O/cancellation/reaping path. Initial
copy/fsync still uses synchronous filesystem I/O, not a cancellation-latency bound.

If the original selection is unavailable, Bash preserves the original header,
reports `pending / original_output_capture_incomplete` through the existing
recovery interface, and never samples the current log as replacement output.
Actual cancellation drain and physical guardian discharge do not certify source
publication. Once physically drained, a guardian may retire local execution with
notification duty still held by the exact confirmed native registration. This
creates no enqueue, source acceptance, delivery or listener ACK. Explicit native
missing-output notification is a **pairing dependency**: the current source reply
preserves the failure but does not itself materialize it for the recipient.

A pin is a hard link to the same append-only inode; the full body retains another
copy. Disk capacity, full terminal snapshot memory, wire expansion, and
storage-loss uncertainty remain visible limits. No new TTL or reclamation
policy is introduced. Unrecoverable selection loss is not retried by the Bash
physical guardian; the native continuation remains responsible for its retained
notification obligation, pending the coordinated missing-output capability.

### Long-running retention and rotation

A 60-day running handle keeps one growing log inode for all 60 days. Its selected
prefix, when an event occurs, can be as large as the whole run to that point;
capture creates a second full body file. Filesystem space and inode lifetime,
not a product byte cap, bound this design. A daily or startup pathname rotation
would break the single-file prefix and status/snapshot representation unless a
durable segment manifest, exact cross-segment selection, and recovery rules were
added together. This implementation performs no such rotation. Startup only
invokes the existing sharded state reaper; it never rewrites a live log.

There is no separate 30-day closed-log reaper. The existing per-handle state TTL
defaults to 48 hours after the relevant terminal age, but paired v2 source
retention requires an exact durable release, accepted root result, settled
delivery, physical custody discharge, and any causal parent gate before the
whole directory can be removed. These vetoes may retain a closed 30-day record
and its full log indefinitely when the other side has not released it. Reaping
is best effort on later CLI startup, bounded by the configured scan and shard
limits; there is no detached maintenance daemon or guaranteed deletion time.
