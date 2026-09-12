# Retained output and exact local acceptance

`status --observe-only` reads without progressing completion. `snapshot HANDLE` additionally
returns a terminal, bounded log prefix in JSON, without trimming or lossy decoding:

- `snapshot`: `{version:1, handle, created_at_unix_ms, bytes, sha256, encoding:"hex"}`;
- `output`: lowercase hex, exactly `bytes * 2` characters, SHA-256 over decoded bytes;
- `status`: the terminal status header observed during acquisition.

The byte bound is captured from the open log's length. Reads stop there even if output appends.
A short read or missing source fails; it is not an empty successful snapshot. The hash identifies
acquired bytes, not a file's eventual size, a workload's physical cessation, or an atomic snapshot
of all metadata. Terminal ready-sentinel/root-completion output may still grow. A rewritten source
can prevent future recovery/acceptance, even though bytes already acquired by a caller remain useful.

After validating the entire response, length, hash and identity, the consumer calls
`consume HANDLE --snapshot '<snapshot JSON>'`. This rejects malformed, wrong-handle, stale-source,
wrong-encoding and changed-prefix identities before publishing the durable `consumed` marker.
The old bare consume command is no longer sufficient evidence and requires the identity argument;
this is a coordinated CLI/adapter contract change, not a backwards-compatible old-adapter rollout.
Partial prefixes may be explicitly acquired with `snapshot HANDLE --bytes N` and accepted as **only
those N bytes** (including zero). No unseen suffix is thereby locally accepted.

A successful response has `version:1`, the exact `handle` and `snapshot`,
`local_acceptance:"accepted"`, boolean `consumed`, `remote_ack:"unconfirmed"` and
`physical_drain:"unconfirmed"`. `consumed:true` means this call created the existing marker;
`false` means it already existed, not rejection. Every retry still validates the identified source
prefix and authority. The marker remains a coarse local hint to the existing completion protocol,
not a ledger of per-prefix receipts; duplicates do not replay completed work or rewrite delivery
metadata. A successful process exit without a valid correlated reply does not confirm acceptance.
The hint's existing remote `--consumed` meaning is unchanged. No new remote RPC or ACK/drain proof
is introduced; full remote integration remains AGE-363 residual scope with AGE-360/361 dependencies.

## Authority and lifetime

Snapshot observation preserves existing account-local status read access. Knowledge of a handle or
snapshot does not grant control. Consume uses the existing live caller-chain/pinned-helper acting
session rule, or exact caller ancestry for sessionless handles. Same-session recovery in a new
invocation remains authorized; the historical owner's invocation UUID is not a new recovery gate.
No provenance/schema-7 shortcut or ambient owner-string override is introduced.

`output.lock` excludes reaping during acquisition and acceptance; reaping takes the existing delivery
lock then tries the output lock without waiting. Output operations never acquire the delivery or
reconciliation locks. The lock does not exclude appenders or change TTL/delivery/physical-retention
eligibility. It is released after the individual operation; it does not pin a caller's unread source
between commands. A cleanup race can therefore yield explicit unavailable/unknown, never a recreated
source or fabricated acceptance. A caller must keep already acquired bytes when acceptance fails.

Restart recovery is limited to the **existing retained source-state lifetime** (configured state TTL
and existing physical/delivery vetoes). There is no new expiry, indefinite pin, separate snapshot
store, or guarantee after cleanup. To recover an earlier prefix, read `snapshot HANDLE --bytes N`
and compare the entire identity to the saved identity. Appended bytes do not invalidate that prefix;
truncation/replacement may. If the prior identity was also lost, a new snapshot is a new observation,
not proof of recovering the former one. No adapter-memory persistence is claimed after process loss.

## OpenCode representation and failure behavior

The bundled adapter obtains and validates the whole snapshot before consumption/progression. Valid
UTF-8 is returned unchanged, including leading/trailing whitespace, BOM, NUL and newlines. Bytes that
cannot round-trip through UTF-8 are returned as explicitly labelled hex. The output block is last;
status, exact identity and local/remote uncertainty precede it. If a running textual status read races
terminal state and exact acquisition fails, that text is retained without exact-acceptance claims.

Consume errors/rejection, malformed/stale/lost replies, timeout/abort and later progression failure
cannot replace acquired output. Only a validated reply changes local acceptance to accepted. Unknown
acceptance does not justify replaying the workload: observe retained state or retry the same bounded
identity using existing authority. A failed/partial snapshot response never authorizes a marker.

Wire hex expands bytes 2x; acquisition/adapter memory is proportional to the acquired prefix, as with
full status. Persistent storage remains the existing log plus a small lock file and existing marker,
not a copy per read/acceptance. No aggregate capacity or universal reliability claim is made.
