# Native completion continuation (AGE-360 candidate)

This is the Bash half of a matched runner protocol, **not a production cutover or
paired verification claim**. Runner owns the independently rooted notification
continuation, listener materialization/ACK and activation custody. Original Bash
workloads keep their existing supervisor/guardian ancestry and cancellation route.

Native admission uses the inherited `OULIPOLY_COMPLETION_ENDPOINT`, a nonmutating
pinned-runner `notify agent-bash-capability --json`, and a same-UID live owner hello.
These establish availability only. The registration worker retains exact source
bytes and a launch fence before invoking runner registration. Only an exact
structured committed receipt lets that worker move `unreleased` to `may_launch`
before daemon/workload forks. `launched` binds the actual root process identity.
No error/EOF/absent readback authorizes workload or registration replay. Native
registration authority without an inherited endpoint is rejected before launch;
there is no failed-v2 fallback. Historical non-native helper handles retain their
recorded executor, not a claim of native continuation capability.

## Durable source and local responsibilities

- `source-registration-v2.json`: immutable registration bytes, source incarnation,
  domain, original listener, paths, pinned runner/Bash images and environment hash.
- `source-launch-v2.json`, `launch.lock`: serialized one-use launch authority. Only
  an unspent fence can become `revoked_never_launched`; `may_launch` without outcome
  remains uncertain even after every recorded PID disappears.
- `registration-receipt-v2.json`: exact original registration response. Distinct
  from `registration-confirmation-v2.json`, whose authority is completion-only.
- `source-outcome-v2.json`, `completion-snapshot-v2.json`: immutable original-source
  evidence and notification body, recovered from one durable source bundle if
  publication is interrupted. These are not `snapshot`/`accept-output` receipts.
- `continuation-v2.json`: local registration/enqueue facts, **not** recipient ACK.
- `continuation-<operation>-<attempt>.*`: retained intent, complete stdout/stderr and
  actual worker wait result. A zero process exit is not structured acceptance.
  Existing delivery-role custody remains independently responsible for descendants.

Original live observation distinguishes Root wait/output close, Tree drain, ready
sentinel and cancellation. Only the actual adopting guardian can certify original
cessation after supervisor loss. List/status rc70 does not supply source evidence.
The last guardian remains cancellation-responsive during local delivery. Live and
guardian reapers retain reaped transfer results until integration succeeds.

## Completion-only recovery

Runner invokes the **registered pinned Bash image**, under the registered private
`delivery-helper-environment.json`, with its exact State readback confirmation:

```text
completion-reconcile-v2 --registration-file PATH --confirmation PATH --json
```

Recovery validates source/domain/registration/image/environment identities. It
can revoke an unspent fence only after exact original-worker-gone evidence, or use
an already voluntarily revoked fence. It cannot register, launch workload argv,
replace original reapers, or infer cessation from its own empty process tree.
A live registration worker and `may_launch` uncertainty remain pending. No product
execution deadline, polling expiration, prefix ACK or coarse consume operation is
part of this path. Local output receipt never changes listener state.

Bash can end its local enqueue responsibility after exact acceptance, or retain
source material under confirmed durable runner recovery ownership. This does not
release original/local physical custody. Source cleanup is conservative: v2
artifacts are not TTL-reaped. Current wire has no source-release transaction that
joins late listeners and active recovery readers; unbounded retention is visible
rather than an invented ACK-based cleanup rule.

## Verification and open pairing edges

`tests/fixtures/age360/paired-wire.json` imports runner revision 4 byte-for-byte.
The fixture and unit test retain exact canonical bytes and digests. Revision 3
permits genuine early-exit outcomes for ready registrations, without fake readiness.
Source tests use native Bash processes in private user/network namespaces with an
explicitly simulated runner. They are not native State admission, mailbox ACK,
independent runner ownership, migration or provider-reliability evidence. Root owns
runner's `age360_completion_continuation` paired target and final delivery.

Revision 4 adds a complete-body artifact alongside the bounded JSON event. Bash
freezes `completion-output-v2.bin` as unchanged raw bytes, then streams SHA256 with
a 64 KiB buffer in 1 MiB quanta, yielding to the original loop between quanta. Bodies above 64 KiB use the canonical `retained-output-v1`
descriptor; smaller bodies keep the existing inline UTF-8-lossy string. The cutoff
bounds even worst-case inline escaping independently of the 1 GiB configured log
ceiling. Registration bytes and snapshot/outcome JSON limits are unchanged.

Runner owns validation and retention of its content-addressed body copy and the
notification's explicit attachment path/hash/length/encoding. There is no additional
truncation, larger JSON allocation bound, prefix-as-event or Bash-owned competing
wire. Actual attachment consumption, native delivery and late listener retrieval
still need root paired verification. AGE365 owns production transition/reclamation.

## Review correction: original observation survives publication retry

The live loop retains its finalized terminal metadata and observed wait/drain
facts separately from subsequent cancellation and status changes. Cancellation
accepted after ordinary terminal metadata publication cannot relabel that event
as cancelled. A cancelled certificate additionally refuses publication without
actual original drain and output closure.

Publication failures no longer unwind the original event loop or close its live
output readers. Local delivery and supervisor retirement wait for publication;
output collection, cancellation and reaping continue. Hashing yields to these
duties between quanta; initial copy/fsync still uses synchronous filesystem I/O.
Failed publication retries
at most once per second (a retry interval, never a workload deadline). The last
error remains in `source-publication-error.txt`, including after later success.

Private `source-observation-v2.json` retains original evidence and snapshot headers;
`completion-output-v2.bin` freezes the entire selected bounded log using a streaming
copy before JSON publication. These are not an alternative public wire or event
ACK. Recovery can finish this staged original observation rather than invent a
new cessation result. Once frozen, later ready output cannot replace its bytes.
An I/O failure before raw capture succeeds leaves an outstanding capture. The
selected inode/prefix remains original even if the live log advances; a successor
can recover that selection, but cannot resample newer mutable log bytes when the
original selected storage is unavailable. Loss before any durable
observation still cannot be recovered as that exact event. Neither limitation authorizes loss of the surviving observer.
`source_ready` replies include hashes of the exact retained snapshot/outcome files.

### Executable source barriers (fixture builds only)

Build the actual source binary with `cargo build --locked --features source-fault-tests`.
Default builds contain no active hooks. Set `AGENT_BASH_SOURCE_FAULT` in the original
Bash launch environment to one of:

- `after-terminal-metadata`: yields after the first terminal publication and
  original event/selection retention, before body capture. The original loop keeps servicing I/O and
  cancellation. Root can accept a real cancellation here before source publication.
- `publication-error`: injects ENOSPC after the original observation and raw output
  are retained, before the immutable public bundle/outcome/snapshot publication.
- `during-output-hash`: yields after at least one real 1 MiB hash quantum and before
  continuing the hash. The source test writes more than a pipe buffer and cancels
  the original workload while this barrier remains unreleased, then verifies the
  eventual source still contains the original ready evidence and full body.

Each reached source point writes `fault-<name>.reached.json` in its registered
handle directory, containing its actual PID/starttime/boot identity. It retries
without advancing until `fault-<name>.release` exists in that same directory.
No timeout, fabricated source certificate, registration acceptance or native
runner proof is supplied by a marker. These hooks are inherited only by explicit
fixture builds. Root must use private namespaces and actual paired candidates.

The source suite additionally puts a directory at `source-outcome-v2.json` after
the staging barrier to execute a real immutable-publication I/O failure. It proves
more than one pipe buffer of subsequent workload output is read while publication
fails, then removes that fixture-owned obstruction and checks exact recovery
hashes and original ready bytes. The source cases check full artifact publication for 4 MiB NUL output (which would
escape beyond 16 MiB) and configured 20 MiB invalid UTF-8 output. Both keep a ready
workload writing and cancellable, with unchanged original artifact bytes. They use
a simulated runner, not native attachment delivery. A private publisher unit test
copies/hashes the supported 1 GiB ceiling and checks process peak RSS below 128 MiB;
that is a source resource experiment, not original-work reaping evidence.

## Missing original output (additive wire revision 5)

The runner-owned `missing-original-output-v1` contract is imported verbatim at
`tests/fixtures/age360/missing-output-wire.json`; revision4 successful output is
unchanged. Bash retains genuine original event/outcome bytes and rc. Missing
output is not empty success, a new workload failure, readiness, physical drain,
notification acceptance or ACK. If no original outcome survives, recovery remains
pending; it never reconstructs an outcome from cancellation or later log bytes.

The original selection now records device/inode/exclusive prefix and the source
directory identity. A completion-only successor can publish missing evidence only
after the exact original observer is gone/mismatched and a successful inventory
of that same directory establishes loss. An explicit original selection-failure
record with no orphaned pin yields `original_selection_not_retained`; absence of
the selected inode across managed storage yields `selected_storage_lost`; durable
shortening of that same inode yields `selected_storage_short`. The latter records
its actual length after syncing/rechecking the inode. An intact live-log alias,
replacement pin, unaccounted hard link, surviving body/unvalidated copy candidate,
ambiguous symlink or changed source directory prevents attestation. No timestamp, retry
count, pending response or failed open is permanent-loss proof. In particular a
transient permission/read failure with intact storage stays pending and can later
produce the original successful bytes.

`missing-output-observation-v2.json` retains the attributable producer and exact
original observation/outcome linkage before immutable outcome/snapshot publication.
It is source evidence, not another authority store. Recovery returns
`source_output_missing` with exact hashes only after both public files are durable;
`source_ready` remains exclusively successful output. Runner acceptance owns retry
suppression, ordinary recipient delivery, late listeners and exact ACK. Bash does
not alter physical-drain or artifact-retention duties.

This is a managed local source-storage observation, not filesystem omniscience:
Bash owns the pin/log/body/copy inventory and original writer lifetime. Unknown
external backups, hostile concurrent filesystem mutation, unsupported old selection
records and unvalidated copy recovery are not certified. Such ambiguities that
are observed remain pending. No existing-domain migration or full-owner-loss policy
is introduced here.

## Capture ownership and interrupted publication

The original event turn now commits the event/outcome and snapshot header **inside
`output-selection-v2.json`**, together with the selected inode and exclusive
boundary, before returning to log I/O. `source-observation-v2.json` is an immutable
projection of this record. A guardian or completion-only recovery can restore that
projection after observer loss, but cannot attach its later cancellation/cessation
to an earlier selection. Old selection-only records lacking event evidence remain
uncertain rather than acquiring a new label. Death before event/selection retention
still loses that exact observation; metadata alone is not its reconstruction.

`source-capture.lock` is an exclusive **nonblocking**, cooperating capture lease.
All capturers acquire it before opening original bytes; recovery holds it across
capture failure, storage inventory and durable missing-output publication. A busy
lease means pending, including when the owner is paused with the only recoverable
open descriptor and no surviving pathname. No whole-body hashing occurs under
this lease; recovery hashing also remains outside `completion.lock`. Live I/O and
cancellation do not acquire the capture lease. Initial copy/fsync remains
synchronous and is not a latency guarantee.

Capture enumerates managed aliases and validates the opened descriptor against the
original directory/device/inode and selected boundary. It never requires restoring
the canonical selected pathname. Each newly created copy has a local receipt bound
to the exact selection digest, target inode/device, expected length and writer
identity. A complete receipt is retained only after exact-length copy and fsync.
Recovery can promote that surviving exact copy after an interruption before its
final hardlink, without manufacturing a public header, output bytes or ACK.
A dead writer's exact short, unfinished copy cannot represent the complete output;
its bytes and receipt are preserved but no longer indefinitely inhibit otherwise
valid loss inventory. Live/unknown writer identities and unvalidated copies remain
uncertain. In particular, a full copy interrupted before its completion receipt
cannot be promoted from length alone when original storage is also lost. These
rules are local cooperating-producer evidence, not authentication against hostile
same-account file rewriting, external backup discovery or an upgrade/migration
protocol for already-pinned recovery executables.

Fixture-only `selection-before-header` yields after the bound selection but before
header projection. `guardian-capture-open`, `guardian-capture-partial`, and
`guardian-capture-complete` first defer the live capture and later SIGSTOP the actual
adopting guardian at the selected-open, partial-copy or fsynced/receipted-copy
boundary. Deterministic source tests remove the original observer and selected
pathname, exercise actual guardian drain, and check recovery while capture is
owned and after resume/death. The tests do not claim native recipient receipt.
