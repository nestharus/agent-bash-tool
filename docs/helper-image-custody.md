# Delivery-helper image custody (AGE-357)

## Scope and ownership

Linux agent-bash supervisors start an **image-only child** before launching their
workload, unless a live ancestor already owns an image endpoint. Clients discover
the outermost endpoint from their actual `/proc` ancestry (PID + start time), not
an environment variable or a handle's delivery authority. The abstract Unix
socket namespace includes effective UID, PID and start time; the custodian checks
`SO_PEERCRED` UID and the connecting process's actual founding ancestry. An
unrelated root cannot acquire from that service just by knowing its socket name.
There is no machine service, runner hook, database, persistent daemon or shared
cross-root owner.

Only the founding supervisor owns the custodian. It clean-execs its **own running
agent-bash image** via `/proc/self/exe`, with empty environment, null standard
streams, and one listener descriptor. No registration token, caller heap, spool
lock, log pipe or helper command is retained in that process. The listener is
CLOEXEC in the supervisor and workload; the custodian receives only the intended
fd 3. Parent-death SIGKILL plus a parent-identity recheck closes the startup race.

The supervisor's existing waiter reaps all children. While the custodian remains
an unreaped exact child, Tree completion may establish emptiness when `/proc`'s
**entire direct-child set is exactly that child**. No other process or descendant
is exempt. Normal cancellation skips only that same child so cancellation's
completion delivery can still acquire images. Supervisor teardown kills and reaps
it; supervisor loss kills it through the kernel parent-death signal. Guardian
recovery has no descendant exemption. Independent roots have independent services
and may duplicate images. Root-scope completion deliberately ends this service
when the owning supervisor ends, even if an opaque descendant remains elsewhere.

Acquisitions before the first supervisor exists (initial root registration/owner
lookup), and acquisitions outside any live owning tree (including external
recovery), use bounded **operation-local** sealed images. They do not launch an
unowned custodian or hold private images in idle supervisors. Nested registrations,
activation, completion, detach and in-tree recovery all use the same acquisition
function and hence share content, not request authority. A collection of
independent top-level invocations in an unmanaged runner tree is **not** deduped
across those roots by this change. Only the outer owning custodian retains images;
nested idle supervisors do not retain private full-image copies.

## Publication and integrity

A single-threaded, one-request-at-a-time custodian serializes cold publication.
The key is protocol v1 + exact length + raw SHA-256. A miss checks retained plus
new byte/count budgets **before** allocating, copies/hashes a bounded source,
rejects changed length or digest, and adds WRITE, GROW, SHRINK and SEAL seals.
Cold misses retire least-recently-used store references until the new image fits.
Retirement never signals a workload or invalidates an already handed-out FD/mapping.
Script and native interpreter acquisitions use the same store, and held script
images survive interpreter admission even when that admission retires their store
entry. An image larger than the byte budget still fails closed.

Cold allocation attempts have a token bucket: an initial burst equal to the count
budget, refilling one token per second up to that count. Attempts consume tokens
even if materialization fails. With no token the server replies with explicit
image-only backpressure (`B1`, no FD), leaving its store unchanged. Warm requests
need no token. The client retries this response within its original acquisition
deadline against the same endpoint. No helper has been admitted by an image RPC.

The receiver requires one complete packet and one FD; truncated/extra/malformed
ancillary data is rejected and all received descriptors are closed. It checks
regular-file type, executable mode, length, all four seals and the image's raw
digest itself, then opens an independent read-only `/proc/self/fd` alias and
checks device/inode identity. Neither the endpoint nor the sender's assertion is
an attestation. Seals do not freeze executable mode: subsequent execution errors
retain the existing truthful delivery classification.

All internal image inspection, hashing and copying uses positional reads with
short-read/EINTR/EOF handling. Shared SCM_RIGHTS offsets do not control these
reads; independent aliases also isolate opaque consumers. Shebang parsing uses
the selected sealed image, not another mutable source-path read. Cache validation
hashes disk bytes without constructing a throwaway executable image.

Per-handle path, metadata, environment digest and content checks remain required
on **every** load, including hits. Bound content is checked before acquisition so
a changed snapshot retains `delivery_helper_changed` even when the store is full;
it is checked again during acquisition to reject intervening mutation. Delivery
requests, environments, one-use registration authority, execution admission,
transfer-worker ownership, and unknown/nonreplayable notification outcomes are
unchanged. A failed image RPC does not authorize replay of an admitted helper.

## Conservative configurable limits

All values are environment settings, validated fail-closed rather than silently
clamped. Defaults are engineering starting limits, **not** a measured production
SLO or a large-fanout capacity result.

| Setting | Default | Accepted range | Meaning |
|---|---:|---:|---|
| `AGENT_BASH_IMAGE_BYTES` | 268435456 (256 MiB) | 1..1073741824 | Retained store bytes plus in-progress cold allocation; maximum source size for operation-local loads |
| `AGENT_BASH_IMAGE_COUNT` | 8 | 1..64 | Distinct retained images, including interpreters; cold-attempt burst size |
| `AGENT_BASH_IMAGE_DEADLINE_MS` | 10000 | 1..60000 | Client acquisition and each accepted server request deadline |

256 MiB accommodates one observed ~128 MiB debug image plus an interpreter, or
several observed ~32 MiB release images, without promising capacity for every
version combination. LRU retirement permits legitimate version turnover without
permanently excluding new content. Rate-limited attempts may still exhaust a
client deadline; there is no implicit fallback or unlimited acquisition retry.
Zero-length executable sources
still consume the count budget. A 64 KiB streaming buffer bounds copy workspace.
Socket listen backlog is 16; send/receive buffers request 4096 bytes (Linux may
adjust/double them), one client is processed at a time, and request/response
payloads are at most 512 bytes with bounded ancillary reception. Queue-full
nonblocking connections retry every 20 ms under the same acquisition deadline,
including the nested-owner presence probe after registration. This is bounded
client backpressure, not an unbounded server queue or a helper-command retry.

### Lifetime and bounded recovery

Normal lifetime follows the actual owning supervisor, with **no maximum session
age**. The former `AGENT_BASH_IMAGE_EPOCH_MS` setting is removed and has no effect.
Idle/request deadline expiry does not retire the store. A live epoch means one
custodian's retained store, not a time allowance. Byte/count pressure retires LRU
store references without restarting a healthy custodian or killing image holders.

The founding supervisor alone restarts a dead custodian, and only after its exact
previous child has been reaped. It retains the same bound listener and finite
queue through recovery; clients cannot elect competing owners or fall back to
private resealing while this tree is alive. Each new child uses the same clean
exec, exact running binary, pinned limits and parent-death custody as startup.
The existing supervisor event loop drives recovery; there is no new host service,
background thread or runner responsibility. Shutdown kills/reaps the current child
and drops the listener; recovery does not keep a completed tree alive.

Recovery waits 1 second after the first observed death, doubling subsequent
short-lived-crash backoff to a 30-second cap. At least 60 seconds of child uptime
resets the next death's backoff to 1 second. Spawn failures also consume a
rate-limited attempt and are logged best-effort in the bounded workload log. There
is at most one spawn attempt per backoff interval, never a permanent crash-count
poison state. Actual launch may be later due to event-loop scheduling/blocking.
Recovery does not kill a healthy child on any timer. Each replacement starts
empty and allocates only for acquisitions, within the same per-live-epoch budgets.

A client retries queue pressure and explicit cold-creation backpressure under its
original deadline. Recovery grants **no helper-command replay**, and interrupted
accepted RPCs are not retried. Connections still queued in the retained listener can be
accepted by the replacement. Connections accepted by the dead child fail; callers
may also time out before recovery, particularly at higher backoff. These are real
acquisition failures, not successful delivery or notification retry authority.
Later independent acquisitions can succeed once recovery runs. Existing admitted
helpers keep their original execution/outcome semantics even across service loss.

Deadlines are checked between positional reads and in socket polling, not a claim
that Linux can preempt a stuck regular-file/FUSE/kernel syscall. Provenance
validation, selected-image acquisition and interpreter loading are separately
bounded stages, so the setting is not an end-to-end delivery SLA. Hash-only hits
still read the image, and bound loads additionally hash the handle snapshot;
this correction removes full-image allocation/write amplification, not hashing
CPU or disk read amplification. Operation-local script loads may hold both helper
and interpreter (up to twice the source limit) until the request ends; they have
no retained custodian epoch.

## What this does not bound or prove

Per-epoch byte limits do **not** bound host-wide shmem across independent roots,
retired epochs, crashes or opaque descendants. An executable mapping and a wake
that reopens `/proc/self/exe` can outlive every original FD or custodian. Automatic
recovery can create another inode for the same digest while the old mapping lives.
Backoff limits replacement frequency; cold-attempt tokens limit creation within
each store, and per-store budgets bound retained plus in-progress allocations.
Retirement as well as crashes can leave old client mappings alive. Neither these
limits nor LRU bound cumulative surviving mappings across an unlimited session. There is no lease ledger, durable cross-crash
accounting or universal freed-image claim. There is also no correction here to
the runner's detached wake custody.

The deterministic tests use tiny native images, two concurrent clients, private
process trees, and explicit fixture cleanup. They cover sharing, clean bootstrap,
per-handle routing/authority, malformed requests, positional I/O, sealing failures,
capacity, repeated recovery/self-exec retention, no admitted-command replay,
independent-root cancellation during recovery backoff and founding
supervisor/guardian loss. They are **not** the retained 420-producer
failure rerun, the 10,100-producer AGE-353 goal, a real runner wake test, or evidence
that the historical EBUSY page-reference holder has been identified.

## Founding-owner completion continuity

Completion publication in the live supervisor leaves delivery pending. Its event
loop tries the delivery lock without waiting, then launches one active transfer
worker that acquires the images, writes the admission claim, executes the helper
and persists its result. The supervisor retains the inherited lock until its
existing wildcard reaper observes that exact worker and integrates the result.
There is no recovery thread, second reaper, or idle monitor per image generation.
The worker closes inherited descriptors other than stdio and its delivery lock;
it does not keep the founding listener alive after supervisor loss.

Both ready and normal-exit publication use this boundary. Pending delivery keeps
the supervisor alive even for Root completion scope. A root exit observed during
a ready transfer is retained in memory and merged into current metadata once the
lock is available, rather than blocking recovery or overwriting the worker's
result. Accepted cancellation drains the workload tree before starting its own
completion transfer; that new notification is not cancelled again. Owner exit
can cancel an already active ready transfer, preserving non-replayable uncertainty
when the worker dies without a conclusive handback. Such an unknown outcome closes
replay but retains adopted-tree custody even in Root scope: otherwise a surviving
helper could be orphaned. Unrelated surviving Root-scope descendants can therefore
also prolong supervision after worker loss. The existing guardian adopts
and reaps remaining children after abnormal supervisor loss, even when delivery
metadata becomes terminal before the worker exits.

The retained correction-2 fixture establishes the old three failures. The same
stimuli now pass with tiny images: founding exit/ready acquisition during recovery,
and descendant acquisition while the founding helper remains admitted and held.
Additional private tests cover root-status integration, pending Root-scope delivery,
cancellation, worker/supervisor loss, exact invocation counts and lock/reap cleanup.
This is **not** a rerun of the 420-case outage, proof of uninterrupted acquisition,
or a large-image/multi-day throughput result. Request deadlines and recovery
backoff remain; interrupted accepted image RPCs still fail without helper replay.

Session-bound control lookup now propagates inability to determine eligibility
(`EX_IOERR`, preserving the image-service error), rather than reporting that the
caller was proven ineligible (`EX_NOPERM`). Neither outcome authorizes mutation.
Status with `--observe-only` remains available without an eligibility lookup;
ordinary status/mode no longer silently turn lookup errors into observational
success. A successfully attested mismatching session still gets no control rights.

### External transfer uncertainty and retained state

External status/retry completion and detach activation do not inherit the founding
reapers' adoption. Their synchronous transfer workers now publish a separate
`external-transfer-custody` boot marker before spawning the helper. Confirmed
non-admission or a raw helper wait result clears only the creating attempt's marker;
a wait error or worker loss leaves it. Activation distinguishes nonzero helper exit
from wait uncertainty before both become logical errors. Successor reconciliation
may close replay but cannot remove the marker. A later successful transfer cannot
discharge older external uncertainty, and founding-tree discharge is independent.

Startup cleanup retains current-boot or unreadable/malformed evidence despite
expired logical timestamps. Normal ended controls remain eligible for eventual
ordinary cleanup after their own marker is removed; a different valid boot removes
the marker veto without bypassing other retention checks. This is a conservative
retention measure, not another custody topology or arbitrary orphan attribution.
It does not prove that waiting for a helper inventories all descendants it may create.

Founding custody also has an accepted loss case: the guardian can die and the
supervisor can **exit normally under Root semantics with descendants remaining**.
When those descendants later end under an outer reaper, nobody discharges this
handle's marker. This does not require simultaneous abnormal loss of both reapers.
External worker-loss evidence similarly remains after the helper actually ends
without a production discharge witness. No timer or known-dead supervisor guess
clears either uncertainty. Retained storage on a long-lived boot is an accepted cost
pending separately authorized recovery, not globally bounded retention.

The private external fixture exercises admitted completion and activation worker
loss, caller-plus-worker loss followed by successor reconciliation, aged startup
scans while the helper survives, and retention after harness-observed helper exit.
Normal zero and nonzero exits provide finite-cleanup controls for each operation.
These are bounded tiny-process experiments, not production mailbox/wake evidence,
arbitrary descendant tracking, large-fanout tests or a multiday soak.
