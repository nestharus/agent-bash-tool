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
Published entries are never evicted within the epoch. Script and native
interpreter acquisitions use the same store; capacity failure is immediate, not
a wait while indefinitely holding the first half of a script pair.

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
| `AGENT_BASH_IMAGE_BYTES` | 268435456 (256 MiB) | 1..1073741824 | Aggregate newly published bytes per owning epoch; maximum source size for operation-local loads |
| `AGENT_BASH_IMAGE_COUNT` | 8 | 1..64 | Distinct retained images per epoch, including interpreters |
| `AGENT_BASH_IMAGE_DEADLINE_MS` | 10000 | 1..60000 | Client acquisition and each accepted server request deadline |
| `AGENT_BASH_IMAGE_EPOCH_MS` | 86400000 (24 h) | 1..86400000 | Nonrenewable maximum server epoch lifetime |

256 MiB accommodates one observed ~128 MiB debug image plus an interpreter, or
several observed ~32 MiB release images, without promising capacity for every
version combination. One version at capacity rejects another: there is no LRU,
implicit fallback or unlimited resealing retry. Zero-length executable sources
still consume the count budget. A 64 KiB streaming buffer bounds copy workspace.
Socket listen backlog is 16; send/receive buffers request 4096 bytes (Linux may
adjust/double them), one client is processed at a time, and request/response
payloads are at most 512 bytes with bounded ancillary reception. Queue-full
nonblocking connect rejects immediately instead of opening an unbounded queue.

The server retires on epoch timeout. **No automatic restart in the same owner is
implemented.** Its supervisor keeps the namespace bound until teardown, including
after a crash, so a missing server cannot silently trigger unlimited private
reconstruction. New acquisitions then time out or reject at the queue bound; an
already admitted helper retains its original outcome uncertainty. A new managed
root can establish a new epoch. Long-lived server workloads therefore need an
explicit availability decision before using a 24-hour service lifetime; increasing
past 24 hours is not accepted by this implementation.

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
that reopens `/proc/self/exe` can outlive every original FD or custodian. Explicit
restart can create another inode for the same digest while the old mapping lives.
There is no lease ledger, durable cross-crash accounting or universal freed-image
claim. There is also no correction here to the runner's detached wake custody.

The deterministic tests use tiny native images, two concurrent clients, private
process trees, and explicit fixture cleanup. They cover sharing, clean bootstrap,
per-handle routing/authority, malformed requests, positional I/O, sealing failures,
capacity, retirement/self-exec retention, independent-root cancellation and
founding supervisor/guardian loss. They are **not** the retained 420-producer
failure rerun, the 10,100-producer AGE-353 goal, a real runner wake test, or evidence
that the historical EBUSY page-reference holder has been identified.
