# Paired root original-work v1

Agent-bash and agent-runner form one optional, explicitly versioned process
boundary. Current paired trees inherit `OULIPOLY_ORIGINAL_WORK_REQUIRED_V1=1`,
`OULIPOLY_COMPLETION_ENDPOINT`, and a valid `OULIPOLY_ROOT_AUTHORITY_V1`
(`root-authority-v1`) grant. In a marked tree, a missing or invalid endpoint or
grant fails closed and is recorded as terminal evidence; it never silently
falls back. With no marker and no grant, a genuine standalone caller keeps the
existing spooler behavior. An endpoint-only legacy
completion-continuation-v2 caller also remains standalone, while a grant with
no endpoint is always rejected as malformed paired context.
Before standalone selection with a missing grant, agent-bash checks its live
same-UID ancestor chain for the exact paired-worker image and internal argument.
A descendant whose wrapper removed its marker and grant is rejected while that
worker remains an ancestor, including when the endpoint survives. Before admitting a missing-grant caller as standalone, agent-bash also
queries its inherited Linux session keyring. A same-UID ring named
`oulipoly-paired-original-work-v1:` plus a canonical random v4 UUID rejects
standalone even after the paired worker has exited, the process has execed or
called setsid, and its descendants have reparented. The ring is a negative
standalone-admission signal only, not authority to submit paired work. An
invalid marker or ambiguous/unsupported kernel query fails preaccept rather
than proving independence; an unrelated/default readable ring permits genuine
independent entry. The runner must establish this uniquely named inheritable
ring before launching each provider child; absent that paired prerequisite,
this selector cannot protect a descendant after all other context disappears.

## Submit boundary

`run` still creates the normal private handle directory, pins its delivery
helper, and writes initial metadata. It then atomically writes
`root-work-intent-v1.json` before contacting the root. The request carries
pinned descriptors for the running agent-bash executable, the intent file, cwd,
and handle directory. Root and nested registration are mutually exclusive
tagged forms; nested registration names the exact active parent work id inherited
through `OULIPOLY_ROOT_WORK_ID` and supplies its private
`OULIPOLY_ROOT_PARENT_CAPABILITY_V1`.

The runner validates the capability, protocol, process ancestry and descriptors,
then exclusively creates `root-work-accepted-v1.json`. A lost response is
`acceptance_outcome_unknown`; it is never resubmitted. A duplicate can report
the already accepted exact identity but cannot launch it again.

## Root-owned worker

After acceptance, the runner execs the pinned agent-bash image as an internal
worker. It does not daemonize or open an endpoint and cannot accept or replay
work. It reconstructs the pinned completion registration, sends prepared phase
`P`, and waits without a deadline. Only runner `G` authorizes the workload
fork. `C`, `O`, `K`, or `F` before `G` records terminal cancellation with no workload
dispatch. The already admitted completion-v2 source is selected and published
before the worker reports terminality to the root; failed persistence keeps the
worker and root result pending with bounded retry cadence. After grant, the existing event loop retains output, subreaper,
completion-continuation, and cancellation behavior.

The root retains the submit reply until `P`, so `run` keeps the existing
guarantee that a successful dispatch response follows admitted completion
registration. Exclusive durable acceptance happens earlier; loss of the caller
during registration therefore remains root-owned and never authorizes replay.

Each accepted worker receives a separate 256-bit child capability over a
CLOEXEC descriptor. Agent-bash removes any inherited parent capability before
registration and exposes the new one to the workload only after `G`. A nested
request therefore proves both exact descendant process ancestry and its exact
causal parent; possession of the root-wide grant or another work id is not
sufficient.

When local terminal publication is possible, the worker sends `R`. Runner sends
settlement `S` only after every causal nested child has a terminal outcome. The
worker then performs its normal publication and sends `T`. `T` is not a mailbox
or listener ACK. The worker stays alive until its physical workload tree and
completion helper duties are drained; runner owns and reaps that exact worker
session.

Cancellation names the exact root, work, per-work cancel capability, and
requesting process incarnation, and is first persisted by runner as
`root-work-cancel-v1.json` with its actual principal and cause. Receipt failure
leaves cancellation pending with no process effect; runner retries that exact
obligation with bounded per-operation backoff. Explicit, owner-exit, and
causal-parent cancellation share the same durable path but cannot be relabeled
as one another. If the worker control channel is lost, runner signals and
drains the exact session. If runner is lost, control EOF makes the worker
cancel and drain as last custodian.
For current completion-v2 cancellation sources, causal-parent cancellation is
bound to the exact durable `root-work-cancel-v1.json` receipt. Root authority
loss is bound to the accepted work and the paired worker's original observed
loss event; a dead guardian cannot create a later root-side receipt. Both keep
their distinct completion reason and use the existing cancelled source kind.

Runner writes `root-work-result-v1.json` only after exact worker wait and empty
session evidence and binds it to a private per-operation result nonce, so a
conflicting pre-existing result is not accepted as success. Agent-bash writes
`root-work-diagnostic-v1.jsonl` for intent,
transport, peer, ambiguous-response, response, and cancellation phases. The
JSONL is serialized by `root-work-diagnostic-v1.lock`, rotates once to
`root-work-diagnostic-v1.jsonl.1` at 1 MiB, and bounds individual records at
128 KiB. An accepted paired handle is not eligible for normal terminal reaping
until agent-bash validates the accepted intent, completion snapshot, and
terminal outcome and writes their immutable digest binding in the separate
`source-retention-release-v1.json` record. This leaves every
completion-continuation-v2 schema and semantic unchanged. After release, the
existing TTL, delivery, and process-custody gates apply. An accepted root handle
also remains retained until its exact private `root-work-result-v1.json` is
available. Source release, private root result, parent-child retention, TTL,
delivery and process custody are separate gates. A child remains retained while
its exact parent handle directory exists. No new global scan or database table exists.

The old AGE-319 notification tables/commands and recovery owner are not part of
this protocol.
