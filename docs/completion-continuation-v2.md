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

`tests/fixtures/age360/paired-wire.json` imports runner revision 2 byte-for-byte:
SHA256 `f31a19425bdafb0c4609b517060b9b24569ca1a72fdac5a9840a6da7e8c39022`.
Source tests use native Bash processes in private user/network namespaces with an
explicitly simulated runner. They are not native State admission, mailbox ACK,
independent runner ownership, migration or provider-reliability evidence. Root owns
runner's `age360_completion_continuation` paired target and final delivery.

Consequential pairing edges remain visible: ready-mode exit **before** a sentinel
needs an agreed valid actual-exit representation (not unknown status); full JSON
notification bodies exceeding the wire's 16 MiB bound need a paired rendering
policy distinct from full local output retention. Unsupported source publication
retains evidence rather than silently changing the protocol. AGE365 owns production
lineage/migration/install authority.
