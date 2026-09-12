# Opt-in local delivery-attempt diagnostics (AGE-364)

Linux agent-bash can emit lossy observations for its existing `register`,
`activate`, and `complete` helper calls. This adds no runner RPC, storage schema,
activation domain, delivery acceptance rule, or custody protocol.

## Enablement and lifetime

An explicit inherited `AGENT_BASH_DIAGNOSTIC_SOCKET` names an abstract Unix
**datagram** receiver in the same network namespace (1–100 UTF-8 bytes, without a
leading NUL). For example, start the optional foreground collector first:

```sh
python3 tools/collect-attempt-diagnostics.py my-attempts --seconds 60 > observations.json
# In another shell in the same network namespace, for the desired invocation:
AGENT_BASH_DIAGNOSTIC_SOCKET=my-attempts agent-bash run --delivery sync -- /bin/true
```

The collector is the unchanged AGE-353 profiling helper, included for reader
compatibility and test support; this slice does not complete the AGE-353 experiment.
Its output is produced only when collection stops. The operator owns that output's
location, permissions, retention and deletion. No collector is started implicitly.

Each executing helper attempt reads the current agent-bash process environment.
An unset variable bypasses socket setup, randomness, source hashing, clocks and
JSON/evidence construction. Missing/invalid sinks or unavailable randomness disable
that attempt's observations. New control/recovery processes need their own opt-in;
there is no durable enablement or restart replay. No pinned helper environment is
rewritten or broadened. Existing environment capture rules remain unchanged.

The sender opens one nonblocking CLOEXEC socket inside the actual executing worker,
**after** its existing descriptor-close preparation, and drops it after the raw
spawn/wait result. No descriptor is exempted from that preparation. A lost process
may leave only a prefix or no observations. There is no diagnostic custodian,
retained file, retry, sync, stderr fallback or delivery obligation.

## Wire contract and interpretation

The reused envelope is `schema: "owned-attempt-diagnostic-v3"`; the historical
`owned` name is not evidence of an owned-delivery protocol on main. Fields are:

- `attempt_id`: 16 nonblocking random bytes encoded as 32 hex digits; probabilistic
  uniqueness, new for every observed attempt (including retries).
- `source_id`: SHA-256 of `owned-attempt-source-v1\0`, then each of raw Unix
  `StatePaths.root` bytes and UTF-8 handle bytes, each preceded by its unsigned
  64-bit big-endian byte length. No canonicalization; path aliases remain distinct.
- `operation`: only `register`, `activate`, or `complete` on this implementation.
- `phase`, `evidence`: `started` with `{}` immediately before attempting the helper;
  then `wait_returned` with numeric `raw_status` (Unix wait status), `spawn_error`
  or `wait_error` with numeric/null `os_error`. Result phases describe the local
  raw spawn/wait outcome, before logical success conversion or custody cleanup.
- `pid`, `unix_time_us` (nullable wall clock), and `elapsed_us` (local monotonic
  duration from sender creation). These are observations, not ordering authority.

There are at most two send attempts per observed helper call. Fields are fixed
labels, fixed-size hashes/IDs and numeric scalars; no command, environment, path,
handle, error text, helper stdout/stderr, or payload is serialized. The serializer
also rejects datagrams over 4096 bytes. The source hash provides correlation, not
anonymity, payload hashing, recipient identification or authentication. Peers in
the same namespace can forge records; the collector does not authenticate/schema-
validate senders.

A datagram send is atomic: failure drops that whole record, never retries a partial
write. A truncated receiver buffer is not supported evidence. Missing, late,
evicted, duplicate-discarded, restarted or failed emission is **unknown**, not a
negative result. No diagnostic can change the returned helper result, metadata,
retry eligibility or custody cleanup decision. Instrumentation still consumes CPU
and syscalls and can perturb timing; nonblocking does not mean zero overhead.

`wait_returned` is NOT physical tree drain, recipient receipt, remote ACK, durable
settlement or payload acceptance. `started` is not proof of helper admission.
Pre-helper preparation failures and custody-marker admission failures have no event.
Main does not emit cumulative `enqueue`/`progress`/`consume`, `drained`, ECHILD or
remote-ACK events. Those later phases remain pending in AGE-353's residual work.

## Bounds and verification limits

Runtime retains one socket and a small envelope per active instrumented call, with
no on-disk diagnostic storage. Aggregate concurrent overhead is not globally capped.
Source hashing costs scale with root/handle length. The optional collector retains
at most 64 attempts and 12 first phase records per attempt, each <=4096 bytes; its
Python object overhead is additional, and transport loss remains unknown.

`delivery::attempt_diagnostics::tests` covers attribution/retries, disabled evidence
laziness, synthetic local errors, full/closed sinks and a 10,000-attempt debug-build
wall/CPU/FD micro-measurement. The `age364_` spooler test exercises real helper hooks
through pinned private fake helpers, including a later detach process, nonzero
completion, disabled/missing/full/closed sinks, and feeds real emitted bytes into
an independent source-hash calculation and the unchanged collector. Existing
custody, environment and worker tests remain relevant regressions. These bounded
checks do not prove production latency, syscall counts, complete restart history,
native runner receipt, remote settlement, or the larger AGE-353 fanout experiment.
