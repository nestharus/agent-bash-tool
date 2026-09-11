# Private process tests

Run the normal parallel signals independently (build concurrency is not libtest
concurrency):

```sh
mkdir -p /tmp/abt
TMPDIR=/tmp/abt timeout --kill-after=10s 600s cargo test --locked -j2 --bin agent-bash
TMPDIR=/tmp/abt timeout --kill-after=10s 1200s cargo test --locked -j2 --test spooler_cli
TMPDIR=/tmp/abt timeout --kill-after=10s 600s cargo test --locked -j2 --test image_custody
```

The ordinary spooler cases re-execute the exact test in a fresh Linux user/network
namespace. This requires `unshare` with `--map-current-user`, unprivileged user and
network namespace support, and `timeout`. Missing capability is a test failure,
not a skip or permission to use a host ancestor service. `--nocapture` retains
per-case parent/child network-namespace evidence. The test-only harness supplies
empty private homes and a minimal environment; explicit test settings still apply.
The adapter runtime (`BUN`, or `bun` resolved from the caller PATH) is passed as
an executable path rather than inheriting the caller PATH or home.
The outer libtest workers remain normally parallel, not globally serialized.

Image service discovery uses real process ancestry and abstract AF_UNIX sockets.
Private state directories, removed runner identities, and environment variables
alone cannot isolate it. A network namespace separates those sockets even from
live ancestors without changing production discovery, service budgets or deadlines.
The process trees *inside* each fixture still use production ancestry checks,
service creation, sharing and recovery. Each image-custody scenario gets one such
boundary, keeping its deliberate concurrent shared-service clients together.
The eight-registration warm-cache case launches its client workload beneath a
private production supervisor, so warmup and all eight concurrent registrations
have a common live ancestor image owner. Its tiny compiled native fake helper
(`cc` required) logs its executing image inode. Each registration must match the
independently acquired and retained ancestor-store image, not merely finish within
the unchanged eight-second admission bound. Per-registration state roots remain
separate; production image capacity and deadlines are not overridden.
This is not coverage of host networking or delegated cgroups; cgroup tests retain
their existing unavailable-delegation behavior.

The unit test that acquires a helper image and the fork-using guardian scenario
also re-execute privately. The reaper lock test runs alone in a fresh process so
unrelated test forks cannot inherit its descriptor. It deliberately forks one
acknowledged owner: parent close must retain the state while the child holds the
flock, then child close and exact reap must permit deletion. There is no production
`LOCK_UN` workaround. This exercises a possible interference mechanism without
identifying any historical failed run's exact lock holder.

The two guardian cancellation/delivery waits and the list/status delivery checks
include bounded failure metadata, separating cancellation/drain evidence from
helper admission, retry and delivery failure. A passing isolated run does not
retroactively turn an earlier shared-ancestor or serial run into parallel success.
