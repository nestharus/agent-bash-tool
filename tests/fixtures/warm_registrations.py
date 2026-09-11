"""Eight real registrations under one private production image owner.

Invoked only inside spooler_cli's user/network namespace boundary. The native
fake helper records its executing image inode, independently of admission timing.
"""
from concurrent.futures import ThreadPoolExecutor
import ctypes
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

import image_custody as f

SCRIPT = str(Path(__file__).resolve())
CONCURRENCY = 8
ADMISSION_BOUND = 8


def workload(root, helper):
    root = Path(root)
    # Discovery probes only private namespace ancestors. The founding supervisor
    # stays alive while this workload launches all nine sibling registrations.
    owner = next(pid for pid in reversed(f.ancestors()) if f.probe(pid))
    assert owner in f.ancestors() and owner != os.getpid()
    held = f.acquire(owner, helper)
    try:
        inode = os.fstat(held).st_ino
        assert inode != os.stat(helper).st_ino, "must execute a cached image, not source"

        def register(index):
            env = os.environ.copy()
            env.update(XDG_STATE_HOME=str(root / f"registration-{index}"),
                       AGENT_BASH_AGENT_RUNNER_BIN=helper,
                       IMAGE_FIXTURE_LOG=str(root / f"helper-{index}.log"))
            return json.loads(f.run(env, "run", "--", "/bin/true"))

        warmup = register("warmup")
        started = time.monotonic()
        with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
            items = list(pool.map(register, range(CONCURRENCY)))
        elapsed = time.monotonic() - started
        assert elapsed < ADMISSION_BOUND, (elapsed, ADMISSION_BOUND)
        # Timing alone cannot satisfy sharing: every actual registration helper
        # must execute the same image independently acquired from the ancestor.
        for index, item in zip(["warmup", *range(CONCURRENCY)], [warmup, *items]):
            lines = (root / f"helper-{index}.log").read_text().splitlines()
            registrations = [line for line in lines if "agent-bash-register" in line]
            assert len(registrations) == 1, (index, lines)
            assert int(registrations[0].split()[0]) == inode, (index, inode, lines)
            meta = f.wait(lambda: f.terminal_delivery(item["meta"]))
            assert meta["delivery"]["exit_code"] == 0, meta
        print(json.dumps(dict(owner=owner, inode=inode, registrations=CONCURRENCY,
                              elapsed=elapsed, bound=ADMISSION_BOUND,
                              helper_bytes=os.stat(helper).st_size)), flush=True)
    finally:
        os.close(held)


def suite():
    assert ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0

    def interrupted(signum, frame):
        raise RuntimeError("private registration fixture interrupted")

    signal.signal(signal.SIGTERM, interrupted)
    try:
        with tempfile.TemporaryDirectory(prefix="warm-") as tmp:
            root = Path(tmp)
            helper = root / "helper"
            subprocess.run(["cc", "-O2", "-Wall", "-Wextra",
                            str(Path(SCRIPT).with_name("image_helper.c")), "-o", str(helper)],
                           check=True, timeout=10)
            env = os.environ.copy()
            env.update(XDG_STATE_HOME=str(root / "founder"),
                       XDG_CONFIG_HOME=str(root / "config"),
                       AGENT_BASH_AGENT_RUNNER_BIN="/bin/true")
            # No production image capacity, epoch or deadline overrides.
            item = json.loads(f.run(env, "run", "--delivery", "sync", "--",
                                    sys.executable, SCRIPT, "workload", f.BIN, str(root), str(helper)))
            meta = f.wait(lambda: (m if (m := f.read_json(item["meta"]))
                                  and m.get("state") in ["DONE", "ERROR"] else None), 35)
            log = Path(item["log"]).read_text()
            assert meta.get("rc") == 0, (meta, log)
            assert '"registrations": 8' in log, log
            print(log, end="")
    finally:
        f.cleanup()


if __name__ == "__main__":
    if sys.argv[1] == "suite":
        suite()
    else:
        workload(sys.argv[3], sys.argv[4])
