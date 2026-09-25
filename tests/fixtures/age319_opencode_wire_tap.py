#!/usr/bin/python3
"""Observe the real Bash response bytes without replacing the Bash producer."""
import json
import os
from pathlib import Path
import subprocess
import sys

gate = Path(os.environ['AGE319_PAIRED_GATE'])
with (gate / 'adapter-bash-calls.jsonl').open('a') as log:
    log.write(json.dumps(sys.argv[1:]) + '\n')
result = subprocess.run([os.environ['AGE319_PAIRED_REAL_BASH'], *sys.argv[1:]],
                        capture_output=True)
(gate / 'bash-causal-output').write_bytes(result.stdout)
sys.stdout.buffer.write(result.stdout)
sys.stderr.buffer.write(result.stderr)
sys.exit(result.returncode)
