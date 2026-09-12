#!/usr/bin/env python3
"""Explicit foreground profiling receiver; bounded memory, dump only at stop.
Run in the same network namespace as agent-bash. No daemon or custody ownership.
"""
import argparse
from collections import OrderedDict
import json
import socket
import time


class History:
    """Last 64 observed attempts, at most 12 first phase records of <=4096 bytes.

    FIFO by first observation (not time expiry). Success cannot replace an older
    failure until 64 distinct later attempts are observed. Loss is always unknown.
    """
    def __init__(self):
        self.attempts = OrderedDict()
        self.evicted = 0
        self.discarded = 0

    def add(self, data):
        if len(data) > 4096:
            self.discarded += 1
            return
        try:
            text = data.decode('utf-8')
            value = json.loads(text)
            key, phase = value['attempt_id'], value['phase']
            if not isinstance(key, str) or not isinstance(phase, str):
                raise ValueError('identity')
        except (ValueError, KeyError, TypeError, RecursionError):
            self.discarded += 1
            return
        if key not in self.attempts:
            if len(self.attempts) == 64:
                self.attempts.popitem(last=False)
                self.evicted += 1
            self.attempts[key] = {}
        records = self.attempts[key]
        if phase not in records and len(records) < 12:
            records[phase] = text
        else:
            self.discarded += 1

    def result(self):
        return dict(attempts=self.attempts, evicted=self.evicted,
                    discarded=self.discarded, transport_loss='unknown',
                    authority='none; absent records and process loss are unknown')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('name', help='AGENT_BASH_DIAGNOSTIC_SOCKET abstract name')
    parser.add_argument('--seconds', type=float, default=60)
    args = parser.parse_args()
    if not 0 < args.seconds <= 3600:
        parser.error('seconds must be in (0, 3600]')
    history = History()
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as receiver:
        receiver.bind('\0' + args.name)
        receiver.settimeout(.1)
        end = time.monotonic() + args.seconds
        try:
            while time.monotonic() < end:
                try:
                    history.add(receiver.recv(4097))
                except socket.timeout:
                    pass
        except KeyboardInterrupt:
            pass
    # Receiver has closed: a stalled output destination cannot block producers.
    print(json.dumps(history.result()))


if __name__ == '__main__':
    main()
