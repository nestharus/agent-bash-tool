"""Goal C consumer-view controls using the existing real-CLI/stand-in-owner fixture.

OpenCode 1.18.30's generic truncator passes strings through only when both
51200 rendered UTF-8 bytes and 2000 split lines fit. These controls assert that
boundary and stream-byte conservation, not the adapter's chosen prefix size.
They are offline controls, not native model/runtime witnesses. The existing
controls in test_opencode_root_v1.py reconcile producer and inline-view facts;
the shared real-CLI/stand-in-owner fixture remains unchanged.
"""
import base64
import re
import unittest

from test_opencode_root_v1 import (
    ACCEPTED, STARTED, CLOSED, END, AGENT_BASH, BUN,
)

import test_opencode_root_v1 as fixture


@unittest.skipUnless(BUN and AGENT_BASH, 'requires BUN and AGENT_BASH_TEST_BIN')
class RootV1Presentation(unittest.TestCase):
    call = fixture.RootV1Adapter.call

    def events(self, payload, end=True):
        return [ACCEPTED, STARTED,
                {'event': 'output', 'b64': base64.b64encode(payload).decode()}] + (
            [dict(CLOSED, bytes=len(payload)),
             dict(END, status='code:7', output={'state': 'closed', 'bytes': len(payload)})]
            if end else [])

    def view(self, result):
        self.assertLessEqual(len(result.encode()), 51200, 'fits default rendered-byte boundary')
        self.assertLessEqual(len(result.split('\n')), 2000, 'fits default whole-line boundary')
        self.assertNotIn('Full output saved', result)
        self.assertNotIn('tool call succeeded', result)
        header, body = result.split('---\n', 1)
        return header, body

    def losses(self, result, payload, mode):
        header, body = self.view(result)
        actual = body.encode() if mode == 'utf8' else bytes.fromhex(body)
        self.assertGreater(len(actual), 0, 'payload is inline, not whole-line collapsed')
        self.assertEqual(actual, payload[:len(actual)], 'literal stream prefix, no substitution')
        producer = re.search(r'(\d+) received stream bytes; (\d+) stream bytes carried; '
                             r'(\d+) bytes omitted and discarded \(not retained\)', header)
        consumer = re.search(r'first (\d+) of (\d+) producer-carried stream bytes shown inline; '
                             r'(\d+) additional stream bytes omitted here \(not retained for recovery\); '
                             r'(\d+) rendered UTF-8 bytes', header)
        self.assertIsNotNone(producer, 'producer layer and stream-byte unit identified')
        self.assertIsNotNone(consumer, 'consumer layer, stream and rendered units identified')
        received, carried, discarded = map(int, producer.groups())
        shown, consumer_carried, additional, rendered = map(int, consumer.groups())
        self.assertEqual(received, len(payload))
        self.assertEqual(carried, consumer_carried)
        self.assertEqual(received, carried + discarded)
        self.assertEqual(carried, shown + additional)
        self.assertEqual(shown, len(actual), 'shown describes actual consumer body')
        self.assertEqual(rendered, len(body.encode()), 'hex expansion has its own unit')
        self.assertIn(f'{shown} bytes shown inline, {mode})', header)
        self.assertGreater(additional, 0)
        return carried, discarded

    def test_long_line_and_newline_heavy_prefixes_survive_both_default_limits(self):
        for payload in [b'nonce\n' + b'A' * 100000, b'a\n' * 50000]:
            with self.subTest(shape=payload[:8]):
                result = self.call(self.events(payload), {'command': 'fixture'})[0]['result']
                carried, discarded = self.losses(result, payload, 'utf8')
                self.assertEqual(carried, 65536, 'producer prefix is still 64 KiB')
                self.assertEqual(discarded, len(payload) - 65536)
                self.assertIn('exited with code 7 (code:7, observer work-pid1-wait)', result)
                self.assertIn('full stream counted, closed, matched by the end', result)

    def test_hex_and_utf8_units_and_character_boundaries(self):
        for payload, mode in [(b'\x00\xff' * 50000, 'hex'),
                              (b'x' + '€'.encode() * 33000, 'utf8')]:
            with self.subTest(mode=mode):
                result = self.call(self.events(payload), {'command': 'fixture'})[0]['result']
                self.losses(result, payload, mode)
                if mode == 'utf8':
                    self.assertNotIn('\ufffd', result)

    def test_consumer_only_loss_does_not_claim_complete_output(self):
        payload = b'x' * 60000
        result = self.call(self.events(payload), {'command': 'fixture'})[0]['result']
        carried, discarded = self.losses(result, payload, 'utf8')
        self.assertEqual((carried, discarded), (len(payload), 0))
        self.assertIn('output partial', result)
        self.assertNotIn('output complete', result)

    def test_unknown_and_unproven_do_not_gain_output_or_wait_proof(self):
        payload = b'x' * 100000
        unknown = self.call(self.events(payload, end=False), {'command': 'fixture'})[0]['result']
        # Unknown adds an explicit suffix outside the payload; keep it in the
        # overall boundary check and remove it only for stream-byte comparison.
        self.view(unknown)
        self.losses(unknown.removesuffix('\n(output above is partial and unproven)'), payload, 'utf8')
        self.assertIn('outcome unknown', unknown)
        self.assertIn('Do not replay', unknown)
        self.assertNotIn('exited with code', unknown)
        self.assertNotIn('full stream counted', unknown)
        events = self.events(payload)
        events[-2] = dict(CLOSED, bytes=1)
        unproven = self.call(events, {'command': 'fixture'})[0]['result']
        self.losses(unproven, payload, 'utf8')
        self.assertIn('exited with code 7', unproven)
        self.assertIn('output delivery unproven', unproven)
        self.assertIn('output-byte-count-mismatch', unproven)
        self.assertNotIn('full stream counted', unproven)
        self.assertNotIn('output complete', unproven)

    def test_large_then_small_and_empty_keep_literal_payload_in_one_call(self):
        payloads = {'large': b'x' * 100000, 'small': b'next\n', 'empty': b''}

        def replies(request):
            return self.events(payloads[request['argv'][-1]])

        response, requests = self.call(replies, [{'command': name} for name in payloads])
        self.losses(response['results'][0], payloads['large'], 'utf8')
        for result, payload in zip(response['results'][1:], ['next\n', '']):
            header, body = self.view(result)
            self.assertEqual(body, payload)
            self.assertIn('output complete', header)
            self.assertNotIn('omitted', header)
            self.assertIn('exited with code 7', header)
        self.assertEqual([r['argv'] for r in requests],
                         [['bash', '-lc', name] for name in payloads])


if __name__ == '__main__':
    unittest.main()
