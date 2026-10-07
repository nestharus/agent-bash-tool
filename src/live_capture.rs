//! Optional ephemeral capture of supervised stdout/stderr bytes.
//!
//! This is a producer-side copy for a later live viewer, not custody. The
//! retained output log, drainage, terminalization and completion never consult
//! it, and recording cannot fail or block: overflow evicts the oldest records and
//! leaves an exact gap. Nothing here is persisted, published or authorized.
//! Without a consumer the supervisor holds no capture at all.
//!
//! No consumer exists in the default build yet; only tests and the explicit
//! fixture build construct or read a capture.
#![cfg_attr(not(any(test, feature = "source-fault-tests")), allow(dead_code))]
use std::collections::VecDeque;

/// Fixed charge per retained record, so a flood of tiny chunks is bounded by the
/// same budget as payload. This is accounting, not a process memory ceiling.
pub(crate) const RECORD_CHARGE: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Channel {
    Stdout,
    Stderr,
}

/// Stream position: next record sequence and per-channel byte offsets. A caller
/// keeps its own position; positions from another capture have no meaning here.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Position {
    pub(crate) seq: u64,
    pub(crate) stdout_bytes: u64,
    pub(crate) stderr_bytes: u64,
}

impl Position {
    fn advance(self, channel: Channel, len: usize) -> Self {
        let len = len as u64;
        match channel {
            Channel::Stdout => Self {
                seq: self.seq + 1,
                stdout_bytes: self.stdout_bytes + len,
                ..self
            },
            Channel::Stderr => Self {
                seq: self.seq + 1,
                stderr_bytes: self.stderr_bytes + len,
                ..self
            },
        }
    }
}

/// One drained chunk in host observation order. Cross-channel order is only the
/// order in which the supervisor read the two pipes.
#[derive(Debug)]
pub(crate) struct Record {
    pub(crate) start: Position,
    pub(crate) channel: Channel,
    pub(crate) bytes: Vec<u8>,
}

/// Records evicted or never retained between two positions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Gap {
    pub(crate) from: Position,
    pub(crate) to: Position,
}

pub(crate) struct Read<'a> {
    pub(crate) gap: Option<Gap>,
    pub(crate) records: Vec<&'a Record>,
    pub(crate) next: Position,
}

pub(crate) struct LiveCapture {
    budget: usize,
    charged: usize,
    records: VecDeque<Record>,
    next: Position,
}

impl LiveCapture {
    pub(crate) fn new(budget: usize) -> Self {
        Self {
            budget,
            charged: 0,
            records: VecDeque::new(),
            next: Position::default(),
        }
    }

    /// Infallible and I/O-free by construction; the drain path cannot observe a
    /// capture failure because there is none to observe.
    pub(crate) fn record(&mut self, channel: Channel, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let start = self.next;
        self.next = start.advance(channel, bytes.len());
        let charge = bytes.len() + RECORD_CHARGE;
        if charge > self.budget {
            // Retained records must stay a contiguous suffix, so an unfittable
            // chunk ends everything before it as well as itself.
            self.records.clear();
            self.charged = 0;
            return;
        }
        while self.charged + charge > self.budget {
            let evicted = self.records.pop_front().expect("charged records");
            self.charged -= evicted.bytes.len() + RECORD_CHARGE;
        }
        self.charged += charge;
        self.records.push_back(Record {
            start,
            channel,
            bytes: bytes.to_vec(),
        });
    }

    pub(crate) fn charged(&self) -> usize {
        self.charged
    }

    /// Position of the oldest retained record, or `next` when none is retained.
    pub(crate) fn first(&self) -> Position {
        self.records
            .front()
            .map_or(self.next, |record| record.start)
    }

    /// Everything retained at or after `cursor`, with the exact gap when records
    /// at the cursor were already evicted. `None` means the cursor is not one
    /// this capture has reached.
    pub(crate) fn read_from(&self, cursor: Position) -> Option<Read<'_>> {
        if cursor.seq > self.next.seq {
            return None;
        }
        let first = self.first();
        let gap = (cursor.seq < first.seq).then_some(Gap {
            from: cursor,
            to: first,
        });
        let records = self
            .records
            .iter()
            .filter(|record| record.start.seq >= cursor.seq)
            .collect();
        Some(Read {
            gap,
            records,
            next: self.next,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn concat(read: &Read<'_>, channel: Channel) -> Vec<u8> {
        read.records
            .iter()
            .filter(|record| record.channel == channel)
            .flat_map(|record| record.bytes.iter().copied())
            .collect()
    }

    #[test]
    fn retained_suffix_plus_gap_accounts_for_every_byte_on_both_channels() {
        let budget = 3 * (100 + RECORD_CHARGE);
        let mut capture = LiveCapture::new(budget);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        for i in 0..40_u8 {
            let chunk: Vec<u8> = (0..100).map(|j| i.wrapping_mul(31) ^ j).collect();
            let channel = if i % 3 == 0 {
                Channel::Stderr
            } else {
                Channel::Stdout
            };
            match channel {
                Channel::Stdout => stdout.extend_from_slice(&chunk),
                Channel::Stderr => stderr.extend_from_slice(&chunk),
            }
            capture.record(channel, &chunk);
            assert!(capture.charged() <= budget);
        }
        let read = capture.read_from(Position::default()).unwrap();
        let gap = read.gap.expect("overflow leaves a gap");
        assert_eq!(gap.from, Position::default());
        assert_eq!(read.records.len(), 3);
        assert_eq!(gap.to.seq + read.records.len() as u64, read.next.seq);
        assert_eq!(read.next.seq, 40);
        let lost_out = (gap.to.stdout_bytes - gap.from.stdout_bytes) as usize;
        let lost_err = (gap.to.stderr_bytes - gap.from.stderr_bytes) as usize;
        assert_eq!(concat(&read, Channel::Stdout), stdout[lost_out..]);
        assert_eq!(concat(&read, Channel::Stderr), stderr[lost_err..]);
        assert_eq!(read.next.stdout_bytes, stdout.len() as u64);
        assert_eq!(read.next.stderr_bytes, stderr.len() as u64);
    }

    #[test]
    fn cursor_inside_retained_suffix_has_no_gap_and_future_cursor_is_unknown() {
        let mut capture = LiveCapture::new(1 << 20);
        capture.record(Channel::Stdout, b"\x00\xff");
        capture.record(Channel::Stderr, b"\x80");
        capture.record(Channel::Stdout, b"");
        let all = capture.read_from(Position::default()).unwrap();
        assert!(all.gap.is_none());
        assert_eq!(all.records.len(), 2);
        let resumed = capture.read_from(all.records[1].start).unwrap();
        assert!(resumed.gap.is_none());
        assert_eq!(resumed.records.len(), 1);
        assert_eq!(resumed.records[0].bytes, b"\x80");
        let at_end = capture.read_from(all.next).unwrap();
        assert!(at_end.records.is_empty() && at_end.gap.is_none());
        let future = Position {
            seq: all.next.seq + 1,
            ..all.next
        };
        assert!(capture.read_from(future).is_none());
    }

    #[test]
    fn unfittable_chunk_is_counted_and_keeps_retained_records_contiguous() {
        let mut capture = LiveCapture::new(RECORD_CHARGE + 8);
        capture.record(Channel::Stdout, b"abcd");
        capture.record(Channel::Stderr, &[7; 9]);
        assert_eq!(capture.charged(), 0);
        let read = capture.read_from(Position::default()).unwrap();
        assert!(read.records.is_empty());
        assert_eq!(read.gap.unwrap().to, read.next);
        assert_eq!(read.next.stdout_bytes, 4);
        assert_eq!(read.next.stderr_bytes, 9);
        capture.record(Channel::Stdout, b"ef");
        let read = capture.read_from(Position::default()).unwrap();
        assert_eq!(read.gap.unwrap().to.seq, 2);
        assert_eq!(read.records[0].bytes, b"ef");
        assert_eq!(read.records[0].start.stdout_bytes, 4);
    }
}
