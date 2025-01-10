//! Crate-local test-only mock platform for easily running tests in the various modules.

// Pull in `std` for the test-only world, so that we have a nicer/easier time writing tests
extern crate std;

use std::cell::RefCell;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::vec::Vec;

use super::*;

/// A mock platform that is a [`platform::Provider`](Provider), useful purely for testing within
/// this crate.
///
/// Some great features of this mock platform are:
///
/// - Full determinism
///   + time moves at one millisecond per "now" call
///   + IP packets are placed into a deterministic ring buffer and spin back around
/// - Debuging output goes to stderr
/// - It will not mock you for using it during tests
pub(crate) struct MockPlatform {
    current_time: AtomicU64,
    ip_packets: RefCell<VecDeque<Vec<u8>>>,
}

impl MockPlatform {
    pub(crate) fn new() -> Self {
        MockPlatform {
            current_time: AtomicU64::new(0),
            ip_packets: RefCell::new(VecDeque::new()),
        }
    }
}

impl Provider for MockPlatform {}

pub(crate) struct MockRawMutex {}

impl RawMutex for MockRawMutex {
    fn underlying_atomic(&self) -> &core::sync::atomic::AtomicU32 {
        unimplemented!("raw mutex for MockPlatform")
    }

    fn wake_many(&self, n: usize) -> usize {
        unimplemented!("raw mutex for MockPlatform")
    }

    fn block(&self, val: u32) -> Result<(), ImmediatelyWokenUp> {
        unimplemented!("raw mutex for MockPlatform")
    }

    fn block_or_timeout(
        &self,
        val: u32,
        time: core::time::Duration,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        unimplemented!("raw mutex for MockPlatform")
    }
}

impl RawMutexProvider for MockPlatform {
    type RawMutex = MockRawMutex;

    fn new_raw_mutex(&self) -> Self::RawMutex {
        unimplemented!("raw mutex for MockPlatform")
    }
}

impl IPInterfaceProvider for MockPlatform {
    fn send_ip_packet(&self, packet: &[u8]) -> Result<(), SendError> {
        self.ip_packets.borrow_mut().push_back(packet.into());
        Ok(())
    }

    fn receive_ip_packet(&self, packet: &mut [u8]) -> Result<usize, ReceiveError> {
        if self.ip_packets.borrow().is_empty() {
            Err(ReceiveError::WouldBlock)
        } else {
            let mut ipp = self.ip_packets.borrow_mut();
            let v = ipp.pop_front().unwrap();
            assert!(v.len() <= packet.len());
            packet[..v.len()].copy_from_slice(&v);
            Ok(v.len())
        }
    }
}

pub(crate) struct MockInstant {
    time: u64,
}

impl Instant for MockInstant {
    fn checked_duration_since(&self, earlier: &Self) -> Option<core::time::Duration> {
        if earlier.time <= self.time {
            Some(core::time::Duration::from_millis(self.time - earlier.time))
        } else {
            None
        }
    }
}

impl TimeProvider for MockPlatform {
    type Instant = MockInstant;

    fn now(&self) -> Self::Instant {
        MockInstant {
            time: self.current_time.fetch_add(1, Ordering::SeqCst),
        }
    }
}

impl PunchthroughProvider for MockPlatform {
    type Punchthrough = trivial_providers::ImpossiblePunchthrough;
}

impl DebugLogProvider for MockPlatform {
    fn debug_log_print(&self, msg: &str) {
        std::eprintln!("{msg}");
    }
}
