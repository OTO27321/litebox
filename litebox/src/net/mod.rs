//! Network-related functionality

use core::net::SocketAddr;

use crate::platform;

use bitflags::bitflags;
use thiserror::Error;

mod phy;
mod sockets;

/// The `Network` provides access to all networking related functionality provided by LiteBox.
///
/// A LiteBox `Network` is parametric in the platform it runs on.
pub struct Network<Platform: platform::Provider> {
    platform: &'static Platform,
}

/// Possible errors from a [`Network`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum NetError {
    #[error("Unsupported protocol {0}")]
    UnsupportedProtocol(u8),
    #[error("Unsupported address {0}")]
    UnsupportedAddress(SocketAddr),
    #[error("Not a valid open file descriptor")]
    InvalidFd,
    #[error("Port allocation failed: {0}")]
    PortAllocationFailure(#[from] sockets::LocalPortAllocationError),
    #[error("Socket is in an invalid state")]
    SocketInInvalidState,
    #[error("Operation finished")]
    OperationFinished,
}

/// A convenience type-alias for networking results
type Result<T> = core::result::Result<T, NetError>;

impl<Platform: platform::Provider> Network<Platform> {
    /// Construct a new `Network` instance
    ///
    /// This function is expected to only be invoked once per platform, as an initialization step,
    /// and the created `Network` handle is expected to be shared across all usage over the
    /// system.
    pub fn new(platform: &'static Platform) -> Self {
        Self { platform }
    }
}

/// An owned file descriptor for a socket
///
/// This file descriptor **must** be consumed by a `close` operation, otherwise will panic at
/// run-time upon being dropped.
pub struct SocketFd {
    pub(crate) fd: crate::fd::OwnedFd,
}
impl SocketFd {
    fn as_usize(&self) -> usize {
        self.fd.as_raw_fd().try_into().unwrap()
    }
}

impl<Platform: platform::Provider> Network<Platform> {
    /// Creates a socket.
    pub fn socket(&self, protocol: Protocol) -> Result<SocketFd> {
        todo!()
    }

    /// Close the socket at `fd`
    pub fn close(&self, fd: SocketFd) -> Result<()> {
        let SocketFd { mut fd } = fd;
        fd.mark_as_closed();
        todo!()
    }

    /// Initiate a connection to an IP address
    pub fn connect(&self, fd: &SocketFd, addr: &SocketAddr) -> Result<()> {
        todo!()
    }

    /// Bind a socket to a specific address and port.
    pub fn bind(&self, fd: &SocketFd, addr: &SocketAddr) -> Result<()> {
        todo!()
    }

    /// Prepare a socket to accept incoming connections.
    pub fn listen(&self, fd: &SocketFd, backlog: i32) -> Result<()> {
        todo!()
    }

    /// Accept a new incoming connection on a listening socket.
    pub fn accept(&self, fd: &SocketFd) -> Result<SocketFd> {
        todo!()
    }

    /// Send data over a connected socket.
    pub fn send(&self, fd: &SocketFd, buf: &[u8], flags: SendFlags) -> Result<usize> {
        todo!()
    }

    /// Receive data from a connected socket.
    pub fn receive(&self, fd: &SocketFd, buf: &mut [u8], flags: ReceiveFlags) -> Result<usize> {
        todo!()
    }
}

/// Protocols for sockets supported by LiteBox
#[non_exhaustive]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Raw { protocol: u8 },
}

bitflags! {
    /// Flags for the `receive` function.
    pub struct ReceiveFlags: u32 {
        /// `MSG_CMSG_CLOEXEC`: close-on-exec for the associated file descriptor
        const CMSG_CLOEXEC = 0x40000000;
        /// `MSG_DONTWAIT`: non-blocking operation
        const DONTWAIT = 0x40;
        /// `MSG_ERRQUEUE`: destination for error messages
        const ERRQUEUE = 0x2000;
        /// `MSG_OOB`: requests receipt of out-of-band data
        const OOB = 0x1;
        /// `MSG_PEEK`: requests to peek at incoming messages
        const PEEK = 0x2;
        /// `MSG_TRUNC`: truncate the message
        const TRUNC = 0x20;
        /// `MSG_WAITALL`: wait for the full amount of data
        const WAITALL = 0x100;
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}

bitflags! {
    /// Flags for the `send` function.
    pub struct SendFlags: u32 {
        /// `MSG_CONFIRM`: requests confirmation of the message delivery.
        const CONFIRM = 0x800;
        /// `MSG_DONTROUTE`: send the message directly to the interface, bypassing routing.
        const DONTROUTE = 0x4;
        /// `MSG_DONTWAIT`: non-blocking operation, do not wait for buffer space to become available.
        const DONTWAIT = 0x40;
        /// `MSG_EOR`: indicates the end of a record for message-oriented sockets.
        const EOR = 0x80;
        /// `MSG_MORE`: indicates that more data will follow.
        const MORE = 0x8000;
        /// `MSG_NOSIGNAL`: prevents the sending of SIGPIPE signals when writing to a socket that is closed.
        const NOSIGNAL = 0x4000;
        /// `MSG_OOB`: sends out-of-band data.
        const OOB = 0x1;
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}
