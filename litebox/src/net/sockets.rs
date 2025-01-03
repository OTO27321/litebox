//! Connection to the socket (i.e., "above") side for networking.

use core::net::SocketAddr;
use core::num::{NonZeroU16, NonZeroU64};

use alloc::vec;
use alloc::vec::Vec;

use hashbrown::HashSet;
use smoltcp::iface::SocketSet;
use smoltcp::socket::{icmp, raw, tcp, udp};
use thiserror::Error;

use crate::fd::OwnedFd;
use crate::platform::{self, Instant};
use crate::utilities::rng::FastRng;

use super::phy;
use super::{NetError, Protocol, SocketFd};

/// Maximum number of sockets that can ever be active
const MAX_NUMBER_OF_SOCKETS: usize = 1024;

/// Maximum size of rx/tx buffers for sockets
const SOCKET_BUFFER_SIZE: usize = 65536;

/// Limits maximum number of packets in a buffer
const MAX_PACKET_COUNT: usize = 32;

pub(crate) struct Sockets<
    Platform: platform::IPInterfaceProvider + platform::TimeProvider + 'static,
> {
    /// The set of sockets
    socket_set: SocketSet<'static>,
    /// Handles into the `socket_set`; the position/index corresponds to the `raw_fd` of the
    /// `SocketFd` given out from this module.
    handles: Vec<Option<SocketHandle>>,
    /// The actual "physical" device, that connects to the platform
    device: phy::Device<Platform>,
    /// The smoltcp network interface
    interface: smoltcp::iface::Interface,
    /// Initial instant of creation, used as an arbitrary stop point from when time begins
    zero_time: Platform::Instant,
    /// An allocator for local ports
    local_port_allocator: LocalPortAllocator,
}

/// [`SocketHandle`] stores all relevant information for a specific [`SocketFd`], for easy access
/// from [`SocketFd`], _except_ the `Socket` itself which is stored in the [`Sockets::socket_set`].
struct SocketHandle {
    /// The handle into the `socket_set`
    handle: smoltcp::iface::SocketHandle,
    /// The protocol for this socket
    protocol: Protocol,
    /// A local port associated with this socket, if any
    local_port: Option<LocalPort>,
}

impl<Platform: platform::IPInterfaceProvider + platform::TimeProvider + 'static> Sockets<Platform> {
    fn new(platform: &'static Platform) -> Self {
        let mut device = phy::Device::new(platform);
        let config = smoltcp::iface::Config::new(smoltcp::wire::HardwareAddress::Ip);
        let interface =
            smoltcp::iface::Interface::new(config, &mut device, smoltcp::time::Instant::ZERO);
        Self {
            socket_set: SocketSet::new(vec![]),
            handles: vec![],
            device,
            interface,
            zero_time: platform.now(),
            local_port_allocator: LocalPortAllocator::new(),
        }
    }

    // Explicitly private-only function
    fn now(&self) -> smoltcp::time::Instant {
        smoltcp::time::Instant::from_micros(
            // This conversion from u128 to i64 should practically never fail, since 2^63
            // microseconds is roughly 250 years. If a system has been up for that long, then it
            // deserves to panic.
            i64::try_from(
                self.zero_time
                    .duration_since(&self.device.platform.now())
                    .as_micros(),
            )
            .unwrap(),
        )
    }

    fn socket(&mut self, protocol: Protocol) -> Result<SocketFd, NetError> {
        let handle = match protocol {
            Protocol::Tcp => self.socket_set.add(tcp::Socket::new(
                smoltcp::storage::RingBuffer::new(vec![0u8; SOCKET_BUFFER_SIZE]),
                smoltcp::storage::RingBuffer::new(vec![0u8; SOCKET_BUFFER_SIZE]),
            )),
            Protocol::Udp => self.socket_set.add(udp::Socket::new(
                smoltcp::storage::PacketBuffer::new(
                    vec![smoltcp::storage::PacketMetadata::EMPTY; MAX_PACKET_COUNT],
                    vec![0u8; SOCKET_BUFFER_SIZE],
                ),
                smoltcp::storage::PacketBuffer::new(
                    vec![smoltcp::storage::PacketMetadata::EMPTY; MAX_PACKET_COUNT],
                    vec![0u8; SOCKET_BUFFER_SIZE],
                ),
            )),
            Protocol::Icmp => self.socket_set.add(icmp::Socket::new(
                smoltcp::storage::PacketBuffer::new(
                    vec![smoltcp::storage::PacketMetadata::EMPTY; MAX_PACKET_COUNT],
                    vec![0u8; SOCKET_BUFFER_SIZE],
                ),
                smoltcp::storage::PacketBuffer::new(
                    vec![smoltcp::storage::PacketMetadata::EMPTY; MAX_PACKET_COUNT],
                    vec![0u8; SOCKET_BUFFER_SIZE],
                ),
            )),
            Protocol::Raw { protocol } => {
                // TODO: Should we maintain a specific allow-list of protocols for raw sockets?
                // Should we allow everything except TCP/UDP/ICMP? Should we allow everything? These
                // questions should be resolved; for now I am disallowing everything else.
                return Err(NetError::UnsupportedProtocol(protocol));

                self.socket_set.add(raw::Socket::new(
                    smoltcp::wire::IpVersion::Ipv4,
                    smoltcp::wire::IpProtocol::from(protocol),
                    smoltcp::storage::PacketBuffer::new(
                        vec![smoltcp::storage::PacketMetadata::EMPTY; MAX_PACKET_COUNT],
                        vec![0u8; SOCKET_BUFFER_SIZE],
                    ),
                    smoltcp::storage::PacketBuffer::new(
                        vec![smoltcp::storage::PacketMetadata::EMPTY; MAX_PACKET_COUNT],
                        vec![0u8; SOCKET_BUFFER_SIZE],
                    ),
                ))
            }
        };

        // TODO: We can do reuse of fds if we maintained a free-list or similar; for now, we just
        // grab an entirely new fd anytime there is a new socket to be made.

        let raw_fd = self.handles.len().try_into().unwrap();
        self.handles.push(Some(SocketHandle {
            handle,
            protocol,
            local_port: None,
        }));

        Ok(SocketFd {
            fd: OwnedFd::new(raw_fd),
        })
    }

    #[expect(clippy::unnecessary_wraps)]
    fn close(&mut self, fd: SocketFd) -> Result<(), NetError> {
        let socket_handle = core::mem::take(&mut self.handles[fd.as_usize()]).unwrap();
        let socket = self.socket_set.remove(socket_handle.handle);
        match socket {
            smoltcp::socket::Socket::Raw(_) | smoltcp::socket::Socket::Icmp(_) => {
                // There is no close/abort for raw and icmp sockets
            }
            smoltcp::socket::Socket::Udp(mut socket) => {
                socket.close();
            }
            smoltcp::socket::Socket::Tcp(mut socket) => {
                // TODO: Should we `.close()` or should we `.abort()`?
                socket.abort();
            }
        }
        let SocketFd { mut fd } = fd;
        fd.mark_as_closed();
        Ok(())
    }

    fn connect(&mut self, fd: &SocketFd, addr: &SocketAddr) -> Result<(), NetError> {
        let SocketAddr::V4(addr) = addr else {
            return Err(NetError::UnsupportedAddress(*addr));
        };

        let socket_handle = self.handles[fd.as_usize()]
            .as_mut()
            .ok_or(NetError::InvalidFd)?;

        match socket_handle.protocol {
            Protocol::Tcp => {
                let socket: &mut tcp::Socket = self.socket_set.get_mut(socket_handle.handle);
                let local_port = self.local_port_allocator.ephemeral_port()?;
                let local_endpoint = local_port.port();
                socket.connect(self.interface.context(), *addr, local_endpoint);
                let old_port = core::mem::replace(&mut socket_handle.local_port, Some(local_port));
                if old_port.is_some() {
                    // Need to think about how to handle this situation
                    unimplemented!()
                }
                Ok(())
            }
            Protocol::Udp => unimplemented!(),
            Protocol::Icmp => unimplemented!(),
            Protocol::Raw { protocol } => unimplemented!(),
        }
    }

    fn send(
        &mut self,
        fd: &SocketFd,
        buf: &[u8],
        flags: super::SendFlags,
    ) -> Result<usize, NetError> {
        let socket_handle = self.handles[fd.as_usize()]
            .as_mut()
            .ok_or(NetError::InvalidFd)?;

        if !flags.is_empty() {
            unimplemented!()
        }

        match socket_handle.protocol {
            Protocol::Tcp => self
                .socket_set
                .get_mut::<tcp::Socket>(socket_handle.handle)
                .send_slice(buf)
                .map_err(|tcp::SendError::InvalidState| NetError::SocketInInvalidState),
            Protocol::Udp => unimplemented!(),
            Protocol::Icmp => unimplemented!(),
            Protocol::Raw { protocol } => unimplemented!(),
        }
    }

    fn receive(
        &mut self,
        fd: &SocketFd,
        buf: &mut [u8],
        flags: super::ReceiveFlags,
    ) -> Result<usize, NetError> {
        let socket_handle = self.handles[fd.as_usize()]
            .as_mut()
            .ok_or(NetError::InvalidFd)?;

        if !flags.is_empty() {
            unimplemented!()
        }

        match socket_handle.protocol {
            Protocol::Tcp => self
                .socket_set
                .get_mut::<tcp::Socket>(socket_handle.handle)
                .recv_slice(buf)
                .map_err(|e| match e {
                    tcp::RecvError::InvalidState => NetError::OperationFinished,
                    tcp::RecvError::Finished => NetError::SocketInInvalidState,
                }),
            Protocol::Udp => unimplemented!(),
            Protocol::Icmp => unimplemented!(),
            Protocol::Raw { protocol } => unimplemented!(),
        }
    }
}

/// An allocator for local ports, making sure that no already-allocated ports are given out
pub(crate) struct LocalPortAllocator {
    allocated: HashSet<NonZeroU16>,
    rng: FastRng,
}

impl Default for LocalPortAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalPortAllocator {
    /// Sets up a new local port allocator
    pub(crate) fn new() -> Self {
        Self {
            allocated: HashSet::new(),
            rng: FastRng::new_from_seed(NonZeroU64::new(0x13374a4159421337).unwrap()),
        }
    }

    /// Allocate a new ephemeral local port (i.e., port in the range 49152 and 65535)
    pub(crate) fn ephemeral_port(&mut self) -> Result<LocalPort, LocalPortAllocationError> {
        for _ in 0..100 {
            let port =
                NonZeroU16::new(u16::try_from(self.rng.next_in_range_u32(49152..65536)).unwrap())
                    .unwrap();
            if let Ok(local_port) = self.specific_port(port) {
                return Ok(local_port);
            }
        }
        // If we haven't yet found a port after 100 tries, it is highly likely lots of ports are
        // already in use, so we should start looking over them one by one
        for port in 49152..=65535 {
            let port = NonZeroU16::new(port).unwrap();
            if let Ok(local_port) = self.specific_port(port) {
                return Ok(local_port);
            }
        }
        // If we _still_ haven't found any, then we have run out of ports to give out
        Err(LocalPortAllocationError::NoAvailableFreePorts)
    }

    /// Allocate a specific local port, if available
    pub(crate) fn specific_port(
        &mut self,
        port: NonZeroU16,
    ) -> Result<LocalPort, LocalPortAllocationError> {
        if self.allocated.insert(port) {
            Ok(LocalPort { port })
        } else {
            Err(LocalPortAllocationError::AlreadyInUse(port.get()))
        }
    }

    /// Marks a [`LocalPort`] as available again, consuming it
    pub(crate) fn deallocate(&mut self, port: LocalPort) {
        let was_removed = self.allocated.remove(&port.port);
        // As an invariant, the only production of `LocalPort` can happen from here, thus it should
        // be impossible to have a `LocalPort` containing a non-allocated spot.
        assert!(was_removed);
    }
}

/// A token expressing ownership over a specific local port.
///
/// Explicitly not cloneable/copyable.
pub(crate) struct LocalPort {
    port: NonZeroU16,
}

impl LocalPort {
    fn port(&self) -> u16 {
        self.port.get()
    }
}

/// Errors that could be returned when allocating a [`LocalPort`]
#[derive(Debug, Error)]
pub enum LocalPortAllocationError {
    #[error("Port {0} is already in use")]
    AlreadyInUse(u16),
    #[error("No free ports are available")]
    NoAvailableFreePorts,
}
