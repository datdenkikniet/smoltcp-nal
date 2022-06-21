use core::{
    future::Future,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};

use heapless::Vec;
use nanorand::{Rng, WyRand};
use smoltcp::{
    iface::{Interface, SocketHandle, SocketSet},
    phy::{Device, PacketId},
    socket::{
        dhcpv4,
        dns::{self, QueryHandle as DnsQueryHandle},
        tcp::{self, RecvError},
        udp, AnySocket,
    },
    time::Instant,
    wire::{IpAddress, IpCidr, IpEndpoint, Ipv4Address, Ipv4Cidr},
};

use crate::lockable::Lockable;

// The start of TCP port dynamic range allocation.
const TCP_PORT_DYNAMIC_RANGE_START: u16 = 49152;

struct RandWrap(core::cell::UnsafeCell<WyRand>);

impl RandWrap {
    const fn new() -> Self {
        Self(core::cell::UnsafeCell::new(WyRand::new_seed(0)))
    }

    pub fn seed(&self, seed: &[u8]) {
        critical_section::with(|_| (unsafe { &mut *self.0.get() }).reseed(seed));
    }

    pub fn rand_bytes(&self, buf: &mut [u8]) {
        buf.chunks_mut(8).for_each(|chunk| {
            let r = critical_section::with(|_| (unsafe { &mut *self.0.get() }).rand());
            chunk.copy_from_slice(&r[..chunk.len()]);
        });
    }
}

unsafe impl Sync for RandWrap {}

// Used to generate ephemeral ports with an RNG
static RAND: RandWrap = RandWrap::new();

#[derive(Clone, Copy)]
enum StackState {
    DhcpPending,
    DhcpConfigured { dns_state: DnsState },
}

#[derive(Clone, Copy)]
enum DnsState {
    DnsPending { query_handle: DnsQueryHandle },
    Finished,
}

///! Network abstraction layer for smoltcp.
pub struct NetworkStack<'a, 's, DeviceT> {
    pub network_interface: Interface<'a>,
    device: DeviceT,
    socket_set: SocketSet<'s>,
    dhcp_handle: SocketHandle,
    dns_handle: SocketHandle,
    dns_result: Vec<IpAddress, 4>,
    pub(crate) tcp_handle: SocketHandle,
    pub(crate) udp_handle: SocketHandle,
    name_servers: Vec<IpAddress, 3>,
    state: StackState,
    now_fn: fn() -> Instant,
}

impl<'a, 's, DeviceT> NetworkStack<'a, 's, DeviceT>
where
    DeviceT: for<'c> Device<'c>,
{
    #[cfg(test)]
    pub(crate) fn socket_set(&mut self) -> &mut SocketSet<'s> {
        &mut self.socket_set
    }

    pub fn device(&mut self) -> &mut DeviceT {
        &mut self.device
    }

    pub fn new(
        device: DeviceT,
        mut socket_set: SocketSet<'s>,
        interface: Interface<'a>,
        tcp_handle: SocketHandle,
        udp_handle: SocketHandle,
        dns_handle: SocketHandle,
        now_fn: fn() -> Instant,
    ) -> (Self, TcpReader, TcpWriter) {
        let dhcp_handle = socket_set.add(dhcpv4::Socket::new());

        (
            Self {
                device,
                socket_set,
                network_interface: interface,
                dhcp_handle,
                dns_handle,
                dns_result: Vec::new(),
                tcp_handle,
                udp_handle,
                name_servers: Vec::new(),
                state: StackState::DhcpPending,
                now_fn,
            },
            TcpReader::new(),
            TcpWriter::new(),
        )
    }

    fn is_ip_unspecified(&self) -> bool {
        // Note(unwrap): This stack only supports Ipv4.
        if let Some(addr) = self.network_interface.ipv4_addr() {
            addr.is_unspecified()
        } else {
            panic!("This stack only supports Ipv4.");
        }
    }

    pub fn connect<'dns_name, 'stack_borrow, Stack>(
        me: &'stack_borrow mut Stack,
        dns_name: &'dns_name str,
        port: u16,
    ) -> ConnectFuture<'dns_name, 'stack_borrow, Stack> {
        ConnectFuture {
            stack: me,
            inner: ConnectFutureInner { dns_name, port },
        }
    }

    pub fn is_connected(&mut self) -> bool {
        let tcp_socket = self.socket_set.get::<tcp::Socket>(self.tcp_handle);

        tcp_socket.may_send() && tcp_socket.may_recv()
    }

    fn set_ipv4_address(&mut self, address: Ipv4Cidr) {
        self.socket_set
            .get_mut::<tcp::Socket>(self.tcp_handle)
            .abort();

        self.network_interface.update_ip_addrs(|addrs| {
            let addr = if let Some(addr) = addrs
                .iter_mut()
                .filter(|cidr| match cidr.address() {
                    IpAddress::Ipv4(_) => true,
                    #[allow(unreachable_patterns)]
                    _ => false,
                })
                .next()
            {
                addr
            } else {
                panic!("This stack requires at least 1 Ipv4 Address");
            };

            *addr = IpCidr::Ipv4(address);
        });
    }

    fn handle_dhcpv4_event(&mut self, event: dhcpv4::Event) -> Result<bool, smoltcp::Error> {
        match event {
            dhcpv4::Event::Configured(config) => {
                if config.address.address().is_unicast()
                    && self.network_interface.ipv4_address() != Some(config.address.address())
                {
                    self.set_ipv4_address(config.address);
                    #[cfg(feature = "defmt")]
                    defmt::info!("DHCP address: {}", config.address);
                }

                // Store DNS server addresses for later read-back
                self.name_servers.clear();
                for server in config.dns_servers.iter() {
                    if let Some(server) = server {
                        // Note(unwrap): The name servers vector is at least as long as the
                        // number of DNS servers reported via DHCP.
                        self.name_servers.push(IpAddress::Ipv4(*server)).ok();
                        #[cfg(feature = "defmt")]
                        defmt::trace!("DNS server received: {}", server);
                    }
                }

                // Update the DNS handle with the servers received through DHCP
                #[cfg(feature = "defmt")]
                defmt::trace!(
                    "Updating DNS with servers: {}",
                    self.name_servers.as_slice()
                );

                self.socket_set
                    .get_mut::<dns::Socket>(self.dns_handle)
                    .update_servers(self.name_servers.as_slice());

                if let Some(route) = config.router {
                    // Note: If the user did not provide enough route storage, we may not be
                    // able to store the gateway.
                    self.network_interface
                        .routes_mut()
                        .add_default_ipv4_route(route)?;
                } else {
                    self.network_interface
                        .routes_mut()
                        .remove_default_ipv4_route();
                }
                Ok(true)
            }
            dhcpv4::Event::Deconfigured => {
                self.network_interface
                    .routes_mut()
                    .remove_default_ipv4_route();
                self.set_ipv4_address(Ipv4Cidr::new(Ipv4Address::UNSPECIFIED, 0));
                Ok(false)
            }
        }
    }

    fn start_dns_lookup(&mut self, lookup: &str) -> Result<DnsQueryHandle, ()> {
        let handle = self.dns_handle;
        let dns_socket = self.socket_set.get_mut::<dns::Socket>(handle);
        let cx = self.network_interface.context();

        let query_handle = match dns_socket.start_query(cx, lookup) {
            Err(_e) => {
                #[cfg(feature = "defmt")]
                defmt::info!("DNS query error: {}", _e);
                return Err(());
            }
            Ok(q) => q,
        };

        self.dns_result = Vec::new();

        Ok(query_handle)
    }

    // Get an ephemeral port number.
    fn get_ephemeral_port(&mut self) -> u16 {
        loop {
            // Get the next ephemeral port by generating a random, valid TCP port continuously
            // until an unused port is found.
            let random_offset = {
                let mut data = [0; 2];
                RAND.rand_bytes(&mut data);
                u16::from_be_bytes([data[0], data[1]])
            };

            let port = TCP_PORT_DYNAMIC_RANGE_START
                + random_offset % (u16::MAX - TCP_PORT_DYNAMIC_RANGE_START);
            return port;
        }
    }

    pub fn seed_rng(&self, seed: &[u8]) {
        RAND.seed(seed)
    }

    /// Try to connect to TCP
    /// If the socket is already connected but cannot send or receive, the current connect
    /// (if any) will be aborted and a connection will be reattempted
    pub(crate) fn try_connect_sockets(&mut self, remote: IpAddress, port: u16) -> Result<(), bool> {
        if self.is_ip_unspecified() {
            return Err(false);
        }

        let connected = self.is_connected();
        let local_addr = if let Some(addr) = self.addresses().first().map(|a| a.address()) {
            addr
        } else {
            return Err(false);
        };

        let local_port = self.get_ephemeral_port();

        let udp_socket = self.udp_handle.clone();
        let udp_socket = self.socket_set.get_mut::<udp::Socket>(udp_socket);
        udp_socket.bind((local_addr, port)).map_err(|_| false)?;

        let tcp_socket = self.tcp_handle.clone();

        let tcp_socket = self.socket_set.get_mut::<tcp::Socket>(tcp_socket);
        let ctx = self.network_interface.context();

        // If we're already connected to a socket capable of both RX and TX, don't
        // attempt to reconnect
        if connected {
            return Ok(());
        }

        tcp_socket.abort();
        let result = match remote {
            IpAddress::Ipv4(ipv4) => {
                let result = tcp_socket
                    .connect(ctx, (ipv4, port), local_port)
                    .map_err(|_| true);
                tcp_socket.set_nagle_enabled(false);
                tcp_socket.set_timeout(Some(smoltcp::time::Duration::from_secs(5)));
                result
            }
        };

        result
    }

    pub fn poll_iface(&mut self) -> smoltcp::Result<bool> {
        let Self {
            network_interface,
            device,
            socket_set,
            ..
        } = self;
        network_interface.poll((self.now_fn)(), device, socket_set)
    }

    pub fn recv_udp(&mut self) -> Option<PacketId> {
        let Self {
            socket_set,
            udp_handle,
            ..
        } = self;

        let udp_socket = socket_set.get_mut::<udp::Socket>(*udp_handle);

        let (_, meta) = udp_socket.recv().ok()?;

        meta.packet_id()
    }

    pub fn send_udp(&mut self, data: &[u8]) -> Option<PacketId> {
        let address = self.dns_result.first()?;
        let endpoint = IpEndpoint {
            addr: *address,
            port: 7878,
        };

        let Self {
            socket_set,
            network_interface,
            udp_handle,
            ..
        } = self;

        let udp_socket = socket_set.get_mut::<udp::Socket>(*udp_handle);

        let (buffer, pkt_id) = udp_socket
            .send_marked(network_interface, data.len(), endpoint)
            .ok()?;

        buffer.copy_from_slice(data);

        Some(pkt_id)
    }

    pub fn addresses(&self) -> &[IpCidr] {
        self.network_interface.ip_addrs()
    }

    /// Handle a disconnection of the physical interface.
    pub fn handle_link_reset(&mut self) {
        // Reset the DHCP client.
        self.socket_set
            .get_mut::<dhcpv4::Socket>(self.dhcp_handle)
            .reset();

        // Close all of the sockets and de-configure the interface.
        self.socket_set.iter_mut().for_each(|(_h, socket)| {
            if let Some(socket) = tcp::Socket::downcast_mut(socket) {
                socket.abort();
            }

            if let Some(socket) = udp::Socket::downcast_mut(socket) {
                socket.close();
            }
        });

        self.network_interface.update_ip_addrs(|addrs| {
            addrs.iter_mut().next().map(|addr| {
                *addr = IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address::UNSPECIFIED, 0));
            });
        });
    }
}

pub struct TcpReader {
    // TODO: this should have a stack waker
    _phantom: PhantomData<()>,
}

impl Unpin for TcpReader {}

impl TcpReader {
    fn new() -> Self {
        Self {
            _phantom: Default::default(),
        }
    }

    pub fn read<'me, 'buffer, 'borrow, Stack>(
        &mut self,
        stack: &'borrow mut Stack,
        buffer: &'buffer mut [u8],
    ) -> TcpReadFuture<'buffer, 'borrow, Stack> {
        TcpReadFuture::new(stack, buffer, ReadMode::FillBuffer { full_buffer: false })
    }

    pub fn read_all<'me, 'buffer, 'stack, Stack>(
        &mut self,
        stack: &'stack mut Stack,
        buffer: &'buffer mut [u8],
    ) -> TcpReadFuture<'buffer, 'stack, Stack> {
        TcpReadFuture::new(stack, buffer, ReadMode::FillBuffer { full_buffer: true })
    }

    /// The RX buffer must fit the largest amount of contiguous data that
    /// will occur before a `delimiter` occurs.
    pub fn read_frame<'me, 'buffer, 'stack, Stack>(
        &mut self,
        stack: &'stack mut Stack,
        buffer: &'buffer mut [u8],
        delimiter: u8,
    ) -> TcpReadFuture<'buffer, 'stack, Stack> {
        TcpReadFuture::new(stack, buffer, ReadMode::Delimited { delimiter })
    }
}

#[derive(Clone, Copy)]
pub enum ReadMode {
    FillBuffer { full_buffer: bool },
    Delimited { delimiter: u8 },
}

pub struct TcpReadFuture<'buffer, 'stack_borrow, Stack> {
    stack: &'stack_borrow mut Stack,
    inner: TcpReadFutureInner<'buffer>,
}

impl<'buffer, 'stack_borrow, Stack> TcpReadFuture<'buffer, 'stack_borrow, Stack> {
    fn new(
        stack: &'stack_borrow mut Stack,
        buffer: &'buffer mut [u8],
        read_mode: ReadMode,
    ) -> Self {
        Self {
            stack,
            inner: TcpReadFutureInner {
                buffer,
                rx_index: 0,
                read_mode,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, defmt::Format, PartialEq)]
pub enum TcpRecvError {
    NotConnected,
    NoDelimiterFound,
    MessageWillNotFit,
    TcpError,
}

struct TcpReadFutureInner<'buffer> {
    buffer: &'buffer mut [u8],
    /// Whether or not the entire buffer should be filled before
    /// the future has completed
    rx_index: usize,
    read_mode: ReadMode,
}

impl<'buffer> TcpReadFutureInner<'buffer> {
    fn poll<'stack, 's, DeviceT>(
        &mut self,
        stack: &mut NetworkStack<'stack, 's, DeviceT>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<usize, TcpRecvError>>
    where
        DeviceT: for<'c> Device<'c>,
    {
        if let Err(_e) = stack.poll_iface() {
            #[cfg(feature = "defmt")]
            defmt::error!("Interface polling error: {}", _e);
        }

        if !stack.is_connected() {
            return Poll::Ready(Err(TcpRecvError::NotConnected));
        }

        let tcp_handle = stack.tcp_handle.clone();
        let tcp_socket = stack.socket_set.get_mut::<tcp::Socket>(tcp_handle);

        let total_buffer_len = self.buffer.len();
        let buffer = &mut self.buffer[self.rx_index..];
        let read_mode = self.read_mode.clone();
        let rx_index = self.rx_index;

        let res = tcp_socket.recv(|recv_data| {
            match read_mode {
                ReadMode::FillBuffer { full_buffer } => {
                    let read_len = recv_data.len().min(buffer.len());
                    buffer[..read_len].copy_from_slice(&recv_data[..read_len]);

                    let result = if rx_index + read_len >= total_buffer_len || !full_buffer {
                        Poll::Ready(Ok(()))
                    } else {
                        Poll::Pending
                    };

                    (read_len, (result, read_len))
                }
                ReadMode::Delimited { delimiter } => {
                    let delimiter_index = recv_data
                        .iter()
                        .enumerate()
                        .find(|(_idx, v)| **v == delimiter)
                        .map(|(idx, _v)| idx + 1);

                    // Current behaviour is to attempt to read a delimiter. If we know that
                    // the data required to do so will not fit in the receive buffer, we do not
                    // read any more data from the socket

                    if let Some(delimiter) = delimiter_index {
                        if buffer.len() < delimiter {
                            (0, (Poll::Ready(Err(TcpRecvError::MessageWillNotFit)), 0))
                        } else {
                            // delimiter <= recv_buffer.len(), so we can use the buffer freely without
                            // panicking
                            buffer[..delimiter].copy_from_slice(&recv_data[..delimiter]);
                            (delimiter, (Poll::Ready(Ok(())), delimiter))
                        }
                    } else {
                        if buffer.len() < recv_data.len() {
                            (0, (Poll::Ready(Err(TcpRecvError::NoDelimiterFound)), 0))
                        } else {
                            let read_len = recv_data.len().min(buffer.len());
                            buffer[..read_len].copy_from_slice(&recv_data[..read_len]);
                            (read_len, (Poll::Pending, read_len))
                        }
                    }
                }
            }
        });

        if let Ok((Poll::Pending, _)) = res {
            tcp_socket.register_recv_waker(cx.waker());
        }

        match res {
            Ok((res, bytes_read)) => {
                self.rx_index += bytes_read;
                res.map(|r| r.map(|_| self.rx_index))
            }
            Err(e) => match e {
                RecvError::InvalidState => Poll::Ready(Err(TcpRecvError::TcpError)),
                RecvError::Finished => Poll::Ready(Err(TcpRecvError::TcpError)),
            },
        }
    }
}

impl<'buffer, 'stack_borrow, 'stack, 's, DeviceT, Stack> Future
    for TcpReadFuture<'buffer, 'stack_borrow, Stack>
where
    Stack: Lockable<T = NetworkStack<'stack, 's, DeviceT>>,
    DeviceT: for<'c> Device<'c>,
{
    type Output = Result<usize, TcpRecvError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let inner = &mut this.inner;
        this.stack.lock(|stack| inner.poll(stack, cx))
    }
}

impl<'a, 'buffer, 'stack_borrow, 'stack, 's, DeviceT> Future
    for TcpReadFuture<'buffer, 'stack_borrow, NetworkStack<'a, 's, DeviceT>>
where
    DeviceT: for<'c> Device<'c>,
{
    type Output = Result<usize, TcpRecvError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let inner = &mut this.inner;
        inner.poll(this.stack, cx)
    }
}

pub struct TcpWriter {
    // TODO: this should have a stack waker
    _phantom: PhantomData<()>,
}

impl TcpWriter {
    fn new() -> Self {
        Self {
            _phantom: Default::default(),
        }
    }

    pub fn write<'stack_borrow, 'buffer, Stack>(
        &mut self,
        stack: &'stack_borrow mut Stack,
        data: &'buffer [u8],
    ) -> TcpWriteFuture<'stack_borrow, 'buffer, Stack> {
        TcpWriteFuture::new(stack, data, false)
    }

    pub fn write_all<'stack_borrow, 'buffer, Stack>(
        &mut self,
        stack: &'stack_borrow mut Stack,
        data: &'buffer [u8],
    ) -> TcpWriteFuture<'stack_borrow, 'buffer, Stack> {
        TcpWriteFuture::new(stack, data, true)
    }
}

pub struct TcpWriteFuture<'stack_borrow, 'buffer, Stack> {
    stack: &'stack_borrow mut Stack,
    inner: TcpWriteFutureInner<'buffer>,
}
impl<'stack_borrow, 'buffer, Stack> TcpWriteFuture<'stack_borrow, 'buffer, Stack> {
    pub(crate) fn new(
        stack: &'stack_borrow mut Stack,
        buffer: &'buffer [u8],
        full_buffer: bool,
    ) -> Self {
        TcpWriteFuture {
            stack,
            inner: TcpWriteFutureInner {
                buffer,
                full_buffer,
                tx_index: 0,
            },
        }
    }
}

struct TcpWriteFutureInner<'buffer> {
    buffer: &'buffer [u8],
    /// Whether or not we should pend until the entire buffer is sent
    full_buffer: bool,
    tx_index: usize,
}

impl<'buffer> TcpWriteFutureInner<'buffer> {
    fn poll<'stack, 's, DeviceT>(
        &mut self,
        stack: &mut NetworkStack<'stack, 's, DeviceT>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<usize, ()>>
    where
        DeviceT: for<'c> Device<'c>,
    {
        if let Err(_e) = stack.poll_iface() {
            #[cfg(feature = "defmt")]
            defmt::error!("Interface polling error: {}", _e);
        }

        if !stack.is_connected() {
            return Poll::Ready(Err(()));
        }

        let tcp_handle = stack.tcp_handle.clone();
        let tcp_socket = stack.socket_set.get_mut::<tcp::Socket>(tcp_handle);

        let to_send_buffer = &self.buffer[self.tx_index..];
        let send_result = tcp_socket.send_slice(to_send_buffer);

        let result = match send_result {
            Ok(bytes_sent) => {
                self.tx_index += bytes_sent;
                if self.tx_index >= self.buffer.len() || !self.full_buffer {
                    // tx_index _should_ always equal to or less than buffer.len() here if all bytes
                    // have been sent, but would be very annoying to debug
                    if self.tx_index > self.buffer.len() {
                        #[cfg(feature = "defmt")]
                        defmt::error!("Sent more bytes than were in the send buffer");
                    }
                    Poll::Ready(Ok(self.tx_index))
                } else {
                    tcp_socket.register_send_waker(cx.waker());
                    Poll::Pending
                }
            }
            Err(_) => Poll::Ready(Err(())),
        };

        if let Err(_e) = stack.poll_iface() {
            #[cfg(feature = "defmt")]
            defmt::error!("Interface polling error: {}", _e);
        }

        result
    }
}

impl<'a, 'buffer, 'stack, 's, DeviceT, Stack> Future for TcpWriteFuture<'a, 'buffer, Stack>
where
    DeviceT: for<'c> Device<'c>,
    Stack: Lockable<T = NetworkStack<'stack, 's, DeviceT>>,
{
    type Output = Result<usize, ()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let inner = &mut this.inner;
        this.stack.lock(|stack| inner.poll(stack, cx))
    }
}

pub struct ConnectFuture<'dns_name, 'stack_borrow, Stack> {
    stack: &'stack_borrow mut Stack,
    inner: ConnectFutureInner<'dns_name>,
}

struct ConnectFutureInner<'a> {
    dns_name: &'a str,
    port: u16,
}

impl<'a> ConnectFutureInner<'a> {
    fn poll<DeviceT>(
        &self,
        stack: &mut NetworkStack<'_, '_, DeviceT>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ()>>
    where
        DeviceT: for<'c> Device<'c>,
    {
        if let Err(_e) = stack.poll_iface() {
            #[cfg(feature = "defmt")]
            defmt::error!("Interface polling error: {}", _e);
        }

        let dhcp_handle = stack.dhcp_handle.clone();

        // Handle possible DHCP events
        let dhcp_event = stack
            .socket_set
            .get_mut::<dhcpv4::Socket>(dhcp_handle)
            .poll();

        if let Some(event) = dhcp_event {
            #[cfg(feature = "defmt")]
            defmt::debug!("Got dhcp event: {}", event);
            match stack.handle_dhcpv4_event(event) {
                Ok(true) => {
                    #[cfg(feature = "defmt")]
                    defmt::info!("DHCP completed, starting dns.");
                    let dns_started = stack.start_dns_lookup(self.dns_name);
                    if let Ok(query_handle) = dns_started {
                        stack.state = StackState::DhcpConfigured {
                            dns_state: DnsState::DnsPending { query_handle },
                        };
                    }
                }
                Ok(false) => {
                    #[cfg(feature = "defmt")]
                    defmt::info!("DHCP is deconfigured. Restarting DHCP");
                    stack
                        .socket_set
                        .get_mut::<dhcpv4::Socket>(dhcp_handle)
                        .reset();
                    stack.state = StackState::DhcpPending;
                }
                Err(_) => return Poll::Ready(Err(())),
            }
        }

        let dns_state = if let StackState::DhcpConfigured { dns_state } = stack.state {
            dns_state
        } else {
            stack
                .socket_set
                .get_mut::<dhcpv4::Socket>(dhcp_handle)
                .register_waker(cx.waker());
            return Poll::Pending;
        };

        let dns_handle = stack.dns_handle;

        match dns_state {
            DnsState::DnsPending { query_handle } => {
                match stack
                    .socket_set
                    .get_mut::<dns::Socket>(dns_handle)
                    .get_query_result(query_handle)
                {
                    Ok(res) => {
                        #[cfg(feature = "defmt")]
                        defmt::info!("DNS completed: {}", res);
                        stack.dns_result = res;
                        stack.state = StackState::DhcpConfigured {
                            dns_state: DnsState::Finished,
                        };
                        // Wake the waker immediately so that the state machine
                        // will be ran again to start TCP connection (due to
                        // DnsState::Finished)
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Err(e) => match e {
                        dns::GetQueryResultError::Pending => {
                            stack
                                .socket_set
                                .get_mut::<dns::Socket>(dns_handle)
                                .register_query_waker(query_handle, cx.waker());
                            Poll::Pending
                        }
                        dns::GetQueryResultError::Failed => {
                            #[cfg(feature = "defmt")]
                            defmt::warn!("DNS failed! Restarting from the beginning");
                            stack
                                .socket_set
                                .get_mut::<dhcpv4::Socket>(dhcp_handle)
                                .reset();
                            stack.state = StackState::DhcpPending;
                            // Wake the waker immediately so that we can restart
                            // the entire process
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        }
                    },
                }
            }
            DnsState::Finished => {
                if let Some(address) = stack.dns_result.first() {
                    let address = address.clone();
                    match stack.try_connect_sockets(address, self.port) {
                        Ok(_) => {
                            #[cfg(feature = "defmt")]
                            defmt::info!("Setting up TCP connection...");
                            return Poll::Ready(Ok(()));
                        }
                        Err(_) => {
                            #[cfg(feature = "defmt")]
                            defmt::error!("Failed to connect to TCP!");
                            stack
                                .socket_set
                                .get_mut::<dhcpv4::Socket>(dhcp_handle)
                                .reset();
                            stack.state = StackState::DhcpPending;
                            // Wake the waker immediately so that we can restart
                            // the entire process
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        }
                    }
                } else {
                    // DNS has completed, but we didn't get any results. Reset DHCP so that
                    // we may obtain a new address and maybe new DNS servers
                    #[cfg(feature = "defmt")]
                    defmt::info!("DNS completed without results. Restarting DHCP client");
                    stack
                        .socket_set
                        .get_mut::<dhcpv4::Socket>(dhcp_handle)
                        .reset();
                    stack.state = StackState::DhcpPending;
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
        }
    }
}

impl<'a, 'stack_borrow, 'stack, 's, DeviceT, Stack> Future
    for ConnectFuture<'a, 'stack_borrow, Stack>
where
    DeviceT: for<'c> Device<'c>,
    Stack: Lockable<T = NetworkStack<'stack, 's, DeviceT>>,
{
    type Output = Result<(), ()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let inner = &mut this.inner;

        this.stack.lock(|stack| inner.poll(stack, cx))
    }
}
