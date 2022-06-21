extern crate alloc;
extern crate std;

use std::time::SystemTime;

use alloc::boxed::Box;
use smoltcp::{
    iface::{InterfaceBuilder, NeighborCache, SocketHandle, SocketSet, SocketStorage},
    phy::{Loopback, Medium},
    socket::{dns, tcp},
    time::Instant,
    wire::{EthernetAddress, IpAddress, IpCidr, Ipv4Address},
};

use crate::async_nal::{NetworkStack, TcpReader, TcpRecvError};

#[derive(Debug, Clone)]
pub struct Clock {}

impl Clock {
    pub fn elapsed() -> Instant {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis();

        Instant::from_millis(now as i64)
    }
}

fn setup_stack(
    data: &[u8],
) -> (
    NetworkStack<'static, 'static, Loopback>,
    SocketHandle,
    TcpReader,
) {
    let mut loopback = Loopback::new(Medium::Ethernet);

    let ip_addrs = [IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8)];
    let neighbor_cache_entries = &mut Box::leak(Box::new([None; 8]))[..];
    let neighbor_cache = NeighborCache::new(neighbor_cache_entries);

    let socket_storage = &mut Box::leak(Box::new([
        SocketStorage::default(),
        SocketStorage::default(),
        SocketStorage::default(),
        SocketStorage::default(),
    ]))[..];
    let mut socket_set = SocketSet::new(socket_storage);

    let iface = InterfaceBuilder::new()
        .hardware_addr(EthernetAddress::default().into())
        .neighbor_cache(neighbor_cache)
        .ip_addrs(ip_addrs)
        .finalize(&mut loopback);

    let rx_buffer = &mut Box::leak(Box::new([0u8; 2048]))[..];
    let rx_buffer = tcp::SocketBuffer::new(rx_buffer);
    let tx_buffer = &mut Box::leak(Box::new([0u8; 2048]))[..];
    let tx_buffer = tcp::SocketBuffer::new(tx_buffer);
    let tcp_socket = tcp::Socket::new(rx_buffer, tx_buffer);
    let tcp_handle = socket_set.add(tcp_socket);

    let rx_buffer = &mut Box::leak(Box::new([0u8; 2048]))[..];
    let rx_buffer = tcp::SocketBuffer::new(rx_buffer);
    let tx_buffer = &mut Box::leak(Box::new([0u8; 2048]))[..];
    let tx_buffer = tcp::SocketBuffer::new(tx_buffer);
    let server_tcp_socket = tcp::Socket::new(rx_buffer, tx_buffer);
    let server_tcp_handle = socket_set.add(server_tcp_socket);
    socket_set
        .get_mut::<tcp::Socket>(server_tcp_handle)
        .listen(smoltcp::wire::IpListenEndpoint {
            addr: None,
            port: 7878,
        })
        .unwrap();

    let ip_addrs = &mut [IpAddress::Ipv4(Ipv4Address::UNSPECIFIED); 4][..];
    let queries = Box::leak(Box::new([None, None, None, None, None, None, None, None]));
    let dns_socket = dns::Socket::new(ip_addrs, &mut queries[..]);
    let dns_handle = socket_set.add(dns_socket);

    let (mut stack, read_handle, _write_handle) = NetworkStack::new(
        loopback,
        socket_set,
        iface,
        tcp_handle,
        dns_handle,
        Clock::elapsed,
    );

    stack
        .try_connect_sockets(IpAddress::v4(127, 0, 0, 1), 7878)
        .unwrap();

    // Poll a few times to get the TCP sockets to connect
    stack.poll_iface().unwrap();
    stack.poll_iface().unwrap();

    let server_tcp_socket = stack.socket_set().get_mut::<tcp::Socket>(server_tcp_handle);
    server_tcp_socket.send_slice(data).unwrap();

    stack.poll_iface().unwrap();
    stack.poll_iface().unwrap();

    (stack, server_tcp_handle, read_handle)
}

#[tokio::test]
async fn multiple_frames_buffered() {
    let (mut stack, _server_tcp_handle, mut read_handle) =
        setup_stack(&[1, 2, 3, 4, 5, 0, 6, 7, 8, 9, 10, 0]);

    let read_buffer = &mut [0u8; 50];
    let read_res = read_handle
        .read_frame(&mut stack, read_buffer, 0)
        .await
        .unwrap();

    assert_eq!(&[1, 2, 3, 4, 5, 0], &read_buffer[..read_res]);

    let read_buffer2 = &mut [0u8; 50];
    let read_res2 = read_handle
        .read_frame(&mut stack, read_buffer2, 0)
        .await
        .unwrap();

    assert_eq!(&[6, 7, 8, 9, 10, 0], &read_buffer2[..read_res2]);
}

#[tokio::test]
async fn no_data() {
    let (mut stack, _server_tcp_handle, mut read_handle) = setup_stack(&[]);

    let read_buffer = &mut [0u8; 50];
    let read_res = read_handle.read_frame(&mut stack, read_buffer, 0);

    let read_res = tokio::time::timeout(std::time::Duration::from_millis(1), read_res).await;

    // Assert that the read timed out (which it should)
    // Technically the underlying TCP socket should be timing out, but we're
    // not polling that so it won't
    assert!(read_res.is_err());
}

#[tokio::test]
async fn full_buffer() {
    let (mut stack, _server_tcp_handle, mut read_handle) = setup_stack(&[1, 2, 3, 0]);

    let read_buffer = &mut [0u8; 2];
    let read_res = read_handle.read_frame(&mut stack, read_buffer, 0).await;

    // Assert that the message will not fit
    assert!(read_res == Err(TcpRecvError::MessageWillNotFit));
}
