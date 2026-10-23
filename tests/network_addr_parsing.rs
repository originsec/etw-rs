//! Integration tests for network address field parsing from real ETW events.
//!
//! All three tests use loopback connections with known ground-truth values so
//! address and port fields can be asserted exactly:
//!
//! - `SocketAddr` from `Microsoft-Windows-TCPIP` event 1002 (SOCKADDR binary)
//! - `Ipv4Addr` + `u16` port from `Microsoft-Windows-Kernel-Network`
//!   `TCPIP_CONNECTION_ATTEMPTED_IPV4` (raw u32 address, raw u16 port)
//! - `Ipv6Addr` + `u16` port from `Microsoft-Windows-Kernel-Network`
//!   `TCPIP_CONNECTION_ATTEMPTED_IPV6` (16-byte binary address, raw u16 port)
//!
//! The Kernel-Network port fields are network-byte-order on the wire but
//! declared as TDH `UInt16`, so the parser reads them little-endian per spec
//! and callers `swap_bytes()` to compare to host-order port numbers — same
//! convention `parse_sockaddr_v4` / `_v6` apply internally for the SOCKADDR
//! port. The `Ipv4Addr` / `Ipv6Addr` impls decode network-order addresses
//! internally, so no swap is needed for `daddr` / `saddr`.

#![cfg(not(miri))]
// Win32 API calls are not supported under Miri.
// Tests use println for output and unwrap/expect for cleaner test code
#![expect(
    clippy::print_stdout,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::clone_on_ref_ptr,
    reason = "test binary: printing aids diagnosis and panics are the failure mode"
)]

#[path = "common/mod.rs"]
mod common;

use etw::Trace;
use example_providers::kernel::{network, tcpip};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

#[test]
fn test_tcpip_parses_sockaddr_fields() {
    // Bind a loopback listener so we know the exact destination address and port.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    let listen_port = listener.local_addr().unwrap().port();
    let expected_dst: SocketAddr = SocketAddr::from(([127, 0, 0, 1], listen_port));

    let mut trace =
        Trace::new("etw-rs_Test_TCPIP_SockAddr").expect("Failed to create trace session");

    let Some(()) = common::skip_or_panic("trace.start", trace.start()) else {
        return;
    };

    // Event 1002 (TcpRequestConnect) requires TCPIP_DIAGNOSIS + CONNECT_PATH + ENDPOINT.
    trace
        .enable_provider(
            tcpip::GUID,
            tcpip::keyword::TCPIP_DIAGNOSIS
                | tcpip::keyword::CONNECT_PATH
                | tcpip::keyword::ENDPOINT,
        )
        .expect("Failed to enable TCPIP provider");

    let captured: Arc<Mutex<Option<(SocketAddr, SocketAddr)>>> = Arc::new(Mutex::new(None));
    let captured_clone = Arc::clone(&captured);
    let got_event = Arc::new(AtomicBool::new(false));
    let got_event_clone = got_event.clone();
    let listen_port_cb = listen_port;

    trace.set_event_callback(move |event, context| {
        if event.id() != tcpip::event::TCP_REQUEST_CONNECT {
            return Ok(());
        }
        let mut parser = context.parser(event)?;
        let _tcb: usize = parser.get("Tcb")?;
        let _local_len: u32 = parser.get("LocalAddressLength")?;
        let local_addr: SocketAddr = parser.get("LocalAddress")?;
        let _remote_len: u32 = parser.get("RemoteAddressLength")?;
        let remote_addr: SocketAddr = parser.get("RemoteAddress")?;
        if remote_addr.port() == listen_port_cb {
            println!("TCPIP TcpRequestConnect: local={local_addr} remote={remote_addr}");
            *captured_clone.lock().unwrap() = Some((local_addr, remote_addr));
            got_event_clone.store(true, Ordering::Relaxed);
        }
        Ok(())
    });

    trace
        .start_processing_thread()
        .expect("Failed to start processing");

    // Accept in background so the three-way handshake completes.
    let accept_handle = std::thread::spawn(move || {
        let _ = listener.accept();
    });

    let _stream = TcpStream::connect(expected_dst).expect("connect to loopback listener");

    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(100));
        if got_event.load(Ordering::Relaxed) {
            break;
        }
    }
    let _ = accept_handle.join();
    trace.stop().expect("Failed to stop session");

    let captured = captured.lock().unwrap();
    let (local_addr, remote_addr) = captured.expect(
        "no TcpRequestConnect event for our loopback connection — \
         check TCPIP provider keywords",
    );

    // SocketAddr exact match: parser must decode SOCKADDR_IN binary to the correct IP + port.
    assert_eq!(
        remote_addr, expected_dst,
        "TcpRequestConnect.RemoteAddress {remote_addr} != expected {expected_dst}"
    );
    assert_eq!(
        remote_addr.ip(),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        "RemoteAddress IP should be loopback 127.0.0.1"
    );
    assert_eq!(
        local_addr.ip(),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        "LocalAddress IP should be loopback 127.0.0.1"
    );

    println!("Validated: local={local_addr} remote={remote_addr} (expected remote={expected_dst})");
}

#[test]
fn test_kernel_network_ipv4_parses_ipv4addr_and_u16_fields() {
    // Bind a loopback listener so daddr / saddr have known values (127.0.0.1)
    // and the destination port is exactly listen_port.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    let listen_port = listener.local_addr().unwrap().port();

    let mut trace =
        Trace::new("etw-rs_Test_KernelNet_IPv4").expect("Failed to create trace session");

    let Some(()) = common::skip_or_panic("trace.start", trace.start()) else {
        return;
    };

    let Some(()) = common::skip_or_panic(
        "Failed to enable Kernel-Network provider",
        trace.enable_provider(network::GUID, network::keyword::IPV4),
    ) else {
        return;
    };

    struct Captured {
        daddr: Ipv4Addr,
        saddr: Ipv4Addr,
        dport: u16,
        sport: u16,
    }
    let captured: Arc<Mutex<Option<Captured>>> = Arc::new(Mutex::new(None));
    let captured_clone = Arc::clone(&captured);
    let got_event = Arc::new(AtomicBool::new(false));
    let got_event_clone = got_event.clone();
    // Match against the listener port in network byte order: the kernel writes
    // dport/sport big-endian on the wire and the u16 FromProperty reads them
    // little-endian per TDH spec.
    let listen_port_be = listen_port.swap_bytes();

    trace.set_event_callback(move |event, context| {
        if event.id() != network::event::TCPIP_CONNECTION_ATTEMPTED_IPV4 {
            return Ok(());
        }
        let mut parser = context.parser(event)?;
        let dport: u16 = parser.get("dport")?;
        if dport != listen_port_be {
            return Ok(());
        }
        let daddr: Ipv4Addr = parser.get("daddr")?;
        let saddr: Ipv4Addr = parser.get("saddr")?;
        let sport: u16 = parser.get("sport")?;
        *captured_clone.lock().unwrap() = Some(Captured {
            daddr,
            saddr,
            dport,
            sport,
        });
        got_event_clone.store(true, Ordering::Relaxed);
        Ok(())
    });

    trace
        .start_processing_thread()
        .expect("Failed to start processing");

    let accept_handle = std::thread::spawn(move || {
        let _ = listener.accept();
    });
    let _stream = TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], listen_port)))
        .expect("connect to loopback listener");

    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(100));
        if got_event.load(Ordering::Relaxed) {
            break;
        }
    }
    let _ = accept_handle.join();
    trace.stop().expect("Failed to stop session");

    let captured = captured.lock().unwrap();
    let c = captured.as_ref().unwrap_or_else(|| {
        panic!(
            "no TCPIP_CONNECTION_ATTEMPTED_IPV4 event for our loopback flow \
             -> 127.0.0.1:{listen_port} — check Kernel-Network provider availability"
        )
    });

    // Ipv4Addr exact match: parser must decode raw u32 bytes to network order.
    assert_eq!(
        c.daddr,
        Ipv4Addr::LOCALHOST,
        "daddr {} should be 127.0.0.1",
        c.daddr
    );
    assert_eq!(
        c.saddr,
        Ipv4Addr::LOCALHOST,
        "saddr {} should be 127.0.0.1",
        c.saddr
    );
    // u16 match: parser reads bytes as LE per TDH spec; ports are BE on the
    // wire, so swap to compare against host-order port numbers.
    assert_eq!(
        c.dport.swap_bytes(),
        listen_port,
        "dport bswap {} should match our listener port {listen_port}",
        c.dport.swap_bytes()
    );
    assert_ne!(c.sport, 0, "sport should be a non-zero ephemeral port");

    println!(
        "Validated: {}:{} -> {}:{} (expected dst 127.0.0.1:{listen_port}, ports BE on wire)",
        c.saddr,
        c.sport.swap_bytes(),
        c.daddr,
        c.dport.swap_bytes()
    );
}

#[test]
fn test_kernel_network_ipv6_parses_ipv6addr_and_u16_fields() {
    let Ok(listener) = TcpListener::bind("[::1]:0") else {
        println!("WARNING: IPv6 loopback not available, skipping");
        return;
    };
    let listen_port = listener.local_addr().unwrap().port();

    let mut trace =
        Trace::new("etw-rs_Test_KernelNet_IPv6").expect("Failed to create trace session");

    let Some(()) = common::skip_or_panic("trace.start", trace.start()) else {
        return;
    };

    let Some(()) = common::skip_or_panic(
        "Failed to enable Kernel-Network provider",
        trace.enable_provider(network::GUID, network::keyword::IPV6),
    ) else {
        return;
    };

    struct Captured {
        daddr: Ipv6Addr,
        saddr: Ipv6Addr,
        dport: u16,
        sport: u16,
    }
    let captured: Arc<Mutex<Option<Captured>>> = Arc::new(Mutex::new(None));
    let captured_clone = Arc::clone(&captured);
    let got_event = Arc::new(AtomicBool::new(false));
    let got_event_clone = got_event.clone();
    // Same port byte-order convention as the IPv4 test above.
    let listen_port_be = listen_port.swap_bytes();

    trace.set_event_callback(move |event, context| {
        if event.id() != network::event::TCPIP_CONNECTION_ATTEMPTED_IPV6 {
            return Ok(());
        }
        let mut parser = context.parser(event)?;
        let dport: u16 = parser.get("dport")?;
        if dport != listen_port_be {
            return Ok(());
        }
        let daddr: Ipv6Addr = parser.get("daddr")?;
        let saddr: Ipv6Addr = parser.get("saddr")?;
        let sport: u16 = parser.get("sport")?;
        *captured_clone.lock().unwrap() = Some(Captured {
            daddr,
            saddr,
            dport,
            sport,
        });
        got_event_clone.store(true, Ordering::Relaxed);
        Ok(())
    });

    trace
        .start_processing_thread()
        .expect("Failed to start processing");

    let accept_handle = std::thread::spawn(move || {
        let _ = listener.accept();
    });
    if TcpStream::connect(format!("[::1]:{listen_port}")).is_err() {
        println!("WARNING: IPv6 loopback connect failed, skipping");
        let _ = accept_handle.join();
        trace.stop().expect("stop");
        return;
    }

    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(100));
        if got_event.load(Ordering::Relaxed) {
            break;
        }
    }
    let _ = accept_handle.join();
    trace.stop().expect("Failed to stop session");

    let captured = captured.lock().unwrap();
    let c = captured.as_ref().unwrap_or_else(|| {
        panic!(
            "no TCPIP_CONNECTION_ATTEMPTED_IPV6 event for our loopback flow \
             -> [::1]:{listen_port} — check Kernel-Network provider availability"
        )
    });

    // Ipv6Addr exact match: parser must decode 16-byte binary to network order.
    assert_eq!(
        c.daddr,
        Ipv6Addr::LOCALHOST,
        "daddr {} should be ::1",
        c.daddr
    );
    assert_eq!(
        c.saddr,
        Ipv6Addr::LOCALHOST,
        "saddr {} should be ::1",
        c.saddr
    );
    // u16 match: same convention as IPv4 test (kernel BE, parser LE, swap).
    assert_eq!(
        c.dport.swap_bytes(),
        listen_port,
        "dport bswap {} should match our listener port {listen_port}",
        c.dport.swap_bytes()
    );
    assert_ne!(c.sport, 0, "sport should be a non-zero ephemeral port");

    println!(
        "Validated: [{}]:{} -> [{}]:{} (expected dst [::1]:{listen_port}, ports BE on wire)",
        c.saddr,
        c.sport.swap_bytes(),
        c.daddr,
        c.dport.swap_bytes()
    );
}
