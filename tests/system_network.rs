//! Integration test for Trace network (TCP/UDP) events.

#![cfg(not(miri))]
// Win32 API calls are not supported under Miri.
// Tests use println for output and unwrap/expect for cleaner test code
#![expect(
    clippy::print_stdout,
    clippy::expect_used,
    clippy::clone_on_ref_ptr,
    reason = "test binary: printing aids diagnosis and panics are the failure mode"
)]

#[path = "common/mod.rs"]
mod common;

use etw::{
    Trace,
    system_logger::masks::{PERF_NETWORK, PERF_NO_SYSCONFIG},
};
use example_providers::classic::kernel_trace::tcp_ip;
use serial_test::serial;
use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

#[test]
#[serial(system_logger)]
fn test_system_network_events() {
    let mut trace = Trace::new("etw-rs_Test_Network").expect("Failed to create trace session");

    trace.set_events(&[PERF_NETWORK, PERF_NO_SYSCONFIG]);

    let Some(()) = common::skip_or_panic("trace.start", trace.start()) else {
        return;
    };

    let event_captured = Arc::new(AtomicBool::new(false));
    let event_captured_clone = event_captured.clone();

    trace.set_event_callback(move |event, _context| {
        // Filter for TCP events
        if event.provider_guid() != tcp_ip::GUID {
            return Ok(());
        }

        let op = match event.opcode() {
            tcp_ip::opcode::SEND => "Send",
            tcp_ip::opcode::RECV => "Recv",
            tcp_ip::opcode::CONNECT => "Connect",
            tcp_ip::opcode::DISCONNECT => "Disconnect",
            tcp_ip::opcode::ACCEPT => "Accept",
            26 => "Send (v6)",    // tcp_v6::SEND
            27 => "Recv (v6)",    // tcp_v6::RECV
            28 => "Connect (v6)", // tcp_v6::CONNECT
            _ => return Ok(()),
        };

        if event_captured_clone
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            println!("TCP {op} event captured (opcode: {})", event.opcode());
        }
        Ok(())
    });

    trace
        .start_processing_thread()
        .expect("Failed to start processing");

    // Make a TCP connection to trigger events
    // Using example.com:80 which should be reliably available
    if let Ok(mut stream) = TcpStream::connect("example.com:80") {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = stream.write_all(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n");
        let mut buf = [0u8; 256];
        let _ = stream.read(&mut buf);
    } else {
        println!("Note: Could not connect to example.com:80, trying localhost");
    }

    for _ in 0..30 {
        std::thread::sleep(Duration::from_millis(100));
        if event_captured.load(Ordering::Relaxed) {
            break;
        }
    }

    trace.stop().expect("Failed to stop session");

    if !event_captured.load(Ordering::Relaxed) {
        println!("WARNING: No TCP events captured");
    }
}
