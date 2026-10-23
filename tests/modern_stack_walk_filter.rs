//! Integration test for modern (manifest) stack walks with
//! `ProviderFilter::stack_walk()`.
//!
//! Adapted from `examples/05_delayed_stack_walks.rs`. Confirms that
//! `enable_provider_ex` accepts a `ProviderFilter` carrying both an
//! `event_ids` filter and a `stack_walk` filter and delivers TCP events
//! end-to-end. Uses a localhost TCP listener instead of an external host
//! so the test has no network dependency.
//!
//! This is the only integration test exercising the
//! `EVENT_FILTER_TYPE_STACKWALK` filter descriptor path in
//! `session/trace.rs::enable_provider_core`.
//!
//! # Requirements
//!
//! Administrator (manifest provider with stack tracing).

#![cfg(not(miri))]
// Win32 API calls are not supported under Miri.
#![expect(
    clippy::print_stdout,
    clippy::expect_used,
    clippy::clone_on_ref_ptr,
    reason = "test binary: printing aids diagnosis and panics are the failure mode"
)]

#[path = "common/mod.rs"]
mod common;

use etw::{EnableProperty, EventIdFilter, ProviderFilter, Trace};
use example_providers::kernel::tcpip;
use std::{
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering::Relaxed},
    },
    thread,
    time::{Duration, Instant},
};
use windows::Win32::System::Diagnostics::Etw::TRACE_LEVEL_INFORMATION;

#[test]
fn test_modern_stack_walk_filter() {
    // Bind a localhost listener so we can reliably trigger TCP_REQUEST_CONNECT
    // without any external network dependency.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind localhost");
    let local: SocketAddr = listener.local_addr().expect("local_addr");

    let mut trace = Trace::new("etw-rs_Test_ModernStackWalk").expect("session creation");
    let Some(()) = common::skip_or_panic("trace.start", trace.start()) else {
        return;
    };

    trace
        .enable_provider_ex(
            tcpip::GUID,
            TRACE_LEVEL_INFORMATION,
            tcpip::keyword::CONNECT_PATH,
            EnableProperty::STACK_TRACE,
            Some(
                ProviderFilter::new()
                    .event_ids(EventIdFilter::include(&[tcpip::event::TCP_REQUEST_CONNECT]))
                    .stack_walk(EventIdFilter::include(&[tcpip::event::TCP_REQUEST_CONNECT])),
            ),
        )
        .expect("enable_provider_ex with STACK_TRACE + ProviderFilter::stack_walk");

    let our_pid = std::process::id();
    let connect_events = Arc::new(AtomicUsize::new(0));
    let connect_events_cb = connect_events.clone();

    trace.set_event_callback(move |event, _ctx| {
        if event.provider_guid() == tcpip::GUID
            && event.id() == tcpip::event::TCP_REQUEST_CONNECT
            && event.process_id() == our_pid
        {
            connect_events_cb.fetch_add(1, Relaxed);
        }
        Ok(())
    });

    trace
        .start_processing_thread()
        .expect("start_processing_thread");

    // Drive a TCP connect from this process so we know which events are ours.
    let acceptor = thread::spawn(move || {
        // Accept and immediately drop. We only need the SYN to fire the
        // TCP_REQUEST_CONNECT event in the connecting process.
        let _ = listener.accept();
    });

    // Allow the trace to begin draining before the connect.
    thread::sleep(Duration::from_millis(200));

    let _stream = TcpStream::connect_timeout(&local, Duration::from_secs(2))
        .expect("connect to localhost listener");
    let _ = acceptor.join();

    // Wait up to 5s for our TCP_REQUEST_CONNECT to land.
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && connect_events.load(Relaxed) == 0 {
        thread::sleep(Duration::from_millis(50));
    }

    trace.stop().expect("stop");

    let n = connect_events.load(Relaxed);
    println!("TCP_REQUEST_CONNECT events for pid {our_pid}: {n}");
    assert!(
        n > 0,
        "no TCP_REQUEST_CONNECT events captured for our process — \
         ProviderFilter combination may have suppressed delivery"
    );
}
