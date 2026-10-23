//! Integration test for Microsoft-Windows-DNS-Client provider
//!
//! Requirements:
//! - Requires Performance Log Users group membership (or Administrator) for ETW session creation
//! - Requires active network connectivity for DNS queries

#![cfg(not(miri))]
// Win32 API calls are not supported under Miri.
// Tests use println for output and unwrap/expect for cleaner test code
#![expect(
    clippy::print_stdout,
    clippy::expect_used,
    clippy::clone_on_ref_ptr,
    clippy::missing_const_for_fn,
    clippy::undocumented_unsafe_blocks,
    reason = "test binary: printing aids diagnosis and panics are the failure mode"
)]

#[path = "common/mod.rs"]
mod common;

use etw::{ALL_KEYWORDS, Trace, session::EventIdFilter};
use example_providers::user::dns_client;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use windows::Win32::System::{
    Diagnostics::Etw::TRACE_LEVEL_INFORMATION, Threading::GetCurrentThreadId,
};

const QUERY_START: u16 = 3008;

/// Test capturing DNS query start events with kernel-level Event ID filtering.
///
/// Drops other threads' events in the callback, giving an exact expected
/// count: 2 events per hostname (A + AAAA).
#[test]
fn test_user_dns_client_events() {
    let mut trace = Trace::new("etw-rs_Test_DnsClient").expect("Failed to create trace session");

    let Some(()) = common::skip_or_panic("trace.start", trace.start()) else {
        return;
    };

    // Enable DNS provider with Event ID filter — only receive QUERY_START events.
    // Filtering to a single event type gives a predictable count: one event per
    // DNS query type (A + AAAA) per hostname.
    trace
        .enable_provider_ex(
            dns_client::GUID,
            TRACE_LEVEL_INFORMATION,
            ALL_KEYWORDS,
            0,
            Some(EventIdFilter::include(&[QUERY_START]).into()),
        )
        .expect("Failed to enable DNS Client provider with filter");

    // Counter for captured events
    let event_count = Arc::new(AtomicUsize::new(0));

    // Our event callback — kernel-level Event ID filter means we only receive QUERY_START.
    // Callback-side thread ID check isolates our queries from background DNS noise.
    let tid = unsafe { GetCurrentThreadId() };
    let event_count_clone = event_count.clone();
    trace.set_event_callback(move |event, context| {
        if event.thread_id() != tid {
            return Ok(());
        }

        debug_assert_eq!(
            event.id(),
            QUERY_START,
            "Unexpected event ID {} — filter should have blocked it",
            event.id()
        );

        let mut parser = context.parser(event)?;

        let query: String = parser.get("QueryName")?;
        let query_type: u32 = parser.get("QueryType")?;
        println!(
            "Captured DNS event:\n  Event ID: {}\n  QueryName: {query}\n  QueryType: {} ({})",
            event.id(),
            query_type,
            dns_record_type_name(query_type as u16)
        );

        event_count_clone.fetch_add(1, Ordering::Relaxed);
        Ok(())
    });

    trace
        .start_processing_thread()
        .expect("Failed to start event processing");

    // Trigger DNS queries
    let successful_queries = trigger_dns_queries();

    // Wait for events to be captured (up to 5 seconds).
    // Each hostname lookup triggers A + AAAA queries = 2 events per hostname.
    // The callback counts only this thread's queries, so the count should be exact.
    let expected = 2 * successful_queries;
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(100));
        if event_count.load(Ordering::Relaxed) >= expected {
            break;
        }
    }

    trace.stop().expect("Failed to stop session");

    // Report results
    let captured = event_count.load(Ordering::Relaxed);
    println!("\nCaptured {captured} DNS query events (expected {expected})");

    assert_eq!(
        captured, expected,
        "Expected {expected} query events (2 per hostname for A+AAAA)"
    );
}

/// Trigger DNS queries to generate ETW events
///
/// Returns the number of successful DNS queries.
fn trigger_dns_queries() -> usize {
    use std::net::ToSocketAddrs;

    let hostnames = ["example.com", "microsoft.com", "google.com"];
    let mut successful = 0;

    for hostname in &hostnames {
        println!("  Querying: {hostname}");
        if format!("{hostname}:443").to_socket_addrs().is_ok() {
            successful += 1;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    successful
}

/// Convert DNS record type number to name
fn dns_record_type_name(record_type: u16) -> &'static str {
    match record_type {
        1 => "A (IPv4 address)",
        2 => "NS (Name server)",
        5 => "CNAME (Canonical name)",
        6 => "SOA (Start of authority)",
        12 => "PTR (Pointer)",
        15 => "MX (Mail exchange)",
        16 => "TXT (Text)",
        28 => "AAAA (IPv6 address)",
        33 => "SRV (Service)",
        _ => "Unknown",
    }
}
