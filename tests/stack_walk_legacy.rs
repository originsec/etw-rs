//! Integration test for legacy (system logger) stack walks.
//!
//! Adapted from `examples/11_typical_system_trace.rs`.
//!
//! The lib's in-file unit tests already cover `StackWalkData::from_event`'s
//! mock path. This test exercises it end-to-end against real ETW events to
//! catch any divergence between the assumed and actual on-the-wire layout.
//!
//! # Requirements
//!
//! - Administrator (kernel system trace).

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

use etw::{
    Trace,
    stack_walk::StackWalkData,
    system_logger::masks::{PERF_NO_SYSCONFIG, PERF_PROCESS},
};
use example_providers::classic::{process, stack_walk};
use serial_test::serial;
use std::{
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

#[test]
#[serial(system_logger)]
fn test_legacy_stack_walk_parsing() {
    let mut trace = Trace::new("etw-rs_Test_LegacyStack").expect("session creation");
    trace
        .set_events(&[PERF_PROCESS, PERF_NO_SYSCONFIG])
        .set_stack_walking(&[process::hook_id::START])
        .expect("set_stack_walking");
    let Some(()) = common::skip_or_panic("trace.start", trace.start()) else {
        return;
    };

    let process_starts = Arc::new(AtomicUsize::new(0));
    let stack_walks = Arc::new(AtomicUsize::new(0));
    let parse_failures = Arc::new(AtomicUsize::new(0));
    let consistency_failures = Arc::new(AtomicUsize::new(0));

    let process_starts_cb = process_starts.clone();
    let stack_walks_cb = stack_walks.clone();
    let parse_failures_cb = parse_failures.clone();
    let consistency_failures_cb = consistency_failures.clone();

    trace.set_event_callback(move |event, _context| {
        // Wrap in catch_unwind so a panic on the processing thread is reported
        // rather than silently killing the thread.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            match event.provider_guid() {
                g if g == process::CLASS_GUID && event.opcode() == process::opcode::START => {
                    process_starts_cb.fetch_add(1, Ordering::Relaxed);
                }
                g if g == stack_walk::CLASS_GUID && event.opcode() == stack_walk::opcode::STACK => {
                    stack_walks_cb.fetch_add(1, Ordering::Relaxed);
                    match StackWalkData::from_event(event) {
                        Ok(data) => {
                            // Internal consistency: slice length must match the
                            // computed frame count.
                            if data.addresses().len() != data.len() {
                                consistency_failures_cb.fetch_add(1, Ordering::Relaxed);
                            }
                            // is_empty must agree with len.
                            #[expect(
                                clippy::len_zero,
                                reason = "the len == 0 comparison is precisely what is under test"
                            )]
                            if data.is_empty() != (data.len() == 0) {
                                consistency_failures_cb.fetch_add(1, Ordering::Relaxed);
                            }
                            // address(0) is None iff stack is empty.
                            if data.is_empty() && data.address(0).is_some() {
                                consistency_failures_cb.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        Err(_) => {
                            parse_failures_cb.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                _ => {}
            }
        }));
        if result.is_err() {
            consistency_failures_cb.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    });

    trace
        .start_processing_thread()
        .expect("start_processing_thread");

    // Spawn child processes to trigger PROCESS_START events with stack walks.
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && stack_walks.load(Ordering::Relaxed) == 0 {
        let _ = Command::new("cmd.exe")
            .args(["/c", "echo", "test"])
            .output();
        thread::sleep(Duration::from_millis(100));
    }

    trace.stop().expect("stop");

    let starts = process_starts.load(Ordering::Relaxed);
    let walks = stack_walks.load(Ordering::Relaxed);
    let parse_fails = parse_failures.load(Ordering::Relaxed);
    let consistency_fails = consistency_failures.load(Ordering::Relaxed);
    println!(
        "process starts: {starts}, stack walks: {walks}, parse failures: {parse_fails}, consistency failures: {consistency_fails}"
    );

    assert!(starts > 0, "no PROCESS_START events captured");
    assert!(walks > 0, "no StackWalk events captured");
    assert_eq!(parse_fails, 0, "StackWalkData parse failures");
    assert_eq!(consistency_fails, 0, "StackWalkData consistency failures");
}
