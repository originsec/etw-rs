//! Integration test for `Trace::enable_object_type_filter`.
//!
//! The filter restricts PERF_OB_HANDLE events to the requested object-type
//! pool tags. The test checks the stored configuration and that events
//! still arrive; it does not check which tags arrive.
//!
//! This is the only test exercising
//! `system_logger/mod.rs::enable_object_type_filter` and its
//! `NtSetSystemInformation(EVENT_TRACE_OBJECT_TYPE_FILTER_INFORMATION)`
//! call.
//!
//! # Requirements
//!
//! Administrator (kernel system trace).

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

use etw::{Trace, pool_tag, system_logger::masks::PERF_OB_HANDLE};
use serial_test::serial;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering::Relaxed},
    },
    thread::sleep,
    time::Duration,
};

#[test]
#[serial(system_logger)]
fn test_enable_object_type_filter() {
    let mut trace = Trace::new("etw-rs_Test_ObjFilter").expect("session creation");
    trace.set_events(&[PERF_OB_HANDLE]);
    let Some(()) = common::skip_or_panic("trace.start", trace.start()) else {
        return;
    };

    // Filter to Process and Thread object types only.
    trace
        .enable_object_type_filter(&[pool_tag(b"Proc"), pool_tag(b"Thre")])
        .expect("enable_object_type_filter");

    // Accessor round-trip: the configured tags should be readable back.
    let stored = trace.object_type_tags();
    assert_eq!(stored.len(), 2);
    assert!(stored.contains(&pool_tag(b"Proc")));
    assert!(stored.contains(&pool_tag(b"Thre")));

    let event_count = Arc::new(AtomicUsize::new(0));
    let event_count_cb = event_count.clone();

    trace.set_event_callback(move |_event, _ctx| {
        event_count_cb.fetch_add(1, Relaxed);
        Ok(())
    });

    trace
        .start_processing_thread()
        .expect("start_processing_thread");

    // Some background activity over a short window should produce object
    // handle events for processes and threads.
    sleep(Duration::from_secs(2));

    trace.stop().expect("stop");

    let n = event_count.load(Relaxed);
    println!("events captured under object_type_filter[Proc,Thre]: {n}");
    assert!(n > 0, "no events captured under object_type_filter");
}

#[test]
#[serial(system_logger)]
fn test_enable_object_type_filter_empty_is_noop() {
    let mut trace = Trace::new("etw-rs_Test_ObjFilterEmpty").expect("session creation");
    trace.set_events(&[PERF_OB_HANDLE]);
    let Some(()) = common::skip_or_panic("trace.start", trace.start()) else {
        return;
    };

    // Empty tag list is a documented no-op (returns Ok without invoking the
    // NtSetSystemInformation path).
    trace
        .enable_object_type_filter(&[])
        .expect("empty tag list should succeed as a no-op");

    // No tags should be stored.
    assert!(trace.object_type_tags().is_empty());

    trace.stop().expect("stop");
}

/// The tag cap is reachable from runtime data, so exceeding it must come back
/// as an error the caller can handle — not a panic — and leave no filter set.
#[test]
#[serial(system_logger)]
fn test_enable_object_type_filter_too_many_returns_error() {
    let mut trace = Trace::new("etw-rs_Test_ObjFilterTooMany").expect("session creation");
    trace.set_events(&[PERF_OB_HANDLE]);
    let Some(()) = common::skip_or_panic("trace.start", trace.start()) else {
        return;
    };

    let tags = [b"Proc", b"Thre", b"File", b"Key ", b"Toke"].map(pool_tag);
    let err = trace
        .enable_object_type_filter(&tags)
        .expect_err("5 tags exceeds ETW_MAX_OBJECT_TYPE_FILTER");
    assert!(
        matches!(
            err,
            etw::Error::InvalidParameter {
                parameter: "object type filter",
                problem: etw::ParameterProblem::TooMany { count: 5, max: 4 }
            }
        ),
        "got {err:?}"
    );
    assert!(trace.object_type_tags().is_empty());

    trace.stop().expect("stop");
}
