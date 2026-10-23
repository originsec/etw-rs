//! Integration tests verifying that buffer configuration survives start().
//!
//! These tests configure buffer properties, start a trace session, then
//! verify the OS received the requested values (via properties readback).

#![cfg(not(miri))]
// Win32 API calls are not supported under Miri.
// Tests use println for output and unwrap/expect for cleaner test code
#![expect(
    clippy::print_stdout,
    clippy::expect_used,
    reason = "test binary: printing aids diagnosis and panics are the failure mode"
)]

#[path = "common/mod.rs"]
mod common;

use etw::Trace;

/// Test that Trace buffer configuration survives start().
#[test]
fn test_realtime_trace_buffer_config() {
    let mut trace = Trace::new("etw-rs_Test_RT_BufCfg").expect("Failed to create trace session");

    // Configure buffer properties before start
    let _ = trace
        .set_buffer_size(128)
        .set_minimum_buffers(8)
        .set_maximum_buffers(64)
        .set_flush_timer(2);

    let Some(()) = common::skip_or_panic("trace.start", trace.start()) else {
        return;
    };

    // After start, the OS writes back actual values. BufferSize should be
    // what we requested (or clamped by OS). It must not be zero.
    let props = trace.properties();
    println!(
        "After start: BufferSize={} MinBuf={} MaxBuf={} FlushTimer={}",
        props.BufferSize, props.MinimumBuffers, props.MaximumBuffers, props.FlushTimer
    );

    assert_eq!(props.BufferSize, 128, "BufferSize should survive start()");
    assert!(
        props.MinimumBuffers >= 8,
        "MinimumBuffers should be at least what we requested (got {})",
        props.MinimumBuffers
    );
    assert!(
        props.MaximumBuffers >= props.MinimumBuffers,
        "MaximumBuffers ({}) should be >= MinimumBuffers ({})",
        props.MaximumBuffers,
        props.MinimumBuffers
    );
    assert_eq!(props.FlushTimer, 2, "FlushTimer should survive start()");

    trace.stop().expect("Failed to stop session");
}

/// Test that Trace buffer configuration survives start() for a system trace.
#[test]
#[serial_test::serial(system_logger)]
fn test_system_trace_buffer_config() {
    let mut trace = Trace::new("etw-rs_Test_ST_BufCfg").expect("Failed to create trace session");

    // Configure buffer properties before start (also enables system logger mode)
    use etw::system_logger::masks::PERF_PROCESS;
    let _ = trace
        .set_buffer_size(128)
        .set_minimum_buffers(8)
        .set_maximum_buffers(64)
        .set_flush_timer(2);
    trace.set_events(&[PERF_PROCESS]);

    let Some(()) = common::skip_or_panic("trace.start", trace.start()) else {
        return;
    };

    // After start, the OS writes back actual values
    let props = trace.properties();
    println!(
        "After start: BufferSize={} MinBuf={} MaxBuf={} FlushTimer={}",
        props.BufferSize, props.MinimumBuffers, props.MaximumBuffers, props.FlushTimer
    );

    assert_eq!(props.BufferSize, 128, "BufferSize should survive start()");
    assert!(
        props.MinimumBuffers >= 8,
        "MinimumBuffers should be at least what we requested (got {})",
        props.MinimumBuffers
    );
    assert!(
        props.MaximumBuffers >= props.MinimumBuffers,
        "MaximumBuffers ({}) should be >= MinimumBuffers ({})",
        props.MaximumBuffers,
        props.MinimumBuffers
    );
    assert_eq!(props.FlushTimer, 2, "FlushTimer should survive start()");

    trace.stop().expect("Failed to stop session");
}

/// A new session must be able to take over a name that is already in use.
///
/// `start()` stops any existing session with the same name before calling
/// `StartTraceW`. `ControlTraceW(STOP)` reports `ERROR_MORE_DATA` when the
/// caller's buffer has no room for the logger-name strings it writes back —
/// but the session is stopped regardless, so recovery must treat that status
/// as a completed stop. Before it did, a duplicate name failed takeover with
/// `Win32Error(234, MORE_DATA)` instead of starting.
#[test]
fn test_start_takes_over_existing_session_name() {
    let mut first = Trace::new("etw-rs_Test_Takeover").expect("Failed to create trace session");
    let Some(()) = common::skip_or_panic("first.start", first.start()) else {
        return;
    };

    let mut second = Trace::new("etw-rs_Test_Takeover").expect("Failed to create trace session");
    second
        .start()
        .expect("start() with an in-use name should stop the existing session and succeed");
    second.stop().expect("Failed to stop session");
    // `first` now holds a stale handle; its Drop must tolerate the session
    // having been stopped out from under it.
}

/// `session_id()` is `None` before `start()` and `Some` once the session has a
/// live control ID — the after-start half of the accessor's contract, which the
/// unit test cannot cover without an ETW session.
#[test]
fn test_session_id_is_some_after_start() {
    let mut trace = Trace::new("etw-rs_Test_SessionId").expect("Failed to create trace session");
    assert_eq!(trace.session_id(), None, "no control ID before start()");

    let Some(()) = common::skip_or_panic("trace.start", trace.start()) else {
        return;
    };

    let id = trace
        .session_id()
        .expect("a started session must expose a control ID");
    assert_ne!(id, 0, "the control ID must not be the NULL sentinel");

    trace.stop().expect("Failed to stop session");
}
