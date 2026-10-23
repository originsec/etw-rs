//! Integration tests for runtime configuration of trace sessions.

#![cfg(not(miri))] // Win32 API calls are not supported under Miri.
// Tests use unwrap/expect for cleaner test code
#![expect(
    clippy::print_stdout,
    clippy::unwrap_used,
    reason = "test binary: printing aids diagnosis and panics are the failure mode"
)]

#[path = "common/mod.rs"]
mod common;

use etw::Trace;
use example_providers::kernel::process;
use serial_test::serial;

// ═══════════════════════════════════════════════════════════════════════════════
// Trace: runtime provider enable/disable
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_realtime_enable_disable_provider() {
    let mut trace = Trace::new("etw-rs_Test_RtEnable").unwrap();
    let Some(()) = common::skip_or_panic("trace.start", trace.start()) else {
        return;
    };

    // Enable a provider on the running session
    let Some(()) = common::skip_or_panic(
        "enable_provider",
        trace.enable_provider(process::GUID, process::keyword::PROCESS),
    ) else {
        return;
    };

    // Re-enable same provider with different keywords (should update, not duplicate)
    trace
        .enable_provider(
            process::GUID,
            process::keyword::PROCESS | process::keyword::THREAD,
        )
        .unwrap();

    // Disable the provider
    trace.disable_provider(process::GUID).unwrap();

    // Disabling again should fail — provider is no longer enabled
    let err = trace.disable_provider(process::GUID).unwrap_err();
    assert!(
        err.to_string().contains("not enabled"),
        "Expected 'not enabled' error, got: {err}"
    );

    trace.stop().unwrap();
}

#[test]
#[should_panic(expected = "Cannot disable provider: session not started")]
fn test_realtime_disable_before_start_fails() {
    let mut trace = Trace::new("etw-rs_Test_RtDisableBeforeStart").unwrap();
    let _ = trace.disable_provider(process::GUID);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Trace: runtime group mask update
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
#[serial(system_logger)]
fn test_system_trace_update_events() {
    use etw::system_logger::masks::*;

    let mut trace = Trace::new("etw-rs_Test_StUpdate").unwrap();
    trace.set_events(&[PERF_PROCESS]);
    let Some(()) = common::skip_or_panic("trace.start", trace.start()) else {
        return;
    };

    // Add context switch events at runtime
    trace
        .update_events(&[PERF_PROCESS, PERF_CONTEXT_SWITCH])
        .unwrap();

    trace.stop().unwrap();
}

#[test]
#[should_panic(expected = "Trace session must be started before calling update_events")]
fn test_system_trace_update_events_before_start_fails() {
    let mut trace = Trace::new("etw-rs_Test_StUpdateBeforeStart").unwrap();
    let _ = trace.update_events(&[]);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Trace: runtime stack walk update
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
#[serial(system_logger)]
fn test_system_trace_update_stack_walking() {
    use etw::system_logger::masks::*;

    // Hook IDs: (group_id << 8) | opcode. Process group = 0x03, START = 1, END = 2.
    const PROCESS_START: u16 = 0x0301;
    const PROCESS_END: u16 = 0x0302;

    let mut trace = Trace::new("etw-rs_Test_StStack").unwrap();
    trace.set_events(&[PERF_PROCESS]);
    trace.set_stack_walking(&[PROCESS_START]).unwrap();
    let Some(()) = common::skip_or_panic("trace.start", trace.start()) else {
        return;
    };

    // Add stack walking for process end at runtime
    trace
        .update_stack_walking(&[PROCESS_START, PROCESS_END])
        .unwrap();

    // Clear all stack walking
    trace.update_stack_walking(&[]).unwrap();

    trace.stop().unwrap();
}
