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

use etw::{Trace, session::NO_PER_PROCESSOR_BUFFERING};
use example_providers::kernel::process;
use serial_test::serial;
use std::{
    process::Command,
    sync::{Arc, Mutex},
    thread::sleep,
    time::{Duration, Instant},
};

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

fn spawn_child() -> u32 {
    let mut child = Command::new("cmd.exe")
        .args(["/c", "exit"])
        .spawn()
        .unwrap();
    let pid = child.id();
    let _ = child.wait();
    pid
}

fn wait_for_pid(seen: &Mutex<Vec<u32>>, pid: u32) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if seen.lock().unwrap().contains(&pid) {
            return true;
        }
        sleep(Duration::from_millis(100));
    }
    false
}

#[test]
fn test_realtime_enable_disable_while_processing() {
    let mut trace = Trace::new("etw-rs_Test_RtLiveDelivery").unwrap();
    // One buffer stream delivers events in log order, which the absence check
    // below relies on. It also halves worst-case latency to one flush interval.
    let _ = trace.set_log_file_mode(NO_PER_PROCESSOR_BUFFERING);

    let seen: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_cb = Arc::clone(&seen);
    trace.set_event_callback(move |event, context| {
        if event.id() == process::event::PROCESS_START {
            let pid: u32 = context.parser(event)?.get("ProcessID")?;
            seen_cb.lock().unwrap().push(pid);
        }
        Ok(())
    });

    let Some(()) =
        common::skip_or_panic("start_processing_thread", trace.start_processing_thread())
    else {
        return;
    };

    let before_enable = spawn_child();

    let Some(()) = common::skip_or_panic(
        "enable_provider",
        trace.enable_provider(process::GUID, process::keyword::PROCESS),
    ) else {
        return;
    };
    let enabled = spawn_child();
    assert!(
        wait_for_pid(&seen, enabled),
        "no ProcessStart for PID {enabled} after enabling on a processing session"
    );

    trace.disable_provider(process::GUID).unwrap();
    let disabled = spawn_child();

    // Events arrive in log order, so once the re-enabled child is seen, the disabled
    // child's start would already have been delivered had it been logged.
    trace
        .enable_provider(process::GUID, process::keyword::PROCESS)
        .unwrap();
    let reenabled = spawn_child();
    assert!(
        wait_for_pid(&seen, reenabled),
        "no ProcessStart for PID {reenabled} after re-enabling on a processing session"
    );

    trace.stop().unwrap();

    let seen = seen.lock().unwrap();
    assert!(
        !seen.contains(&before_enable),
        "ProcessStart for PID {before_enable} delivered before the provider was enabled"
    );
    assert!(
        !seen.contains(&disabled),
        "ProcessStart for PID {disabled} delivered after the provider was disabled"
    );
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
