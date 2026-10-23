//! Runtime alignment probe as an integration test.
//!
//! This test validates ETW payload alignment invariants for:
//! - Trace events (classic kernel path)
//! - Trace events (modern provider path)
//! - STACK_TRACE64 extended data payloads
//!
//! Alignment assumptions documented by this test:
//! - Platform scope is x64/aarch64 only (this crate's supported targets).
//! - Non-empty `EVENT_RECORD::UserData` is expected to be 8-byte aligned.
//! - Zero-length `UserData` may appear (for example EventTrace header records); these records are
//!   excluded from alignment failure checks.
//! - `STACK_TRACE64` extended data is expected to be:
//!   1. 8-byte aligned when non-empty
//!   2. At least 8 bytes (match ID)
//!   3. Followed by zero or more 8-byte addresses (`(len - 8) % 8 == 0`)
//!
//! Marked `#[ignore = "slow"]` because the system + modern traces together take ~13 s.
//! Run with `cargo test -- --include-ignored` or on the elevated CI runner.

#![cfg(not(miri))] // Win32 API calls are not supported under Miri.
#![expect(
    clippy::print_stdout,
    reason = "test binary: printing aids diagnosis and panics are the failure mode"
)]

#[path = "common/mod.rs"]
mod common;

use etw::{
    EnableProperty, Trace,
    event::extended_data_type,
    system_logger::{
        self, CALLSTACK_ENABLE, EXCLUDE_KERNEL,
        masks::{PERF_NO_SYSCONFIG, PERF_PROCESS, PERF_PROFILE},
    },
};
use example_providers::{
    classic::kernel_trace::stack_walk,
    kernel::process::{self, GUID as MODERN_PROCESS_GUID},
};
use std::{
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};
use windows::Win32::System::Diagnostics::Etw::TRACE_LEVEL_INFORMATION;

#[derive(Default)]
struct Violations {
    system: Vec<String>,
    modern: Vec<String>,
    ext_stack: Vec<String>,
}

#[test]
#[ignore = "slow"]
#[serial_test::serial(system_logger)]
fn test_userdata_alignment() {
    let violations = Arc::new(Mutex::new(Violations::default()));
    let system_events = Arc::new(AtomicUsize::new(0));
    let modern_events = Arc::new(AtomicUsize::new(0));
    let stack_walk_events = Arc::new(AtomicUsize::new(0));
    let stack_ext_seen = Arc::new(AtomicUsize::new(0));

    let Some(()) = common::skip_or_panic(
        "system trace pass",
        run_system_trace_pass(
            Duration::from_secs(6),
            Arc::clone(&violations),
            Arc::clone(&system_events),
            Arc::clone(&stack_walk_events),
        ),
    ) else {
        return;
    };

    let Some(()) = common::skip_or_panic(
        "modern trace pass",
        run_modern_trace_pass(
            Duration::from_secs(6),
            Arc::clone(&violations),
            Arc::clone(&modern_events),
            Arc::clone(&stack_ext_seen),
        ),
    ) else {
        return;
    };

    let v = violations
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    assert!(
        v.system.is_empty(),
        "Found misaligned Trace UserData:\n{}",
        v.system.join("\n")
    );
    assert!(
        v.modern.is_empty(),
        "Found misaligned Trace UserData:\n{}",
        v.modern.join("\n")
    );
    assert!(
        v.ext_stack.is_empty(),
        "Found invalid STACK_TRACE64 extended data alignment/shape:\n{}",
        v.ext_stack.join("\n")
    );

    assert!(
        system_events.load(Ordering::Relaxed) > 0,
        "No non-empty Trace payloads observed"
    );
    assert!(
        modern_events.load(Ordering::Relaxed) > 0,
        "No non-empty Trace payloads observed"
    );
    assert!(
        stack_walk_events.load(Ordering::Relaxed) > 0,
        "No stack walk events observed"
    );
    assert!(
        stack_ext_seen.load(Ordering::Relaxed) > 0,
        "No STACK_TRACE64 extended data observed"
    );
}

fn run_system_trace_pass(
    duration: Duration,
    violations: Arc<Mutex<Violations>>,
    observed_non_empty: Arc<AtomicUsize>,
    stack_walk_events: Arc<AtomicUsize>,
) -> etw::Result<()> {
    system_logger::profiling::enable_profile_privilege()?;
    system_logger::profiling::set_profile_interval(10_000_000)?;

    let mut trace = Trace::new("etw-rs_Test_UserDataAlign_System")?;
    trace
        .set_events(&[PERF_PROCESS, PERF_PROFILE, PERF_NO_SYSCONFIG])
        // Hook IDs: (group_id << 8) | opcode
        // Process START: group 0x03, opcode 1; PerfInfo SAMPLED_PROFILE: group 0x0F, opcode 46
        .set_stack_walking(&[0x0301, 0x0F2E])?
        .start()?;

    // LBR is optional by CPU/OS support.
    let _ = trace.enable_lbr(EXCLUDE_KERNEL | CALLSTACK_ENABLE, &[0x0F2E]);

    trace.set_event_callback(move |event, _context| {
        let data = event.user_data();
        if data.is_empty() {
            // Header-like records with no payload are valid and intentionally
            // excluded from the non-empty UserData alignment invariant.
            return Ok(());
        }

        observed_non_empty.fetch_add(1, Ordering::Relaxed);
        if event.provider_guid() == stack_walk::GUID && event.opcode() == stack_walk::opcode::STACK
        {
            stack_walk_events.fetch_add(1, Ordering::Relaxed);
        }
        let align = (data.as_ptr() as usize) & 7;
        if align != 0 {
            let mut v = violations
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            v.system.push(format!(
                "provider={:?} id={} opcode={} version={} len={} align8={align}",
                event.provider_guid(),
                event.id(),
                event.opcode(),
                event.version(),
                data.len(),
            ));
        }

        Ok(())
    });

    trace.start_processing_thread()?;
    thread::sleep(duration);
    trace.stop()?;
    Ok(())
}

fn run_modern_trace_pass(
    duration: Duration,
    violations: Arc<Mutex<Violations>>,
    observed_non_empty: Arc<AtomicUsize>,
    stack_ext_seen: Arc<AtomicUsize>,
) -> etw::Result<()> {
    let mut trace = Trace::new("etw-rs_Test_UserDataAlign_Modern")?;
    trace.start()?;

    trace.enable_provider_ex(
        MODERN_PROCESS_GUID,
        TRACE_LEVEL_INFORMATION,
        process::keyword::PROCESS,
        EnableProperty::STACK_TRACE,
        None,
    )?;

    let keep_running = Arc::new(AtomicBool::new(true));
    let keep_running_worker = Arc::clone(&keep_running);
    let workload = thread::spawn(move || {
        while keep_running_worker.load(Ordering::Relaxed) {
            let _ = Command::new("cmd.exe")
                .args(["/c", "echo", "align"])
                .output();
            thread::sleep(Duration::from_millis(40));
        }
    });

    trace.set_event_callback(move |event, _context| {
        let data = event.user_data();
        if !data.is_empty() {
            observed_non_empty.fetch_add(1, Ordering::Relaxed);
            let align = (data.as_ptr() as usize) & 7;
            if align != 0 {
                let mut v = violations
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                v.modern.push(format!(
                    "provider={:?} id={} opcode={} version={} len={} align8={align}",
                    event.provider_guid(),
                    event.id(),
                    event.opcode(),
                    event.version(),
                    data.len(),
                ));
            }
        }

        if let Some(stack_data) = event.find_extended_data(extended_data_type::STACK_TRACE64) {
            stack_ext_seen.fetch_add(1, Ordering::Relaxed);
            if !stack_data.is_empty() {
                let align = (stack_data.as_ptr() as usize) & 7;
                let len = stack_data.len();
                let valid_shape = len >= 8 && (len - 8).is_multiple_of(8);
                if align != 0 || !valid_shape {
                    let mut v = violations
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    v.ext_stack.push(format!(
                        "provider={:?} id={} opcode={} version={} len={len} align8={align} valid_shape={valid_shape}",
                        event.provider_guid(),
                        event.id(),
                        event.opcode(),
                        event.version(),
                    ));
                }
            }
        }

        Ok(())
    });

    trace.start_processing_thread()?;
    thread::sleep(duration);
    keep_running.store(false, Ordering::Relaxed);
    let _ = workload.join();
    trace.stop()?;
    Ok(())
}
