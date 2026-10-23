//! Integration test for Last Branch Record (LBR) tracing: `enable_lbr` configuration,
//! LBR record capture, and `LbrData` parsing against real events.
//!
//! Adapted from `examples/12_last_branch_records.rs`.
//!
//! # Requirements
//!
//! - Administrator (kernel system trace).
//! - x86_64 — LBR is an Intel/AMD-specific MSR feature.
//! - Intel Pentium+ or AMD Zen4+ CPU. Hyper-V VMs support LBR for non-hybrid CPUs; nested
//!   virtualisation typically does not.

#![cfg(not(miri))]
// Win32 API calls are not supported under Miri.
// Tests use println for output and unwrap/expect for cleaner test code
#![expect(
    clippy::print_stdout,
    clippy::expect_used,
    clippy::clone_on_ref_ptr,
    reason = "test binary: printing aids diagnosis and panics are the failure mode"
)]
#![cfg(target_arch = "x86_64")]

#[path = "common/mod.rs"]
mod common;

use etw::{
    Error::Win32Error,
    Trace,
    stack_walk::LbrData,
    system_logger::{
        self, CALLSTACK_ENABLE, EXCLUDE_KERNEL,
        masks::{PERF_NO_SYSCONFIG, PERF_PROFILE},
    },
};
use example_providers::classic::{lbr, perf_info};
use serial_test::serial;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::Foundation::ERROR_NOT_SUPPORTED;

#[test]
#[serial(system_logger)]
fn test_lbr_capture_and_accessors() {
    let Some(()) = common::skip_or_panic(
        "enable_profile_privilege",
        system_logger::profiling::enable_profile_privilege(),
    ) else {
        return;
    };
    // 1 ms sampling interval — high frequency so we capture LBR records quickly.
    system_logger::profiling::set_profile_interval(10_000)
        .expect("set_profile_interval should succeed");

    let mut trace = Trace::new("etw-rs_Test_Lbr").expect("session creation");
    trace.set_events(&[PERF_PROFILE, PERF_NO_SYSCONFIG]);
    let Some(()) = common::skip_or_panic("trace.start", trace.start()) else {
        return;
    };

    let lbr_flags = EXCLUDE_KERNEL | CALLSTACK_ENABLE;
    let lbr_event_ids = [perf_info::hook_id::SAMPLED_PROFILE];
    match trace.enable_lbr(lbr_flags, &lbr_event_ids) {
        Ok(()) => {}
        Err(Win32Error(ERROR_NOT_SUPPORTED)) => {
            // The CPU lacks LBR (see Requirements above). Hardware, not privilege,
            // so this skips even under CI: a hosted runner's CPU model varies.
            println!("Skipping test: LBR not supported on this host (Win32 error 50)");
            trace.stop().expect("stop");
            return;
        }
        Err(e) => panic!("enable_lbr: {e:?}"),
    }

    // Accessor round-trip: configuration we just set should be readable.
    assert_eq!(trace.lbr_config(), Some(lbr_flags));
    assert_eq!(trace.lbr_events(), &lbr_event_ids[..]);

    let lbr_records = Arc::new(AtomicUsize::new(0));
    let sample_records = Arc::new(AtomicUsize::new(0));
    let consistency_failures = Arc::new(AtomicUsize::new(0));

    let lbr_records_cb = lbr_records.clone();
    let sample_records_cb = sample_records.clone();
    let consistency_failures_cb = consistency_failures.clone();

    trace.set_event_callback(move |event, _context| {
        // Wrap in catch_unwind so a panic on the processing thread is counted
        // as a failure rather than silently killing the thread.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            match event.provider_guid() {
                g if g == perf_info::CLASS_GUID
                    && event.opcode() == perf_info::opcode::SAMPLED_PROFILE =>
                {
                    sample_records_cb.fetch_add(1, Ordering::Relaxed);
                }
                g if g == lbr::CLASS_GUID && event.opcode() == lbr::opcode::RECORD => {
                    let n = lbr_records_cb.fetch_add(1, Ordering::Relaxed);
                    match LbrData::from_event(event) {
                        Ok(data) => {
                            if data.branches().len() != data.num_branches() {
                                consistency_failures_cb.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        Err(_) => {
                            consistency_failures_cb.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    // Exercise the alternate-Debug path on the first record only —
                    // this routes through `format_properties` when a schema is
                    // registered. Discard the output to avoid console spam.
                    if n == 0 {
                        let _ = format!("{event:#?}");
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

    // Drive CPU work in another thread so the profiler has something to sample.
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_cb = stop.clone();
    let worker = thread::spawn(move || {
        let mut acc: u64 = 0;
        while !stop_cb.load(Ordering::Relaxed) {
            // Inexpensive loop body — just keep the CPU busy with branches.
            for i in 0..1000 {
                acc = acc.wrapping_add(i);
            }
        }
        acc
    });

    // Wait up to 5 seconds for at least one LBR record.
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && lbr_records.load(Ordering::Relaxed) == 0 {
        thread::sleep(Duration::from_millis(50));
    }

    stop.store(true, Ordering::Relaxed);
    let _ = worker.join();
    trace.stop().expect("stop");

    let lbr = lbr_records.load(Ordering::Relaxed);
    let samples = sample_records.load(Ordering::Relaxed);
    let bad = consistency_failures.load(Ordering::Relaxed);
    println!("LBR records: {lbr}, sample records: {samples}, parse failures: {bad}");

    assert!(samples > 0, "no SAMPLED_PROFILE events captured");
    assert!(
        lbr > 0,
        "no LBR records captured — hardware may not support LBR (Hyper-V hybrid CPU?)"
    );
    assert_eq!(bad, 0, "LbrData parse / consistency failures");
}

/// The event cap is reachable from runtime data, so exceeding it must come back
/// as an error — not a panic — before any LBR state reaches the kernel.
#[test]
#[serial(system_logger)]
fn test_enable_lbr_too_many_events_returns_error() {
    let Some(()) = common::skip_or_panic(
        "enable_profile_privilege",
        system_logger::profiling::enable_profile_privilege(),
    ) else {
        return;
    };
    let mut trace = Trace::new("etw-rs_Test_LbrTooMany").expect("session creation");
    trace.set_events(&[PERF_PROFILE, PERF_NO_SYSCONFIG]);
    let Some(()) = common::skip_or_panic("trace.start", trace.start()) else {
        return;
    };

    let err = trace
        .enable_lbr(EXCLUDE_KERNEL, &[0x0F2E, 0x0F2F, 0x0F30, 0x0F31, 0x0F32])
        .expect_err("5 events exceeds TRACE_LBR_MAXIMUM_EVENTS");
    assert!(
        matches!(
            err,
            etw::Error::InvalidParameter {
                parameter: "LBR events",
                problem: etw::ParameterProblem::TooMany { count: 5, max: 4 }
            }
        ),
        "got {err:?}"
    );
    assert!(trace.lbr_events().is_empty());

    trace.stop().expect("stop");
}
