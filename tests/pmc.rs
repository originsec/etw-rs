//! Integration test for Performance Monitoring Counter (PMC) sampling.
//!
//! Covers `enable_pmc` configuration, `SAMPLED_PROFILE` capture, and argument
//! rejection. A session accepts its PMC counter list only once, so a rejected
//! call must fail before the OS call that would use it up.
//!
//! # Requirements
//!
//! - Administrator (kernel system trace).
//! - x86_64 — PMC counters are CPU-architecture-specific MSRs.

#![cfg(not(miri))]
// Win32 API calls are not supported under Miri.
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
    Trace,
    system_logger::{
        self,
        masks::{PERF_NO_SYSCONFIG, PERF_PROFILE},
        profiling::ProfileSource,
    },
};
use example_providers::classic::perf_info;
use serial_test::serial;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

#[test]
#[serial(system_logger)]
fn test_pmc_enable_and_capture() {
    let Some(()) = common::skip_or_panic(
        "enable_profile_privilege",
        system_logger::profiling::enable_profile_privilege(),
    ) else {
        return;
    };
    // 1 ms sampling interval — high frequency so events arrive quickly.
    system_logger::profiling::set_profile_interval(10_000)
        .expect("set_profile_interval should succeed");

    let mut trace = Trace::new("etw-rs_Test_Pmc").expect("session creation");
    trace.set_events(&[PERF_PROFILE, PERF_NO_SYSCONFIG]);
    let Some(()) = common::skip_or_panic("trace.start", trace.start()) else {
        return;
    };

    let counters = [ProfileSource::ProfileTotalCycles];
    let pmc_event_ids = [perf_info::hook_id::SAMPLED_PROFILE];
    trace
        .enable_pmc(&counters, &pmc_event_ids)
        .expect("enable_pmc");

    let samples = Arc::new(AtomicUsize::new(0));
    let samples_cb = samples.clone();

    trace.set_event_callback(move |event, _context| {
        if event.provider_guid() == perf_info::CLASS_GUID
            && event.opcode() == perf_info::opcode::SAMPLED_PROFILE
        {
            samples_cb.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    });

    trace
        .start_processing_thread()
        .expect("start_processing_thread");

    // Drive CPU work so the profiler has something to sample.
    let stop = Arc::new(AtomicBool::new(false));
    let stop_cb = stop.clone();
    let worker = thread::spawn(move || {
        let mut acc: u64 = 0;
        while !stop_cb.load(Ordering::Relaxed) {
            for i in 0..1000 {
                acc = acc.wrapping_add(i);
            }
        }
        acc
    });

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && samples.load(Ordering::Relaxed) == 0 {
        thread::sleep(Duration::from_millis(50));
    }

    stop.store(true, Ordering::Relaxed);
    let _ = worker.join();
    trace.stop().expect("stop");

    let n = samples.load(Ordering::Relaxed);
    println!("SAMPLED_PROFILE events with PMC: {n}");
    assert!(n > 0, "no SAMPLED_PROFILE events captured under PMC");
}

/// Both caps are reachable from runtime data, so exceeding either must come back
/// as an error naming the offending argument — not a panic.
#[test]
#[serial(system_logger)]
fn test_enable_pmc_too_many_returns_error() {
    let Some(()) = common::skip_or_panic(
        "enable_profile_privilege",
        system_logger::profiling::enable_profile_privilege(),
    ) else {
        return;
    };
    let mut trace = Trace::new("etw-rs_Test_PmcTooMany").expect("session creation");
    trace.set_events(&[PERF_PROFILE, PERF_NO_SYSCONFIG]);
    let Some(()) = common::skip_or_panic("trace.start", trace.start()) else {
        return;
    };

    let five_counters = [
        ProfileSource::ProfileTotalCycles,
        ProfileSource::ProfileTotalIssues,
        ProfileSource::ProfileBranchInstructions,
        ProfileSource::ProfileCacheMisses,
        ProfileSource::ProfileBranchMispredictions,
    ];
    let one_event = [perf_info::hook_id::SAMPLED_PROFILE];
    let err = trace
        .enable_pmc(&five_counters, &one_event)
        .expect_err("5 counters exceeds ETW_MAX_PMC_EVENTS");
    assert!(
        matches!(
            err,
            etw::Error::InvalidParameter {
                parameter: "PMC counters",
                problem: etw::ParameterProblem::TooMany { count: 5, max: 4 }
            }
        ),
        "got {err:?}"
    );

    let err = trace
        .enable_pmc(
            &five_counters[..1],
            &[0x0F2E, 0x0F2F, 0x0F30, 0x0F31, 0x0F32],
        )
        .expect_err("5 events exceeds ETW_MAX_PMC_EVENTS");
    assert!(
        matches!(
            err,
            etw::Error::InvalidParameter {
                parameter: "PMC events",
                problem: etw::ParameterProblem::TooMany { count: 5, max: 4 }
            }
        ),
        "got {err:?}"
    );

    trace.stop().expect("stop");
}

/// The kernel accepts only one PMC counter list per session (a second returns
/// `ERROR_WMI_ALREADY_ENABLED`), so a bad hook ID must be rejected before the
/// counters are sent — otherwise the corrected retry can never succeed.
#[test]
#[serial(system_logger)]
fn test_enable_pmc_unrecognised_hook_leaves_session_configurable() {
    let Some(()) = common::skip_or_panic(
        "enable_profile_privilege",
        system_logger::profiling::enable_profile_privilege(),
    ) else {
        return;
    };
    let mut trace = Trace::new("etw-rs_Test_PmcBadHook").expect("session creation");
    trace.set_events(&[PERF_PROFILE, PERF_NO_SYSCONFIG]);
    let Some(()) = common::skip_or_panic("trace.start", trace.start()) else {
        return;
    };

    let counters = [ProfileSource::ProfileTotalCycles];
    let err = trace
        .enable_pmc(&counters, &[0xFFFF])
        .expect_err("0xFFFF is not a known hook ID");
    assert!(
        matches!(
            err,
            etw::Error::InvalidParameter {
                parameter: "PMC event hook ID",
                problem: etw::ParameterProblem::Unrecognised { value: 0xFFFF }
            }
        ),
        "got {err:?}"
    );

    trace
        .enable_pmc(&counters, &[perf_info::hook_id::SAMPLED_PROFILE])
        .expect("corrected retry after a rejected hook ID");

    trace.stop().expect("stop");
}

/// The kernel rejects an empty list with `ERROR_INVALID_PARAMETER`, so an empty
/// event list sent after the counters would use up the session's one counter
/// list; both must be rejected before any OS call.
#[test]
#[serial(system_logger)]
fn test_enable_pmc_empty_list_leaves_session_configurable() {
    let Some(()) = common::skip_or_panic(
        "enable_profile_privilege",
        system_logger::profiling::enable_profile_privilege(),
    ) else {
        return;
    };
    let mut trace = Trace::new("etw-rs_Test_PmcEmpty").expect("session creation");
    trace.set_events(&[PERF_PROFILE, PERF_NO_SYSCONFIG]);
    let Some(()) = common::skip_or_panic("trace.start", trace.start()) else {
        return;
    };

    let counters = [ProfileSource::ProfileTotalCycles];
    let events = [perf_info::hook_id::SAMPLED_PROFILE];
    let err = trace
        .enable_pmc(&[], &events)
        .expect_err("an empty counter list must be rejected");
    assert!(
        matches!(
            err,
            etw::Error::InvalidParameter {
                parameter: "PMC counters",
                problem: etw::ParameterProblem::Empty
            }
        ),
        "got {err:?}"
    );

    let err = trace
        .enable_pmc(&counters, &[])
        .expect_err("an empty event list must be rejected");
    assert!(
        matches!(
            err,
            etw::Error::InvalidParameter {
                parameter: "PMC events",
                problem: etw::ParameterProblem::Empty
            }
        ),
        "got {err:?}"
    );

    trace
        .enable_pmc(&counters, &events)
        .expect("corrected retry after a rejected empty list");

    trace.stop().expect("stop");
}
