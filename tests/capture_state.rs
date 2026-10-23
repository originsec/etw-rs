//! Integration test for `Trace::capture_state` (manifest-provider rundown).
//!
//! Adapted from `examples/06_rundown_events.rs`. Asserts that
//! `EVENT_CONTROL_CODE_CAPTURE_STATE` causes the kernel Process provider
//! to emit PROCESS_RUNDOWN events for currently-running processes, both
//! when called before and after `start_processing_thread`.
//!
//! This is the only test exercising `Trace::capture_state` and its
//! `EnableTraceEx2` invocation in `session/trace.rs::capture_state_core`.

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

use etw::Trace;
use example_providers::kernel::{self, process::keyword::PROCESS};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering::Relaxed},
    },
    thread::sleep,
    time::Duration,
};

#[test]
fn test_capture_state_emits_rundown() {
    const PROCESS_RUNDOWN: u16 = example_providers::kernel::process::event::PROCESS_RUNDOWN;

    let mut trace = Trace::new("etw-rs_Test_CaptureState").expect("session creation");
    let Some(()) = common::skip_or_panic("trace.start", trace.start()) else {
        return;
    };
    let Some(()) = common::skip_or_panic(
        "enable_provider",
        trace.enable_provider(kernel::process::GUID, PROCESS),
    ) else {
        return;
    };

    let rundown_count = Arc::new(AtomicUsize::new(0));
    let rundown_count_cb = rundown_count.clone();

    trace.set_event_callback(move |event, _ctx| {
        if event.provider_guid() == kernel::process::GUID && event.id() == PROCESS_RUNDOWN {
            rundown_count_cb.fetch_add(1, Relaxed);
        }
        Ok(())
    });

    // Approach 1: capture_state BEFORE start_processing_thread.
    // Events buffer until ProcessTrace drains them.
    trace
        .capture_state(kernel::process::GUID)
        .expect("capture_state before processing");
    trace
        .start_processing_thread()
        .expect("start_processing_thread");

    // Drain buffered rundown events.
    sleep(Duration::from_secs(2));
    let after_first_call = rundown_count.load(Relaxed);

    // Approach 2: capture_state AFTER start_processing_thread.
    trace
        .capture_state(kernel::process::GUID)
        .expect("capture_state after processing");

    sleep(Duration::from_secs(3));
    let after_second_call = rundown_count.load(Relaxed);

    trace.stop().expect("stop");

    println!(
        "PROCESS_RUNDOWN total: after-first-call={after_first_call}, \
         after-second-call={after_second_call}"
    );
    assert!(
        after_first_call > 0,
        "no PROCESS_RUNDOWN events after first capture_state + processing thread start"
    );
    assert!(
        after_second_call > after_first_call,
        "second capture_state produced no additional PROCESS_RUNDOWN events \
         (was {after_first_call}, became {after_second_call})"
    );
}

#[test]
fn test_capture_state_unknown_provider_errors() {
    let mut trace = Trace::new("etw-rs_Test_CaptureStateBad").expect("session creation");
    let Some(()) = common::skip_or_panic("trace.start", trace.start()) else {
        return;
    };

    // capture_state on a provider that wasn't enabled on this session must
    // return InvalidParameter.
    let bogus = etw::Guid::from_u128(0xDEADBEEF_DEAD_BEEF_DEAD_BEEFDEADBEEF);
    let r = trace.capture_state(bogus);
    // A well-formed GUID that simply is not enabled is ProviderNotEnabled, not
    // InvalidParameter — the argument was valid, the session just has no such
    // provider.
    assert!(
        matches!(r, Err(etw::Error::ProviderNotEnabled { .. })),
        "expected ProviderNotEnabled, got: {r:?}"
    );

    trace.stop().expect("stop");
}
