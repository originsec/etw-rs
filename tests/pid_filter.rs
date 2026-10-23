//! Integration test for kernel-side PID pre-filtering (`EVENT_FILTER_TYPE_PID`).
//!
//! `EVENT_FILTER_TYPE_PID` is a *scope* filter: the ETW runtime enforces it at
//! provider-enablement time, enabling the provider only in the listed
//! processes. It therefore works only for providers registered per-process in
//! user mode (manifest / `TraceLogging`).
//!
//! Kernel-mode providers (e.g. Microsoft-Windows-Kernel-Process) are enabled
//! globally in the kernel with no per-process enablement hook, so the filter is
//! **silently ignored** — verified during development: filtering to a PID that
//! matched no process still delivered events from ~40 processes. To prove the
//! filter end-to-end without that confound, this test registers its own ETW
//! provider and emits from the current process, so the logging PID is known
//! exactly. Enabling with our PID delivers the events; enabling with any other
//! PID delivers nothing, because no other process emits this provider.

#![cfg(not(miri))]
// Win32 API calls are not supported under Miri.
#![expect(
    clippy::print_stdout,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::clone_on_ref_ptr,
    reason = "test binary: printing aids diagnosis and panics are the failure mode"
)]

#[path = "common/mod.rs"]
mod common;

use etw::{ProviderFilter, Trace};
use std::{
    sync::{Arc, Mutex},
    thread::sleep,
    time::Duration,
};
use windows::{
    Win32::System::Diagnostics::Etw::{
        EVENT_DESCRIPTOR, EventRegister, EventUnregister, EventWrite, REGHANDLE,
        TRACE_LEVEL_VERBOSE,
    },
    core::GUID,
};

/// Ad-hoc provider GUID owned solely by this test; nothing else emits it, so a
/// consumer sees its events only when this process is in the enable scope.
const TEST_PROVIDER: GUID = GUID::from_u128(0x6f2a_7c14_9b03_4de1_a5c8_71e2_0f9d_3b46);

/// The same GUID as an `etw::Guid` for the consumer-side etw-rs calls;
/// `TEST_PROVIDER` stays a `windows` GUID for the raw `EventRegister` FFI.
const TEST_PROVIDER_RS: etw::Guid = etw::Guid::from_u128(0x6f2a_7c14_9b03_4de1_a5c8_71e2_0f9d_3b46);

/// Events emitted per phase. More than one so a lossy realtime buffer still
/// leaves evidence, but the assertions only require the all-or-nothing outcome.
const EMITS_PER_PHASE: usize = 5;

/// In-process ETW provider registration (RAII).
struct TestProvider(REGHANDLE);

impl TestProvider {
    fn register() -> Self {
        let mut handle = REGHANDLE(0);
        // SAFETY: providerid points to a valid GUID; no enable callback; handle
        // is a valid out-param. EventRegister returns a Win32 status.
        let status =
            unsafe { EventRegister(&TEST_PROVIDER, None, None, std::ptr::from_mut(&mut handle)) };
        assert_eq!(status, 0, "EventRegister failed: {status}");
        Self(handle)
    }

    fn emit(&self) {
        // Level 4 (Information) ≤ the session's Verbose enable level. Keyword 0
        // with a MatchAnyKeyword of 0 means "match regardless of keyword".
        let descriptor = EVENT_DESCRIPTOR {
            Id: 1,
            Level: 4,
            ..Default::default()
        };
        // SAFETY: handle came from a successful EventRegister; descriptor is
        // valid for the call; no user data.
        let status = unsafe { EventWrite(self.0, std::ptr::from_ref(&descriptor), None) };
        assert_eq!(status, 0, "EventWrite failed: {status}");
    }
}

impl Drop for TestProvider {
    fn drop(&mut self) {
        // SAFETY: handle came from a successful EventRegister and is unregistered once.
        unsafe {
            let _ = EventUnregister(self.0);
        }
    }
}

/// Run one filtered session: enable our provider scoped to `filter_pids`, emit
/// [`EMITS_PER_PHASE`] events from this process, and return the header PID of
/// every delivered event. `None` means the host lacked privilege to trace.
fn run_phase(session: &str, provider: &TestProvider, filter_pids: &[u32]) -> Option<Vec<u32>> {
    let mut trace = Trace::new(session).expect("create trace");

    let header_pids: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
    let cb = header_pids.clone();
    trace.set_event_callback(move |event, _context| {
        if event.provider_guid() == TEST_PROVIDER_RS {
            cb.lock().unwrap().push(event.process_id());
        }
        Ok(())
    });

    let filter = ProviderFilter::new().pids(filter_pids);
    // MatchAnyKeyword 0 ⇒ deliver regardless of keyword (our event uses keyword 0).
    common::skip_or_panic(
        "enable_provider_ex(pid filter)",
        trace.enable_provider_ex(TEST_PROVIDER_RS, TRACE_LEVEL_VERBOSE, 0, 0, Some(filter)),
    )?;

    trace.start_processing_thread().expect("start processing");
    // Enablement propagates to the in-process registration asynchronously.
    sleep(Duration::from_millis(500));
    for _ in 0..EMITS_PER_PHASE {
        provider.emit();
    }
    // Allow the realtime buffers to flush before stopping.
    sleep(Duration::from_secs(1));
    trace.stop().expect("stop session");

    let delivered = header_pids.lock().unwrap().clone();
    Some(delivered)
}

#[test]
fn test_pid_filter_scopes_delivery_to_listed_pid() {
    let own_pid = std::process::id();
    let provider = TestProvider::register();

    // Positive: our PID is in scope ⇒ our emissions are delivered, and every
    // delivered event necessarily carries our PID in its header.
    let Some(matched) = run_phase("etw-rs_Test_PidFilterMatch", &provider, &[own_pid]) else {
        return; // insufficient privilege — skip
    };
    println!(
        "PID filter [own={own_pid}]: delivered {} events",
        matched.len()
    );
    assert!(
        !matched.is_empty(),
        "no events delivered when our PID was in the filter scope"
    );
    assert!(
        matched.iter().all(|&p| p == own_pid),
        "delivered events carried unexpected header PIDs: {matched:?}"
    );

    // Negative: a PID that is not ours. Nothing else emits this provider, so a
    // working scope filter delivers zero. (Any real process at that PID would
    // still not emit our private provider.)
    let other_pid = own_pid ^ 0x00A5_0000;
    assert_ne!(other_pid, own_pid);
    let Some(unmatched) = run_phase("etw-rs_Test_PidFilterMiss", &provider, &[other_pid]) else {
        return;
    };
    println!(
        "PID filter [other={other_pid}]: delivered {} events",
        unmatched.len()
    );
    assert!(
        unmatched.is_empty(),
        "PID filter did not exclude our process: {unmatched:?}"
    );
}
