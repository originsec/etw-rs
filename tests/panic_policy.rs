//! Integration tests for the event-callback panic policy.
//!
//! These drive a real DNS-Client session and deliberately panic inside the
//! event callback to exercise [`Trace::set_panic_callback`] and the default
//! (log + stop) policy. A callback panic prints a message + backtrace to stderr
//! on the consumer thread — that noise is expected, not a test failure.
//!
//! The *deterministic* proof of the policy logic lives in the unit tests in
//! `src/session/common.rs` (`panic_handling_tests`), which need no ETW/DNS.
//! These integration tests are end-to-end plumbing checks: they confirm the
//! poison flag, entry-guard drain, and buffer-callback stop actually fire
//! against a live `ProcessTrace`.
//!
//! Requirements:
//! - Performance Log Users (or Administrator) for ETW session creation.
//! - Active network connectivity so DNS queries emit QUERY_START events.
//!
//! They run by default — `#[ignore = "slow"]` is reserved for tests that take
//! more than ~10 s, and these do not. They wait on observable state (poison flag
//! / event counts) with generous timeouts rather than fixed sleeps, and fail with
//! an explicit diagnostic if no DNS events are delivered at all (an environment
//! problem rather than a logic failure).

#![cfg(not(miri))]
// Win32 API calls are not supported under Miri.
// Tests use println for output and unwrap/expect for cleaner test code.
#![expect(
    clippy::print_stdout,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::clone_on_ref_ptr,
    clippy::undocumented_unsafe_blocks,
    reason = "test binary: printing aids diagnosis and panics are the failure mode"
)]

#[path = "common/mod.rs"]
mod common;

use etw::{
    ALL_KEYWORDS, PanicResponse, RawEvent, Trace, processing_context::ProcessingContext,
    session::EventIdFilter,
};
use example_providers::user::dns_client;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use windows::Win32::System::{
    Diagnostics::Etw::TRACE_LEVEL_INFORMATION, Threading::GetCurrentThreadId,
};

const QUERY_START: u16 = 3008;

/// The exact panic payload the event callback produces. Shared so the hook
/// message-assertions stay coupled to it without a floating string literal.
const PANIC_MSG: &str = "boom on first counted event";

/// Trigger `n` unique DNS queries so each emits a fresh QUERY_START event.
///
/// Unique subdomains defeat the resolver cache; the queries run on the calling
/// thread, so their ETW events carry this thread's ID for filtering.
fn trigger_unique_dns(tag: &str, n: usize) {
    use std::net::ToSocketAddrs;
    for i in 0..n {
        let hostname = format!("etwrs-{tag}-{i}.example.com");
        // Resolution result is irrelevant — the query itself emits QUERY_START.
        let _ = format!("{hostname}:443").to_socket_addrs();
        std::thread::sleep(Duration::from_millis(30));
    }
}

/// Poll `pred` until it returns true or `timeout` elapses. Returns the final
/// value of `pred`. Signal-based waiting (not a fixed sleep) keeps the tests
/// robust to buffer-flush and DNS latency.
fn wait_for(mut pred: impl FnMut() -> bool, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if pred() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    pred()
}

/// Event callback that counts this-thread QUERY_START events and panics (once)
/// on the first counted event, so the panic policy has something to react to.
fn counting_callback(
    tid: u32,
    count: Arc<AtomicUsize>,
) -> impl FnMut(&RawEvent, &mut ProcessingContext) -> etw::Result<()> + Send + 'static {
    move |event, _ctx| {
        if event.thread_id() != tid {
            return Ok(());
        }
        let n = count.fetch_add(1, Ordering::SeqCst) + 1;
        // `assert!` with a bare message panics with exactly PANIC_MSG as the
        // payload (unlike `assert_ne!`), which the hook tests assert against.
        assert!(n != 1, "{PANIC_MSG}");
        Ok(())
    }
}

/// Assert that at least one of our events was delivered, with a diagnostic that
/// distinguishes an environment problem from a logic failure.
fn assert_events_flowed(count: &AtomicUsize) {
    assert!(
        count.load(Ordering::SeqCst) >= 1,
        "no DNS QUERY_START events were delivered on this thread within the timeout — \
         this test needs an elevated session, network connectivity, and getaddrinfo to emit \
         events on the calling thread; treat a failure here as an environment issue"
    );
}

/// Build + start a DNS trace with the counting callback already installed.
/// Returns `None` if the environment can't start an ETW session (non-elevated).
fn start_dns_trace(name: &str, count: &Arc<AtomicUsize>) -> Option<Trace> {
    let mut trace = Trace::new(name).expect("Failed to create trace session");
    common::skip_or_panic("trace.start", trace.start())?;
    trace
        .enable_provider_ex(
            dns_client::GUID,
            TRACE_LEVEL_INFORMATION,
            ALL_KEYWORDS,
            0,
            Some(EventIdFilter::include(&[QUERY_START]).into()),
        )
        .expect("Failed to enable DNS Client provider");
    let tid = unsafe { GetCurrentThreadId() };
    trace.set_event_callback(counting_callback(tid, count.clone()));
    Some(trace)
}

/// Default policy: a callback panic stops dispatch and the trace stops cleanly.
///
/// The first of our events panics; with no hook the default policy poisons the
/// trace, so every later event is drained without dispatch — the counter stays
/// at exactly 1 and `is_poisoned()` becomes observable.
#[test]
fn default_policy_stops_dispatch_after_panic() {
    let count = Arc::new(AtomicUsize::new(0));
    let Some(mut trace) = start_dns_trace("etw-rs_Test_PanicDefault", &count) else {
        return;
    };
    trace
        .start_processing_thread()
        .expect("Failed to start event processing");

    trigger_unique_dns("default", 40);
    // Wait for the panic to fire and poison the trace, then send more events
    // that must be drained without dispatch.
    wait_for(|| trace.is_poisoned(), Duration::from_secs(20));
    trigger_unique_dns("default2", 20);
    std::thread::sleep(Duration::from_millis(500));

    assert_events_flowed(&count);
    assert!(
        trace.is_poisoned(),
        "default policy should poison the trace"
    );

    trace
        .stop()
        .expect("stop should succeed on a poisoned trace");

    let captured = count.load(Ordering::SeqCst);
    println!("default policy: dispatched {captured} event(s) before stop");
    assert_eq!(
        captured, 1,
        "default policy should stop dispatch at the panicking event"
    );
}

/// `Continue` keeps dispatching after a callback panic.
///
/// Only the first counted event panics; the hook returns `Continue`, so the
/// trace is not poisoned and later events keep incrementing the counter. The
/// hook must also receive the original panic message.
#[test]
fn continue_keeps_dispatching_after_panic() {
    let seen_messages = Arc::new(Mutex::new(Vec::<String>::new()));
    let count = Arc::new(AtomicUsize::new(0));
    let Some(mut trace) = start_dns_trace("etw-rs_Test_PanicContinue", &count) else {
        return;
    };
    let seen_cb = seen_messages.clone();
    trace.set_panic_callback(move |payload| {
        seen_cb
            .lock()
            .unwrap()
            .push(payload.message().unwrap_or("<none>").to_owned());
        PanicResponse::Continue
    });
    trace
        .start_processing_thread()
        .expect("Failed to start event processing");

    trigger_unique_dns("continue", 40);
    // Continue must keep dispatching, so the count climbs past the panic event.
    let got_two = wait_for(
        || count.load(Ordering::SeqCst) >= 2,
        Duration::from_secs(20),
    );

    assert_events_flowed(&count);
    // The real logic check: Continue must NOT poison. A regression that poisoned
    // instead would trip here (and would also pin the count at 1).
    assert!(!trace.is_poisoned(), "Continue must not poison the trace");

    trace.stop().expect("stop should succeed");

    let captured = count.load(Ordering::SeqCst);
    let messages = seen_messages.lock().unwrap();
    println!("continue policy: dispatched {captured} event(s); hook saw {messages:?}");
    // With the trace un-poisoned (asserted above), every delivered event is
    // counted, so count < 2 means fewer than 2 events reached the callback —
    // an under-delivery/environment issue, not a dispatch-continuation failure.
    assert!(
        got_two && captured >= 2,
        "fewer than 2 QUERY_START events reached the callback (got {captured}); with the trace \
         un-poisoned this indicates under-delivery on this thread (environment), not a logic fault"
    );
    assert_eq!(messages.len(), 1, "hook should fire once for the one panic");
    assert_eq!(
        messages[0], PANIC_MSG,
        "hook should receive the original panic message"
    );
}

/// A `StopTrace` hook receives the payload and stops dispatch.
///
/// The hook records the message and returns `StopTrace`; the trace is poisoned,
/// so the counter stays at 1 like the default policy, but the caller also
/// observes the payload.
#[test]
fn stop_trace_hook_receives_payload_and_stops() {
    let seen_message = Arc::new(Mutex::new(None::<String>));
    let count = Arc::new(AtomicUsize::new(0));
    let Some(mut trace) = start_dns_trace("etw-rs_Test_PanicStop", &count) else {
        return;
    };
    let seen_cb = seen_message.clone();
    trace.set_panic_callback(move |payload| {
        *seen_cb.lock().unwrap() = payload.message().map(str::to_owned);
        PanicResponse::StopTrace
    });
    trace
        .start_processing_thread()
        .expect("Failed to start event processing");

    trigger_unique_dns("stop", 40);
    wait_for(|| trace.is_poisoned(), Duration::from_secs(20));
    trigger_unique_dns("stop2", 20);
    std::thread::sleep(Duration::from_millis(500));

    assert_events_flowed(&count);
    assert!(
        trace.is_poisoned(),
        "StopTrace verdict should poison the trace"
    );

    trace
        .stop()
        .expect("stop should succeed on a poisoned trace");

    let captured = count.load(Ordering::SeqCst);
    let message = seen_message.lock().unwrap().clone();
    println!("stop hook: dispatched {captured} event(s); hook saw {message:?}");
    assert_eq!(captured, 1, "StopTrace should stop dispatch at the panic");
    assert_eq!(
        message.as_deref(),
        Some(PANIC_MSG),
        "hook should receive the original panic message"
    );
}

/// A hook that itself panics degrades to the default policy (stop).
///
/// The dispatch panics, then the hook panics while handling it. The library must
/// swallow the hook's panic and fall back to stopping, so dispatch stops (count
/// stays at 1) rather than the hook's unwind crossing the FFI boundary.
#[test]
fn panicking_hook_degrades_to_stop() {
    let count = Arc::new(AtomicUsize::new(0));
    let Some(mut trace) = start_dns_trace("etw-rs_Test_PanicHookPanic", &count) else {
        return;
    };
    trace.set_panic_callback(|_payload| -> PanicResponse {
        panic!("hook itself panics");
    });
    trace
        .start_processing_thread()
        .expect("Failed to start event processing");

    trigger_unique_dns("hookpanic", 40);
    wait_for(|| trace.is_poisoned(), Duration::from_secs(20));
    trigger_unique_dns("hookpanic2", 20);
    std::thread::sleep(Duration::from_millis(500));

    assert_events_flowed(&count);
    assert!(
        trace.is_poisoned(),
        "a panicking hook should degrade to poison"
    );

    trace
        .stop()
        .expect("stop should succeed on a poisoned trace");

    let captured = count.load(Ordering::SeqCst);
    println!("panicking hook: dispatched {captured} event(s) before stop");
    assert_eq!(
        captured, 1,
        "a panicking hook should degrade to the default stop policy"
    );
}
