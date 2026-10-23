//! Caller-installed policy for panics that escape the event callback.
//!
//! Event callbacks run on the ETW consumer thread, inside `ProcessTrace`'s
//! stack. A panic there must not unwind across the `extern "system"` boundary
//! (that would be undefined behaviour), so the callback trampoline catches it.
//! What happens *next* is policy, and
//! belongs to the caller: install a hook with
//! [`Trace::set_panic_callback`](crate::Trace::set_panic_callback) to choose
//! between [`PanicResponse::Continue`] and [`PanicResponse::StopTrace`].
//!
//! Without a hook, the default policy is to log the panic and stop the trace.
//!
//! # Requires `panic = "unwind"`
//!
//! The whole trampoline rests on [`std::panic::catch_unwind`] catching the panic
//! before it reaches the `extern "system"` frame. That only works under the
//! default `panic = "unwind"` strategy. If the final binary is built with
//! `panic = "abort"` (common for size-optimised release builds), `catch_unwind`
//! is a no-op and the **first** panicking event aborts the whole process — no
//! policy runs. An embedder that opts into `panic = "abort"` is opting out of
//! this safety net; keep `panic = "unwind"` if callback/parser panics must be
//! survivable.
//!
//! # Hook contract
//!
//! The hook runs inline on the consumer thread while buffer delivery for the
//! whole session is stalled, so it must:
//! - keep to cheap work (log, count, send on a channel);
//! - not call control APIs on this trace (return [`PanicResponse::StopTrace`] instead) — stopping
//!   the session blocks on work the consumer thread itself performs, so doing it from the hook can
//!   deadlock;
//! - not unwind — a panicking hook degrades to the default policy. [`PanicPayload::resume_unwind`]
//!   belongs on a *receiving* thread, never inside the hook.

use std::{
    any::Any,
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

/// Payload of a panic that escaped the event callback.
///
/// Wraps the [`Box<dyn Any + Send>`] produced by the panic so it can be
/// inspected, transported to another thread, or re-raised there.
pub struct PanicPayload(Box<dyn Any + Send + 'static>);

impl PanicPayload {
    pub(crate) fn new(payload: Box<dyn Any + Send + 'static>) -> Self {
        Self(payload)
    }

    /// Returns the panic message when the payload is a string.
    ///
    /// The payload is a string for `panic!("...")` and formatted panics (the
    /// common case). Returns `None` for non-string payloads, e.g. a
    /// [`std::panic::panic_any`] with a custom type.
    #[must_use]
    pub fn message(&self) -> Option<&str> {
        self.0
            .downcast_ref::<&'static str>()
            .copied()
            .or_else(|| self.0.downcast_ref::<String>().map(String::as_str))
    }

    /// Returns the raw payload, exactly as produced by the panic.
    #[must_use]
    pub fn into_inner(self) -> Box<dyn Any + Send + 'static> {
        self.0
    }

    /// Re-raises the panic on the current thread.
    ///
    /// Intended for test harnesses that transported the payload off the consumer
    /// thread and want the original panic to fail the test. The standard panic
    /// hook already ran at the original panic site (with the real backtrace);
    /// [`std::panic::resume_unwind`] deliberately skips it, so nothing is
    /// reported twice.
    ///
    /// # Panics
    ///
    /// Always — that is its purpose. Never call it from inside a
    /// [`Trace::set_panic_callback`](crate::Trace::set_panic_callback) hook: the
    /// hook must not unwind across the ETW callback boundary.
    pub fn resume_unwind(self) -> ! {
        std::panic::resume_unwind(self.0)
    }
}

impl fmt::Debug for PanicPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.message() {
            Some(message) => write!(f, "PanicPayload({message:?})"),
            None => write!(f, "PanicPayload(<non-string payload>)"),
        }
    }
}

/// Verdict returned by a panic callback: what the trace should do next.
///
/// Marked `#[non_exhaustive]` so future policies can be added without a breaking
/// release; downstream `match`es must include a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PanicResponse {
    /// Keep dispatching subsequent events.
    ///
    /// This is an explicit claim that the callback's state is per-event, so
    /// dispatching into it after a panic is sound.
    Continue,
    /// Stop the trace at the end of the current buffer.
    ///
    /// Already-delivered events drain without being dispatched, the buffer
    /// callback requests that `ProcessTrace` return, and the processing thread
    /// exits cleanly. Stopping the *session* (and freeing its kernel-side
    /// buffers) remains the owner's job, via [`Trace::stop`](crate::Trace::stop)
    /// or by dropping the trace.
    ///
    /// Note: because the processing thread has already exited by the time the
    /// owner calls `stop()`, the rundown events that `ControlTraceW(STOP)` flushes
    /// are **not** consumed — teardown reconciliation data (process/handle/file
    /// rundown) is lost for a trace stopped this way, unlike a clean `stop()`.
    StopTrace,
}

/// A caller-installed panic policy hook.
///
/// `FnMut` is sound because ETW invokes the event callback from a single
/// `ProcessTrace` thread per trace, so the hook is never re-entered concurrently.
pub(crate) type PanicCallback = Box<dyn FnMut(PanicPayload) -> PanicResponse + Send>;

/// Shared flag set when a panic policy decides to stop a trace.
///
/// Backed by an `Arc<AtomicBool>` so the ETW consumer thread (via
/// `CallbackState`) and the owning `Trace` can each hold a handle to the same
/// cell. Centralising the memory orderings here means the happens-before
/// contract — the consumer stores with `Release`, readers load with `Acquire` —
/// is decided once instead of at every call site.
#[derive(Clone, Debug)]
pub(crate) struct PoisonFlag(Arc<AtomicBool>);

impl PoisonFlag {
    /// Creates an un-poisoned flag.
    pub(crate) fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    /// Marks the trace as poisoned. Called on the consumer thread.
    pub(crate) fn poison(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Clears the flag so a stopped trace can be reused. Called by the owner at
    /// [`start()`](crate::Trace::start), while no consumer thread is running.
    pub(crate) fn clear(&self) {
        self.0.store(false, Ordering::Release);
    }

    /// Returns whether the trace has been poisoned.
    pub(crate) fn is_poisoned(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "test-only assertions")]
mod tests {
    use super::*;

    fn catch(f: impl FnOnce() + std::panic::UnwindSafe) -> PanicPayload {
        PanicPayload::new(std::panic::catch_unwind(f).expect_err("closure should panic"))
    }

    #[test]
    fn message_from_str_literal_panic() {
        let payload = catch(|| panic!("boom"));
        assert_eq!(payload.message(), Some("boom"));
        assert_eq!(format!("{payload:?}"), "PanicPayload(\"boom\")");
    }

    #[test]
    fn message_from_formatted_panic() {
        let code = 7;
        let payload = catch(move || panic!("boom {code}"));
        assert_eq!(payload.message(), Some("boom 7"));
    }

    #[test]
    fn message_from_non_string_payload() {
        let payload = catch(|| std::panic::panic_any(42_u32));
        assert_eq!(payload.message(), None);
        assert_eq!(format!("{payload:?}"), "PanicPayload(<non-string payload>)");
        assert_eq!(payload.into_inner().downcast_ref::<u32>(), Some(&42));
    }

    #[test]
    fn resume_unwind_reraises_original_payload() {
        let payload = catch(|| panic!("reraised"));
        // AssertUnwindSafe: the payload is consumed by the closure; nothing
        // observes it after the unwind.
        let reraised = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            payload.resume_unwind()
        }))
        .expect_err("resume_unwind should re-raise");
        assert_eq!(reraised.downcast_ref::<&str>(), Some(&"reraised"));
    }

    #[test]
    fn panic_response_is_copy_and_comparable() {
        let a = PanicResponse::StopTrace;
        let b = a;
        assert_eq!(a, b);
        assert_ne!(PanicResponse::Continue, PanicResponse::StopTrace);
    }

    #[test]
    fn poison_flag_set_and_clear_roundtrip() {
        let flag = PoisonFlag::new();
        assert!(!flag.is_poisoned());
        flag.poison();
        assert!(flag.is_poisoned());
        // clear() is what Trace::start() calls so a reused trace dispatches
        // again; a regression here would silently leave a restarted trace dark.
        flag.clear();
        assert!(!flag.is_poisoned());
    }

    #[test]
    fn poison_flag_clones_share_one_cell() {
        // The owner (`Trace`) and the consumer (`CallbackState`) each hold a
        // clone; they must observe the same cell.
        let owner = PoisonFlag::new();
        let consumer = owner.clone();
        consumer.poison();
        assert!(
            owner.is_poisoned(),
            "poison on one clone must be visible on the other"
        );
        owner.clear();
        assert!(
            !consumer.is_poisoned(),
            "clear on one clone must be visible on the other"
        );
    }
}
