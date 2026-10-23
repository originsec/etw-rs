//! ETW session management.
//!
//! This module provides [`Trace`] for consuming ETW events by enabling
//! individual providers via `EnableTraceEx2` and/or kernel event groups
//! via `PERFINFO_GROUPMASK` (system logger mode).
//!
//! System logger mode is enabled automatically when system logger APIs
//! ([`Trace::set_events`], [`Trace::set_stack_walking`], etc.) are called.
//!
//! Shared types (callbacks, statistics, clock resolution) live here at the
//! module root and are re-exported from the crate root.

pub(crate) mod common;
pub(crate) mod enumerate;
pub mod panic_policy;
pub mod system_logger;
pub(crate) mod trace;

use crate::{event::RawEvent, processing_context::ProcessingContext};
use windows_sys::Win32::System::Diagnostics::Etw;

// ═══════════════════════════════════════════════════════════════════════════════
// Shared Types
// ═══════════════════════════════════════════════════════════════════════════════

/// Type alias for the event callback function.
///
/// The callback receives a reference to the raw event and a mutable reference
/// to the schema cache for TDH lookups. It returns `Result<()>` to allow use
/// of the `?` operator. Errors are logged but do not stop event processing.
pub type EventCallback =
    Box<dyn FnMut(&RawEvent, &mut ProcessingContext) -> crate::Result<()> + Send>;

/// Independent session mode - session is not affected by rundown of other sessions.
///
/// Pass this to [`Trace::set_log_file_mode()`].
pub use Etw::EVENT_TRACE_INDEPENDENT_SESSION_MODE as INDEPENDENT_SESSION_MODE;
/// Disable per-processor buffering - use global buffers instead.
///
/// Pass this to [`Trace::set_log_file_mode()`].
pub use Etw::EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING as NO_PER_PROCESSOR_BUFFERING;
/// Persist the trace session across hybrid shutdown.
///
/// Pass this to [`Trace::set_log_file_mode()`].
pub use Etw::EVENT_TRACE_PERSIST_ON_HYBRID_SHUTDOWN as PERSIST_ON_HYBRID_SHUTDOWN;
/// Secure mode - restricts who can log events to the session.
///
/// Pass this to [`Trace::set_log_file_mode()`].
pub use Etw::EVENT_TRACE_SECURE_MODE as SECURE_MODE;
/// Stop the trace session on hybrid shutdown.
///
/// Pass this to [`Trace::set_log_file_mode()`].
pub use Etw::EVENT_TRACE_STOP_ON_HYBRID_SHUTDOWN as STOP_ON_HYBRID_SHUTDOWN;
/// System logger mode flag for tracing system providers.
///
/// This flag is set automatically when system logger APIs are used on [`Trace`].
/// It can also be set explicitly via [`Trace::set_log_file_mode()`].
pub use Etw::EVENT_TRACE_SYSTEM_LOGGER_MODE as SYSTEM_LOGGER_MODE;
/// Raw timestamp mode - timestamps are not converted to system time.
///
/// Pass this to [`Trace::set_process_trace_mode()`].
pub use Etw::PROCESS_TRACE_MODE_RAW_TIMESTAMP as RAW_TIMESTAMP_MODE;

/// Keyword value that matches all events regardless of their keyword.
pub const ALL_KEYWORDS: u64 = 0xFFFF_FFFF_FFFF_FFFF;

/// Statistics from an ETW trace session.
///
/// These values are populated after calling [`Trace::stop()`] or
/// [`Trace::query()`].
#[derive(Debug, Clone, Copy, Default)]
pub struct TraceStatistics {
    /// Number of buffers allocated for the session.
    pub buffers_count: u32,
    /// Number of buffers that are free.
    pub buffers_free: u32,
    /// Number of buffers written.
    pub buffers_written: u32,
    /// Number of events lost because the buffers were full.
    pub events_lost: u32,
    /// Number of buffers lost during real-time delivery.
    pub realtime_buffers_lost: u32,
}

impl std::fmt::Display for TraceStatistics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "buffers: {}/{} free, {} written, {} lost | events_lost: {}",
            self.buffers_free,
            self.buffers_count,
            self.buffers_written,
            self.realtime_buffers_lost,
            self.events_lost
        )
    }
}

/// Clock resolution for ETW timestamps.
///
/// Pass these constants to `Wnode.ClientContext` to configure timestamp precision.
#[derive(Debug)]
pub struct ClockResolution;

impl ClockResolution {
    /// Query Performance Counter (QPC) - high resolution, default.
    pub const QPC: u32 = 1;
    /// System time - tracks changes to the system's clock.
    pub const SYSTEM_TIME: u32 = 2;
    /// CPU cycle counter - highest resolution but varies with CPU frequency.
    pub const CPU_CYCLE: u32 = 3;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Re-exports from submodules
// ═══════════════════════════════════════════════════════════════════════════════

pub use common::{EventIdFilter, ProviderFilter, ProviderIdentifier};
pub use enumerate::{SessionProperties, query_sessions};
pub use panic_policy::{PanicPayload, PanicResponse};
pub use trace::{EnableProperty, ProcessTraceMode, Trace};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_statistics_display() {
        let s = TraceStatistics {
            buffers_count: 8,
            buffers_free: 3,
            buffers_written: 42,
            events_lost: 0,
            realtime_buffers_lost: 1,
        };
        assert_eq!(
            format!("{s}"),
            "buffers: 3/8 free, 42 written, 1 lost | events_lost: 0"
        );
    }
}
