//! Shared infrastructure for ETW trace sessions.
//!
//! This module contains shared types, FFI declarations, constants, callback
//! infrastructure, and display wrappers used by [`Trace`](crate::Trace).

// This module is pub(crate), so `pub` items inside it are effectively pub(crate).
// Using `pub(crate)` explicitly would trigger `redundant_pub_crate`.
#![expect(
    unreachable_pub,
    reason = "items are re-exported through the crate root"
)]

use super::{
    ClockResolution, EventCallback,
    panic_policy::{PanicCallback, PanicPayload, PanicResponse, PoisonFlag},
};
use crate::{
    Error, ParameterProblem, Result, event::RawEvent, processing_context::ProcessingContext,
};
use windows_sys::Win32::{
    Foundation::{ERROR_CTX_CLOSE_PENDING, ERROR_SUCCESS, WIN32_ERROR},
    System::{
        Diagnostics::Etw::{
            EVENT_RECORD, EVENT_TRACE, PROCESSTRACE_HANDLE, TRACE_LEVEL_INFORMATION,
        },
        Threading::{
            THREAD_PRIORITY, THREAD_PRIORITY_ABOVE_NORMAL, THREAD_PRIORITY_BELOW_NORMAL,
            THREAD_PRIORITY_HIGHEST, THREAD_PRIORITY_IDLE, THREAD_PRIORITY_LOWEST,
            THREAD_PRIORITY_NORMAL, THREAD_PRIORITY_TIME_CRITICAL,
        },
    },
};

// ═══════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════

/// Maximum session name length in UTF-16 code units (including null terminator).
pub const MAXIMUM_SESSION_NAME: usize = 64;

/// Invalid session ID value (no session started).
pub const INVALID_SESSION_ID: u64 = 0;

/// Invalid process trace handle value (sentinel from `OpenTraceW`).
pub const INVALID_PROCESSTRACE_HANDLE: u64 = 0xFFFF_FFFF_FFFF_FFFF;

// ═══════════════════════════════════════════════════════════════════════════════
// Provider Enablement Types
// ═══════════════════════════════════════════════════════════════════════════════

/// Information about an enabled provider.
///
/// Fields are tracked for Debug output and future re-enable-on-restart support.
pub struct EnabledProvider {
    pub name: Option<String>,
    pub guid: crate::Guid,
    pub level: u8,
    pub match_any_keyword: u64,
    pub enable_property: u32,
    pub filter: Option<ProviderFilter>,
}

/// Event ID filter for use with
/// [`Trace::enable_provider_ex`](crate::Trace::enable_provider_ex).
///
/// Allows filtering events at the kernel level by event ID.
///
/// The ID list must hold between 1 and 256 distinct IDs; anything else is
/// rejected with [`Error::InvalidParameter`](crate::Error::InvalidParameter)
/// when the filter is applied by
/// [`enable_provider_ex`](crate::Trace::enable_provider_ex).
///
/// # Example
///
/// ```no_run
/// use etw::session::EventIdFilter;
///
/// // Only receive events 3006 and 3008
/// let filter = EventIdFilter::include(&[3006, 3008]);
///
/// // Receive all events except 1 and 2
/// let filter = EventIdFilter::exclude(&[1, 2]);
/// ```
#[derive(Debug, Clone)]
pub struct EventIdFilter {
    /// If true, only the listed event IDs are included. If false, listed IDs are excluded.
    pub filter_in: bool,
    /// The event IDs to filter.
    pub event_ids: Vec<u16>,
}

impl EventIdFilter {
    /// Creates a filter that only includes the specified event IDs.
    pub fn include(event_ids: &[u16]) -> Self {
        Self {
            filter_in: true,
            event_ids: event_ids.to_vec(),
        }
    }

    /// Creates a filter that excludes the specified event IDs.
    pub fn exclude(event_ids: &[u16]) -> Self {
        Self {
            filter_in: false,
            event_ids: event_ids.to_vec(),
        }
    }
}

/// Filter type constants for `EVENT_FILTER_DESCRIPTOR.Type`.
pub mod filter_type {
    use windows_sys::Win32::System::Diagnostics::Etw::{
        EVENT_FILTER_TYPE_EVENT_ID as WINDOWS_EVENT_FILTER_TYPE_EVENT_ID,
        EVENT_FILTER_TYPE_PID as WINDOWS_EVENT_FILTER_TYPE_PID,
        EVENT_FILTER_TYPE_STACKWALK as WINDOWS_EVENT_FILTER_TYPE_STACKWALK,
    };

    /// Filter by event ID (include or exclude specific events).
    pub const EVENT_FILTER_TYPE_EVENT_ID: u32 = WINDOWS_EVENT_FILTER_TYPE_EVENT_ID;

    /// Filter which events get stack walk traces collected.
    pub const EVENT_FILTER_TYPE_STACKWALK: u32 = WINDOWS_EVENT_FILTER_TYPE_STACKWALK;

    /// Scope a provider's enablement to a set of process IDs (include-only).
    ///
    /// A *scope* filter, not an event filter: it is applied when the provider is
    /// enabled, so it only affects providers registered per-process in user
    /// mode. See [`ProviderFilter::pids`](super::ProviderFilter::pids).
    pub const EVENT_FILTER_TYPE_PID: u32 = WINDOWS_EVENT_FILTER_TYPE_PID;
}

/// ETW `EVENT_FILTER_EVENT_ID` structure for filtering events by ID.
const MAX_EVENT_ID_FILTER_COUNT: usize = 256;

#[repr(C)]
pub struct EventFilterEventId {
    pub filter_in: u8,
    pub reserved: u8,
    pub count: u16,
    pub events: [u16; MAX_EVENT_ID_FILTER_COUNT],
}

/// Maximum number of process IDs an `EVENT_FILTER_TYPE_PID` descriptor accepts.
///
/// ETW caps this filter at 8 PIDs; supplying more makes `EnableTraceEx2` fail
/// with `ERROR_INVALID_PARAMETER`.
const MAX_EVENT_FILTER_PID_COUNT: usize = 8;

/// Composed filter for
/// [`Trace::enable_provider_ex`](crate::Trace::enable_provider_ex).
///
/// Combines multiple filter types into a single descriptor array passed to
/// `EnableTraceEx2`.
///
/// # Example
///
/// ```no_run
/// use etw::{EnableProperty, EventIdFilter, Guid, ProviderFilter, Trace};
/// use windows_sys::Win32::System::Diagnostics::Etw::TRACE_LEVEL_VERBOSE;
///
/// const DNS_CLIENT: Guid = Guid::from_u128(0x1c95126e_7b3a_49a7_b0fc_767ef4f3a323);
///
/// let mut session = Trace::new("MySession")?;
/// session.start()?;
///
/// let filter = ProviderFilter::new()
///     .event_ids(EventIdFilter::include(&[1, 2]))
///     .stack_walk(EventIdFilter::include(&[1]));
///
/// session.enable_provider_ex(
///     DNS_CLIENT,
///     TRACE_LEVEL_VERBOSE,
///     etw::ALL_KEYWORDS,
///     EnableProperty::STACK_TRACE,
///     Some(filter),
/// )?;
/// # Ok::<(), etw::Error>(())
/// ```
#[derive(Debug, Clone, Default)]
pub struct ProviderFilter {
    pub(crate) event_ids: Option<EventIdFilter>,
    pub(crate) stack_walk: Option<EventIdFilter>,
    pub(crate) pids: Option<Vec<u32>>,
}

impl ProviderFilter {
    /// Creates an empty provider filter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter which events are delivered to the callback.
    #[must_use]
    pub fn event_ids(mut self, filter: EventIdFilter) -> Self {
        self.event_ids = Some(filter);
        self
    }

    /// Filter which events get stack walk traces collected.
    #[must_use]
    pub fn stack_walk(mut self, filter: EventIdFilter) -> Self {
        self.stack_walk = Some(filter);
        self
    }

    /// Scope delivery to events written by the given process IDs (include-only,
    /// at most 8 PIDs).
    ///
    /// This is an ETW *scope* filter (`EVENT_FILTER_TYPE_PID`): the ETW runtime
    /// enforces it at provider-enablement time, enabling the provider only in
    /// the listed processes — so it works only for providers registered
    /// per-process in user mode (manifest / `TraceLogging`). Kernel-mode
    /// providers such as `Microsoft-Windows-Kernel-Process` are enabled
    /// globally in the kernel with no per-process enablement hook, so
    /// `EnableTraceEx2` accepts the descriptor but **silently ignores** it —
    /// every process's events are still delivered (verified empirically). For
    /// kernel providers, filter on a payload PID field in the callback instead;
    /// note their `EVENT_HEADER.ProcessId` is the creator for a start event but
    /// the exiting process itself for a stop event, so it is not a reliable
    /// scope key.
    ///
    /// An empty or oversized (> 8) set is rejected when the filter is applied by
    /// [`enable_provider_ex`](crate::Trace::enable_provider_ex).
    #[must_use]
    pub fn pids(mut self, pids: &[u32]) -> Self {
        self.pids = Some(pids.to_vec());
        self
    }

    /// Returns `true` if no filters have been set.
    #[cfg(test)]
    const fn is_empty(&self) -> bool {
        self.event_ids.is_none() && self.stack_walk.is_none() && self.pids.is_none()
    }
}

impl From<EventIdFilter> for ProviderFilter {
    fn from(filter: EventIdFilter) -> Self {
        Self::new().event_ids(filter)
    }
}

/// Provider identifier that can be either a name or a GUID
#[derive(Debug)]
pub enum ProviderIdentifier {
    /// Provider name (resolved to a GUID at enable time)
    Name(String),
    /// Provider GUID
    Guid(crate::Guid),
}

impl ProviderIdentifier {
    /// Resolve to a `(name, GUID)` pair. Name is `None` when the provider was specified by GUID
    /// directly.
    pub fn resolve(self) -> Result<(Option<String>, crate::Guid)> {
        match self {
            Self::Name(name) => {
                let guid = crate::resolve::provider_guid_from_name(&name)?;
                Ok((Some(name), guid))
            }
            Self::Guid(guid) => Ok((None, guid)),
        }
    }
}

impl From<&str> for ProviderIdentifier {
    fn from(name: &str) -> Self {
        Self::Name(name.to_owned())
    }
}

impl From<String> for ProviderIdentifier {
    fn from(name: String) -> Self {
        Self::Name(name)
    }
}

impl From<&crate::Guid> for ProviderIdentifier {
    fn from(guid: &crate::Guid) -> Self {
        Self::Guid(*guid)
    }
}

impl From<crate::Guid> for ProviderIdentifier {
    fn from(guid: crate::Guid) -> Self {
        Self::Guid(guid)
    }
}

/// Returns [`ParameterProblem::Duplicates`] if any of `items` repeats.
pub(crate) fn ensure_unique<T: Eq + std::hash::Hash>(
    parameter: &'static str,
    items: impl IntoIterator<Item = T>,
) -> Result<()> {
    let mut seen = std::collections::HashSet::new();
    if items.into_iter().all(|item| seen.insert(item)) {
        Ok(())
    } else {
        Err(Error::InvalidParameter {
            parameter,
            problem: ParameterProblem::Duplicates,
        })
    }
}

/// Serialise an [`EventIdFilter`] into an aligned [`EventFilterEventId`].
pub fn serialize_event_id_filter(filter: &EventIdFilter) -> Result<EventFilterEventId> {
    if filter.event_ids.is_empty() {
        return Err(Error::InvalidParameter {
            parameter: "event ID filter",
            problem: ParameterProblem::Empty,
        });
    }

    if filter.event_ids.len() > MAX_EVENT_ID_FILTER_COUNT {
        return Err(Error::InvalidParameter {
            parameter: "event ID filter",
            problem: ParameterProblem::TooMany {
                count: filter.event_ids.len(),
                max: MAX_EVENT_ID_FILTER_COUNT,
            },
        });
    }

    ensure_unique("event ID filter", &filter.event_ids)?;

    let mut result = EventFilterEventId {
        filter_in: u8::from(filter.filter_in),
        reserved: 0,
        count: filter.event_ids.len() as u16,
        events: [0u16; MAX_EVENT_ID_FILTER_COUNT],
    };
    result.events[..filter.event_ids.len()].copy_from_slice(&filter.event_ids);

    Ok(result)
}

/// Validate a PID filter's process-ID list against ETW limits.
///
/// The list itself is the wire format for an `EVENT_FILTER_TYPE_PID`
/// descriptor (a packed array of `u32` PIDs), so no serialisation step is
/// needed beyond this bounds check.
///
/// # Errors
///
/// Returns [`Error::InvalidParameter`] if the list is empty or exceeds the
/// 8-PID `EVENT_FILTER_TYPE_PID` maximum.
pub const fn validate_pid_filter(pids: &[u32]) -> Result<()> {
    if pids.is_empty() {
        return Err(Error::InvalidParameter {
            parameter: "PID filter",
            problem: ParameterProblem::Empty,
        });
    }

    if pids.len() > MAX_EVENT_FILTER_PID_COUNT {
        return Err(Error::InvalidParameter {
            parameter: "PID filter",
            problem: ParameterProblem::TooMany {
                count: pids.len(),
                max: MAX_EVENT_FILTER_PID_COUNT,
            },
        });
    }

    Ok(())
}

/// Convert trace level to string.
pub const fn trace_level_name(level: u8) -> &'static str {
    match level {
        0 => "Disabled",
        1 => "Critical",
        2 => "Error",
        3 => "Warning",
        4 => "Information",
        5 => "Verbose",
        0xFF => "All",
        _ => "Unknown",
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// FFI Declarations
// ═══════════════════════════════════════════════════════════════════════════════

/// Manual definition for `EVENT_TRACE_LOGFILEW`.
///
/// See: <https://github.com/microsoft/windows-rs/issues/3597>
#[repr(C)]
#[expect(
    non_snake_case,
    reason = "field names mirror the Win32 struct definition"
)]
pub struct EVENT_TRACE_LOGFILEW {
    pub LogFileName: windows_sys::core::PWSTR,
    pub LoggerName: windows_sys::core::PWSTR,
    pub CurrentTime: i64,
    pub BuffersRead: u32,
    pub ProcessTraceMode: u32,
    pub _padding1: [u8; size_of::<EVENT_TRACE>()],
    /// `TRACE_LOGFILE_HEADER` — 280 bytes on 64-bit Windows.
    pub _padding2: [u8; 280],
    pub BufferCallback: Option<unsafe extern "system" fn(*mut Self) -> u32>,
    pub BufferSize: u32,
    pub Filled: u32,
    pub EventsLost: u32,
    pub EventRecordCallback: Option<unsafe extern "system" fn(*mut EVENT_RECORD)>,
    pub IsKernelTrace: u32,
    pub Context: *mut std::ffi::c_void,
}

const _: () = assert!(size_of::<EVENT_TRACE_LOGFILEW>() == 448);

#[link(name = "advapi32")]
unsafe extern "system" {
    pub fn OpenTraceW(logfile: *mut EVENT_TRACE_LOGFILEW) -> PROCESSTRACE_HANDLE;
    pub fn ProcessTrace(
        handlearray: *mut PROCESSTRACE_HANDLE,
        handlecount: u32,
        starttime: *mut i64,
        endtime: *mut i64,
    ) -> WIN32_ERROR;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Callback State
// ═══════════════════════════════════════════════════════════════════════════════

/// State shared with the ETW callback.
pub struct CallbackState {
    pub session_name: String,
    pub event_callback: Option<EventCallback>,
    pub processing_context: ProcessingContext,
    /// Set once a panic policy decides to stop the trace.
    ///
    /// From then on, already-delivered events are drained without being
    /// dispatched (entry guard in [`event_record_callback`]) and
    /// [`buffer_record_callback`] requests that `ProcessTrace` return.
    ///
    /// A [`PoisonFlag`] clone shared with the owning `Trace`, so the owner can
    /// observe the poison state (and reset it on restart) without forming a
    /// reference to this `CallbackState`, which the consumer thread borrows
    /// mutably while dispatching. The consumer thread writes it; the owner only
    /// reads/resets.
    pub poisoned: PoisonFlag,
    /// Caller-installed panic policy hook. `None` selects the default policy:
    /// log the panic and stop the trace.
    ///
    /// Invoked only on the consumer thread (ETW dispatches from a single
    /// `ProcessTrace` thread per trace), and installed only while processing is
    /// stopped, so it needs no lock.
    pub panic_callback: Option<PanicCallback>,
}

impl CallbackState {
    /// Returns whether a panic policy has decided to stop this trace.
    #[inline]
    pub fn is_poisoned(&self) -> bool {
        self.poisoned.is_poisoned()
    }

    /// Applies the panic policy to a payload caught by the trampoline.
    ///
    /// Invokes the caller-installed hook when there is one; any misbehaviour of
    /// the hook (panicking) degrades to the default policy. The default
    /// policy — and any [`PanicResponse::StopTrace`] verdict — poisons this
    /// trace so the buffer callback ends the processing thread cleanly.
    ///
    /// `provider` is the GUID of the event being dispatched when the panic
    /// happened, so the "stopping the trace" log names which source went dark.
    /// The poison store happens *before* any logging, so a faulting global
    /// logger cannot cost us the stop decision.
    pub fn handle_panic(&mut self, provider: crate::Guid, payload: Box<dyn std::any::Any + Send>) {
        let payload = PanicPayload::new(payload);
        // Capture the message before `payload` may be moved into the hook below.
        let message = payload.message().map(str::to_owned);

        #[expect(
            clippy::option_if_let_else,
            reason = "the suggested map_or nests a catch_unwind + match in a closure, which reads worse"
        )]
        let (response, reason): (PanicResponse, &str) = match self.panic_callback.as_mut() {
            None => (PanicResponse::StopTrace, "default policy"),
            Some(hook) => {
                // The hook must not unwind across the FFI boundary either, so it
                // gets the same catch_unwind treatment as the event callback.
                let verdict =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| hook(payload)));
                match verdict {
                    Ok(response) => (response, "panic_callback verdict"),
                    Err(_hook_panic) => {
                        (PanicResponse::StopTrace, "panic_callback itself panicked")
                    }
                }
            }
        };

        let message = message.as_deref().unwrap_or("<non-string panic payload>");
        if matches!(response, PanicResponse::StopTrace) {
            // Store the stop decision before logging (see the method docs); the
            // `provider`/`message` above only format values, they do not log.
            self.poisoned.poison();
            log::error!(
                "ETW session '{}': event callback panicked (provider {provider}): {message}; \
                 stopping the trace ({reason})",
                self.session_name
            );
        } else {
            // `Continue` is the embedder's explicit choice to keep dispatching.
            // Log at debug (not error) so a panic storm is visible under
            // RUST_LOG=debug without the hook itself having to log.
            log::debug!(
                "ETW session '{}': event callback panicked (provider {provider}): {message}; \
                 continuing ({reason})",
                self.session_name
            );
        }
    }
}

/// Static callback for ETW event records.
///
/// # Safety
///
/// This function is called by the ETW subsystem. The `event_record` pointer is
/// guaranteed valid by ETW for the duration of the callback.
pub unsafe extern "system" fn event_record_callback(event_record: *mut EVENT_RECORD) {
    if event_record.is_null() {
        return;
    }

    // SAFETY: ETW guarantees the event_record is valid for this callback's duration.
    unsafe {
        let context = (*event_record).UserContext;
        if context.is_null() {
            return;
        }

        let state = &mut *context.cast::<CallbackState>();

        // Entry guard: once a panic policy poisoned this trace, drain the
        // already-delivered events without dispatching into possibly-corrupt
        // callback state. `buffer_record_callback` requests that `ProcessTrace`
        // return at the end of the current buffer.
        if state.is_poisoned() {
            return;
        }

        if state.event_callback.is_none() {
            log::error!(
                "ETW session '{}': callback fired but event_callback is None — events are being lost",
                state.session_name
            );
            return;
        }

        // SAFETY: RawEvent is #[repr(transparent)] over EVENT_RECORD
        let event = RawEvent::from_ptr(event_record);

        // The two fields are borrowed disjointly inside the closure, so both
        // borrows end when `catch_unwind` returns and `state` is free to use in
        // the panic arm below.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // `event_callback` is Some (checked above); the else arm is
            // unreachable but keeps the borrow disjoint without an `expect`.
            if let Some(callback) = state.event_callback.as_mut() {
                callback(event, &mut state.processing_context)
            } else {
                Ok(())
            }
        }));

        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                log::debug!(
                    "ETW session '{}': event callback error: {e}",
                    state.session_name
                );
            }
            Err(payload) => {
                // This arm runs OUTSIDE the dispatch catch above, yet it still
                // logs — and logging calls into the embedder's global logger,
                // which could itself panic. Such a panic must not unwind across
                // this `extern "system"` boundary, so the whole arm is guarded;
                // `handle_panic` stores its stop decision before logging, so the
                // policy still takes effect even if a swallowed panic is in the
                // log call. The provider GUID is read here (cold path only), not
                // per event — `event` stays valid for the whole callback.
                let provider = event.provider_guid();
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    state.handle_panic(provider, payload);
                }));
            }
        }
    }
}

/// ETW buffer-completion callback that stops a poisoned trace.
///
/// ETW invokes this after delivering each buffer's events. Returning `FALSE`
/// makes `ProcessTrace` return at the end of the current buffer, ending the
/// processing thread's blocking call — this is how a
/// [`PanicResponse::StopTrace`](super::panic_policy::PanicResponse::StopTrace)
/// policy stops the consumer without another thread calling `CloseTrace`.
///
/// Two behaviours are relied upon here (observed by testing, not documented by
/// MSDN): on the `FALSE` route `ProcessTrace` returns `ERROR_SUCCESS`, **not**
/// the documented `ERROR_CANCELLED`, so cancellation is detected via the poison
/// flag and never the return code; and ETW keeps invoking this for buffers
/// already queued when `FALSE` was first returned, so the body must stay
/// idempotent (it only reads a flag).
///
/// # Safety
///
/// Called by the ETW subsystem. `logfile` is valid for the callback's duration,
/// and its `Context` field is the `CallbackState` pointer installed by
/// `open_and_spawn_processing_thread`, which outlives the processing thread.
pub unsafe extern "system" fn buffer_record_callback(logfile: *mut EVENT_TRACE_LOGFILEW) -> u32 {
    /// `TRUE`: keep delivering buffers to the event callback.
    const CONTINUE_PROCESSING: u32 = 1;
    /// `FALSE`: request that `ProcessTrace` return at the end of the current buffer.
    const STOP_PROCESSING: u32 = 0;

    // The body is a read-only flag check; a panic here would be a bug in this
    // crate, and stopping delivery is the conservative way out. The log itself
    // is guarded too, so a faulting logger cannot turn recovery into an unwind
    // across the boundary.
    let verdict = std::panic::catch_unwind(|| {
        if logfile.is_null() {
            return CONTINUE_PROCESSING;
        }
        // SAFETY: ETW guarantees `logfile` is valid for this callback.
        let context = unsafe { (*logfile).Context };
        if context.is_null() {
            return CONTINUE_PROCESSING;
        }
        // SAFETY: Context is the CallbackState pointer installed at open time,
        // valid until the processing thread is joined in stop(). Only read here.
        let state = unsafe { &*context.cast::<CallbackState>() };
        if state.is_poisoned() {
            STOP_PROCESSING
        } else {
            CONTINUE_PROCESSING
        }
    });

    verdict.unwrap_or_else(|_| {
        let _ = std::panic::catch_unwind(|| {
            log::error!("panic in ETW buffer callback; stopping the trace");
        });
        STOP_PROCESSING
    })
}

// ═══════════════════════════════════════════════════════════════════════════════
// Processing Thread Helpers
// ═══════════════════════════════════════════════════════════════════════════════

/// Set thread priority and description on the current thread.
///
/// Called from the processing thread after spawn.
pub fn processing_thread_setup(priority: THREAD_PRIORITY, thread_description: &str) {
    use windows_sys::Win32::System::Threading::{
        GetCurrentThread, SetThreadDescription, SetThreadPriority,
    };

    // SAFETY: GetCurrentThread returns a pseudo-handle that doesn't need closing.
    unsafe {
        if priority != THREAD_PRIORITY_NORMAL {
            let _ = SetThreadPriority(GetCurrentThread(), priority);
        }

        let thread_desc = format!("{thread_description}\0");
        let thread_desc_wide: Vec<u16> = thread_desc.encode_utf16().collect();
        let _ = SetThreadDescription(GetCurrentThread(), thread_desc_wide.as_ptr());
    }
}

/// Run `ProcessTrace` as a blocking call and return the status code.
pub fn process_trace_blocking(process_trace_handle: u64, session_name: &str) -> u32 {
    // SAFETY: ProcessTrace is a Win32 API. The handle is valid from OpenTraceW.
    unsafe {
        let mut handle = PROCESSTRACE_HANDLE {
            Value: process_trace_handle,
        };
        let status = ProcessTrace(
            &raw mut handle,
            1,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );

        if status == ERROR_CTX_CLOSE_PENDING {
            log::debug!("ProcessTrace stopped via CloseTrace for session '{session_name}'");
        } else if status == ERROR_SUCCESS {
            log::debug!("ProcessTrace completed normally for session '{session_name}'");
        } else {
            log::debug!(
                "ProcessTrace returned {:?}: {} for session '{}'",
                status,
                crate::ResolveMessage::resolve_message(&status),
                session_name
            );
        }

        status
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Display Helpers
// ═══════════════════════════════════════════════════════════════════════════════

/// Wrapper for displaying shutdown timeout values.
pub struct ShutdownTimeoutDisplay(pub u32);

impl std::fmt::Debug for ShutdownTimeoutDisplay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0 == u32::MAX {
            write!(f, "INFINITE")
        } else {
            write!(f, "{}ms", self.0)
        }
    }
}

/// Wrapper for displaying session ID values.
pub struct SessionIdDisplay(pub u64);

impl std::fmt::Debug for SessionIdDisplay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0 == INVALID_SESSION_ID {
            write!(f, "INVALID_SESSION_ID")
        } else {
            write!(f, "{}", self.0)
        }
    }
}

/// Wrapper for displaying process trace handle values.
pub struct TraceHandleDisplay(pub u64);

impl std::fmt::Debug for TraceHandleDisplay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0 == INVALID_PROCESSTRACE_HANDLE {
            write!(f, "INVALID_PROCESSTRACE_HANDLE")
        } else {
            write!(f, "0x{:X}", self.0)
        }
    }
}

/// Wrapper for displaying the processing thread handle.
pub struct ProcessingThreadDisplay<'a>(pub &'a Option<std::thread::JoinHandle<u32>>);

impl std::fmt::Debug for ProcessingThreadDisplay<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use std::os::windows::io::AsRawHandle;
        match self.0 {
            Some(handle) => write!(f, "0x{:X}", handle.as_raw_handle() as usize),
            None => write!(f, "None"),
        }
    }
}

/// Wrapper for displaying thread priority values.
pub struct ThreadPriorityDisplay(pub THREAD_PRIORITY);

impl std::fmt::Debug for ThreadPriorityDisplay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            THREAD_PRIORITY_IDLE => write!(f, "Idle"),
            THREAD_PRIORITY_LOWEST => write!(f, "Lowest"),
            THREAD_PRIORITY_BELOW_NORMAL => write!(f, "BelowNormal"),
            THREAD_PRIORITY_NORMAL => write!(f, "Normal"),
            THREAD_PRIORITY_ABOVE_NORMAL => write!(f, "AboveNormal"),
            THREAD_PRIORITY_HIGHEST => write!(f, "Highest"),
            THREAD_PRIORITY_TIME_CRITICAL => write!(f, "TimeCritical"),
            _ => write!(f, "{}", self.0),
        }
    }
}

/// Wrapper for displaying flush timer values (0 = OS minimum).
pub struct FlushTimer(pub u32);

impl std::fmt::Debug for FlushTimer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0 == 0 {
            write!(f, "minimum (1s)")
        } else {
            write!(f, "{}s", self.0)
        }
    }
}

/// Wrapper for displaying buffer count values (0 = OS default).
pub struct BufferCount(pub u32);

impl std::fmt::Debug for BufferCount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0 == 0 {
            write!(f, "OS default")
        } else {
            write!(f, "{}", self.0)
        }
    }
}

/// Wrapper for displaying buffer size values (0 = OS default).
pub struct BufferSize(pub u32);

impl std::fmt::Debug for BufferSize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0 == 0 {
            write!(f, "OS default")
        } else {
            write!(f, "{}KB", self.0)
        }
    }
}

/// Wrapper for displaying process trace mode flags.
pub struct ProcessTraceModeFlags(pub u32);

impl std::fmt::Debug for ProcessTraceModeFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use windows_sys::Win32::System::Diagnostics::Etw::{
            PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME,
        };

        let mut flags: Vec<&str> = Vec::new();
        let mut remaining = self.0;

        const PROCESS_TRACE_MODE_RAW_TIMESTAMP: u32 = 0x0000_1000;

        if remaining & PROCESS_TRACE_MODE_REAL_TIME != 0 {
            flags.push("REAL_TIME");
            remaining &= !PROCESS_TRACE_MODE_REAL_TIME;
        }
        if remaining & PROCESS_TRACE_MODE_EVENT_RECORD != 0 {
            flags.push("EVENT_RECORD");
            remaining &= !PROCESS_TRACE_MODE_EVENT_RECORD;
        }
        if remaining & PROCESS_TRACE_MODE_RAW_TIMESTAMP != 0 {
            flags.push("RAW_TIMESTAMP");
            remaining &= !PROCESS_TRACE_MODE_RAW_TIMESTAMP;
        }

        if flags.is_empty() && remaining == 0 {
            write!(f, "None")
        } else if remaining != 0 {
            if flags.is_empty() {
                write!(f, "0x{remaining:X}")
            } else {
                write!(f, "{} | 0x{:X}", flags.join(" | "), remaining)
            }
        } else {
            write!(f, "{}", flags.join(" | "))
        }
    }
}

/// Wrapper for displaying log file mode flags.
pub struct LogFileModeFlags(pub u32);

impl std::fmt::Debug for LogFileModeFlags {
    #[expect(
        clippy::cognitive_complexity,
        reason = "a linear sequence of flag checks, not complex logic"
    )]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut flags: Vec<&str> = Vec::new();
        let mut remaining = self.0;

        const EVENT_TRACE_FILE_MODE_SEQUENTIAL: u32 = 0x0000_0001;
        const EVENT_TRACE_FILE_MODE_CIRCULAR: u32 = 0x0000_0002;
        const EVENT_TRACE_FILE_MODE_APPEND: u32 = 0x0000_0004;
        const EVENT_TRACE_FILE_MODE_NEWFILE: u32 = 0x0000_0008;
        const EVENT_TRACE_FILE_MODE_PREALLOCATE: u32 = 0x0000_0020;
        const EVENT_TRACE_NONSTOPPABLE_MODE: u32 = 0x0000_0040;
        const EVENT_TRACE_SECURE_MODE: u32 = 0x0000_0080;
        const EVENT_TRACE_REAL_TIME_MODE: u32 = 0x0000_0100;
        const EVENT_TRACE_DELAY_OPEN_FILE_MODE: u32 = 0x0000_0200;
        const EVENT_TRACE_BUFFERING_MODE: u32 = 0x0000_0400;
        const EVENT_TRACE_PRIVATE_LOGGER_MODE: u32 = 0x0000_0800;
        const EVENT_TRACE_ADD_HEADER_MODE: u32 = 0x0000_1000;
        const EVENT_TRACE_USE_KBYTES_FOR_SIZE: u32 = 0x0000_2000;
        const EVENT_TRACE_USE_GLOBAL_SEQUENCE: u32 = 0x0000_4000;
        const EVENT_TRACE_USE_LOCAL_SEQUENCE: u32 = 0x0000_8000;
        const EVENT_TRACE_RELOG_MODE: u32 = 0x0001_0000;
        const EVENT_TRACE_PRIVATE_IN_PROC: u32 = 0x0002_0000;
        const EVENT_TRACE_STOP_ON_HYBRID_SHUTDOWN: u32 = 0x0040_0000;
        const EVENT_TRACE_PERSIST_ON_HYBRID_SHUTDOWN: u32 = 0x0080_0000;
        const EVENT_TRACE_USE_PAGED_MEMORY: u32 = 0x0100_0000;
        const EVENT_TRACE_SYSTEM_LOGGER_MODE: u32 = 0x0200_0000;
        const EVENT_TRACE_INDEPENDENT_SESSION_MODE: u32 = 0x0800_0000;
        const EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING: u32 = 0x1000_0000;
        const EVENT_TRACE_ADDTO_TRIAGE_DUMP: u32 = 0x8000_0000;

        macro_rules! check_flag {
            ($flag:expr, $name:expr) => {
                if remaining & $flag != 0 {
                    flags.push($name);
                    remaining &= !$flag;
                }
            };
        }

        check_flag!(EVENT_TRACE_FILE_MODE_SEQUENTIAL, "SEQUENTIAL");
        check_flag!(EVENT_TRACE_FILE_MODE_CIRCULAR, "CIRCULAR");
        check_flag!(EVENT_TRACE_FILE_MODE_APPEND, "APPEND");
        check_flag!(EVENT_TRACE_FILE_MODE_NEWFILE, "NEWFILE");
        check_flag!(EVENT_TRACE_FILE_MODE_PREALLOCATE, "PREALLOCATE");
        check_flag!(EVENT_TRACE_NONSTOPPABLE_MODE, "NONSTOPPABLE");
        check_flag!(EVENT_TRACE_SECURE_MODE, "SECURE");
        check_flag!(EVENT_TRACE_REAL_TIME_MODE, "REAL_TIME");
        check_flag!(EVENT_TRACE_DELAY_OPEN_FILE_MODE, "DELAY_OPEN_FILE");
        check_flag!(EVENT_TRACE_BUFFERING_MODE, "BUFFERING");
        check_flag!(EVENT_TRACE_PRIVATE_LOGGER_MODE, "PRIVATE_LOGGER");
        check_flag!(EVENT_TRACE_ADD_HEADER_MODE, "ADD_HEADER");
        check_flag!(EVENT_TRACE_USE_KBYTES_FOR_SIZE, "USE_KBYTES_FOR_SIZE");
        check_flag!(EVENT_TRACE_USE_GLOBAL_SEQUENCE, "USE_GLOBAL_SEQUENCE");
        check_flag!(EVENT_TRACE_USE_LOCAL_SEQUENCE, "USE_LOCAL_SEQUENCE");
        check_flag!(EVENT_TRACE_RELOG_MODE, "RELOG");
        check_flag!(EVENT_TRACE_PRIVATE_IN_PROC, "PRIVATE_IN_PROC");
        check_flag!(
            EVENT_TRACE_STOP_ON_HYBRID_SHUTDOWN,
            "STOP_ON_HYBRID_SHUTDOWN"
        );
        check_flag!(
            EVENT_TRACE_PERSIST_ON_HYBRID_SHUTDOWN,
            "PERSIST_ON_HYBRID_SHUTDOWN"
        );
        check_flag!(EVENT_TRACE_USE_PAGED_MEMORY, "USE_PAGED_MEMORY");
        check_flag!(EVENT_TRACE_SYSTEM_LOGGER_MODE, "SYSTEM_LOGGER");
        check_flag!(EVENT_TRACE_INDEPENDENT_SESSION_MODE, "INDEPENDENT_SESSION");
        check_flag!(
            EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING,
            "NO_PER_PROCESSOR_BUFFERING"
        );
        check_flag!(EVENT_TRACE_ADDTO_TRIAGE_DUMP, "ADDTO_TRIAGE_DUMP");

        if flags.is_empty() && remaining == 0 {
            write!(f, "None")
        } else if remaining != 0 {
            if flags.is_empty() {
                write!(f, "0x{remaining:X}")
            } else {
                write!(f, "{} | 0x{:X}", flags.join(" | "), remaining)
            }
        } else {
            write!(f, "{}", flags.join(" | "))
        }
    }
}

/// Wrapper for displaying clock resolution value.
pub struct ClockResolutionDisplay(pub u32);

impl std::fmt::Debug for ClockResolutionDisplay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            0 => write!(f, "OS default (QPC)"),
            ClockResolution::QPC => write!(f, "QPC"),
            ClockResolution::SYSTEM_TIME => write!(f, "SystemTime"),
            ClockResolution::CPU_CYCLE => write!(f, "CpuCycles"),
            _ => write!(f, "{}", self.0),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Provider Debug Display Helpers
// ═══════════════════════════════════════════════════════════════════════════════

impl std::fmt::Debug for EnabledProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let display_name = self
            .name
            .clone()
            .or_else(|| crate::resolve::provider_name_from_guid(&self.guid));

        if f.alternate() {
            let mut s = f.debug_struct("Provider");

            if let Some(ref name) = display_name {
                s.field("name", name);
            } else {
                s.field("guid", &self.guid);
            }

            if self.level as u32 != TRACE_LEVEL_INFORMATION {
                s.field("level", &trace_level_name(self.level));
            }

            if self.match_any_keyword != 0 {
                s.field(
                    "match_any_keyword",
                    &format_args!("0x{:X}", self.match_any_keyword),
                );
            }

            if self.enable_property != 0 {
                s.field(
                    "enable_property",
                    &EnablePropertyFlags(self.enable_property),
                );
            }

            if let Some(ref pf) = self.filter {
                if let Some(ref ef) = pf.event_ids {
                    s.field("event_filter", &EventFilterDisplay(ef));
                }
                if let Some(ref sw) = pf.stack_walk {
                    s.field("stack_walk_filter", &EventFilterDisplay(sw));
                }
                if let Some(ref pids) = pf.pids {
                    s.field("pid_filter", pids);
                }
            }

            s.finish()
        } else {
            if let Some(ref name) = display_name {
                write!(f, "{name}")?;
            } else {
                write!(f, "{}", self.guid)?;
            }

            let mut parts: Vec<String> = Vec::new();
            if self.level as u32 != TRACE_LEVEL_INFORMATION {
                parts.push(format!("level={}", trace_level_name(self.level)));
            }
            if self.match_any_keyword != 0 {
                parts.push(format!("any=0x{:X}", self.match_any_keyword));
            }
            if self.enable_property != 0 {
                parts.push(format!(
                    "props={:?}",
                    EnablePropertyFlags(self.enable_property)
                ));
            }
            if let Some(ref pf) = self.filter {
                if let Some(ref ef) = pf.event_ids {
                    parts.push(format!("filter={:?}", EventFilterDisplay(ef)));
                }
                if let Some(ref sw) = pf.stack_walk {
                    parts.push(format!("stack_walk={:?}", EventFilterDisplay(sw)));
                }
                if let Some(ref pids) = pf.pids {
                    parts.push(format!("pids={pids:?}"));
                }
            }
            if !parts.is_empty() {
                write!(f, " ({})", parts.join(", "))?;
            }
            Ok(())
        }
    }
}

/// Wrapper for displaying event filter.
pub struct EventFilterDisplay<'a>(pub &'a EventIdFilter);

impl std::fmt::Debug for EventFilterDisplay<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mode = if self.0.filter_in {
            "include"
        } else {
            "exclude"
        };
        if self.0.event_ids.len() <= 3 {
            write!(f, "{}({:?})", mode, self.0.event_ids)
        } else {
            write!(
                f,
                "{}([{}, {}, {}, ... {} more])",
                mode,
                self.0.event_ids[0],
                self.0.event_ids[1],
                self.0.event_ids[2],
                self.0.event_ids.len() - 3
            )
        }
    }
}

/// Wrapper for displaying enable property flags.
pub struct EnablePropertyFlags(pub u32);

impl std::fmt::Debug for EnablePropertyFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use super::trace::EnableProperty;

        let mut flags: Vec<&str> = Vec::new();
        let mut remaining = self.0;

        if remaining & EnableProperty::SID != 0 {
            flags.push("SID");
            remaining &= !EnableProperty::SID;
        }
        if remaining & EnableProperty::TS_ID != 0 {
            flags.push("TS_ID");
            remaining &= !EnableProperty::TS_ID;
        }
        if remaining & EnableProperty::STACK_TRACE != 0 {
            flags.push("STACK_TRACE");
            remaining &= !EnableProperty::STACK_TRACE;
        }
        if remaining & EnableProperty::IGNORE_KEYWORD_0 != 0 {
            flags.push("IGNORE_KEYWORD_0");
            remaining &= !EnableProperty::IGNORE_KEYWORD_0;
        }
        if remaining & EnableProperty::ENABLE_KEYWORD_0 != 0 {
            flags.push("ENABLE_KEYWORD_0");
            remaining &= !EnableProperty::ENABLE_KEYWORD_0;
        }
        if remaining & EnableProperty::PROCESS_START_KEY != 0 {
            flags.push("PROCESS_START_KEY");
            remaining &= !EnableProperty::PROCESS_START_KEY;
        }

        if flags.is_empty() && remaining == 0 {
            write!(f, "None")
        } else if remaining != 0 {
            if flags.is_empty() {
                write!(f, "0x{remaining:X}")
            } else {
                write!(f, "{} | 0x{:X}", flags.join(" | "), remaining)
            }
        } else {
            write!(f, "{}", flags.join(" | "))
        }
    }
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "test-only assertions")]
mod tests {
    use super::*;

    #[test]
    fn test_event_id_filter_include() {
        let filter = EventIdFilter::include(&[1, 2, 3]);
        assert!(filter.filter_in);
        assert_eq!(filter.event_ids, vec![1, 2, 3]);
    }

    #[test]
    fn test_event_id_filter_exclude() {
        let filter = EventIdFilter::exclude(&[100, 200]);
        assert!(!filter.filter_in);
        assert_eq!(filter.event_ids, vec![100, 200]);
    }

    #[test]
    fn test_event_filter_event_id_struct_size() {
        assert_eq!(
            size_of::<EventFilterEventId>(),
            4 + MAX_EVENT_ID_FILTER_COUNT * 2
        );
    }

    #[test]
    fn test_provider_filter_default_is_empty() {
        let pf = ProviderFilter::default();
        assert!(pf.is_empty());
    }

    #[test]
    fn test_provider_filter_event_ids() {
        let pf = ProviderFilter::new().event_ids(EventIdFilter::include(&[1, 2]));
        assert!(!pf.is_empty());
        assert!(pf.event_ids.is_some());
        assert!(pf.stack_walk.is_none());
    }

    #[test]
    fn test_provider_filter_from_event_id_filter() {
        let ef = EventIdFilter::include(&[5, 6, 7]);
        let pf: ProviderFilter = ef.into();
        assert!(!pf.is_empty());
        assert!(pf.event_ids.is_some());
    }

    #[test]
    fn test_serialize_event_id_filter() {
        let ef = EventIdFilter::include(&[100, 200]);
        let buf = serialize_event_id_filter(&ef).expect("serialize should succeed");
        assert_eq!(buf.filter_in, 1);
        assert_eq!(buf.reserved, 0);
        assert_eq!(buf.count, 2);
        assert_eq!(buf.events[0], 100);
        assert_eq!(buf.events[1], 200);
    }

    #[test]
    fn test_provider_filter_stack_walk_accessor() {
        let pf = ProviderFilter::new().stack_walk(EventIdFilter::include(&[10, 20]));
        assert!(!pf.is_empty());
        assert!(pf.event_ids.is_none());
        let sw = pf.stack_walk.as_ref().expect("stack_walk should be set");
        assert!(sw.filter_in);
        assert_eq!(sw.event_ids, vec![10, 20]);
    }

    #[test]
    fn test_provider_filter_pids_accessor() {
        let pf = ProviderFilter::new().pids(&[1234, 5678]);
        assert!(!pf.is_empty());
        assert!(pf.event_ids.is_none());
        assert!(pf.stack_walk.is_none());
        assert_eq!(pf.pids.as_deref(), Some([1234, 5678].as_slice()));
    }

    #[test]
    fn test_validate_pid_filter_accepts_valid() {
        validate_pid_filter(&[1, 2, 3]).expect("in-range PID list should validate");
    }

    #[test]
    fn test_validate_pid_filter_accepts_max() {
        let pids: Vec<u32> = (0..MAX_EVENT_FILTER_PID_COUNT as u32).collect();
        validate_pid_filter(&pids).expect("exactly 8 PIDs should validate");
    }

    #[test]
    fn test_validate_pid_filter_rejects_empty() {
        let err = validate_pid_filter(&[]).expect_err("empty PID list must be rejected");
        // The specific problem matters: "empty" and "too many" are different
        // caller mistakes, and a bare InvalidParameter check cannot tell them apart.
        assert!(
            matches!(
                err,
                Error::InvalidParameter {
                    parameter: "PID filter",
                    problem: ParameterProblem::Empty
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn test_validate_pid_filter_rejects_too_many() {
        let pids: Vec<u32> = (0..=MAX_EVENT_FILTER_PID_COUNT as u32).collect();
        let err =
            validate_pid_filter(&pids).expect_err("9 PIDs exceeds the 8-PID cap and must fail");
        // Pin the counts, not just the variant: the cap and the supplied size are
        // the actionable part, and they are now data rather than prose.
        assert!(
            matches!(
                err,
                Error::InvalidParameter {
                    parameter: "PID filter",
                    problem: ParameterProblem::TooMany { count, max }
                } if count == MAX_EVENT_FILTER_PID_COUNT + 1 && max == MAX_EVENT_FILTER_PID_COUNT
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn test_provider_identifier_from_str_borrows_into_name() {
        let id: ProviderIdentifier = "Microsoft-Windows-DNS-Client".into();
        match id {
            ProviderIdentifier::Name(name) => {
                assert_eq!(name, "Microsoft-Windows-DNS-Client");
            }
            ProviderIdentifier::Guid(_) => panic!("expected Name variant"),
        }
    }

    #[test]
    fn test_provider_identifier_from_string_takes_ownership() {
        let owned = String::from("Microsoft-Windows-Kernel-Process");
        let id: ProviderIdentifier = owned.into();
        match id {
            ProviderIdentifier::Name(name) => {
                assert_eq!(name, "Microsoft-Windows-Kernel-Process");
            }
            ProviderIdentifier::Guid(_) => panic!("expected Name variant"),
        }
    }

    #[test]
    fn test_provider_identifier_from_guid_ref_and_owned() {
        let g = crate::Guid::from_u128(0x1122_3344_5566_7788_99AA_BBCC_DDEE_FF00);

        let id_ref: ProviderIdentifier = (&g).into();
        match id_ref {
            ProviderIdentifier::Guid(guid) => assert_eq!(guid, g),
            ProviderIdentifier::Name(_) => panic!("expected Guid variant"),
        }

        let id_owned: ProviderIdentifier = g.into();
        match id_owned {
            ProviderIdentifier::Guid(guid) => assert_eq!(guid, g),
            ProviderIdentifier::Name(_) => panic!("expected Guid variant"),
        }
    }

    #[test]
    fn test_trace_level_name_known_levels() {
        assert_eq!(trace_level_name(0), "Disabled");
        assert_eq!(trace_level_name(1), "Critical");
        assert_eq!(trace_level_name(2), "Error");
        assert_eq!(trace_level_name(3), "Warning");
        assert_eq!(trace_level_name(4), "Information");
        assert_eq!(trace_level_name(5), "Verbose");
        assert_eq!(trace_level_name(0xFF), "All");
    }

    #[test]
    fn test_trace_level_name_unknown() {
        assert_eq!(trace_level_name(6), "Unknown");
        assert_eq!(trace_level_name(99), "Unknown");
        assert_eq!(trace_level_name(0xFE), "Unknown");
    }

    // =========================================================================
    // Display helper Debug impls
    // =========================================================================

    #[test]
    fn test_shutdown_timeout_display_infinite() {
        assert_eq!(
            format!("{:?}", ShutdownTimeoutDisplay(u32::MAX)),
            "INFINITE"
        );
    }

    #[test]
    fn test_shutdown_timeout_display_finite() {
        assert_eq!(format!("{:?}", ShutdownTimeoutDisplay(5000)), "5000ms");
        assert_eq!(format!("{:?}", ShutdownTimeoutDisplay(0)), "0ms");
    }

    #[test]
    fn test_session_id_display_invalid() {
        assert_eq!(
            format!("{:?}", SessionIdDisplay(INVALID_SESSION_ID)),
            "INVALID_SESSION_ID"
        );
    }

    #[test]
    fn test_session_id_display_normal() {
        assert_eq!(format!("{:?}", SessionIdDisplay(3)), "3");
    }

    #[test]
    fn test_trace_handle_display_invalid() {
        assert_eq!(
            format!("{:?}", TraceHandleDisplay(INVALID_PROCESSTRACE_HANDLE)),
            "INVALID_PROCESSTRACE_HANDLE"
        );
    }

    #[test]
    fn test_trace_handle_display_normal() {
        assert_eq!(format!("{:?}", TraceHandleDisplay(0xABCD)), "0xABCD");
    }

    #[test]
    fn test_processing_thread_display_none() {
        assert_eq!(format!("{:?}", ProcessingThreadDisplay(&None)), "None");
    }

    #[test]
    fn test_thread_priority_display_known() {
        use windows_sys::Win32::System::Threading::{
            THREAD_PRIORITY_ABOVE_NORMAL, THREAD_PRIORITY_BELOW_NORMAL, THREAD_PRIORITY_HIGHEST,
            THREAD_PRIORITY_IDLE, THREAD_PRIORITY_LOWEST, THREAD_PRIORITY_NORMAL,
            THREAD_PRIORITY_TIME_CRITICAL,
        };
        assert_eq!(
            format!("{:?}", ThreadPriorityDisplay(THREAD_PRIORITY_IDLE)),
            "Idle"
        );
        assert_eq!(
            format!("{:?}", ThreadPriorityDisplay(THREAD_PRIORITY_LOWEST)),
            "Lowest"
        );
        assert_eq!(
            format!("{:?}", ThreadPriorityDisplay(THREAD_PRIORITY_BELOW_NORMAL)),
            "BelowNormal"
        );
        assert_eq!(
            format!("{:?}", ThreadPriorityDisplay(THREAD_PRIORITY_NORMAL)),
            "Normal"
        );
        assert_eq!(
            format!("{:?}", ThreadPriorityDisplay(THREAD_PRIORITY_ABOVE_NORMAL)),
            "AboveNormal"
        );
        assert_eq!(
            format!("{:?}", ThreadPriorityDisplay(THREAD_PRIORITY_HIGHEST)),
            "Highest"
        );
        assert_eq!(
            format!("{:?}", ThreadPriorityDisplay(THREAD_PRIORITY_TIME_CRITICAL)),
            "TimeCritical"
        );
    }

    #[test]
    fn test_thread_priority_display_unknown() {
        let out = format!("{:?}", ThreadPriorityDisplay(99));
        assert_eq!(out, "99");
    }

    #[test]
    fn test_flush_timer_display() {
        assert_eq!(format!("{:?}", FlushTimer(0)), "minimum (1s)");
        assert_eq!(format!("{:?}", FlushTimer(3)), "3s");
    }

    #[test]
    fn test_buffer_count_display() {
        assert_eq!(format!("{:?}", BufferCount(0)), "OS default");
        assert_eq!(format!("{:?}", BufferCount(4)), "4");
    }

    #[test]
    fn test_buffer_size_display() {
        assert_eq!(format!("{:?}", BufferSize(0)), "OS default");
        assert_eq!(format!("{:?}", BufferSize(64)), "64KB");
    }

    #[test]
    fn test_process_trace_mode_flags_display() {
        use windows_sys::Win32::System::Diagnostics::Etw::{
            PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME,
        };
        assert_eq!(format!("{:?}", ProcessTraceModeFlags(0)), "None");
        assert_eq!(
            format!("{:?}", ProcessTraceModeFlags(PROCESS_TRACE_MODE_REAL_TIME)),
            "REAL_TIME"
        );
        assert_eq!(
            format!(
                "{:?}",
                ProcessTraceModeFlags(
                    PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD
                )
            ),
            "REAL_TIME | EVENT_RECORD"
        );
        // Unknown bit preserved
        let s = format!("{:?}", ProcessTraceModeFlags(0xDEAD_0000));
        assert!(s.contains("0x"), "unknown bits shown as hex: {s}");
    }

    #[test]
    fn test_log_file_mode_flags_display() {
        assert_eq!(format!("{:?}", LogFileModeFlags(0)), "None");
        assert_eq!(format!("{:?}", LogFileModeFlags(0x0000_0001)), "SEQUENTIAL");
        assert_eq!(
            format!("{:?}", LogFileModeFlags(0x0000_0003)),
            "SEQUENTIAL | CIRCULAR"
        );
        // Unknown bit preserved
        let s = format!("{:?}", LogFileModeFlags(0x0010_0000));
        assert!(s.contains("0x"), "unknown bits shown as hex: {s}");
    }

    #[test]
    fn test_clock_resolution_display() {
        assert_eq!(
            format!("{:?}", ClockResolutionDisplay(0)),
            "OS default (QPC)"
        );
        assert_eq!(
            format!("{:?}", ClockResolutionDisplay(ClockResolution::QPC)),
            "QPC"
        );
        assert_eq!(
            format!("{:?}", ClockResolutionDisplay(ClockResolution::SYSTEM_TIME)),
            "SystemTime"
        );
        assert_eq!(
            format!("{:?}", ClockResolutionDisplay(ClockResolution::CPU_CYCLE)),
            "CpuCycles"
        );
        // Unknown value
        let s = format!("{:?}", ClockResolutionDisplay(99));
        assert_eq!(s, "99");
    }

    #[test]
    fn test_event_filter_display_few_ids() {
        let ef = EventIdFilter::include(&[1, 2, 3]);
        assert_eq!(
            format!("{:?}", EventFilterDisplay(&ef)),
            "include([1, 2, 3])"
        );
    }

    #[test]
    fn test_event_filter_display_many_ids() {
        let ef = EventIdFilter::exclude(&[10, 20, 30, 40]);
        let s = format!("{:?}", EventFilterDisplay(&ef));
        assert_eq!(s, "exclude([10, 20, 30, ... 1 more])");
    }

    #[test]
    fn test_enable_property_flags_display_none() {
        assert_eq!(format!("{:?}", EnablePropertyFlags(0)), "None");
    }

    #[test]
    fn test_enable_property_flags_display_known() {
        use crate::session::trace::EnableProperty;
        assert_eq!(
            format!("{:?}", EnablePropertyFlags(EnableProperty::SID)),
            "SID"
        );
        assert_eq!(
            format!(
                "{:?}",
                EnablePropertyFlags(EnableProperty::SID | EnableProperty::STACK_TRACE)
            ),
            "SID | STACK_TRACE"
        );
    }

    #[test]
    fn test_enable_property_flags_display_unknown() {
        let s = format!("{:?}", EnablePropertyFlags(0xDEAD_0000));
        assert!(s.contains("0x"), "unknown bits shown as hex: {s}");
    }

    #[test]
    fn test_log_file_mode_flags_more_variants() {
        // Each flag tested individually to exercise every check_flag! branch
        let cases: &[(u32, &str)] = &[
            (0x0000_0004, "APPEND"),
            (0x0000_0008, "NEWFILE"),
            (0x0000_0020, "PREALLOCATE"),
            (0x0000_0040, "NONSTOPPABLE"),
            (0x0000_0080, "SECURE"),
            (0x0000_0100, "REAL_TIME"),
            (0x0000_0200, "DELAY_OPEN_FILE"),
            (0x0000_0400, "BUFFERING"),
            (0x0000_0800, "PRIVATE_LOGGER"),
            (0x0000_1000, "ADD_HEADER"),
            (0x0000_2000, "USE_KBYTES_FOR_SIZE"),
            (0x0000_4000, "USE_GLOBAL_SEQUENCE"),
            (0x0000_8000, "USE_LOCAL_SEQUENCE"),
            (0x0001_0000, "RELOG"),
            (0x0002_0000, "PRIVATE_IN_PROC"),
            (0x0040_0000, "STOP_ON_HYBRID_SHUTDOWN"),
            (0x0080_0000, "PERSIST_ON_HYBRID_SHUTDOWN"),
            (0x0100_0000, "USE_PAGED_MEMORY"),
            (0x0200_0000, "SYSTEM_LOGGER"),
            (0x0800_0000, "INDEPENDENT_SESSION"),
            (0x1000_0000, "NO_PER_PROCESSOR_BUFFERING"),
            (0x8000_0000, "ADDTO_TRIAGE_DUMP"),
        ];
        for &(flag, expected) in cases {
            let s = format!("{:?}", LogFileModeFlags(flag));
            assert_eq!(s, expected, "flag 0x{flag:08X}");
        }
        // Mixed known + unknown: known | unknown bit
        let mixed = 0x0000_0004 | 0x0004_0000; // APPEND | unknown
        let s = format!("{:?}", LogFileModeFlags(mixed));
        assert!(s.contains("APPEND"), "should contain APPEND: {s}");
        assert!(s.contains("0x"), "should contain unknown bits as hex: {s}");
    }

    #[test]
    fn test_enabled_provider_debug_minimal() {
        let provider = EnabledProvider {
            name: Some("TestProvider".to_owned()),
            guid: crate::Guid::from_u128(0x1234_5678_0000_0000_0000_0000_0000_0000),
            level: 4, // TRACE_LEVEL_INFORMATION — omitted from output
            match_any_keyword: 0,
            enable_property: 0,
            filter: None,
        };
        // Alternate debug: debug_struct format
        let s = format!("{provider:#?}");
        assert!(s.contains("Provider"), "got: {s}");
        assert!(s.contains("TestProvider"), "got: {s}");
        // Non-alternate: compact format
        let s2 = format!("{provider:?}");
        assert!(s2.contains("TestProvider"), "got: {s2}");
    }

    #[test]
    // `name: None` makes Debug resolve the name from the GUID.
    #[cfg_attr(miri, ignore = "calls TdhEnumerateProviders (Win32)")]
    fn test_enabled_provider_debug_with_keyword_and_filter() {
        let provider = EnabledProvider {
            name: None,
            guid: crate::Guid::from_u128(0xAAAA_BBBB_0000_0000_0000_0000_0000_0000),
            level: 1, // Critical — non-default, should appear in output
            match_any_keyword: 0xFFFF,
            enable_property: 1, // SID
            filter: None,
        };
        let s = format!("{provider:#?}");
        assert!(s.contains("Critical"), "got: {s}");
        assert!(s.contains("FFFF"), "got: {s}");
    }

    #[test]
    fn test_enabled_provider_debug_alternate_with_event_and_stack_filters() {
        // Alternate Debug ({:#?}) with both event_ids and stack_walk filters
        // populated — exercises the filter-display arms.
        let filter = ProviderFilter::new()
            .event_ids(EventIdFilter::include(&[1, 2, 3]))
            .stack_walk(EventIdFilter::include(&[42]));
        let provider = EnabledProvider {
            name: Some("Test-Provider".to_owned()),
            guid: crate::Guid::from_u128(0xAAAA_BBBB_0000_0000_0000_0000_0000_0000),
            level: 4,
            match_any_keyword: 0,
            enable_property: 0,
            filter: Some(filter),
        };
        let s = format!("{provider:#?}");
        assert!(s.contains("event_filter"), "got: {s}");
        assert!(s.contains("stack_walk_filter"), "got: {s}");
    }

    #[test]
    fn test_enabled_provider_debug_compact_with_event_and_stack_filters() {
        // Non-alternate Debug ({:?}) path with both filters set.
        let filter = ProviderFilter::new()
            .event_ids(EventIdFilter::include(&[1, 2, 3]))
            .stack_walk(EventIdFilter::include(&[42]));
        let provider = EnabledProvider {
            name: Some("Test-Provider".to_owned()),
            guid: crate::Guid::from_u128(0xAAAA_BBBB_0000_0000_0000_0000_0000_0000),
            level: 4,
            match_any_keyword: 0,
            enable_property: 0,
            filter: Some(filter),
        };
        let s = format!("{provider:?}");
        assert!(s.contains("filter="), "got: {s}");
        assert!(s.contains("stack_walk="), "got: {s}");
    }

    #[test]
    fn test_enabled_provider_debug_alternate_with_pid_filter() {
        // A PID-scoped provider must be distinguishable from an unfiltered one:
        // EVENT_FILTER_TYPE_PID is silently ignored by kernel-mode providers, so
        // the Debug output is the only place a user can confirm the scope was set.
        let provider = EnabledProvider {
            name: Some("Test-Provider".to_owned()),
            guid: crate::Guid::from_u128(0xAAAA_BBBB_0000_0000_0000_0000_0000_0000),
            level: 4,
            match_any_keyword: 0,
            enable_property: 0,
            filter: Some(ProviderFilter::new().pids(&[1234, 5678])),
        };
        let s = format!("{provider:#?}");
        assert!(s.contains("pid_filter"), "got: {s}");
        assert!(s.contains("1234"), "got: {s}");
        assert!(s.contains("5678"), "got: {s}");
    }

    #[test]
    fn test_enabled_provider_debug_compact_with_pid_filter() {
        // Non-alternate Debug ({:?}) path with only a PID filter set.
        let provider = EnabledProvider {
            name: Some("Test-Provider".to_owned()),
            guid: crate::Guid::from_u128(0xAAAA_BBBB_0000_0000_0000_0000_0000_0000),
            level: 4,
            match_any_keyword: 0,
            enable_property: 0,
            filter: Some(ProviderFilter::new().pids(&[1234, 5678])),
        };
        let s = format!("{provider:?}");
        assert!(s.contains("pids=[1234, 5678]"), "got: {s}");
    }

    #[test]
    fn test_enable_property_flags_all_variants() {
        use crate::session::trace::EnableProperty;
        let cases: &[(u32, &str)] = &[
            (EnableProperty::TS_ID, "TS_ID"),
            (EnableProperty::IGNORE_KEYWORD_0, "IGNORE_KEYWORD_0"),
            (EnableProperty::ENABLE_KEYWORD_0, "ENABLE_KEYWORD_0"),
            (EnableProperty::PROCESS_START_KEY, "PROCESS_START_KEY"),
        ];
        for &(flag, expected) in cases {
            let s = format!("{:?}", EnablePropertyFlags(flag));
            assert_eq!(s, expected, "flag 0x{flag:08X}");
        }
    }

    #[test]
    fn test_serialize_event_id_filter_empty_error() {
        let filter = EventIdFilter::include(&[]);
        let result = serialize_event_id_filter(&filter);
        assert!(result.is_err());
    }

    #[test]
    fn test_serialize_event_id_filter_too_many_ids_error() {
        // MAX_EVENT_ID_FILTER_COUNT is 256
        let ids: Vec<u16> = (0..=256u16).collect(); // 257 IDs
        let filter = EventIdFilter::include(&ids);
        let result = serialize_event_id_filter(&filter);
        assert!(result.is_err());
    }

    /// Filter contents can come from runtime data, so a repeat is an `Err` the
    /// caller can handle rather than a panic.
    #[test]
    fn test_serialize_event_id_filter_duplicate_ids_error() {
        let filter = EventIdFilter::include(&[1, 2, 1]);
        let err = serialize_event_id_filter(&filter)
            .err()
            .expect("duplicate IDs must be rejected");
        assert!(
            matches!(
                err,
                Error::InvalidParameter {
                    parameter: "event ID filter",
                    problem: ParameterProblem::Duplicates,
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn test_ensure_unique() {
        assert!(ensure_unique("p", [1, 2, 3]).is_ok());
        assert!(ensure_unique("p", std::iter::empty::<u8>()).is_ok());
        // A repeat across a chained boundary is how set_pool_tag_filter() sees
        // a tag already added by an earlier call.
        let err = ensure_unique("p", [1, 2].iter().chain(&[3, 1]))
            .expect_err("1 repeats across the chain");
        assert!(
            matches!(
                err,
                Error::InvalidParameter {
                    parameter: "p",
                    problem: ParameterProblem::Duplicates,
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn test_provider_identifier_resolve_guid() {
        let guid = crate::Guid::from_u128(0x1234_5678_0000_0000_0000_0000_0000_0000);
        let id = ProviderIdentifier::Guid(guid);
        let (name, resolved_guid) = id.resolve().expect("should resolve");
        assert!(name.is_none());
        assert_eq!(resolved_guid, guid);
    }
}

// =============================================================================
// Panic-policy handling tests
// =============================================================================
//
// These exercise `CallbackState::handle_panic` directly — the load-bearing
// policy logic — with no ETW/Win32/DNS dependency, so they run on every build
// rather than only behind the elevated integration tests in tests/panic_policy.rs.
#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test-only assertions")]
mod panic_handling_tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn make_state(hook: Option<PanicCallback>) -> CallbackState {
        CallbackState {
            session_name: "test-session".to_owned(),
            event_callback: None,
            processing_context: ProcessingContext::new(),
            poisoned: PoisonFlag::new(),
            panic_callback: hook,
        }
    }

    /// A message-recording hook returning the given verdict, plus the shared
    /// slot it writes the observed message into.
    fn recording_hook(verdict: PanicResponse) -> (PanicCallback, Arc<Mutex<Option<String>>>) {
        let seen = Arc::new(Mutex::new(None::<String>));
        let seen_hook = Arc::clone(&seen);
        let hook: PanicCallback = Box::new(move |payload| {
            *seen_hook.lock().unwrap() = payload.message().map(str::to_owned);
            verdict
        });
        (hook, seen)
    }

    #[test]
    fn default_policy_poisons_the_trace() {
        let mut state = make_state(None);
        assert!(!state.is_poisoned());
        state.handle_panic(crate::Guid::from_u128(0), Box::new("boom"));
        assert!(state.is_poisoned(), "default policy must poison the trace");
    }

    #[test]
    fn continue_hook_does_not_poison_and_receives_payload() {
        let (hook, seen) = recording_hook(PanicResponse::Continue);
        let mut state = make_state(Some(hook));
        state.handle_panic(crate::Guid::from_u128(0), Box::new("boom"));
        assert!(!state.is_poisoned(), "Continue must not poison the trace");
        assert_eq!(seen.lock().unwrap().as_deref(), Some("boom"));
    }

    #[test]
    fn stop_hook_poisons_and_receives_payload() {
        let (hook, seen) = recording_hook(PanicResponse::StopTrace);
        let mut state = make_state(Some(hook));
        state.handle_panic(crate::Guid::from_u128(0), Box::new(String::from("kaboom")));
        assert!(state.is_poisoned(), "StopTrace must poison the trace");
        assert_eq!(seen.lock().unwrap().as_deref(), Some("kaboom"));
    }

    #[test]
    fn panicking_hook_degrades_to_stop() {
        // A hook that unwinds must not cross the FFI boundary; handle_panic
        // catches it and falls back to the default StopTrace policy. (The caught
        // panic prints to captured stderr — expected, not a failure.)
        let hook: PanicCallback = Box::new(|_payload| panic!("hook itself panics"));
        let mut state = make_state(Some(hook));
        state.handle_panic(crate::Guid::from_u128(0), Box::new("boom"));
        assert!(
            state.is_poisoned(),
            "a panicking hook must degrade to the default stop policy"
        );
    }

    #[test]
    fn non_string_payload_still_poisons_under_default() {
        let mut state = make_state(None);
        state.handle_panic(crate::Guid::from_u128(0), Box::new(42_u32));
        assert!(state.is_poisoned());
    }
}
