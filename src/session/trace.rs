//! Unified ETW trace session management.
//!
//! [`Trace`] supports both modern provider-based tracing via `EnableTraceEx2` and
//! system logger tracing via `PERFINFO_GROUPMASK` or `EnableFlags`. System logger mode is
//! activated automatically when system logger APIs are called
//! (e.g. [`set_events`](Trace::set_events),
//! [`set_stack_walking`](Trace::set_stack_walking)).

// This module is pub, so `pub` items inside it are effectively pub.
// Using `pub` explicitly would trigger `redundant_pub_crate`.
#![expect(
    unreachable_pub,
    reason = "items are re-exported through the crate root"
)]

use super::{
    ClockResolution, TraceStatistics,
    common::{
        CallbackState, EnabledProvider, INVALID_PROCESSTRACE_HANDLE, INVALID_SESSION_ID,
        MAXIMUM_SESSION_NAME, ProviderFilter, ProviderIdentifier, buffer_record_callback,
        event_record_callback, process_trace_blocking, processing_thread_setup,
    },
    panic_policy::{PanicPayload, PanicResponse, PoisonFlag},
    system_logger::masks::{ETW_MAX_POOLTAG_FILTER, ETW_MAX_STACKWALK_FILTER, PERF_NUM_MASKS},
};
use crate::{
    Error, ParameterProblem, Result, ThreadFailure, event::RawEvent,
    processing_context::ProcessingContext,
};
use std::os::windows::io::AsRawHandle;
use windows_sys::Win32::{
    Foundation::ERROR_SUCCESS,
    System::{
        Diagnostics::Etw::{
            CONTROLTRACE_HANDLE, EVENT_TRACE_INDEPENDENT_SESSION_MODE, EVENT_TRACE_PROPERTIES,
            EVENT_TRACE_PROPERTIES_V2, EVENT_TRACE_REAL_TIME_MODE, PROCESS_TRACE_MODE_EVENT_RECORD,
            PROCESS_TRACE_MODE_REAL_TIME, StartTraceW, TRACE_LEVEL_INFORMATION,
            WNODE_FLAG_TRACED_GUID, WNODE_FLAG_VERSIONED_PROPERTIES,
        },
        Threading::THREAD_PRIORITY,
    },
};

// ═══════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════

/// Size of an extension item header (type + size_dwords).
const ITEM_HEADER_SIZE: usize = 4;

/// Maximum size of extension data buffer.
///
/// Computed from worst-case combination: extension header + group masks item +
/// stack walk filter item + pool tag filter item.
const MAX_EXTENSION_SIZE: usize = 4 // Extension header
    + ITEM_HEADER_SIZE + PERF_NUM_MASKS * size_of::<u32>()          // group masks
    + ITEM_HEADER_SIZE + ETW_MAX_STACKWALK_FILTER * size_of::<u32>() // stack walk
    + ITEM_HEADER_SIZE + ETW_MAX_POOLTAG_FILTER * size_of::<u32>(); // pool tags

/// `EVENT_TRACE_SYSTEM_LOGGER_MODE` flag for system logger sessions.
const EVENT_TRACE_SYSTEM_LOGGER_MODE: u32 = 0x0200_0000;

// ═══════════════════════════════════════════════════════════════════════════════
// Public API Types
// ═══════════════════════════════════════════════════════════════════════════════

/// Flags for enabling additional event data collection.
///
/// These flags are passed to `EnableTraceEx2` via `ENABLE_TRACE_PARAMETERS.EnableProperty`.
/// Multiple flags can be combined using bitwise OR.
///
/// # Example
///
/// ```no_run
/// use etw::EnableProperty;
///
/// let flags = EnableProperty::STACK_TRACE | EnableProperty::SID;
/// ```
#[derive(Debug)]
pub struct EnableProperty;

impl EnableProperty {
    /// Include security identifier (SID) of the user in extended data.
    pub const SID: u32 = 0x00000001;
    /// Include terminal session identifier in extended data.
    pub const TS_ID: u32 = 0x00000002;
    /// Include call stack trace in extended data (max 192 frames).
    pub const STACK_TRACE: u32 = 0x00000004;
    /// Filter out events where the event's keyword is 0.
    /// Mutually exclusive with [`ENABLE_KEYWORD_0`](Self::ENABLE_KEYWORD_0).
    pub const IGNORE_KEYWORD_0: u32 = 0x00000010;
    /// Include events where the event's keyword is 0.
    /// Mutually exclusive with [`IGNORE_KEYWORD_0`](Self::IGNORE_KEYWORD_0).
    pub const ENABLE_KEYWORD_0: u32 = 0x00000040;
    /// Include Process Start Key in extended data (unique identifier per boot session).
    pub const PROCESS_START_KEY: u32 = 0x00000080;
}

/// Flags for process trace mode configuration.
///
/// These flags are passed to [`Trace::set_process_trace_mode()`] to configure
/// how events are processed. Multiple flags can be combined using bitwise OR.
///
/// By default, `Trace` uses `REAL_TIME | EVENT_RECORD`.
///
/// # Example
///
/// ```no_run
/// use etw::{ProcessTraceMode, Trace};
///
/// let mut trace = Trace::new("MySession")?;
/// // Use raw timestamps instead of converted FILETIME
/// trace.set_process_trace_mode(
///     ProcessTraceMode::REAL_TIME
///         | ProcessTraceMode::EVENT_RECORD
///         | ProcessTraceMode::RAW_TIMESTAMP,
/// );
/// # Ok::<(), etw::Error>(())
/// ```
#[derive(Debug)]
pub struct ProcessTraceMode;

impl ProcessTraceMode {
    /// Process events in real-time (required for real-time tracing).
    pub const REAL_TIME: u32 = 0x0000_0100;
    /// Use EVENT_RECORD structure format (required for modern event processing).
    pub const EVENT_RECORD: u32 = 0x1000_0000;
    /// Return timestamps in their raw format instead of converting to FILETIME.
    ///
    /// When this flag is set, the timestamp interpretation depends on the session's
    /// [`ClockResolution`](crate::ClockResolution) setting:
    /// - `QPC`: QueryPerformanceCounter ticks
    /// - `SYSTEM_TIME`: Already in FILETIME format (no change)
    /// - `CPU_CYCLE`: CPU cycle counts
    ///
    /// When this flag is NOT set (default), ETW converts all timestamps to FILETIME
    /// format (100-nanosecond intervals since January 1, 1601).
    pub const RAW_TIMESTAMP: u32 = 0x0000_1000;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Properties Buffer
// ═══════════════════════════════════════════════════════════════════════════════

/// Extended `EVENT_TRACE_PROPERTIES_V2` with space for session name and extensions.
///
/// The extension space is only used when system logger mode is active.
/// For non-system-logger sessions, the extra bytes are unused overhead.
#[repr(C)]
pub struct TraceProperties {
    pub properties: EVENT_TRACE_PROPERTIES_V2,
    pub session_name: [u16; MAXIMUM_SESSION_NAME],
    pub extension_space: [u8; MAX_EXTENSION_SIZE],
}

// ═══════════════════════════════════════════════════════════════════════════════
// Trace
// ═══════════════════════════════════════════════════════════════════════════════

/// Unified ETW trace session type.
///
/// Supports both modern provider-based tracing via `EnableTraceEx2` and system logger
/// tracing via `PERFINFO_GROUPMASK`. System logger mode is activated
/// automatically when system logger APIs are called
/// (e.g. [`set_events()`](Self::set_events)).
///
/// # Example — Provider-based tracing
///
/// ```no_run
/// use etw::{ALL_KEYWORDS, Guid, Trace};
///
/// let mut trace = Trace::new("MySession")?;
/// trace.start()?;
/// trace.enable_provider(
///     Guid::from_u128(0x1c95126e_7b3a_49a7_b0fc_767ef4f3a323),
///     ALL_KEYWORDS,
/// )?;
/// trace.set_event_callback(|event, _cache| {
///     println!("Event ID: {}", event.id());
///     Ok(())
/// });
/// trace.start_processing_thread()?;
/// std::thread::sleep(std::time::Duration::from_secs(5));
/// trace.stop()?;
/// # Ok::<(), etw::Error>(())
/// ```
///
/// # Example — System logger tracing
///
/// ```no_run
/// use etw::{Trace, system_logger::masks::*};
///
/// let mut trace = Trace::new("MySystemTrace")?;
/// trace.set_events(&[PERF_PROCESS, PERF_THREAD]);
/// trace.set_stack_walking(&[0x0301]); // Process START
/// trace.start()?;
/// trace.set_event_callback(|event: &etw::RawEvent, _cache| {
///     println!("Event ID: {}", event.id());
///     Ok(())
/// });
/// trace.start_processing_thread()?;
/// std::thread::sleep(std::time::Duration::from_secs(5));
/// trace.stop()?;
/// # Ok::<(), etw::Error>(())
/// ```
pub struct Trace {
    // Lifecycle (flattened from TraceCore)
    pub(crate) session_name: String,
    pub(crate) session_id: u64,
    pub(crate) process_trace_handle: u64,
    pub(crate) processing_thread: Option<std::thread::JoinHandle<u32>>,
    pub(crate) thread_priority: THREAD_PRIORITY,
    pub(crate) thread_description: Option<String>,
    pub(crate) callback_state: Box<CallbackState>,
    /// Owner-side clone of [`CallbackState::poisoned`]. Reading this never
    /// forms a reference to `callback_state` (which the consumer thread borrows
    /// mutably while dispatching), so the owner can observe/reset poison at any
    /// time.
    pub(crate) poison_flag: PoisonFlag,
    pub(crate) process_trace_mode: u32,
    pub(crate) thread_shutdown_timeout_ms: u32,
    pub(crate) thread_startup_timeout_ms: u32,
    /// Providers enabled via `EnableTraceEx2`.
    pub(crate) enabled_providers: Vec<EnabledProvider>,

    // Properties buffer (always sized for extensions)
    pub(crate) props_buf: TraceProperties,

    // System logger config (populated when system logger APIs are called)
    pub(crate) group_masks: [u32; PERF_NUM_MASKS],
    pub(crate) enable_flags: u32,
    pub(crate) stack_events: Vec<u16>,
    pub(crate) pool_tags: Vec<u32>,
    pub(crate) object_type_tags: Vec<u32>,
    pub(crate) lbr_config: Option<super::system_logger::LbrConfig>,
    pub(crate) lbr_events: Vec<u16>,
    pub(crate) pmc_counters: Vec<super::system_logger::ProfileSource>,
    pub(crate) pmc_events: Vec<u16>,
}

impl Trace {
    // ═══════════════════════════════════════════════════════════════════════
    // Construction
    // ═══════════════════════════════════════════════════════════════════════

    /// Create a new ETW trace session named `session_name`.
    ///
    /// `session_name` must be 1-63 printable ASCII characters. Creates a session
    /// with `EVENT_TRACE_REAL_TIME_MODE` and `EVENT_TRACE_INDEPENDENT_SESSION_MODE`
    /// enabled by default. System logger mode is activated automatically when
    /// system logger APIs are called.
    ///
    /// The session is not started until [`start()`](Self::start) is called.
    ///
    /// This implicitly calls
    /// [`validate_all_schemas()`](crate::validate_all_schemas) so that any
    /// schema drift against the live Windows TDH registry surfaces before
    /// any ETW session state is allocated. The call is cached on success,
    /// so constructing additional `Trace` instances is a single atomic load.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidParameter`] if the session name is empty, too long, or contains
    ///   non-printable characters.
    /// - Any error returned by [`validate_all_schemas()`](crate::validate_all_schemas) when a
    ///   registered schema does not match the TDH registry.
    pub fn new(session_name: &str) -> Result<Self> {
        // Reported as three distinct problems rather than one combined message:
        // "too long" and "has a control character" need different fixes.
        let problem = if session_name.is_empty() {
            Some(ParameterProblem::Empty)
        } else if session_name.len() >= MAXIMUM_SESSION_NAME {
            Some(ParameterProblem::TooLong {
                length: session_name.len(),
                max: MAXIMUM_SESSION_NAME - 1,
            })
        } else if !session_name
            .bytes()
            .all(|b| b.is_ascii_graphic() || b == b' ')
        {
            Some(ParameterProblem::Malformed {
                requirement: "printable ASCII",
            })
        } else {
            None
        };
        if let Some(problem) = problem {
            return Err(Error::InvalidParameter {
                parameter: "session name",
                problem,
            });
        }

        // Implicit, success-cached schema validation. Runs the registered TDH
        // validators at most once per process on the success path. Callers who
        // want dedicated handling can call `validate_all_schemas()` explicitly
        // before `Trace::new` — the second call short-circuits on the flag.
        crate::validate_all_schemas()?;

        // Poison flag is shared between the owner (`Trace`) and the consumer
        // thread (`CallbackState`); both hold a clone of the same allocation.
        let poison_flag = PoisonFlag::new();

        let mut trace = Self {
            session_name: session_name.to_owned(),
            session_id: INVALID_SESSION_ID,
            process_trace_handle: INVALID_PROCESSTRACE_HANDLE,
            processing_thread: None,
            thread_priority: windows_sys::Win32::System::Threading::THREAD_PRIORITY_NORMAL,
            thread_description: None,
            callback_state: Box::new(CallbackState {
                session_name: session_name.to_owned(),
                event_callback: None,
                processing_context: ProcessingContext::new(),
                poisoned: poison_flag.clone(),
                panic_callback: None,
            }),
            poison_flag,
            process_trace_mode: 0,
            thread_shutdown_timeout_ms: 5000,
            thread_startup_timeout_ms: 500,
            enabled_providers: Vec::new(),
            // SAFETY: TraceProperties is a POD-like struct that can be zero-initialised.
            props_buf: unsafe { std::mem::zeroed() },
            group_masks: [0u32; PERF_NUM_MASKS],
            enable_flags: 0,
            stack_events: Vec::new(),
            pool_tags: Vec::new(),
            object_type_tags: Vec::new(),
            lbr_config: None,
            lbr_events: Vec::new(),
            pmc_counters: Vec::new(),
            pmc_events: Vec::new(),
        };

        trace.initialize_properties();
        Ok(trace)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Session Lifecycle
    // ═══════════════════════════════════════════════════════════════════════

    /// Start the trace session.
    ///
    /// If system logger APIs have been called, builds extension data (group masks,
    /// stack walk filters, pool tag filters) before starting. Otherwise starts
    /// directly.
    ///
    /// After starting:
    /// - Set the event callback via [`set_event_callback()`](Self::set_event_callback)
    /// - Begin receiving events via [`start_processing_thread()`](Self::start_processing_thread)
    ///
    /// # Errors
    ///
    /// [`Error::Win32Error`] if `StartTraceW` fails. The code is returned as-is; the two
    /// worth recognising are:
    ///
    /// - `ERROR_ACCESS_DENIED` — not running as Administrator (required for system-logger sessions;
    ///   otherwise membership of *Performance Log Users* suffices).
    ///
    /// - `ERROR_NO_SYSTEM_RESOURCES` — a session budget is full. Windows uses this one code for two
    ///   independent caps, and **does not tell you which was hit**:
    ///
    ///   1. The 8 concurrent system-logger sessions (2 reserved by the OS). Reachable only when
    ///      `EVENT_TRACE_SYSTEM_LOGGER_MODE` is set — see
    ///      [`set_enable_flags()`](Self::set_enable_flags) and [`set_events()`](Self::set_events).
    ///   2. The system-wide cap on concurrent sessions — 64 by default. **Every** session counts
    ///      against this, system loggers included, so a system-logger start can fail on this cap
    ///      rather than on the 8 slots above.
    ///
    ///   Because a system-logger session is subject to both, the flag you passed does not by
    ///   itself identify the cause. `logman query -ets` lists the active sessions and their
    ///   count, which distinguishes them in practice: near 64 total implicates the
    ///   system-wide cap, while a smaller total with 8 system loggers implicates the slots.
    ///
    ///   In either case the usual cause is sessions leaked by tooling that exited without
    ///   stopping them, not genuine concurrent demand; `logman stop <name> -ets` reclaims
    ///   one. The system-wide cap is configurable via the `EtwMaxLoggers` `REG_DWORD` under
    ///   `HKLM\SYSTEM\CurrentControlSet\Control\WMI` (permissible 32–256, reboot required),
    ///   but Microsoft documents that it must not be adjusted programmatically — it is an
    ///   administrator's decision, and raising it costs system resources.
    ///
    /// # Panics
    ///
    /// Panics if the session is already running, if both `set_enable_flags()` and
    /// `set_events()` are used (mutually exclusive modes), if stack walk / pool tag
    /// filters are configured in EnableFlags mode, or if a non-zero maximum buffer
    /// count is below the minimum.
    pub fn start(&mut self) -> Result<()> {
        assert!(!self.is_started(), "Trace session is already running");
        self.assert_buffer_counts();

        // Clear any poison from a previous run so a reused session dispatches
        // again. Sound here because start() runs only while not started (asserted
        // above), hence no consumer thread is touching the flag.
        self.poison_flag.clear();

        // Re-initialise the properties buffer. After stop(), ControlTraceW has
        // overwritten it with session statistics. initialize_properties() resets
        // mandatory header fields while leaving user-configured fields intact.
        self.initialize_properties();

        // System logger mode: validate and build extensions
        if self.is_system_logger_mode() {
            // Validate EnableFlags mode vs GroupMasks mode mutual exclusion.
            assert!(
                !(self.enable_flags != 0 && self.has_group_masks()),
                "Cannot use both set_enable_flags() and set_events(). Choose one."
            );
            assert!(
                !(self.enable_flags != 0
                    && (!self.stack_events.is_empty() || !self.pool_tags.is_empty())),
                "Stack walks and pool tag filters require GroupMasks mode (set_events)"
            );

            // Force SYSTEM_TIME clock resolution for system logger sessions so
            // timestamps are in FILETIME format, matching stack walk EventTimeStamp.
            self.props_buf.properties.Wnode.ClientContext = ClockResolution::SYSTEM_TIME;

            self.build_extensions();
        }

        // Stop any orphaned sessions from previous runs (uses disposable buffer).
        Self::stop_orphaned_session(&self.session_name)?;

        // Start the trace session
        let session_name_wide = Self::to_wide_string(&self.session_name);
        let mut handle = CONTROLTRACE_HANDLE {
            Value: self.session_id,
        };
        // SAFETY: StartTraceW is a Win32 API. All pointers are valid and properly aligned.
        let status = unsafe {
            StartTraceW(
                &raw mut handle,
                session_name_wide.as_ptr(),
                (&raw mut self.props_buf.properties).cast::<EVENT_TRACE_PROPERTIES>(),
            )
        };

        if status != ERROR_SUCCESS {
            self.session_id = INVALID_SESSION_ID;
            return Err(Error::from_win32(status));
        }

        self.session_id = handle.Value;

        Ok(())
    }

    /// Stop the trace session and wait for the processing thread to terminate.
    ///
    /// If the processing thread does not exit within the shutdown timeout
    /// (default 5 seconds), it will be forcefully terminated.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Win32Error`] if `CloseTrace` or `ControlTraceW` fails.
    pub fn stop(&mut self) -> Result<()> {
        use windows_sys::Win32::{
            Foundation::{
                ERROR_CANCELLED, ERROR_CTX_CLOSE_PENDING, ERROR_SUCCESS,
                ERROR_WMI_INSTANCE_NOT_FOUND, HANDLE, WAIT_FAILED, WAIT_TIMEOUT,
            },
            System::{
                Diagnostics::Etw::{
                    CloseTrace, ControlTraceW, EVENT_TRACE_CONTROL_STOP, PROCESSTRACE_HANDLE,
                },
                Threading::{TerminateThread, WaitForSingleObject},
            },
        };

        if !self.is_started() {
            // Invariant: processing requires a started session
            assert!(!self.is_processing());
            return Ok(());
        }

        // IMPORTANT: Stop the trace session BEFORE closing the processing handle.
        // This ensures rundown events are generated and can be processed by the
        // still-running ProcessTrace thread.
        let mut control_err = None;
        if self.session_id != INVALID_SESSION_ID {
            let session_name_wide = Self::to_wide_string(&self.session_name);
            let handle = CONTROLTRACE_HANDLE {
                Value: self.session_id,
            };
            // SAFETY: ControlTraceW is a Win32 API. All pointers are valid.
            let status = unsafe {
                ControlTraceW(
                    handle,
                    session_name_wide.as_ptr(),
                    std::ptr::from_mut(&mut self.props_buf.properties)
                        .cast::<EVENT_TRACE_PROPERTIES>(),
                    EVENT_TRACE_CONTROL_STOP,
                )
            };

            // ERROR_WMI_INSTANCE_NOT_FOUND means session doesn't exist — that's fine.
            // Do NOT early-return on failure: like the CloseTrace path below, the
            // processing thread must still be joined/terminated and process_trace_handle
            // closed before `callback_state` is freed, otherwise the still-running
            // ProcessTrace thread dereferences a dangling Context pointer (use-after-free).
            // Capture the error and surface it after teardown completes.
            control_err = (status != ERROR_SUCCESS && status != ERROR_WMI_INSTANCE_NOT_FOUND)
                .then(|| Error::from_win32(status));
            self.session_id = INVALID_SESSION_ID;

            // Log warnings if events or buffers were lost
            if status == ERROR_SUCCESS {
                let stats = self.statistics();
                if stats.events_lost > 0 || stats.realtime_buffers_lost > 0 {
                    log::warn!(
                        "ETW session '{}' lost {} events and {} real-time buffers",
                        self.session_name,
                        stats.events_lost,
                        stats.realtime_buffers_lost
                    );
                }
            }
        }

        // Now close the trace processing handle — this will cause ProcessTrace to return.
        // Do NOT early-return on CloseTrace failure: the processing thread must still be
        // joined, otherwise Drop sees is_started()=false + is_processing()=true and asserts.
        let close_err = if self.process_trace_handle == INVALID_PROCESSTRACE_HANDLE {
            None
        } else {
            let handle = PROCESSTRACE_HANDLE {
                Value: self.process_trace_handle,
            };
            // SAFETY: CloseTrace is a Win32 API. handle is valid from OpenTraceW.
            let status = unsafe { CloseTrace(handle) };
            self.process_trace_handle = INVALID_PROCESSTRACE_HANDLE;

            // ERROR_CTX_CLOSE_PENDING means CloseTrace was called while ProcessTrace
            // was still running — this is expected and means success.
            (status != ERROR_SUCCESS && status != ERROR_CTX_CLOSE_PENDING)
                .then_some(Error::from_win32(status))
        };

        // Wait for the processing thread to terminate
        if let Some(join_handle) = self.processing_thread.take() {
            let timeout_ms = self.thread_shutdown_timeout_ms;
            let native_handle: HANDLE = join_handle.as_raw_handle();

            // SAFETY: native_handle is valid for the lifetime of join_handle.
            let wait_result = unsafe { WaitForSingleObject(native_handle, timeout_ms) };

            if wait_result == WAIT_FAILED {
                // SAFETY: GetLastError is safe to call after WAIT_FAILED.
                let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
                return Err(Error::from_win32(err));
            }

            if wait_result == WAIT_TIMEOUT {
                log::warn!(
                    "ETW session '{}': processing thread did not exit within {timeout_ms}ms, forcing termination",
                    self.session_name
                );
                // SAFETY: native_handle is valid. Termination is a last resort.
                unsafe {
                    let _ = TerminateThread(native_handle, 1);
                }
                // A force-terminated thread never wrote its join slot, so joining
                // it would be unsound — drop the handle without joining. (Rust's
                // JoinHandle cleans up; don't manually CloseHandle.)
                drop(join_handle);
            } else {
                // Clean exit: the thread has fully signalled, so join() reads its
                // ProcessTrace status without blocking. Surface a genuine failure;
                // CloseTrace-driven shutdown returns ERROR_SUCCESS or
                // ERROR_CTX_CLOSE_PENDING. A StopTrace policy returns ERROR_SUCCESS
                // via the BufferCallback route on tested builds, but MSDN documents
                // that route as ERROR_CANCELLED, so treat that as clean too rather
                // than warn on every panic-stop.
                match join_handle.join() {
                    Ok(status) => {
                        if status != ERROR_SUCCESS
                            && status != ERROR_CTX_CLOSE_PENDING
                            && status != ERROR_CANCELLED
                        {
                            log::warn!(
                                "ETW session '{}': ProcessTrace ended with {:?}: {}",
                                self.session_name,
                                status,
                                crate::ResolveMessage::resolve_message(&status)
                            );
                        }
                    }
                    Err(_panic) => {
                        log::error!(
                            "ETW session '{}': processing thread panicked",
                            self.session_name
                        );
                    }
                }
            }
        }

        // A dark source must not stop in silence, even when an installed panic
        // hook swallowed the payload. Read the owner's `poison_flag` clone (not
        // `callback_state`, which the consumer thread borrows mutably) so this is
        // sound regardless of whether the thread was joined above.
        if self.is_poisoned() {
            log::error!(
                "ETW session '{}': stopped a trace that went dark after a callback panic",
                self.session_name
            );
        }

        self.enabled_providers.clear();

        // Surface the first failure seen during teardown. The processing thread has
        // been joined/terminated and the handles closed regardless of ControlTraceW's
        // result, so `callback_state` is now safe to drop.
        if let Some(err) = control_err.or(close_err) {
            return Err(err);
        }
        Ok(())
    }

    /// Query the trace session statistics.
    ///
    /// Updates the internal properties structure with current session statistics.
    ///
    /// # Errors
    ///
    /// Returns error if `ControlTraceW` fails.
    ///
    /// # Panics
    ///
    /// Panics if the session is not running.
    pub fn query(&mut self) -> Result<()> {
        use windows_sys::Win32::System::Diagnostics::Etw::{
            ControlTraceW, EVENT_TRACE_CONTROL_QUERY,
        };

        assert!(self.is_started(), "Trace session is not running");

        let handle = CONTROLTRACE_HANDLE {
            Value: self.session_id,
        };
        // SAFETY: ControlTraceW is a Win32 API. handle is valid, properties pointer is valid.
        let status = unsafe {
            ControlTraceW(
                handle,
                std::ptr::null(),
                std::ptr::from_mut(&mut self.props_buf.properties).cast::<EVENT_TRACE_PROPERTIES>(),
                EVENT_TRACE_CONTROL_QUERY,
            )
        };

        if status != ERROR_SUCCESS {
            return Err(Error::from_win32(status));
        }

        Ok(())
    }

    /// Start processing events from the trace session.
    ///
    /// Creates a background thread that calls `ProcessTrace` to receive events.
    /// The event callback (set via [`set_event_callback()`](Self::set_event_callback))
    /// will be invoked for each event.
    ///
    /// If the session is not started, this will call [`start()`](Self::start) first.
    ///
    /// Blocks for up to
    /// [`set_processing_thread_startup_timeout()`](Self::set_processing_thread_startup_timeout)
    /// (default 500ms) waiting for the consumer thread to be in steady state, so a
    /// caller that triggers its own activity afterwards can do so safely. Returns
    /// early with `Err(Error::ThreadError)` if the thread exits before the timeout
    /// (`ProcessTrace` failed). After return, the trace is hot — events fire
    /// straight to the callback.
    ///
    /// # Panics
    ///
    /// Panics if [`set_event_callback()`](Self::set_event_callback) has not been called,
    /// or if processing is already started.
    ///
    /// # Errors
    ///
    /// - [`Error::ThreadError`] if the processing thread exits during the startup timeout
    /// - [`Error::Win32Error`] if `OpenTraceW` fails
    pub fn start_processing_thread(&mut self) -> Result<()> {
        assert!(
            self.callback_state.event_callback.is_some(),
            "start_processing_thread() called without set_event_callback() — \
             all events would be silently discarded"
        );

        if !self.is_started() {
            self.start()?;
        }

        assert!(!self.is_processing(), "Trace processing is already running");

        // Guard that calls stop() on drop unless disarmed
        struct StopGuard<'a>(&'a mut Trace, bool);
        impl Drop for StopGuard<'_> {
            fn drop(&mut self) {
                if self.1
                    && let Err(e) = self.0.stop()
                {
                    log::error!(
                        "ETW session '{}': rollback stop() failed after a start error: {e}",
                        self.0.session_name
                    );
                }
            }
        }
        let mut guard = StopGuard(self, true);

        guard.0.open_and_spawn_processing_thread()?;

        guard.1 = false;
        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Event Callback
    // ═══════════════════════════════════════════════════════════════════════

    /// Set the event callback function.
    ///
    /// The callback will be invoked for each event received by the trace session.
    /// A schema cache is provided for TDH lookups. The callback returns `Result<()>`
    /// to allow use of the `?` operator — errors are logged but do not stop processing.
    ///
    /// # Panics
    ///
    /// Panics if event processing is currently active. The callback must be set
    /// before calling `start_processing_thread()`.
    pub fn set_event_callback<F>(&mut self, callback: F)
    where
        F: FnMut(&RawEvent, &mut ProcessingContext) -> Result<()> + Send + 'static,
    {
        // Safety invariant: the processing thread holds a raw pointer to callback_state.
        // Mutating the callback while it's being called is a data race (UB).
        assert!(
            !self.is_processing(),
            "cannot set event callback while processing thread is active"
        );
        self.callback_state.event_callback = Some(Box::new(callback));
    }

    /// Install a panic policy hook for the event callback.
    ///
    /// The hook is invoked inline on the ETW consumer thread whenever the event
    /// callback (or the schema machinery running in the same dispatch) panics.
    /// It receives the [`PanicPayload`] and returns a [`PanicResponse`]: keep
    /// dispatching ([`Continue`](PanicResponse::Continue)) or stop the trace
    /// ([`StopTrace`](PanicResponse::StopTrace)). Without a hook, the default
    /// policy logs the panic and stops the trace.
    ///
    /// When a `StopTrace` verdict is applied, already-delivered events are
    /// drained without being dispatched, `ProcessTrace` returns at the end of
    /// the current buffer, and the processing thread ends cleanly. Stopping the
    /// *session* remains the owner's job, via [`stop()`](Self::stop) or drop.
    ///
    /// # Contract
    ///
    /// The hook runs on the consumer thread inside `ProcessTrace`'s stack, with
    /// buffer delivery for the whole session stalled while it runs. It must keep
    /// to cheap work (log, count, send on a channel); it must **not** call
    /// control APIs on this trace (return [`PanicResponse::StopTrace`] instead,
    /// as stopping the session from here can deadlock); and it must **not**
    /// unwind — a panicking hook degrades to the default policy.
    ///
    /// # Panics
    ///
    /// Panics if event processing is currently active. The hook must be
    /// installed before calling [`start_processing_thread()`](Self::start_processing_thread).
    pub fn set_panic_callback<F>(&mut self, callback: F)
    where
        F: FnMut(PanicPayload) -> PanicResponse + Send + 'static,
    {
        // Safety invariant: the processing thread invokes the hook via a raw
        // pointer to callback_state. Mutating it while processing is active is a
        // data race (UB).
        assert!(
            !self.is_processing(),
            "cannot set panic callback while processing thread is active"
        );
        self.callback_state.panic_callback = Some(Box::new(callback));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Provider Enablement
    // ═══════════════════════════════════════════════════════════════════════

    /// Enable a provider on this session.
    ///
    /// Accepts a provider GUID or a provider name, which is resolved to its GUID.
    /// If the session is not started, this will call [`start()`](Self::start) first.
    /// Uses `TRACE_LEVEL_INFORMATION` by default. For full control, use
    /// [`enable_provider_ex`](Self::enable_provider_ex).
    ///
    /// # Errors
    ///
    /// As for [`enable_provider_ex`](Self::enable_provider_ex).
    pub fn enable_provider(
        &mut self,
        provider: impl Into<ProviderIdentifier>,
        keywords: u64,
    ) -> Result<()> {
        self.enable_provider_ex(provider, TRACE_LEVEL_INFORMATION, keywords, 0, None)
    }

    /// Enable a provider with full control over all parameters.
    ///
    /// Enables `provider` at the given `level` (1=Critical … 5=Verbose) with
    /// `match_any_keyword` as the keyword mask. `enable_property` selects optional
    /// extended data (see [`EnableProperty`]). `filter` optionally restricts event
    /// IDs and stack walks, and scopes enablement to a set of PIDs (see
    /// [`ProviderFilter`]).
    ///
    /// If the session is not started, this will call [`start()`](Self::start) first.
    ///
    /// # Errors
    ///
    /// - [`Error::ProviderNotFound`] or [`Error::ProviderAmbiguous`] if a provider name does not
    ///   resolve to exactly one GUID.
    /// - [`Error::InvalidParameter`] if `level` exceeds 255, or if `filter` holds an event ID or
    ///   stack walk filter that is empty, has more than 256 IDs or repeats an ID, or a PID set that
    ///   is empty or has more than 8 PIDs.
    /// - Any error from the implicit [`start()`](Self::start), or a Win32 error if provider name
    ///   enumeration or `EnableTraceEx2` fails.
    pub fn enable_provider_ex(
        &mut self,
        provider: impl Into<ProviderIdentifier>,
        level: u32,
        match_any_keyword: u64,
        enable_property: u32,
        filter: Option<ProviderFilter>,
    ) -> Result<()> {
        if !self.is_started() {
            self.start()?;
        }

        self.enable_provider_core(provider, level, match_any_keyword, enable_property, filter)
    }

    /// Disable a provider on a running session.
    ///
    /// Calls `EnableTraceEx2` with `EVENT_CONTROL_CODE_DISABLE_PROVIDER` and removes
    /// the provider from the internal tracking list.
    ///
    /// # Errors
    ///
    /// - Provider is not currently enabled
    /// - `EnableTraceEx2` fails
    ///
    /// # Panics
    ///
    /// Panics if the session is not started.
    pub fn disable_provider(&mut self, provider: impl Into<ProviderIdentifier>) -> Result<()> {
        assert!(
            self.is_started(),
            "Cannot disable provider: session not started"
        );

        self.disable_provider_core(provider)
    }

    /// Send `EVENT_CONTROL_CODE_CAPTURE_STATE` to a provider.
    ///
    /// Uses the stored `level` and `match_any_keyword` from the original
    /// [`enable_provider`](Self::enable_provider) call. The provider must already
    /// be enabled on this session.
    ///
    /// # Errors
    ///
    /// Returns error if the provider is not enabled or if `EnableTraceEx2` fails.
    ///
    /// # Panics
    ///
    /// Panics if the session is not started.
    pub fn capture_state(&self, provider: impl Into<ProviderIdentifier>) -> Result<()> {
        assert!(
            self.is_started(),
            "Cannot send capture state: session not started"
        );

        self.capture_state_core(provider)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Property Setters
    // ═══════════════════════════════════════════════════════════════════════

    /// Set the log mode flags. Always sets `EVENT_TRACE_REAL_TIME_MODE` and
    /// `EVENT_TRACE_INDEPENDENT_SESSION_MODE`.
    ///
    /// Must be called before [`start()`](Self::start).
    ///
    /// # Panics
    ///
    /// Panics if called after `start()`.
    #[must_use]
    pub fn set_log_file_mode(&mut self, mode: u32) -> &mut Self {
        assert!(
            !self.is_started(),
            "Cannot modify log file mode after start()"
        );
        self.props_buf.properties.LogFileMode =
            mode | EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_INDEPENDENT_SESSION_MODE;
        self
    }

    /// Set the buffer size in KB.
    ///
    /// Must be called before [`start()`](Self::start).
    ///
    /// # Panics
    ///
    /// Panics if called after `start()`, or if `size_kb` is less than 4.
    #[must_use]
    pub fn set_buffer_size(&mut self, size_kb: u32) -> &mut Self {
        assert!(
            !self.is_started(),
            "Cannot modify buffer size after start()"
        );
        assert!(size_kb >= 4, "Buffer size must be at least 4 KB");
        self.props_buf.properties.BufferSize = size_kb;
        self
    }

    /// Set the minimum number of buffers.
    ///
    /// Must be called before [`start()`](Self::start).
    ///
    /// # Panics
    ///
    /// Panics if called after `start()`.
    #[must_use]
    pub fn set_minimum_buffers(&mut self, count: u32) -> &mut Self {
        assert!(
            !self.is_started(),
            "Cannot modify minimum buffers after start()"
        );
        self.props_buf.properties.MinimumBuffers = count;
        self
    }

    /// Set the maximum number of buffers. 0 lets ETW choose.
    ///
    /// Must be called before [`start()`](Self::start), which panics if a non-zero
    /// `count` is below the minimum buffer count, so the two setters may be called
    /// in either order.
    ///
    /// # Panics
    ///
    /// Panics if called after `start()`.
    #[must_use]
    pub fn set_maximum_buffers(&mut self, count: u32) -> &mut Self {
        assert!(
            !self.is_started(),
            "Cannot modify maximum buffers after start()"
        );
        self.props_buf.properties.MaximumBuffers = count;
        self
    }

    /// Set the flush timer in seconds.
    ///
    /// Must be called before [`start()`](Self::start).
    ///
    /// # Panics
    ///
    /// Panics if called after `start()`.
    #[must_use]
    pub fn set_flush_timer(&mut self, seconds: u32) -> &mut Self {
        assert!(
            !self.is_started(),
            "Cannot modify flush timer after start()"
        );
        self.props_buf.properties.FlushTimer = seconds;
        self
    }

    /// Set the clock resolution for event timestamps.
    ///
    /// Must be called before [`start()`](Self::start).
    ///
    /// Use [`ClockResolution`](super::ClockResolution) constants:
    /// - [`QPC`](super::ClockResolution::QPC) (default) — high resolution
    /// - [`SYSTEM_TIME`](super::ClockResolution::SYSTEM_TIME) — tracks system clock changes
    /// - [`CPU_CYCLE`](super::ClockResolution::CPU_CYCLE) — highest resolution, varies with
    ///   frequency
    ///
    /// **Note:** System logger mode sessions always use `SYSTEM_TIME` regardless
    /// of this setting.
    ///
    /// # Panics
    ///
    /// Panics if called after `start()`.
    #[must_use]
    pub fn set_clock_resolution(&mut self, resolution: u32) -> &mut Self {
        assert!(
            !self.is_started(),
            "Cannot modify clock resolution after start()"
        );
        self.props_buf.properties.Wnode.ClientContext = resolution;
        self
    }

    /// Set whether to exclude kernel stack traces from events.
    ///
    /// When `true`, kernel stack frames are excluded from stack traces captured
    /// via `EnableProperty::STACK_TRACE`. Only user-mode frames will be collected.
    ///
    /// Must be called before [`start()`](Self::start).
    /// Default is `false` (kernel stacks are included).
    ///
    /// # Panics
    ///
    /// Panics if called after `start()`.
    #[must_use]
    pub fn set_exclude_kernel_stack(&mut self, exclude: bool) -> &mut Self {
        assert!(
            !self.is_started(),
            "Cannot modify exclude kernel stack after start()"
        );

        // ExcludeKernelStack is bit 3 in EVENT_TRACE_PROPERTIES_V2.Anonymous3.V2Options
        const EXCLUDE_KERNEL_STACK_BIT: u64 = 1 << 3;
        // SAFETY: Accessing union field V2Options. The memory is valid and properly aligned.
        unsafe {
            if exclude {
                self.props_buf.properties.Anonymous3.V2Options |= EXCLUDE_KERNEL_STACK_BIT;
            } else {
                self.props_buf.properties.Anonymous3.V2Options &= !EXCLUDE_KERNEL_STACK_BIT;
            }
        }
        self
    }

    /// Set all buffer parameters at once.
    ///
    /// Must be called before [`start()`](Self::start).
    ///
    /// # Panics
    ///
    /// Panics if called after `start()`, or if `buffer_size_kb` is
    /// less than 4. [`start()`](Self::start) checks `max_buffers` against
    /// `min_buffers`.
    #[must_use]
    pub fn set_buffer_configuration(
        &mut self,
        buffer_size_kb: u32,
        min_buffers: u32,
        max_buffers: u32,
        flush_timer_seconds: u32,
    ) -> &mut Self {
        let _ = self.set_buffer_size(buffer_size_kb);
        let _ = self.set_minimum_buffers(min_buffers);
        let _ = self.set_maximum_buffers(max_buffers);
        let _ = self.set_flush_timer(flush_timer_seconds);
        self
    }

    /// Set the process trace mode flags.
    ///
    /// By default, `PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD` is used.
    /// Must be called before [`start_processing_thread()`](Self::start_processing_thread).
    ///
    /// # Panics
    ///
    /// Panics if called after processing has started.
    #[must_use]
    pub fn set_process_trace_mode(&mut self, mode: u32) -> &mut Self {
        assert!(
            self.processing_thread.is_none(),
            "Cannot modify process trace mode after processing has started"
        );
        self.process_trace_mode = mode;
        self
    }

    /// Set the processing thread priority.
    ///
    /// Must be called before [`start_processing_thread()`](Self::start_processing_thread).
    ///
    /// # Panics
    ///
    /// Panics if called after processing has started.
    #[must_use]
    pub fn set_processing_thread_priority(&mut self, priority: THREAD_PRIORITY) -> &mut Self {
        assert!(
            self.processing_thread.is_none(),
            "Cannot modify thread priority after processing has started"
        );
        self.thread_priority = priority;
        self
    }

    /// Set the processing thread description.
    ///
    /// Overrides the default `"ETW: {session_name}"` used for both
    /// [`std::thread::Builder::name`] (panic output) and `SetThreadDescription`
    /// (Windows debuggers).
    ///
    /// # Panics
    ///
    /// Panics if called after processing has started.
    #[must_use]
    pub fn set_processing_thread_description(
        &mut self,
        description: impl Into<String>,
    ) -> &mut Self {
        assert!(
            self.processing_thread.is_none(),
            "Cannot modify thread description after processing has started"
        );
        self.thread_description = Some(description.into());
        self
    }

    /// Set the `timeout_ms` for waiting for the processing thread to terminate during stop().
    ///
    /// Default: 5000ms. Use `INFINITE` (`0xFFFFFFFF`) to wait forever.
    ///
    /// If the processing thread does not terminate within this timeout, it will be forcibly
    /// terminated using `TerminateThread()`.
    #[must_use]
    pub const fn set_processing_thread_shutdown_timeout(&mut self, timeout_ms: u32) -> &mut Self {
        self.thread_shutdown_timeout_ms = timeout_ms;
        self
    }

    /// Set the timeout for confirming `ProcessTrace` startup.
    ///
    /// Default: 500ms
    ///
    /// After spawning the processing thread, `start_processing_thread()` waits
    /// this long to detect immediate `ProcessTrace` failures. This is a quick
    /// sanity check for a thread that exits early, not a guarantee that the
    /// trace will subsequently deliver events.
    #[must_use]
    pub const fn set_processing_thread_startup_timeout(&mut self, timeout_ms: u32) -> &mut Self {
        self.thread_startup_timeout_ms = timeout_ms;
        self
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Getters
    // ═══════════════════════════════════════════════════════════════════════

    /// Check if the trace session is currently running.
    #[must_use]
    pub const fn is_started(&self) -> bool {
        self.session_id != INVALID_SESSION_ID
    }

    /// Check if event processing is currently active.
    ///
    /// Note: this reflects whether the processing thread has been *started and
    /// not yet stopped*, not whether it is still alive. If a callback panic
    /// stopped the trace under [`PanicResponse::StopTrace`](crate::PanicResponse)
    /// (the default), the thread has already exited but this still returns `true`
    /// until [`stop()`](Self::stop). Use [`is_poisoned()`](Self::is_poisoned) to
    /// detect a trace that went dark.
    #[must_use]
    pub const fn is_processing(&self) -> bool {
        self.processing_thread.is_some()
    }

    /// Check whether a callback panic policy has stopped this trace.
    ///
    /// Returns `true` once a [`PanicResponse::StopTrace`](crate::PanicResponse)
    /// verdict (or the default policy) has fired: the processing thread has
    /// ended on its own, later events are dropped without dispatch, but the
    /// session stays started until [`stop()`](Self::stop). Poll this to detect a
    /// trace that has gone dark — [`is_processing()`](Self::is_processing) alone
    /// cannot distinguish it from a healthy one — and decide whether to stop and
    /// restart. Cleared by [`start()`](Self::start).
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.poison_flag.is_poisoned()
    }

    /// Get the session name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.session_name
    }

    /// Get session statistics.
    ///
    /// Returns statistics about the trace session including buffer usage and
    /// events lost. The values are most accurate after calling [`stop()`](Self::stop)
    /// or [`query()`](Self::query).
    #[must_use]
    pub const fn statistics(&self) -> TraceStatistics {
        TraceStatistics {
            buffers_count: self.props_buf.properties.NumberOfBuffers,
            buffers_free: self.props_buf.properties.FreeBuffers,
            buffers_written: self.props_buf.properties.BuffersWritten,
            events_lost: self.props_buf.properties.EventsLost,
            realtime_buffers_lost: self.props_buf.properties.RealTimeBuffersLost,
        }
    }

    /// Get const reference to the underlying `EVENT_TRACE_PROPERTIES_V2` structure.
    ///
    /// [`start()`](Self::start) and [`query()`](Self::query) overwrite it with the
    /// kernel's view, so buffer counts are the ones ETW chose, not the ones set.
    #[must_use]
    pub const fn properties(&self) -> &EVENT_TRACE_PROPERTIES_V2 {
        &self.props_buf.properties
    }

    /// Get mutable reference to the underlying `EVENT_TRACE_PROPERTIES_V2` structure.
    ///
    /// # Safety
    ///
    /// Callers must ensure they do not modify fields in ways that violate ETW
    /// invariants (e.g., changing `BufferSize` or `LoggerNameOffset`).
    pub const unsafe fn properties_mut(&mut self) -> &mut EVENT_TRACE_PROPERTIES_V2 {
        &mut self.props_buf.properties
    }

    /// Get raw pointer to the underlying `EVENT_TRACE_PROPERTIES` structure.
    ///
    /// Returns a pointer to `EVENT_TRACE_PROPERTIES` for compatibility with Win32 APIs.
    /// The actual structure is `EVENT_TRACE_PROPERTIES_V2` which is layout-compatible.
    pub const fn properties_as_raw(&mut self) -> *mut EVENT_TRACE_PROPERTIES {
        (&raw mut self.props_buf.properties).cast::<EVENT_TRACE_PROPERTIES>()
    }

    /// Returns whether kernel stack traces are excluded.
    ///
    /// See [`set_exclude_kernel_stack`](Self::set_exclude_kernel_stack) for details.
    pub const fn exclude_kernel_stack(&self) -> bool {
        const EXCLUDE_KERNEL_STACK_BIT: u64 = 1 << 3;
        // SAFETY: Accessing union field V2Options. The memory is valid and properly aligned.
        unsafe { self.props_buf.properties.Anonymous3.V2Options & EXCLUDE_KERNEL_STACK_BIT != 0 }
    }

    /// Get the raw session ID for use with Win32 ETW APIs.
    ///
    /// A bare `u64`, not `CONTROLTRACE_HANDLE`: callers doing raw Win32
    /// interop wrap it in their own bindings' handle type (see
    /// `examples/07_manual.rs`).
    ///
    /// Returns the session's control ID, or `None` before [`start()`](Self::start).
    ///
    /// This is Win32's `CONTROLTRACE_ID` — an opaque identifier, not a kernel
    /// handle. `None` corresponds to the documented NULL sentinel (see
    /// `QueryTraceW`). It is safe to read: an identifier confers no capability
    /// on its own, and controlling an ETW session is gated by privilege, not by
    /// possession of the ID.
    ///
    /// # Interop
    ///
    /// Control operations issued directly through Win32 with this value (e.g.
    /// `ControlTraceW`) are invisible to this `Trace`: its started/processing
    /// state, enabled-provider tracking, and eventual [`stop()`](Self::stop) all
    /// assume they alone own the session. Prefer the typed methods where one
    /// exists.
    #[must_use]
    pub const fn session_id(&self) -> Option<u64> {
        if self.session_id == INVALID_SESSION_ID {
            None
        } else {
            Some(self.session_id)
        }
    }

    /// Returns the `OpenTraceW` processing handle, or `None` when the session is
    /// not processing.
    ///
    /// `None` corresponds to `INVALID_PROCESSTRACE_HANDLE`. Unlike
    /// [`session_id()`](Self::session_id) this is a live, process-local resource
    /// used by `ProcessTrace`; see that method's `# Interop` note — the same
    /// out-of-band caveats apply, and a `CloseTrace` issued here races the
    /// library's own lifecycle management.
    #[must_use]
    pub const fn raw_process_trace_handle(&self) -> Option<u64> {
        if self.process_trace_handle == INVALID_PROCESSTRACE_HANDLE {
            None
        } else {
            Some(self.process_trace_handle)
        }
    }

    /// Returns the processing thread's raw OS handle, or `None` when no
    /// processing thread is running.
    ///
    /// A live, process-local resource — see [`session_id()`](Self::session_id)'s
    /// `# Interop` note for the out-of-band caveats.
    #[must_use]
    pub fn raw_processing_thread_handle(&self) -> Option<isize> {
        self.processing_thread
            .as_ref()
            .map(|h| h.as_raw_handle() as isize)
    }

    /// Get the extension offset within the properties buffer (for debugging).
    #[must_use]
    pub const fn extension_offset(&self) -> usize {
        std::mem::offset_of!(TraceProperties, extension_space)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Mode Detection
    // ═══════════════════════════════════════════════════════════════════════

    /// Returns `true` if any system logger API has been called.
    ///
    /// System logger mode is activated when group_masks are non-zero,
    /// enable_flags is non-zero, stack_events are configured, or pool_tags
    /// are configured.
    pub fn is_system_logger_mode(&self) -> bool {
        self.has_group_masks()
            || self.enable_flags != 0
            || !self.stack_events.is_empty()
            || !self.pool_tags.is_empty()
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Private — Properties Initialisation
    // ═══════════════════════════════════════════════════════════════════════

    /// Checked in `start()`, not in either setter, so the result does not depend
    /// on call order.
    fn assert_buffer_counts(&self) {
        let min = self.props_buf.properties.MinimumBuffers;
        let max = self.props_buf.properties.MaximumBuffers;
        assert!(
            max == 0 || max >= min,
            "Maximum buffers ({max}) must be >= minimum buffers ({min})"
        );
    }

    /// Initialise mandatory properties fields.
    ///
    /// Called from `new()` and again at the start of `start()` (to reset after
    /// stop()). Only overwrites mandatory header fields; user-configured fields
    /// (BufferSize, MinimumBuffers, etc.) are untouched. The extension_space is
    /// zeroed since it's rebuilt fresh in `build_extensions()`.
    fn initialize_properties(&mut self) {
        // Zero the extension space — it will be rebuilt in build_extensions() if needed
        self.props_buf.extension_space = [0u8; MAX_EXTENSION_SIZE];

        // Configure mandatory WNODE header fields
        self.props_buf.properties.Wnode.BufferSize = size_of::<TraceProperties>() as u32;
        // WNODE_FLAG_VERSIONED_PROPERTIES is required for V2Options to be recognised
        self.props_buf.properties.Wnode.Flags =
            WNODE_FLAG_TRACED_GUID | WNODE_FLAG_VERSIONED_PROPERTIES;

        // Set version to V2
        self.props_buf.properties.Anonymous2.V2Control = 2;

        // Ensure the two mandatory flags are always set, while preserving any
        // additional flags the caller set via set_log_file_mode().
        self.props_buf.properties.LogFileMode |=
            EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_INDEPENDENT_SESSION_MODE;

        // Add SYSTEM_LOGGER_MODE if any system logger config is present
        if self.is_system_logger_mode() {
            self.props_buf.properties.LogFileMode |= EVENT_TRACE_SYSTEM_LOGGER_MODE;
        }

        // Set offset for session name
        let name_offset = std::mem::offset_of!(TraceProperties, session_name) as u32;
        self.props_buf.properties.LoggerNameOffset = name_offset;

        // Copy session name
        let session_name_wide = Self::to_wide_string(&self.session_name);
        let copy_len = std::cmp::min(session_name_wide.len(), MAXIMUM_SESSION_NAME - 1);
        self.props_buf.session_name[..copy_len].copy_from_slice(&session_name_wide[..copy_len]);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Private — Provider Core
    // ═══════════════════════════════════════════════════════════════════════

    /// Core implementation of `EnableTraceEx2` with `EVENT_CONTROL_CODE_ENABLE_PROVIDER`.
    fn enable_provider_core(
        &mut self,
        provider: impl Into<ProviderIdentifier>,
        level: u32,
        match_any_keyword: u64,
        enable_property: u32,
        filter: Option<ProviderFilter>,
    ) -> Result<()> {
        use super::common::{
            EventFilterEventId, filter_type, serialize_event_id_filter, validate_pid_filter,
        };
        use windows_sys::Win32::System::Diagnostics::Etw::{
            ENABLE_TRACE_PARAMETERS, ENABLE_TRACE_PARAMETERS_VERSION_2,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_FILTER_DESCRIPTOR, EnableTraceEx2,
        };

        debug_assert!(self.is_started(), "session must be started");

        let (name, guid) = provider.into().resolve()?;
        // ETW trace levels are u8 (0-255).
        if level > u32::from(u8::MAX) {
            return Err(Error::InvalidParameter {
                parameter: "trace level",
                problem: ParameterProblem::TooLarge {
                    value: u64::from(level),
                    max: u64::from(u8::MAX),
                },
            });
        }
        let level = level as u8;

        let handle = CONTROLTRACE_HANDLE {
            Value: self.session_id,
        };

        // Build filter descriptor array. Each active filter type gets one
        // EVENT_FILTER_DESCRIPTOR entry. The backing buffers below must remain
        // alive until after EnableTraceEx2 returns — filter_descs holds raw
        // pointers into them.
        let mut event_id_buf: Option<EventFilterEventId> = None;
        let mut stack_walk_buf: Option<EventFilterEventId> = None;
        let mut pid_buf: Option<Vec<u32>> = None;
        let mut filter_descs: Vec<EVENT_FILTER_DESCRIPTOR> = Vec::new();

        if let Some(ref pf) = filter {
            if let Some(ref ef) = pf.event_ids {
                let buf = event_id_buf.insert(serialize_event_id_filter(ef)?);
                let used_size = 4 + usize::from(buf.count) * size_of::<u16>();
                filter_descs.push(EVENT_FILTER_DESCRIPTOR {
                    Ptr: std::ptr::from_ref(buf) as u64,
                    Size: used_size as u32,
                    Type: filter_type::EVENT_FILTER_TYPE_EVENT_ID,
                });
            }
            if let Some(ref sw) = pf.stack_walk {
                let buf = stack_walk_buf.insert(serialize_event_id_filter(sw)?);
                let used_size = 4 + usize::from(buf.count) * size_of::<u16>();
                filter_descs.push(EVENT_FILTER_DESCRIPTOR {
                    Ptr: std::ptr::from_ref(buf) as u64,
                    Size: used_size as u32,
                    Type: filter_type::EVENT_FILTER_TYPE_STACKWALK,
                });
            }
            if let Some(ref pids) = pf.pids {
                validate_pid_filter(pids)?;
                // The PID list is its own wire format: a packed array of u32s.
                let buf = pid_buf.insert(pids.clone());
                filter_descs.push(EVENT_FILTER_DESCRIPTOR {
                    Ptr: buf.as_ptr() as u64,
                    Size: (buf.len() * size_of::<u32>()) as u32,
                    Type: filter_type::EVENT_FILTER_TYPE_PID,
                });
            }
        }

        let has_filter = !filter_descs.is_empty();
        let has_params = enable_property != 0 || has_filter;
        let enable_params = has_params.then(|| ENABLE_TRACE_PARAMETERS {
            Version: ENABLE_TRACE_PARAMETERS_VERSION_2,
            EnableProperty: enable_property,
            ControlFlags: 0,
            SourceId: windows_sys::core::GUID::from_u128(0),
            EnableFilterDesc: if has_filter {
                filter_descs.as_mut_ptr()
            } else {
                std::ptr::null_mut()
            },
            FilterDescCount: filter_descs.len() as u32,
        });

        // SAFETY: EnableTraceEx2 is a Win32 API. The session handle is valid.
        // The filter_buffers and filter_descs must remain valid for the duration of this call.
        let status = unsafe {
            EnableTraceEx2(
                handle,
                guid.as_sys(),
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                level,
                match_any_keyword,
                0, // match_all_keyword
                0, // Timeout (0 = async)
                enable_params
                    .as_ref()
                    .map_or(std::ptr::null(), std::ptr::from_ref),
            )
        };

        if status != ERROR_SUCCESS {
            return Err(Error::from_win32(status));
        }

        // Update existing entry or insert new one
        if let Some(existing) = self.enabled_providers.iter_mut().find(|p| p.guid == guid) {
            existing.name = name;
            existing.level = level;
            existing.match_any_keyword = match_any_keyword;
            existing.enable_property = enable_property;
            existing.filter = filter;
        } else {
            self.enabled_providers.push(EnabledProvider {
                name,
                guid,
                level,
                match_any_keyword,
                enable_property,
                filter,
            });
        }

        Ok(())
    }

    /// Core implementation of `EnableTraceEx2` with `EVENT_CONTROL_CODE_DISABLE_PROVIDER`.
    fn disable_provider_core(&mut self, provider: impl Into<ProviderIdentifier>) -> Result<()> {
        use windows_sys::Win32::System::Diagnostics::Etw::{
            EVENT_CONTROL_CODE_DISABLE_PROVIDER, EnableTraceEx2,
        };

        debug_assert!(self.is_started(), "session must be started");

        let (name, guid) = provider.into().resolve()?;

        let idx = self
            .enabled_providers
            .iter()
            .position(|p| p.guid == guid)
            .ok_or_else(|| Error::ProviderNotEnabled {
                provider: guid,
                name: name.clone(),
            })?;

        let handle = CONTROLTRACE_HANDLE {
            Value: self.session_id,
        };

        // SAFETY: EnableTraceEx2 is a Win32 API. The session handle is valid.
        let status = unsafe {
            EnableTraceEx2(
                handle,
                guid.as_sys(),
                EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                0, // level (ignored for disable)
                0, // match_any_keyword (ignored for disable)
                0, // match_all_keyword
                0, // Timeout (0 = async)
                std::ptr::null(),
            )
        };

        if status != ERROR_SUCCESS {
            return Err(Error::from_win32(status));
        }

        self.enabled_providers.swap_remove(idx); // O(1); ordering not preserved
        Ok(())
    }

    /// Core implementation of `EnableTraceEx2` with `EVENT_CONTROL_CODE_CAPTURE_STATE`.
    fn capture_state_core(&self, provider: impl Into<ProviderIdentifier>) -> Result<()> {
        use windows_sys::Win32::System::Diagnostics::Etw::{
            EVENT_CONTROL_CODE_CAPTURE_STATE, EnableTraceEx2,
        };

        debug_assert!(self.is_started(), "session must be started");

        let (name, guid) = provider.into().resolve()?;

        // Look up level/keywords from our enabled provider list
        let Some(provider) = self.enabled_providers.iter().find(|p| p.guid == guid) else {
            // Not an InvalidParameter: the GUID is well-formed, it just is not
            // enabled here — which ProviderNotEnabled already names exactly.
            return Err(Error::ProviderNotEnabled {
                provider: guid,
                name,
            });
        };
        let (level, match_any_keyword) = (provider.level, provider.match_any_keyword);

        let handle = CONTROLTRACE_HANDLE {
            Value: self.session_id,
        };

        // SAFETY: EnableTraceEx2 is a Win32 API. The session handle is valid.
        let status = unsafe {
            EnableTraceEx2(
                handle,
                guid.as_sys(),
                EVENT_CONTROL_CODE_CAPTURE_STATE,
                level,
                match_any_keyword,
                0, // match_all_keyword
                0, // Timeout (0 = async)
                std::ptr::null(),
            )
        };

        if status != ERROR_SUCCESS {
            return Err(Error::from_win32(status));
        }

        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Private — Processing Thread
    // ═══════════════════════════════════════════════════════════════════════

    /// Returns the effective thread description: the custom value if set, or the default
    /// `"ETW: <session_name>"`.
    fn effective_thread_description(&self) -> String {
        self.thread_description
            .clone()
            .unwrap_or_else(|| format!("ETW: {}", self.session_name))
    }

    /// Open the trace for processing and spawn the processing thread.
    fn open_and_spawn_processing_thread(&mut self) -> Result<()> {
        use super::common::{EVENT_TRACE_LOGFILEW, OpenTraceW};
        use windows_sys::Win32::Foundation::HANDLE;

        // Open the trace for processing
        let session_name_wide = Self::to_wide_string(&self.session_name);

        // SAFETY: EVENT_TRACE_LOGFILEW is a POD struct that can be zero-initialised.
        let mut log_file: EVENT_TRACE_LOGFILEW = unsafe { std::mem::zeroed() };
        // session_name_wide lives for the duration of this function. OpenTraceW copies the
        // string internally, so the pointer is valid for the duration of the call.
        log_file.LoggerName = session_name_wide.as_ptr().cast_mut();
        log_file.ProcessTraceMode = if self.process_trace_mode == 0 {
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD
        } else {
            self.process_trace_mode
        };
        log_file.EventRecordCallback = Some(event_record_callback);
        // BufferCallback lets a poisoned trace (StopTrace panic policy) end the
        // ProcessTrace loop from the consumer thread itself; it reads the poison
        // flag on the CallbackState reached through Context.
        log_file.BufferCallback = Some(buffer_record_callback);
        log_file.Context = std::ptr::from_mut::<CallbackState>(self.callback_state.as_mut())
            .cast::<std::ffi::c_void>();

        // SAFETY: OpenTraceW is a Win32 API. log_file is properly initialised.
        let handle = unsafe { OpenTraceW(&raw mut log_file) };
        self.process_trace_handle = handle.Value;
        if self.process_trace_handle == INVALID_PROCESSTRACE_HANDLE {
            // SAFETY: GetLastError is always safe to call after a Win32 API failure.
            let open_error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            return Err(Error::from_win32(open_error));
        }

        // Spawn processing thread with a ready signal
        let handle_value = self.process_trace_handle;
        let session_name_clone = self.session_name.clone();
        let priority = self.thread_priority;
        let thread_description = self.effective_thread_description();
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<()>(0);
        let join_handle = std::thread::Builder::new()
            .name(thread_description.clone())
            .spawn(move || {
                processing_thread_setup(priority, &thread_description);
                // Signal the parent that setup is complete and ProcessTrace is about to start
                let _ = ready_tx.send(());
                process_trace_blocking(handle_value, &session_name_clone)
            })
            .map_err(|e| Error::ThreadError {
                reason: ThreadFailure::SpawnFailed(e),
            })?;

        // Phase 1: Wait for thread to signal it has initialised
        if ready_rx.recv().is_err() {
            return Err(Error::ThreadError {
                reason: ThreadFailure::ExitedBeforeReady,
            });
        }

        let native_handle: HANDLE = join_handle.as_raw_handle();
        self.processing_thread = Some(join_handle);

        // Phase 2: Wait `thread_startup_timeout_ms` for ProcessTrace to settle.
        // If the thread exits within the window, ProcessTrace failed; otherwise
        // it's running and the trace is hot. We don't gate on first-event
        // arrival because narrow-filter / self-triggered traces may have no
        // ambient events yet.
        use windows_sys::Win32::{
            Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT},
            System::Threading::WaitForSingleObject,
        };
        // SAFETY: native_handle is valid for the lifetime of join_handle which we own.
        let wait_result =
            unsafe { WaitForSingleObject(native_handle, self.thread_startup_timeout_ms) };
        if wait_result == WAIT_OBJECT_0 {
            // Thread exited within the startup window. Distinguish a callback
            // panic (the default/StopTrace policy poisons the trace and returns
            // ProcessTrace cleanly) from a genuine ProcessTrace startup failure —
            // otherwise the caller gets an opaque "exited with code 0" and is
            // sent looking in the wrong place. (The thread exit code is the Rust
            // runtime's, not ProcessTrace's status, so it is not informative.)
            if self.is_poisoned() {
                return Err(Error::ThreadError {
                    reason: ThreadFailure::PanicDuringStartup,
                });
            }
            let mut exit_code: u32 = 0;
            // SAFETY: native_handle is valid.
            unsafe {
                let _ = windows_sys::Win32::System::Threading::GetExitCodeThread(
                    native_handle,
                    &raw mut exit_code,
                );
            }
            return Err(Error::ThreadError {
                reason: ThreadFailure::ExitedWithCode { code: exit_code },
            });
        }
        debug_assert_eq!(
            wait_result, WAIT_TIMEOUT,
            "WaitForSingleObject returned unexpected value: {wait_result:?}"
        );

        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Private — Helpers
    // ═══════════════════════════════════════════════════════════════════════

    /// Stop an orphaned session with the same name (best-effort cleanup).
    ///
    /// Uses a disposable properties buffer so `ControlTraceW` does not clobber
    /// the caller's configuration.
    ///
    /// Returns `Ok(true)` if an orphaned session was found and stopped,
    /// `Ok(false)` if no session existed, or `Err` on unexpected failure.
    fn stop_orphaned_session(session_name: &str) -> Result<bool> {
        use windows_sys::Win32::{
            Foundation::{ERROR_MORE_DATA, ERROR_SUCCESS, ERROR_WMI_INSTANCE_NOT_FOUND},
            System::Diagnostics::Etw::{
                CONTROLTRACE_HANDLE, ControlTraceW, EVENT_TRACE_CONTROL_STOP,
                EVENT_TRACE_PROPERTIES,
            },
        };

        // Disposable buffer — ControlTraceW overwrites it with the stopped
        // session's values, which we discard.
        // SAFETY: EVENT_TRACE_PROPERTIES is a POD struct.
        let mut props: EVENT_TRACE_PROPERTIES = unsafe { std::mem::zeroed() };
        props.Wnode.BufferSize = size_of::<EVENT_TRACE_PROPERTIES>() as u32;

        let session_name_wide = Self::to_wide_string(session_name);
        // SAFETY: ControlTraceW is a Win32 API. The buffer and session name are valid.
        let status = unsafe {
            ControlTraceW(
                CONTROLTRACE_HANDLE { Value: 0 },
                session_name_wide.as_ptr(),
                &raw mut props,
                EVENT_TRACE_CONTROL_STOP,
            )
        };

        match status {
            ERROR_WMI_INSTANCE_NOT_FOUND => Ok(false),
            // ERROR_MORE_DATA: the disposable buffer has no room for the
            // logger-name strings ControlTraceW writes back. Per its
            // documentation the session has already been stopped when this
            // code is returned, and the error is ignorable when the caller
            // does not need the returned properties — which we discard.
            ERROR_SUCCESS | ERROR_MORE_DATA => {
                // Orphaned session was stopped — sleep to allow the ETW subsystem
                // to release the session name. Without this delay, an immediate
                // StartTrace with the same name may fail with ALREADY_EXISTS.
                std::thread::sleep(std::time::Duration::from_secs(1));
                Ok(true)
            }
            _ => Err(Error::from_win32(status)),
        }
    }

    /// Convert a string to a null-terminated UTF-16 wide string.
    fn to_wide_string(s: &str) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Trait Implementations
// ═══════════════════════════════════════════════════════════════════════════════

impl Drop for Trace {
    fn drop(&mut self) {
        // stop() neutralises the processing thread and closes handles even when
        // ControlTraceW fails, so dropping after a failed stop is sound. Drop cannot
        // propagate the error, but it must not swallow it silently.
        if let Err(e) = self.stop() {
            log::error!(
                "ETW session '{}': stop() failed during drop: {e}",
                self.session_name
            );
        }
    }
}

impl std::fmt::Display for Trace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.session_name)
    }
}

impl std::fmt::Debug for Trace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use super::common::{
            BufferCount, BufferSize, ClockResolutionDisplay, FlushTimer, LogFileModeFlags,
            ProcessTraceModeFlags, ProcessingThreadDisplay, SessionIdDisplay,
            ShutdownTimeoutDisplay, ThreadPriorityDisplay, TraceHandleDisplay,
        };
        #[expect(
            unused_imports,
            reason = "only used by the system-logger arms of the Debug body"
        )]
        use super::system_logger::{GroupMasksDisplay, LbrConfigDisplay, PoolTagsDisplay};

        let process_trace_mode = if self.process_trace_mode == 0 {
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD
        } else {
            self.process_trace_mode
        };

        let is_system_logger = self.is_system_logger_mode();

        let mut s = f.debug_struct("Trace");
        s.field("name", &self.session_name)
            .field("session_id", &SessionIdDisplay(self.session_id))
            .field(
                "log_file_mode",
                &LogFileModeFlags(self.props_buf.properties.LogFileMode),
            )
            .field(
                "clock_resolution",
                &ClockResolutionDisplay(self.props_buf.properties.Wnode.ClientContext),
            )
            .field(
                "flush_timer",
                &FlushTimer(self.props_buf.properties.FlushTimer),
            )
            .field(
                "buffer_size",
                &BufferSize(self.props_buf.properties.BufferSize),
            )
            .field(
                "min_buffers",
                &BufferCount(self.props_buf.properties.MinimumBuffers),
            )
            .field(
                "max_buffers",
                &BufferCount(self.props_buf.properties.MaximumBuffers),
            );

        // Show exclude_kernel_stack if stack traces are enabled on any provider
        let has_stack_traces = self
            .enabled_providers
            .iter()
            .any(|p| p.enable_property & EnableProperty::STACK_TRACE != 0);
        if has_stack_traces {
            s.field("exclude_kernel_stack", &self.exclude_kernel_stack());
        }

        s.field(
            "process_trace_handle",
            &TraceHandleDisplay(self.process_trace_handle),
        )
        .field(
            "processing_thread",
            &ProcessingThreadDisplay(&self.processing_thread),
        )
        .field(
            "thread_priority",
            &ThreadPriorityDisplay(self.thread_priority),
        )
        .field(
            "process_trace_mode",
            &ProcessTraceModeFlags(process_trace_mode),
        )
        .field("thread_description", &self.effective_thread_description())
        .field(
            "shutdown_timeout",
            &ShutdownTimeoutDisplay(self.thread_shutdown_timeout_ms),
        )
        .field("providers", &self.enabled_providers);

        // System logger fields — only shown when system logger mode is active
        if is_system_logger {
            s.field("system_logger_mode", &true)
                .field(
                    "group_masks",
                    &super::system_logger::GroupMasksDisplay(&self.group_masks),
                )
                .field("enable_flags", &format_args!("0x{:08X}", self.enable_flags))
                .field("stack_events", &self.stack_events.len())
                .field(
                    "pool_tags",
                    &super::system_logger::PoolTagsDisplay(&self.pool_tags),
                )
                .field(
                    "object_type_tags",
                    &super::system_logger::PoolTagsDisplay(&self.object_type_tags),
                )
                .field("pmc_counters", &self.pmc_counters.len())
                .field("pmc_events", &self.pmc_events.len())
                .field(
                    "lbr_config",
                    &super::system_logger::LbrConfigDisplay(self.lbr_config),
                )
                .field("lbr_events", &self.lbr_events.len());
        }

        s.finish_non_exhaustive()
    }
}

// SAFETY: Trace is Send but not Sync. The properties field contains raw
// pointers but they're only used within the same thread context (start/stop/process
// methods). The processing thread holds a raw pointer to `callback_state`, so
// `set_event_callback` enforces that it must not be called while processing is
// active (runtime assertion).
unsafe impl Send for Trace {}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
#[expect(clippy::expect_used, reason = "test-only assertions")]
mod tests {
    use super::*;
    use windows_sys::Win32::System::Threading::THREAD_PRIORITY_ABOVE_NORMAL;

    #[test]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_session_creation() {
        let session = Trace::new("TestSession");
        assert!(session.is_ok());

        let session = session.expect("session creation should succeed");
        assert_eq!(session.name(), "TestSession");
        assert!(!session.is_started());
        assert!(!session.is_processing());
        assert!(!session.is_system_logger_mode());
    }

    #[test]
    fn test_session_name_too_long() {
        let long_name = "a".repeat(MAXIMUM_SESSION_NAME);
        let result = Trace::new(&long_name);
        assert!(result.is_err());
    }

    #[test]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_property_setters() {
        let mut session = Trace::new("TestSession").expect("session creation should succeed");

        let _ = session
            .set_buffer_size(64)
            .set_minimum_buffers(3)
            .set_maximum_buffers(10)
            .set_flush_timer(1);

        assert_eq!(session.props_buf.properties.BufferSize, 64);
        assert_eq!(session.props_buf.properties.MinimumBuffers, 3);
        assert_eq!(session.props_buf.properties.MaximumBuffers, 10);
        assert_eq!(session.props_buf.properties.FlushTimer, 1);
    }

    #[test]
    #[should_panic(expected = "Buffer size must be at least 4 KB")]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_buffer_size_validation() {
        let mut session = Trace::new("TestSession").expect("session creation should succeed");
        let _ = session.set_buffer_size(2);
    }

    // Max set first, then min raised past it: no single setter sees the final pair.
    #[test]
    #[should_panic(expected = "Maximum buffers (2) must be >= minimum buffers (10)")]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_start_rejects_max_below_min_set_max_first() {
        let mut session = Trace::new("TestBufMaxFirst").expect("session creation should succeed");
        let _ = session.set_maximum_buffers(2).set_minimum_buffers(10);
        let _ = session.start();
    }

    // The setters accept either order; only start() judges the final pair.
    #[test]
    #[should_panic(expected = "Maximum buffers (2) must be >= minimum buffers (10)")]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_start_rejects_max_below_min_set_min_first() {
        let mut session = Trace::new("TestBufMinFirst").expect("session creation should succeed");
        let _ = session.set_minimum_buffers(10).set_maximum_buffers(2);
        let _ = session.start();
    }

    // 0 means "let ETW choose", so no minimum can exceed it.
    #[test]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_buffer_counts_accept_zero_max() {
        let mut session = Trace::new("TestBufZeroMax").expect("session creation should succeed");
        let _ = session.set_minimum_buffers(10).set_maximum_buffers(0);
        session.assert_buffer_counts();
    }

    #[test]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_processing_thread_priority() {
        let mut session = Trace::new("TestSession").expect("session creation should succeed");
        let _ = session.set_processing_thread_priority(THREAD_PRIORITY_ABOVE_NORMAL);
        assert_eq!(session.thread_priority, THREAD_PRIORITY_ABOVE_NORMAL);
    }

    #[test]
    #[should_panic(expected = "start_processing_thread() called without set_event_callback()")]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_start_processing_without_callback_panics() {
        let mut session = Trace::new("TestNoCallback").expect("session creation should succeed");
        let _ = session.start_processing_thread();
    }

    #[test]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_is_system_logger_mode() {
        let mut session = Trace::new("TestSLM").expect("session creation should succeed");
        assert!(!session.is_system_logger_mode());

        session.set_events(&[super::super::system_logger::masks::PERF_PROCESS]);
        assert!(session.is_system_logger_mode());
    }

    #[test]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_set_log_file_mode_always_adds_realtime_and_independent() {
        use windows_sys::Win32::System::Diagnostics::Etw::{
            EVENT_TRACE_INDEPENDENT_SESSION_MODE, EVENT_TRACE_REAL_TIME_MODE,
        };
        let mut session = Trace::new("TestLogMode").expect("session creation");
        let _ = session.set_log_file_mode(0);
        let mode = session.props_buf.properties.LogFileMode;
        assert_ne!(
            mode & EVENT_TRACE_REAL_TIME_MODE,
            0,
            "REAL_TIME must be set"
        );
        assert_ne!(
            mode & EVENT_TRACE_INDEPENDENT_SESSION_MODE,
            0,
            "INDEPENDENT_SESSION must be set"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_set_clock_resolution() {
        use super::super::ClockResolution;
        let mut session = Trace::new("TestClock").expect("session creation");
        let _ = session.set_clock_resolution(ClockResolution::SYSTEM_TIME);
        assert_eq!(
            session.props_buf.properties.Wnode.ClientContext,
            ClockResolution::SYSTEM_TIME
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_set_exclude_kernel_stack_roundtrip() {
        let mut session = Trace::new("TestKernelStack").expect("session creation");
        assert!(!session.exclude_kernel_stack());

        let _ = session.set_exclude_kernel_stack(true);
        assert!(session.exclude_kernel_stack());

        let _ = session.set_exclude_kernel_stack(false);
        assert!(!session.exclude_kernel_stack());
    }

    #[test]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_set_buffer_configuration() {
        let mut session = Trace::new("TestBufCfg").expect("session creation");
        let _ = session.set_buffer_configuration(64, 4, 16, 2);
        assert_eq!(session.props_buf.properties.BufferSize, 64);
        assert_eq!(session.props_buf.properties.MinimumBuffers, 4);
        assert_eq!(session.props_buf.properties.MaximumBuffers, 16);
        assert_eq!(session.props_buf.properties.FlushTimer, 2);
    }

    #[test]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_set_process_trace_mode() {
        use windows_sys::Win32::System::Diagnostics::Etw::PROCESS_TRACE_MODE_REAL_TIME;
        let mut session = Trace::new("TestPTM").expect("session creation");
        let _ = session.set_process_trace_mode(PROCESS_TRACE_MODE_REAL_TIME);
        assert_eq!(session.process_trace_mode, PROCESS_TRACE_MODE_REAL_TIME);
    }

    #[test]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_set_processing_thread_description() {
        let mut session = Trace::new("TestDesc").expect("session creation");
        assert!(session.thread_description.is_none());
        let _ = session.set_processing_thread_description("my-thread");
        assert_eq!(session.thread_description.as_deref(), Some("my-thread"));
    }

    #[test]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_set_processing_thread_shutdown_timeout() {
        let mut session = Trace::new("TestTimeout").expect("session creation");
        let _ = session.set_processing_thread_shutdown_timeout(10_000);
        assert_eq!(session.thread_shutdown_timeout_ms, 10_000);

        let _ = session.set_processing_thread_shutdown_timeout(u32::MAX); // INFINITE
        assert_eq!(session.thread_shutdown_timeout_ms, u32::MAX);
    }

    #[test]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_properties_as_raw_is_nonnull() {
        let mut session = Trace::new("TestRaw").expect("session creation");
        let ptr = session.properties_as_raw();
        assert!(!ptr.is_null());
    }

    #[test]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_raw_handle_accessors_before_start() {
        let session = Trace::new("TestHandles").expect("session creation");
        // Before start(), each accessor maps its Win32 sentinel to None rather
        // than exposing the raw INVALID_* value.
        assert_eq!(session.session_id(), None);
        assert_eq!(session.raw_process_trace_handle(), None);
        assert_eq!(session.raw_processing_thread_handle(), None);
    }

    #[test]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_trace_display_and_debug() {
        let session = Trace::new("MyTrace").expect("session creation");
        assert_eq!(format!("{session}"), "MyTrace");
        let debug = format!("{session:?}");
        assert!(debug.contains("MyTrace"), "Debug must mention session name");
        assert!(debug.contains("Trace"), "Debug must use struct format");
    }

    #[test]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_statistics_before_start_are_zero() {
        let session = Trace::new("TestStats").expect("session creation");
        let stats = session.statistics();
        assert_eq!(stats.buffers_count, 0);
        assert_eq!(stats.buffers_free, 0);
        assert_eq!(stats.buffers_written, 0);
        assert_eq!(stats.events_lost, 0);
        assert_eq!(stats.realtime_buffers_lost, 0);
    }

    #[test]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_properties_returns_reference() {
        let session = Trace::new("TestProps").expect("session creation");
        let props = session.properties();
        // BufferSize starts at 0 before any setter is called
        // (will be defaulted later in start())
        let _ = props.BufferSize;
    }

    #[test]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_set_processing_thread_startup_timeout() {
        let mut session = Trace::new("TestStartup").expect("session creation");
        let _ = session.set_processing_thread_startup_timeout(500);
        assert_eq!(session.thread_startup_timeout_ms, 500);
    }

    #[test]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_extension_offset_is_nonzero() {
        let session = Trace::new("TestExt").expect("session creation");
        let offset = session.extension_offset();
        // extension_space is at a nonzero offset (after properties + session_name)
        assert!(offset > 0);
    }

    #[test]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_set_event_callback_marks_callback_set() {
        let mut session = Trace::new("TestCb").expect("session creation");
        // Before: event_callback is None
        assert!(session.callback_state.event_callback.is_none());
        session.set_event_callback(|_event, _ctx| Ok(()));
        assert!(session.callback_state.event_callback.is_some());
    }

    #[test]
    fn test_enable_property_constants() {
        assert_eq!(EnableProperty::SID, 0x0000_0001);
        assert_eq!(EnableProperty::TS_ID, 0x0000_0002);
        assert_eq!(EnableProperty::STACK_TRACE, 0x0000_0004);
        assert_eq!(EnableProperty::IGNORE_KEYWORD_0, 0x0000_0010);
        assert_eq!(EnableProperty::ENABLE_KEYWORD_0, 0x0000_0040);
        assert_eq!(EnableProperty::PROCESS_START_KEY, 0x0000_0080);
        // STACK_TRACE | SID can be combined
        assert_eq!(
            EnableProperty::STACK_TRACE | EnableProperty::SID,
            0x0000_0005
        );
    }

    #[test]
    fn test_process_trace_mode_constants() {
        assert_eq!(ProcessTraceMode::REAL_TIME, 0x0000_0100);
        assert_eq!(ProcessTraceMode::EVENT_RECORD, 0x1000_0000);
        assert_eq!(ProcessTraceMode::RAW_TIMESTAMP, 0x0000_1000);
        // Combined modes
        assert_eq!(
            ProcessTraceMode::REAL_TIME | ProcessTraceMode::EVENT_RECORD,
            0x1000_0100
        );
    }
}
