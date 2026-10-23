//! System logger configuration for [`Trace`] sessions.
//!
//! This module provides system logger tracing via `EVENT_TRACE_SYSTEM_LOGGER_MODE`.
//! Calling any system logger API automatically enables system logger mode on the
//! trace session.
//!
//! Submodules:
//! - [`masks`]: `PERF_*` group mask constants
//! - [`profiling`]: CPU sampling interval configuration
//! - [`stack_walk`]: Stack walk and LBR event parsing

#[expect(
    missing_docs,
    reason = "PERF_* constants are documented by the Win32 group mask reference"
)]
pub mod masks;
pub mod profiling;
pub mod stack_walk;

use self::masks::{
    ETW_EXT_ENABLE_FLAGS, ETW_EXT_POOLTAG_FILTER, ETW_EXT_STACKWALK_FILTER,
    ETW_MAX_OBJECT_TYPE_FILTER, ETW_MAX_PMC_EVENTS, ETW_MAX_POOLTAG_FILTER,
    ETW_MAX_STACKWALK_FILTER, PERF_NUM_MASKS, TRACE_LBR_MAXIMUM_EVENTS, add_group_mask,
};
use super::{common::ensure_unique, trace::Trace};
use crate::{Error, ParameterProblem, Result};
use windows_sys::{
    Win32::{
        Foundation::{ERROR_SUCCESS, NTSTATUS},
        System::Diagnostics::Etw::{
            CLASSIC_EVENT_ID, CONTROLTRACE_HANDLE, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            EnableTraceEx2, TraceLbrConfigurationInfo, TraceLbrEventListInfo,
            TracePmcCounterListInfo, TracePmcEventListInfo, TraceSetInformation,
            TraceStackTracingInfo, TraceSystemTraceEnableFlagsInfo,
        },
    },
    core::GUID,
};

// NtSetSystemInformation binding (not in windows-rs)
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtSetSystemInformation(
        system_information_class: u32,
        system_information: *const std::ffi::c_void,
        system_information_length: u32,
    ) -> NTSTATUS;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════

/// Extension marker in `EnableFlags` indicating extension data follows.
///
/// - High byte 0x80 = Extension present
/// - Second byte 0xFF = New extension format
const ENABLE_FLAGS_EXTENSION_MARKER: u32 = 0x80FF_0000;

/// Kernel rundown provider GUID.
///
/// Used with `EnableTraceEx2(EVENT_CONTROL_CODE_ENABLE_PROVIDER)` to trigger
/// kernel rundown events. Reference: krabsetw `krabs::guids::rundown`
const KERNEL_RUNDOWN_GUID: GUID = GUID::from_u128(0x3b9c9951_3480_4220_9377_9c8e5184f5cd);

/// `SystemPerformanceTraceInformation` class for `NtSetSystemInformation`.
const SYSTEM_PERFORMANCE_TRACE_INFORMATION: u32 = 0x1F;

/// `EventTraceObjectTypeFilterInformation` sub-class (0x11).
///
/// Used to filter object handle events (`PERF_OB_HANDLE`) by object type pool tag.
const EVENT_TRACE_OBJECT_TYPE_FILTER_INFORMATION: u32 = 0x11;

// ═══════════════════════════════════════════════════════════════════════════════
// FFI Structures
// ═══════════════════════════════════════════════════════════════════════════════

/// Structure for `EventTraceObjectTypeFilterInformation`.
///
/// Passed to `NtSetSystemInformation(SystemPerformanceTraceInformation)`.
///
/// The `filter` array is sized to `ETW_MAX_TAG_FILTER = 4` (from ntwmi.h). Both
/// `EventTracePoolTagFilterInformation` and `EventTraceObjectTypeFilterInformation`
/// use this same struct and share the same 4-entry limit.
/// Reference: phnt `ntexapi.h` (`EVENT_TRACE_TAG_FILTER_INFORMATION`).
#[repr(C)]
struct EventTraceTagFilterInformation {
    /// Must be `EVENT_TRACE_OBJECT_TYPE_FILTER_INFORMATION` (0x11)
    event_trace_information_class: u32,
    /// Trace session handle from `StartTraceW`
    trace_handle: u64,
    /// Array of pool tags to filter (4-byte ASCII tags). Max 4 entries.
    filter: [u32; ETW_MAX_POOLTAG_FILTER],
}

// ═══════════════════════════════════════════════════════════════════════════════
// Re-exports
// ═══════════════════════════════════════════════════════════════════════════════

/// Maximum number of events that can trigger LBR collection.
///
/// Re-exports [`masks::TRACE_LBR_MAXIMUM_EVENTS`] for convenience.
pub use self::masks::TRACE_LBR_MAXIMUM_EVENTS as LBR_MAXIMUM_EVENTS;
pub use self::profiling::ProfileSource;

// ═══════════════════════════════════════════════════════════════════════════════
// LBR Configuration
// ═══════════════════════════════════════════════════════════════════════════════

/// LBR configuration flags for filtering branch types.
///
/// These flags correspond to the `TRACE_LBR_CONFIGURATION` enum in `evntrace.h`.
/// They control which types of branches are recorded in the Last Branch Record.
/// Use these with [`Trace::enable_lbr()`] to configure LBR tracing.
///
/// # Example
///
/// ```
/// use etw::system_logger::{CALLSTACK_ENABLE, EXCLUDE_JCC, EXCLUDE_USER, LbrConfig};
///
/// // Capture only kernel branches, excluding conditional jumps
/// let config = EXCLUDE_USER | EXCLUDE_JCC;
///
/// // Capture call stacks only
/// let config = CALLSTACK_ENABLE;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LbrConfig(pub u32);

/// Do not exclude any branches (capture all).
pub const LBR_NONE: LbrConfig = LbrConfig(0x0);
/// Exclude branches in kernel privilege level.
pub const EXCLUDE_KERNEL: LbrConfig = LbrConfig(0x1);
/// Exclude branches in user privilege level.
pub const EXCLUDE_USER: LbrConfig = LbrConfig(0x2);
/// Exclude conditional branches (JCC: JNZ, JGE, etc.).
pub const EXCLUDE_JCC: LbrConfig = LbrConfig(0x4);
/// Exclude near relative calls.
pub const EXCLUDE_NEAR_REL_CALL: LbrConfig = LbrConfig(0x8);
/// Exclude near indirect calls.
pub const EXCLUDE_NEAR_IND_CALL: LbrConfig = LbrConfig(0x10);
/// Exclude near returns.
pub const EXCLUDE_NEAR_RET: LbrConfig = LbrConfig(0x20);
/// Exclude near indirect jumps.
pub const EXCLUDE_NEAR_IND_JMP: LbrConfig = LbrConfig(0x40);
/// Exclude near relative jumps.
pub const EXCLUDE_NEAR_REL_JMP: LbrConfig = LbrConfig(0x80);
/// Exclude far ("other") branches.
pub const EXCLUDE_FAR_BRANCH: LbrConfig = LbrConfig(0x100);
/// Record branches in callstack (LIFO) mode.
pub const CALLSTACK_ENABLE: LbrConfig = LbrConfig(0x200);
/// Record sample-based LBR (ARM64 only).
pub const SAMPLED: LbrConfig = LbrConfig(0x400);

impl LbrConfig {
    /// Create a new LbrConfig with the given flags.
    #[must_use]
    pub const fn new(flags: u32) -> Self {
        Self(flags)
    }

    /// Get the raw flags value.
    #[must_use]
    pub const fn flags(self) -> u32 {
        self.0
    }

    /// Check if a specific flag is set.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl std::ops::BitOr for LbrConfig {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for LbrConfig {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl std::ops::BitAnd for LbrConfig {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Extension Writer
// ═══════════════════════════════════════════════════════════════════════════════

/// Helper for building ETW extension data.
///
/// Extension data format:
/// - Header: `[u16: total_dwords] [u16: item_count]`
/// - Items: `[u16: item_dwords] [u16: type] [data...]`
pub(crate) struct ExtensionWriter<'a> {
    buffer: &'a mut [u8],
    offset: usize,
    item_count: u16,
}

impl<'a> ExtensionWriter<'a> {
    pub(crate) const fn new(buffer: &'a mut [u8]) -> Self {
        Self {
            buffer,
            offset: 4, // Skip header (written in finalize)
            item_count: 0,
        }
    }

    /// Add an extension item with the given type and data.
    pub(crate) fn add_item(&mut self, item_type: u16, data: &[u32]) {
        let data_bytes = size_of_val(data);
        let item_header_size = 4; // [u16: size_dwords] [u16: type]

        // Item size includes header + data, rounded up to dwords
        let item_size_bytes = item_header_size + data_bytes;
        let item_size_dwords = item_size_bytes.div_ceil(4);
        let padded_size = item_size_dwords * 4;

        assert!(
            self.offset + padded_size <= self.buffer.len(),
            "Extension buffer overflow"
        );

        // Write item header
        // Size field is the number of dwords INCLUDING the header
        let size_dwords = item_size_dwords as u16;
        self.buffer[self.offset..self.offset + 2].copy_from_slice(&size_dwords.to_le_bytes());
        self.buffer[self.offset + 2..self.offset + 4].copy_from_slice(&item_type.to_le_bytes());

        // Write data
        let data_ptr = data.as_ptr().cast::<u8>();
        #[expect(
            clippy::semicolon_if_nothing_returned,
            reason = "conflicts with semicolon_outside_block here"
        )]
        // SAFETY: data is valid for data_bytes, buffer has space.
        unsafe {
            std::ptr::copy_nonoverlapping(
                data_ptr,
                self.buffer.as_mut_ptr().add(self.offset + 4),
                data_bytes,
            )
        };

        // Zero padding
        for i in (self.offset + 4 + data_bytes)..(self.offset + padded_size) {
            self.buffer[i] = 0;
        }

        self.offset += padded_size;
        self.item_count += 1;
    }

    /// Finalise the extension header.
    pub(crate) fn finalize(&mut self) {
        // Total size in dwords (including header)
        let total_dwords = self.offset.div_ceil(4);

        // Write header: [u16: total_dwords] [u16: item_count]
        self.buffer[0..2].copy_from_slice(&(total_dwords as u16).to_le_bytes());
        self.buffer[2..4].copy_from_slice(&self.item_count.to_le_bytes());
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// System Logger Methods — impl Trace
// ═══════════════════════════════════════════════════════════════════════════════

impl Trace {
    // ═══════════════════════════════════════════════════════════════════════
    // Pre-start configuration
    // ═══════════════════════════════════════════════════════════════════════

    /// Enable kernel event groups from `groups`.
    ///
    /// `groups` is a slice of `PERF_*` constants from [`masks`]. Can be called
    /// multiple times to accumulate groups. Must be called before
    /// [`start()`](Self::start).
    ///
    /// # Panics
    ///
    /// Panics if called after `start()`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use etw::{Trace, system_logger::masks::*};
    ///
    /// let mut trace = Trace::new("MyTrace")?;
    /// trace.set_events(&[PERF_PROCESS, PERF_THREAD, PERF_CONTEXT_SWITCH]);
    /// # Ok::<(), etw::Error>(())
    /// ```
    pub fn set_events(&mut self, groups: &[u32]) -> &mut Self {
        assert!(!self.is_started(), "Cannot modify events after start()");
        for &flag in groups {
            add_group_mask(&mut self.group_masks, flag);
        }
        self
    }

    /// Enable kernel events using classic `EVENT_TRACE_FLAG_*` values.
    ///
    /// Alternative to [`set_events()`](Self::set_events) for enabling kernel events.
    /// Sets the `EnableFlags` field in `EVENT_TRACE_PROPERTIES` directly, which
    /// only supports Masks\[0\] flags (classic `EVENT_TRACE_FLAG_*` constants).
    ///
    /// **Cannot be combined with [`set_events()`](Self::set_events)**, stack walking,
    /// or pool tag filters. Use `EVENT_TRACE_FLAG_*` constants from the
    /// `windows-sys` crate — they are plain `u32` values.
    ///
    /// Must be called before [`start()`](Self::start).
    ///
    /// # Panics
    ///
    /// Panics if called after `start()`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use etw::Trace;
    /// use windows_sys::Win32::System::Diagnostics::Etw::{
    ///     EVENT_TRACE_FLAG_DISK_FILE_IO, EVENT_TRACE_FLAG_PROCESS,
    /// };
    ///
    /// let mut trace = Trace::new("MyTrace")?;
    /// trace.set_enable_flags(EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_DISK_FILE_IO);
    /// # Ok::<(), etw::Error>(())
    /// ```
    pub fn set_enable_flags(&mut self, flags: u32) -> &mut Self {
        assert!(!self.is_started(), "Cannot modify events after start()");
        self.enable_flags |= flags;
        self
    }

    /// Enable stack walking for specific kernel events.
    ///
    /// `hook_ids` is a slice of hook IDs encoded as `(group_id << 8) | opcode`.
    /// Configures the trace to capture call stacks when the specified event
    /// types occur. Must be called before [`start()`](Self::start).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidParameter`] if the total number of accumulated
    /// stack-walk events would exceed [`ETW_MAX_STACKWALK_FILTER`], or if a hook
    /// ID repeats — within `hook_ids` or against one added by an earlier call.
    ///
    /// # Panics
    ///
    /// Panics if called after `start()`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use etw::Trace;
    ///
    /// let mut trace = Trace::new("MyTrace")?;
    /// // Hook IDs: (group_id << 8) | opcode
    /// trace.set_stack_walking(&[
    ///     0x0301, // Process START (group 0x03, opcode 1)
    ///     0x0524, // Thread CSWITCH (group 0x05, opcode 36)
    ///     0x020E, // PageFault HARD (group 0x02, opcode 14)
    /// ])?;
    /// # Ok::<(), etw::Error>(())
    /// ```
    pub fn set_stack_walking(&mut self, hook_ids: &[u16]) -> Result<&mut Self> {
        assert!(
            !self.is_started(),
            "Cannot modify stack walking after start()"
        );
        if self.stack_events.len() + hook_ids.len() > ETW_MAX_STACKWALK_FILTER {
            return Err(Error::InvalidParameter {
                parameter: "stack walk events",
                problem: ParameterProblem::TooMany {
                    count: self.stack_events.len() + hook_ids.len(),
                    max: ETW_MAX_STACKWALK_FILTER,
                },
            });
        }
        ensure_unique(
            "stack walk events",
            self.stack_events.iter().chain(hook_ids),
        )?;
        self.stack_events.extend_from_slice(hook_ids);
        Ok(self)
    }

    /// Set pool tag filtering for pool events.
    ///
    /// When pool tag filtering is enabled, only pool allocation/free events matching
    /// the specified tags will be captured. This requires
    /// [`PERF_POOL`](masks::PERF_POOL) to be enabled via [`set_events()`](Self::set_events).
    ///
    /// Pool tags are 4-byte values, typically ASCII characters. Use [`pool_tag!`](crate::pool_tag)
    /// macro or [`pool_tag`](crate::pool_tag()) function to create tags from strings.
    ///
    /// Must be called before [`start()`](Self::start).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidParameter`] if the total number of accumulated
    /// pool tags would exceed [`ETW_MAX_POOLTAG_FILTER`], or if a tag repeats —
    /// within `tags` or against one added by an earlier call.
    ///
    /// # Panics
    ///
    /// Panics if called after `start()`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use etw::{Trace, pool_tag, system_logger::masks::PERF_POOL};
    ///
    /// let mut trace = Trace::new("MyTrace")?;
    /// trace.set_events(&[PERF_POOL]);
    /// trace.set_pool_tag_filter(&[
    ///     pool_tag(b"Proc"), // Process allocations
    ///     pool_tag(b"Thre"), // Thread allocations
    ///     pool_tag(b"File"), // File allocations
    /// ])?;
    /// # Ok::<(), etw::Error>(())
    /// ```
    pub fn set_pool_tag_filter(&mut self, tags: &[u32]) -> Result<&mut Self> {
        assert!(
            !self.is_started(),
            "Cannot modify pool tag filter after start()"
        );
        if self.pool_tags.len() + tags.len() > ETW_MAX_POOLTAG_FILTER {
            return Err(Error::InvalidParameter {
                parameter: "pool tag filter",
                problem: ParameterProblem::TooMany {
                    count: self.pool_tags.len() + tags.len(),
                    max: ETW_MAX_POOLTAG_FILTER,
                },
            });
        }
        ensure_unique("pool tag filter", self.pool_tags.iter().chain(tags))?;
        self.pool_tags.extend_from_slice(tags);
        Ok(self)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Post-start APIs
    // ═══════════════════════════════════════════════════════════════════════

    /// Trigger a file name rundown via `EnableTraceEx2`.
    ///
    /// Sends `EVENT_CONTROL_CODE_ENABLE_PROVIDER` to the kernel rundown GUID
    /// with the `FILENAME` code (0x10), which triggers `EtwpLogFileNameRundown`
    /// in the kernel. This sends a WMI IRP to `fileinfo.sys`, which emits
    /// FileRundown (opcode 36) events for every file object it is currently
    /// tracking.
    ///
    /// **Requires a live system-logger session with `PERF_FILENAME`,
    /// `PERF_FILE_IO`, or `PERF_FILE_IO_INIT`** — *some* session, not
    /// necessarily this one. The kernel's `EtwpUpdateFileInfoDriverState`
    /// reference-counts the union of those three masks across all active
    /// system-logger sessions: on the first session that sets one of the
    /// flags it `ZwLoadDriver`s `fileinfo.sys`, and on the last such session
    /// stopping it `ZwUnloadDriver`s the driver. While the driver is up
    /// `fileinfo.sys` tracks file opens; file objects opened before any
    /// subscribing session existed don't appear in the rundown.
    ///
    /// If no subscribing session is live when this is called, the rundown
    /// fails with `ERROR_DEV_NOT_EXIST` (Win32 55) because
    /// `WmipBuildTraceDeviceList(0x400000)` finds an empty trace device list.
    /// Keep a session with one of the masks above open across the call — a
    /// brief warm-up that starts and stops is not enough.
    ///
    /// **Important:** Call this *after*
    /// [`start_processing_thread()`](Self::start_processing_thread) to avoid event loss from
    /// buffer pressure. The kernel generates rundown events immediately, and `ProcessTrace`
    /// must be running to drain them.
    ///
    /// # Errors
    ///
    /// [`Error::Win32Error`] if `EnableTraceEx2` fails. The code worth recognising is
    /// `ERROR_DEV_NOT_EXIST` (Win32 55), which here means ETW could not open
    /// `fileinfo.sys`'s device: the driver is resident only while at least one live
    /// system-logger session holds `PERF_FILENAME`, `PERF_FILE_IO`, or
    /// `PERF_FILE_IO_INIT`, per the reference-counting described above. Hold such a
    /// session open across this call.
    ///
    /// # Panics
    ///
    /// Panics if the session has not been started (via [`start()`](Self::start))
    /// or if the processing thread has not been started (via
    /// [`start_processing_thread()`](Self::start_processing_thread)). The kernel generates
    /// rundown events immediately, and `ProcessTrace` must already be draining buffers.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use etw::{Trace, system_logger::masks::PERF_FILENAME};
    ///
    /// let mut trace = Trace::new("MyTrace")?;
    /// trace.set_events(&[PERF_FILENAME]);
    /// trace.start()?;
    /// // ... set callback, start processing ...
    /// trace.send_file_rundown_code()?;
    /// # Ok::<(), etw::Error>(())
    /// ```
    pub fn send_file_rundown_code(&mut self) -> Result<()> {
        assert!(
            self.is_started(),
            "send_file_rundown_code() called before start()"
        );
        assert!(
            self.is_processing(),
            "send_file_rundown_code() called before start_processing_thread(); \
             rundown events will be lost to buffer pressure"
        );

        // start_processing_thread() blocks for thread_startup_timeout_ms (default
        // 500ms) before returning, which is enough time for the system DC_START
        // header event to clear the buffer and confirm ProcessTrace is draining.

        let trace_handle = CONTROLTRACE_HANDLE {
            Value: self.session_id,
        };

        // FILENAME is the only truly valid control code for the special Rundown GUID.
        // Triggers filename rundown -- enumerates open file objects.
        const FILENAME: u64 = 0x10;

        // SAFETY: EnableTraceEx2 is a Win32 API. The trace handle is valid (session is started).
        // We're sending ENABLE_PROVIDER to the kernel rundown GUID to trigger rundown emission.
        let status = unsafe {
            EnableTraceEx2(
                trace_handle,
                &KERNEL_RUNDOWN_GUID,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                0,
                FILENAME, // match_any_keyword = rundown code
                0,
                0,
                std::ptr::null(),
            )
        };

        if status != ERROR_SUCCESS {
            return Err(Error::from_win32(status));
        }

        Ok(())
    }

    /// Set object type filter for handle trace events.
    ///
    /// Filters which object types generate handle trace events. Without this filter,
    /// `PERF_OB_HANDLE` events are generated for all object types. With filtering,
    /// only handles to the specified object types generate events.
    ///
    /// Calling this method again replaces any previously set filter.
    ///
    /// Must be called after [`start()`](Self::start).
    ///
    /// # Win32 API
    ///
    /// Calls `NtSetSystemInformation(SystemPerformanceTraceInformation = 0x1F)` with
    /// sub-class `EventTraceObjectTypeFilterInformation = 0x11`.
    /// `SystemPerformanceTraceInformation` is documented at
    /// <https://learn.microsoft.com/en-us/windows/win32/sysinfo/ntsetsysteminformation>,
    /// but the `EventTraceObjectTypeFilterInformation` sub-class is undocumented.
    /// It is stable in practice and used by PerfView and other ETW tooling.
    ///
    /// `tags` contains pool tags identifying object types to trace (max
    /// [`ETW_MAX_OBJECT_TYPE_FILTER`]). Common tags (use [`pool_tag`](crate::pool_tag)):
    /// `b"Proc"` (processes), `b"Thre"` (threads), `b"File"` (files), `b"Key "` (registry keys).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidParameter`] if `tags.len()` exceeds
    /// [`ETW_MAX_OBJECT_TYPE_FILTER`] or `tags` contains duplicate entries, or an
    /// error if the API call fails.
    ///
    /// # Panics
    ///
    /// Panics if the trace session is not started.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use etw::{Trace, pool_tag, system_logger::masks::PERF_OB_HANDLE};
    ///
    /// let mut trace = Trace::new("ObjectTrace")?;
    /// trace.set_events(&[PERF_OB_HANDLE]);
    /// trace.start()?;
    /// trace.enable_object_type_filter(&[pool_tag(b"Proc"), pool_tag(b"Thre")])?;
    /// # Ok::<(), etw::Error>(())
    /// ```
    pub fn enable_object_type_filter(&mut self, tags: &[u32]) -> Result<()> {
        assert!(
            self.is_started(),
            "Trace session must be started before calling enable_object_type_filter"
        );

        if tags.is_empty() {
            return Ok(());
        }

        if tags.len() > ETW_MAX_OBJECT_TYPE_FILTER {
            return Err(Error::InvalidParameter {
                parameter: "object type filter",
                problem: ParameterProblem::TooMany {
                    count: tags.len(),
                    max: ETW_MAX_OBJECT_TYPE_FILTER,
                },
            });
        }
        ensure_unique("object type filter", tags)?;

        // Build the filter structure
        // SAFETY: EventTraceTagFilterInformation is a POD struct that can be zero-initialised.
        let mut info: EventTraceTagFilterInformation = unsafe { std::mem::zeroed() };
        info.event_trace_information_class = EVENT_TRACE_OBJECT_TYPE_FILTER_INFORMATION;
        info.trace_handle = self.session_id;

        info.filter[..tags.len()].copy_from_slice(tags);

        // Calculate size: header (including repr(C) padding) + actual tags used
        let size = std::mem::offset_of!(EventTraceTagFilterInformation, filter) + size_of_val(tags);

        // SAFETY: NtSetSystemInformation is an NT API. The structure is properly initialised.
        let status = unsafe {
            NtSetSystemInformation(
                SYSTEM_PERFORMANCE_TRACE_INFORMATION,
                std::ptr::from_ref(&info).cast(),
                size as u32,
            )
        };

        if status != 0 {
            return Err(Error::from_ntstatus(status));
        }

        // Update state only after the OS call succeeds.
        self.object_type_tags.clear();
        self.object_type_tags.extend_from_slice(tags);

        Ok(())
    }

    /// Enable Last Branch Record (LBR) tracing.
    ///
    /// LBR records the source and destination addresses of recently taken branches,
    /// providing a lightweight call stack alternative. This requires hardware support
    /// (Intel Skylake+ or AMD Zen+) and Windows 10 19H1 / Server 2019+.
    ///
    /// Must be called after [`start()`](Self::start).
    ///
    /// # Win32 API
    ///
    /// Calls `TraceSetInformation` with:
    /// - `TraceLbrConfigurationInfo` to set filter flags
    /// - `TraceLbrEventListInfo` to set event hook IDs
    ///
    /// `config` sets the LBR filter flags (see [`LbrConfig`]). `events` is a slice
    /// of hook IDs that trigger LBR capture (max [`masks::TRACE_LBR_MAXIMUM_EVENTS`]).
    ///
    /// # Panics
    ///
    /// Panics if the trace session is not started.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidParameter`] if `events` is empty, exceeds
    /// [`masks::TRACE_LBR_MAXIMUM_EVENTS`] or contains duplicate entries; all are
    /// checked before any OS call. Returns an error if either
    /// `TraceSetInformation` call fails.
    ///
    /// If the first OS call (`TraceLbrConfigurationInfo`) succeeds but the second
    /// (`TraceLbrEventListInfo`) fails, the previous config is re-applied as a
    /// best-effort rollback. If the rollback also fails, a warning is logged and
    /// the session LBR state may be inconsistent.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use etw::{
    ///     Trace,
    ///     system_logger::{CALLSTACK_ENABLE, EXCLUDE_KERNEL, masks::PERF_PROFILE},
    /// };
    ///
    /// let mut trace = Trace::new("LbrTrace")?;
    /// trace.set_events(&[PERF_PROFILE]);
    /// trace.start()?;
    /// // PerfInfo group = 0x0F, SAMPLED_PROFILE opcode = 46 (0x2E)
    /// trace.enable_lbr(EXCLUDE_KERNEL | CALLSTACK_ENABLE, &[0x0F2E])?;
    /// # Ok::<(), etw::Error>(())
    /// ```
    ///
    /// # Notes
    ///
    /// - VMware does not support LBR; Hyper-V supports it for non-hybrid CPUs
    /// - LBR provides ~32 branch records on Skylake+ CPUs
    /// - Use `CALLSTACK_ENABLE` for LIFO callstack mode
    pub fn enable_lbr(&mut self, config: LbrConfig, events: &[u16]) -> Result<()> {
        assert!(
            self.is_started(),
            "Trace session must be started before calling enable_lbr"
        );

        // The kernel rejects an empty event list (ERROR_INVALID_PARAMETER), but only
        // after the configuration call has already been applied.
        if events.is_empty() {
            return Err(Error::InvalidParameter {
                parameter: "LBR events",
                problem: ParameterProblem::Empty,
            });
        }
        if events.len() > TRACE_LBR_MAXIMUM_EVENTS {
            return Err(Error::InvalidParameter {
                parameter: "LBR events",
                problem: ParameterProblem::TooMany {
                    count: events.len(),
                    max: TRACE_LBR_MAXIMUM_EVENTS,
                },
            });
        }
        ensure_unique("LBR events", events)?;

        // First, set the LBR configuration flags via TraceLbrConfigurationInfo.
        let config_flags = config.flags();
        // SAFETY: TraceSetInformation is a Win32 API. The buffer contains valid u32.
        let status = unsafe {
            TraceSetInformation(
                CONTROLTRACE_HANDLE {
                    Value: self.session_id,
                },
                TraceLbrConfigurationInfo,
                std::ptr::from_ref(&config_flags).cast(),
                size_of::<u32>() as u32,
            )
        };

        if status != ERROR_SUCCESS {
            return Err(Error::from_win32(status));
        }

        // Second, set the LBR event list via TraceLbrEventListInfo.
        let events_u32: Vec<u32> = events.iter().map(|&e| u32::from(e)).collect();

        // SAFETY: TraceSetInformation is a Win32 API. The buffer contains valid u32 array.
        let status = unsafe {
            TraceSetInformation(
                CONTROLTRACE_HANDLE {
                    Value: self.session_id,
                },
                TraceLbrEventListInfo,
                events_u32.as_ptr().cast(),
                (events_u32.len() * size_of::<u32>()) as u32,
            )
        };

        if status != ERROR_SUCCESS {
            // Best-effort: re-apply the previous config to undo the first call.
            // self.lbr_config still holds the old value at this point.
            let prev_flags = self.lbr_config.map_or(0, LbrConfig::flags);
            // SAFETY: TraceSetInformation is a Win32 API. The buffer contains valid u32.
            let rollback_status = unsafe {
                TraceSetInformation(
                    CONTROLTRACE_HANDLE {
                        Value: self.session_id,
                    },
                    TraceLbrConfigurationInfo,
                    std::ptr::from_ref::<u32>(&prev_flags).cast(),
                    size_of::<u32>() as u32,
                )
            };
            if rollback_status != ERROR_SUCCESS {
                log::warn!(
                    "ETW session '{}': LBR config rollback failed (0x{:08X}); session LBR state may be inconsistent",
                    self.session_name,
                    rollback_status
                );
            }
            return Err(Error::from_win32(status));
        }

        // Both calls succeeded -- update internal state.
        self.lbr_config = Some(config);
        self.lbr_events.clear();
        self.lbr_events.extend_from_slice(events);

        Ok(())
    }

    /// Enable Performance Monitor Counter (PMC) collection.
    ///
    /// Configures hardware performance counter collection for specified events.
    /// PMC provides detailed CPU metrics like cycles, cache misses, and branch
    /// mispredictions.
    ///
    /// Must be called after [`start()`](Self::start).
    ///
    /// # Win32 API
    ///
    /// Calls `TraceSetInformation` with:
    /// - `TracePmcCounterListInfo` to set which counters to collect
    /// - `TracePmcEventListInfo` to set event hook IDs
    ///
    /// `counters` selects the hardware counters to collect (see [`ProfileSource`]).
    /// `events` is a slice of hook IDs that trigger PMC capture (max [`ETW_MAX_PMC_EVENTS`]).
    ///
    /// # Panics
    ///
    /// Panics if the trace session is not started.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidParameter`] if `counters` or `events` is empty or
    /// exceeds [`ETW_MAX_PMC_EVENTS`], either contains duplicate entries, or an
    /// event hook ID is not recognised; all are checked before any OS call. Returns
    /// an error if either `TraceSetInformation` call fails.
    ///
    /// The two calls are not atomic: if `TracePmcCounterListInfo` succeeds and
    /// `TracePmcEventListInfo` fails, the counters stay applied. Windows 11 26200
    /// accepts each list once per session and returns `ERROR_WMI_ALREADY_ENABLED`
    /// for later calls, so a retry on the same session may fail.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use etw::{
    ///     Trace,
    ///     system_logger::{masks::PERF_PROFILE, profiling::ProfileSource},
    /// };
    ///
    /// let mut trace = Trace::new("PmcTrace")?;
    /// trace.set_events(&[PERF_PROFILE]);
    /// trace.start()?;
    /// // PerfInfo group = 0x0F, SAMPLED_PROFILE opcode = 46 (0x2E)
    /// trace.enable_pmc(
    ///     &[
    ///         ProfileSource::ProfileTotalCycles,
    ///         ProfileSource::ProfileBranchMispredictions,
    ///     ],
    ///     &[0x0F2E],
    /// )?;
    /// # Ok::<(), etw::Error>(())
    /// ```
    ///
    /// # Notes
    ///
    /// The profile sampling interval is system-wide and should be set via
    /// [`profiling::set_profile_interval()`].
    pub fn enable_pmc(&mut self, counters: &[ProfileSource], events: &[u16]) -> Result<()> {
        assert!(
            self.is_started(),
            "Trace session must be started before calling enable_pmc"
        );

        for (parameter, count) in [
            ("PMC counters", counters.len()),
            ("PMC events", events.len()),
        ] {
            if count == 0 {
                return Err(Error::InvalidParameter {
                    parameter,
                    problem: ParameterProblem::Empty,
                });
            }
            if count > ETW_MAX_PMC_EVENTS {
                return Err(Error::InvalidParameter {
                    parameter,
                    problem: ParameterProblem::TooMany {
                        count,
                        max: ETW_MAX_PMC_EVENTS,
                    },
                });
            }
        }
        ensure_unique("PMC counters", counters)?;
        ensure_unique("PMC events", events)?;

        // Resolve hook IDs before any OS call: the kernel may refuse a second
        // counter list (ERROR_WMI_ALREADY_ENABLED), so failing after the first call
        // could leave the session unable to take a corrected one.
        //
        // The kernel expects an array of `CLASSIC_EVENT_ID` (24 bytes each: GUID +
        // Type + 7 reserved), not a packed u32 array — passing the wrong layout
        // returns ERROR_INCORRECT_SIZE.
        let mut event_records: Vec<CLASSIC_EVENT_ID> = Vec::with_capacity(events.len());
        for &hook_id in events {
            let guid = self::stack_walk::hook_id_to_guid(hook_id).ok_or_else(|| {
                Error::InvalidParameter {
                    parameter: "PMC event hook ID",
                    problem: ParameterProblem::Unrecognised {
                        value: u32::from(hook_id),
                    },
                }
            })?;
            event_records.push(CLASSIC_EVENT_ID {
                EventGuid: guid.to_sys(),
                Type: hook_id as u8,
                Reserved: [0; 7],
            });
        }

        let counters_u32: Vec<u32> = counters.iter().map(|&c| c as u32).collect();

        // SAFETY: TraceSetInformation is a Win32 API. The buffer contains valid u32 array.
        let status = unsafe {
            TraceSetInformation(
                CONTROLTRACE_HANDLE {
                    Value: self.session_id,
                },
                TracePmcCounterListInfo,
                counters_u32.as_ptr().cast(),
                (counters_u32.len() * size_of::<u32>()) as u32,
            )
        };

        if status != ERROR_SUCCESS {
            return Err(Error::from_win32(status));
        }

        // SAFETY: TraceSetInformation is a Win32 API. The buffer is a valid
        // CLASSIC_EVENT_ID array of `event_records.len()` entries.
        let status = unsafe {
            TraceSetInformation(
                CONTROLTRACE_HANDLE {
                    Value: self.session_id,
                },
                TracePmcEventListInfo,
                event_records.as_ptr().cast(),
                (event_records.len() * size_of::<CLASSIC_EVENT_ID>()) as u32,
            )
        };

        if status != ERROR_SUCCESS {
            return Err(Error::from_win32(status));
        }

        // Both calls succeeded -- update internal state.
        self.pmc_counters.clear();
        self.pmc_counters.extend_from_slice(counters);
        self.pmc_events.clear();
        self.pmc_events.extend_from_slice(events);

        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Live update APIs
    // ═══════════════════════════════════════════════════════════════════════

    /// Update the enabled kernel event groups on a running session.
    ///
    /// Calls `TraceSetInformation(TraceSystemTraceEnableFlagsInfo)` to replace the
    /// current group masks with a new set. This allows enabling or disabling kernel
    /// event groups without restarting the session.
    ///
    /// `groups` is a slice of `PERF_*` constants that completely **replace** the
    /// current group masks (not additive).
    ///
    /// # Errors
    ///
    /// Returns error if `TraceSetInformation` fails.
    ///
    /// # Panics
    ///
    /// Panics if the session is not started, or if it was started with
    /// [`set_enable_flags()`](Self::set_enable_flags) rather than
    /// [`set_events()`](Self::set_events). The two modes use different internal
    /// state and cannot be mixed: internal group mask tracking would become inconsistent.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use etw::{Trace, system_logger::masks::*};
    ///
    /// let mut trace = Trace::new("MyTrace")?;
    /// trace.set_events(&[PERF_PROCESS, PERF_THREAD]);
    /// trace.start()?;
    ///
    /// // Later, add context switch events without restarting
    /// trace.update_events(&[PERF_PROCESS, PERF_THREAD, PERF_CONTEXT_SWITCH])?;
    /// # Ok::<(), etw::Error>(())
    /// ```
    pub fn update_events(&mut self, groups: &[u32]) -> Result<()> {
        assert!(
            self.is_started(),
            "Trace session must be started before calling update_events"
        );

        // The OS would accept this call on an EnableFlags-mode session (it
        // translates flags to group masks internally), but self.group_masks
        // would then diverge from the kernel's actual state -- which was
        // initialised from the translated EnableFlags value we never captured.
        assert!(
            self.enable_flags == 0,
            "update_events() cannot be called on a session started with set_enable_flags(); \
             internal group mask tracking would become inconsistent"
        );

        let mut masks = [0u32; PERF_NUM_MASKS];
        for &flag in groups {
            add_group_mask(&mut masks, flag);
        }

        // SAFETY: TraceSetInformation is a Win32 API. The buffer is a valid PERFINFO_GROUPMASK.
        let status = unsafe {
            TraceSetInformation(
                CONTROLTRACE_HANDLE {
                    Value: self.session_id,
                },
                TraceSystemTraceEnableFlagsInfo,
                masks.as_ptr().cast(),
                size_of_val(&masks) as u32,
            )
        };

        if status != ERROR_SUCCESS {
            return Err(Error::from_win32(status));
        }

        self.group_masks = masks;
        Ok(())
    }

    /// Update stack walk events on a running session.
    ///
    /// Calls `TraceSetInformation(TraceStackTracingInfo)` to replace the current
    /// stack walk event list. This allows enabling or disabling stack collection
    /// for specific events without restarting the session.
    ///
    /// Pass an empty slice to disable all stack walking.
    ///
    /// `hook_ids` is a slice of hook IDs encoded as `(group_id << 8) | opcode`.
    ///
    /// # Panics
    ///
    /// Panics if the session is not started.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidParameter`] if `hook_ids.len()` exceeds
    /// [`ETW_MAX_STACKWALK_FILTER`], if `hook_ids` contains duplicate entries, or
    /// if a hook ID has an unknown group, or an error if `TraceSetInformation`
    /// fails.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use etw::{Trace, system_logger::masks::*};
    ///
    /// let mut trace = Trace::new("MyTrace")?;
    /// trace.set_events(&[PERF_PROCESS]);
    /// // Process group = 0x03, START opcode = 1
    /// trace.set_stack_walking(&[0x0301]);
    /// trace.start()?;
    ///
    /// // Later, also capture stacks on process end (opcode 2)
    /// trace.update_stack_walking(&[0x0301, 0x0302])?;
    /// # Ok::<(), etw::Error>(())
    /// ```
    pub fn update_stack_walking(&mut self, hook_ids: &[u16]) -> Result<()> {
        use windows_sys::Win32::System::Diagnostics::Etw::CLASSIC_EVENT_ID;

        assert!(
            self.is_started(),
            "Trace session must be started before calling update_stack_walking"
        );

        if hook_ids.len() > ETW_MAX_STACKWALK_FILTER {
            return Err(Error::InvalidParameter {
                parameter: "stack walk events",
                problem: ParameterProblem::TooMany {
                    count: hook_ids.len(),
                    max: ETW_MAX_STACKWALK_FILTER,
                },
            });
        }
        ensure_unique("stack walk events", hook_ids)?;

        // Convert hook IDs to CLASSIC_EVENT_ID array
        let mut events: Vec<CLASSIC_EVENT_ID> = Vec::with_capacity(hook_ids.len());
        for &hook_id in hook_ids {
            let guid = self::stack_walk::hook_id_to_guid(hook_id).ok_or_else(|| {
                Error::InvalidParameter {
                    parameter: "stack walk hook ID",
                    problem: ParameterProblem::Unrecognised {
                        value: u32::from(hook_id),
                    },
                }
            })?;
            events.push(CLASSIC_EVENT_ID {
                EventGuid: guid.to_sys(),
                Type: hook_id as u8,
                Reserved: [0; 7],
            });
        }

        // SAFETY: TraceSetInformation is a Win32 API. The buffer is a valid CLASSIC_EVENT_ID array.
        let status = unsafe {
            TraceSetInformation(
                CONTROLTRACE_HANDLE {
                    Value: self.session_id,
                },
                TraceStackTracingInfo,
                events.as_ptr().cast(),
                (events.len() * size_of::<CLASSIC_EVENT_ID>()) as u32,
            )
        };

        if status != ERROR_SUCCESS {
            return Err(Error::from_win32(status));
        }

        // Update internal state
        self.stack_events.clear();
        self.stack_events.extend_from_slice(hook_ids);
        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Getters
    // ═══════════════════════════════════════════════════════════════════════

    /// Get a copy of the current group masks.
    #[must_use]
    pub const fn group_masks(&self) -> [u32; PERF_NUM_MASKS] {
        self.group_masks
    }

    /// Get a reference to the configured stack event hook IDs.
    #[must_use]
    pub fn stack_events(&self) -> &[u16] {
        &self.stack_events
    }

    /// Get a reference to the configured pool tags.
    #[must_use]
    pub fn pool_tags(&self) -> &[u32] {
        &self.pool_tags
    }

    /// Get a reference to the configured object type filter tags.
    #[must_use]
    pub fn object_type_tags(&self) -> &[u32] {
        &self.object_type_tags
    }

    /// Get the LBR configuration, if enabled.
    #[must_use]
    pub const fn lbr_config(&self) -> Option<LbrConfig> {
        self.lbr_config
    }

    /// Get a reference to the configured LBR event hook IDs.
    #[must_use]
    pub fn lbr_events(&self) -> &[u16] {
        &self.lbr_events
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Private / pub(crate) helpers
    // ═══════════════════════════════════════════════════════════════════════

    /// Check if any group masks are enabled.
    pub(crate) fn has_group_masks(&self) -> bool {
        self.group_masks.iter().any(|&m| m != 0)
    }

    /// Build extension data and set `EnableFlags` to point to it.
    ///
    /// Extension data layout:
    /// ```text
    /// +-------------------------------------------------------------+
    /// | Header (4 bytes)                                            |
    /// |   [u16: total_length_in_dwords] [u16: item_count]           |
    /// +-------------------------------------------------------------+
    /// | Item 1 Header (4 bytes)                                     |
    /// |   [u16: item_size_dwords] [u16: type]                       |
    /// | Item 1 Data (N * 4 bytes)                                   |
    /// +-------------------------------------------------------------+
    /// | Item 2 Header (4 bytes)                                     |
    /// |   [u16: item_size_dwords] [u16: type]                       |
    /// | Item 2 Data (M * 4 bytes)                                   |
    /// +-------------------------------------------------------------+
    /// ```
    pub(crate) fn build_extensions(&mut self) {
        // EnableFlags mode: set EnableFlags field directly, no extensions
        if self.enable_flags != 0 {
            self.props_buf.properties.EnableFlags = self.enable_flags;
            return;
        }

        // GroupMasks mode: use extension mechanism
        let ext_offset = std::mem::offset_of!(super::trace::TraceProperties, extension_space);

        // Gather data before borrowing extension_space mutably
        let has_flags = self.has_group_masks();
        let group_masks = self.group_masks;
        let stack_data = self.encode_stack_events();
        let pool_tags = self.pool_tags.clone();

        let mut writer = ExtensionWriter::new(&mut self.props_buf.extension_space);

        // Add enable flags extension (PERFINFO_GROUPMASK - 8 u32s)
        if has_flags {
            writer.add_item(ETW_EXT_ENABLE_FLAGS, &group_masks);
        }

        // Add stack walk filter extension
        if !stack_data.is_empty() {
            writer.add_item(ETW_EXT_STACKWALK_FILTER, &stack_data);
        }

        // Add pool tag filter extension
        if !pool_tags.is_empty() {
            writer.add_item(ETW_EXT_POOLTAG_FILTER, &pool_tags);
        }

        writer.finalize();

        // Set EnableFlags to extension marker + offset
        // Offset is in bytes from the start of EVENT_TRACE_PROPERTIES
        debug_assert!(
            ext_offset <= 0xFFFF,
            "extension offset {ext_offset} must fit in 16 bits"
        );
        self.props_buf.properties.EnableFlags = ENABLE_FLAGS_EXTENSION_MARKER | (ext_offset as u32);
    }

    /// Convert stack event hook IDs to u32 values for the extension.
    ///
    /// Hook IDs are already encoded as `(group_id << 8) | event_type`,
    /// so we just need to widen them to u32.
    fn encode_stack_events(&self) -> Vec<u32> {
        self.stack_events.iter().map(|&id| u32::from(id)).collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Debug Display Helpers
// ═══════════════════════════════════════════════════════════════════════════════

pub(crate) struct PoolTagsDisplay<'a>(pub(crate) &'a [u32]);

impl std::fmt::Debug for PoolTagsDisplay<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.is_empty() {
            return write!(f, "[]");
        }

        write!(f, "[")?;
        for (i, &tag) in self.0.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            // Convert to ASCII, replacing non-printable chars with '.'
            let bytes = tag.to_le_bytes();
            let ascii: String = bytes
                .iter()
                .map(|&b| {
                    if b.is_ascii_graphic() || b == b' ' {
                        b as char
                    } else {
                        '.'
                    }
                })
                .collect();
            write!(f, "\"{ascii}\"")?;
        }
        write!(f, "]")
    }
}

pub(crate) struct LbrConfigDisplay(pub(crate) Option<LbrConfig>);

impl std::fmt::Debug for LbrConfigDisplay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Some(config) = self.0 else {
            return write!(f, "None");
        };

        if config.0 == 0 {
            return write!(f, "NONE (capture all)");
        }

        let mut flags: Vec<&str> = Vec::new();
        let mut remaining = config.0;

        // Check each flag
        if remaining & EXCLUDE_KERNEL.0 != 0 {
            flags.push("EXCLUDE_KERNEL");
            remaining &= !EXCLUDE_KERNEL.0;
        }
        if remaining & EXCLUDE_USER.0 != 0 {
            flags.push("EXCLUDE_USER");
            remaining &= !EXCLUDE_USER.0;
        }
        if remaining & EXCLUDE_JCC.0 != 0 {
            flags.push("EXCLUDE_JCC");
            remaining &= !EXCLUDE_JCC.0;
        }
        if remaining & EXCLUDE_NEAR_REL_CALL.0 != 0 {
            flags.push("EXCLUDE_NEAR_REL_CALL");
            remaining &= !EXCLUDE_NEAR_REL_CALL.0;
        }
        if remaining & EXCLUDE_NEAR_IND_CALL.0 != 0 {
            flags.push("EXCLUDE_NEAR_IND_CALL");
            remaining &= !EXCLUDE_NEAR_IND_CALL.0;
        }
        if remaining & EXCLUDE_NEAR_RET.0 != 0 {
            flags.push("EXCLUDE_NEAR_RET");
            remaining &= !EXCLUDE_NEAR_RET.0;
        }
        if remaining & EXCLUDE_NEAR_IND_JMP.0 != 0 {
            flags.push("EXCLUDE_NEAR_IND_JMP");
            remaining &= !EXCLUDE_NEAR_IND_JMP.0;
        }
        if remaining & EXCLUDE_NEAR_REL_JMP.0 != 0 {
            flags.push("EXCLUDE_NEAR_REL_JMP");
            remaining &= !EXCLUDE_NEAR_REL_JMP.0;
        }
        if remaining & EXCLUDE_FAR_BRANCH.0 != 0 {
            flags.push("EXCLUDE_FAR_BRANCH");
            remaining &= !EXCLUDE_FAR_BRANCH.0;
        }
        if remaining & CALLSTACK_ENABLE.0 != 0 {
            flags.push("CALLSTACK_ENABLE");
            remaining &= !CALLSTACK_ENABLE.0;
        }
        if remaining & SAMPLED.0 != 0 {
            flags.push("SAMPLED");
            remaining &= !SAMPLED.0;
        }

        // Handle unknown flags
        if remaining != 0 {
            write!(f, "{} | 0x{:X}", flags.join(" | "), remaining)
        } else if flags.is_empty() {
            write!(f, "0x{:X}", config.0)
        } else {
            write!(f, "{}", flags.join(" | "))
        }
    }
}

pub(crate) struct GroupMasksDisplay<'a>(pub(crate) &'a [u32; PERF_NUM_MASKS]);

impl std::fmt::Debug for GroupMasksDisplay<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Only show non-zero masks
        let non_zero: Vec<(usize, u32)> = self
            .0
            .iter()
            .enumerate()
            .filter(|&(_, &v)| v != 0)
            .map(|(i, &v)| (i, v))
            .collect();

        if non_zero.is_empty() {
            return write!(f, "[]");
        }

        write!(f, "[")?;
        for (i, (idx, val)) in non_zero.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "[{idx}]={val:#010X}")?;
        }
        write!(f, "]")
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
#[expect(
    clippy::print_stdout,
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test-only assertions and diagnostics"
)]
mod tests {
    use self::masks::*;
    use super::*;

    /// Makes `is_started()` true without a session. ETW resolves a logger from the
    /// handle's low 16 bits and rejects 0xFFFE (`ERROR_INVALID_HANDLE` from
    /// `ControlTraceW`, not-found from `TraceSetInformation`), whereas a small ID
    /// such as 1 can name a real logger if a check regresses into an OS call.
    const FAKE_SESSION_ID: u64 = 0xFFFE;

    // Session properties reach the kernel only in start(), so a setter called
    // after it would silently change nothing; it must fail at the call instead.
    #[test]
    #[should_panic(expected = "Cannot modify maximum buffers after start()")]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_property_setter_after_start_panics() {
        let mut session = Trace::new("TestSetAfterStart").expect("session creation should succeed");
        session.session_id = FAKE_SESSION_ID;
        let _ = session.set_maximum_buffers(64);
    }

    #[test]
    #[should_panic(expected = "Cannot modify events after start()")]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_set_events_after_start_panics() {
        let mut session =
            Trace::new("TestEventsAfterStart").expect("session creation should succeed");
        session.session_id = FAKE_SESSION_ID;
        session.set_events(&[PERF_PROCESS]);
    }

    #[test]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_set_events() {
        let mut session = Trace::new("TestSetEvents").expect("session creation should succeed");

        let _ = session.set_events(&[PERF_PROCESS, PERF_THREAD, PERF_CONTEXT_SWITCH]);

        let masks = session.group_masks();
        // PERF_PROCESS (0x01) | PERF_THREAD (0x02) = 0x03 in masks[0]
        assert_eq!(masks[0], 0x0000_0003);
        // PERF_CONTEXT_SWITCH (0x2000_0004) -> masks[1] = 0x04
        assert_eq!(masks[1], 0x0000_0004);
    }

    #[test]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_set_stack_walking() {
        let mut session =
            Trace::new("TestSetStackWalking").expect("session creation should succeed");

        // Hook IDs: (group_id << 8) | opcode
        // Process START: group 0x03, opcode 1 -> 0x0301
        // Thread CSWITCH: group 0x05, opcode 36 -> 0x0524
        session.set_stack_walking(&[0x0301, 0x0524]).unwrap();

        let events = session.stack_events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0], 0x0301);
        assert_eq!(events[1], 0x0524);
    }

    #[test]
    fn test_extension_writer() {
        let mut buffer = [0u8; 64];
        let mut writer = ExtensionWriter::new(&mut buffer);

        let data: [u32; 2] = [0x1234_5678, 0xDEAD_BEEF];
        writer.add_item(1, &data);
        writer.finalize();

        // Header: total_dwords (4 bytes header + 4 bytes item header + 8 bytes data = 16 bytes = 4
        // dwords) Item count: 1
        assert_eq!(u16::from_le_bytes([buffer[0], buffer[1]]), 4);
        assert_eq!(u16::from_le_bytes([buffer[2], buffer[3]]), 1);

        // Item header: size_dwords (3: header + 2 data dwords), type (1)
        assert_eq!(u16::from_le_bytes([buffer[4], buffer[5]]), 3);
        assert_eq!(u16::from_le_bytes([buffer[6], buffer[7]]), 1);

        // Data
        assert_eq!(
            u32::from_le_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]),
            0x1234_5678
        );
        assert_eq!(
            u32::from_le_bytes([buffer[12], buffer[13], buffer[14], buffer[15]]),
            0xDEAD_BEEF
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_encode_stack_events() {
        let mut session =
            Trace::new("TestEncodeStackEvents").expect("session creation should succeed");

        // Process START: group 0x03, opcode 1 -> 0x0301
        session.set_stack_walking(&[0x0301]).unwrap();

        let encoded = session.encode_stack_events();
        assert_eq!(encoded.len(), 1);
        assert_eq!(encoded[0], 0x0301);
    }

    #[test]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_has_group_masks() {
        let mut session = Trace::new("TestHasGroupMasks").expect("session creation should succeed");
        assert!(!session.has_group_masks());

        let _ = session.set_events(&[PERF_PROCESS]);
        assert!(session.has_group_masks());
    }

    #[test]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_set_pool_tag_filter() {
        let mut session =
            Trace::new("TestSetPoolTagFilter").expect("session creation should succeed");
        assert!(session.pool_tags().is_empty());

        let proc_tag = crate::pool_tag(b"Proc");
        let file_tag = crate::pool_tag(b"File");
        session.set_pool_tag_filter(&[proc_tag, file_tag]).unwrap();

        assert_eq!(session.pool_tags().len(), 2);
        assert_eq!(session.pool_tags()[0], proc_tag);
        assert_eq!(session.pool_tags()[1], file_tag);

        // Verify little-endian encoding: "Proc" = 0x636F7250
        assert_eq!(proc_tag, 0x636F_7250);
    }

    #[test]
    fn test_lbr_config_flags() {
        // Test flag combinations
        let config1 = EXCLUDE_KERNEL | EXCLUDE_USER;
        assert_eq!(config1.flags(), 0x3);
        assert!(config1.contains(EXCLUDE_KERNEL));
        assert!(config1.contains(EXCLUDE_USER));
        assert!(!config1.contains(EXCLUDE_JCC));

        // Test CALLSTACK_ENABLE
        let config2 = CALLSTACK_ENABLE;
        assert_eq!(config2.flags(), 0x200);
        assert!(config2.contains(CALLSTACK_ENABLE));
    }

    #[test]
    fn test_lbr_config_new_round_trips_raw_flags() {
        let raw = EXCLUDE_KERNEL.flags() | CALLSTACK_ENABLE.flags();
        let config = LbrConfig::new(raw);
        assert_eq!(config.flags(), raw);
        assert!(config.contains(EXCLUDE_KERNEL));
        assert!(config.contains(CALLSTACK_ENABLE));
    }

    #[test]
    fn test_lbr_config_bitor_assign() {
        let mut config = EXCLUDE_KERNEL;
        config |= EXCLUDE_USER;
        assert_eq!(config.flags(), 0x3);
        config |= CALLSTACK_ENABLE;
        assert_eq!(config.flags(), 0x203);
    }

    #[test]
    fn test_lbr_config_bitand() {
        let mask = EXCLUDE_KERNEL | EXCLUDE_USER | CALLSTACK_ENABLE;
        let kernel_only = mask & EXCLUDE_KERNEL;
        assert_eq!(kernel_only.flags(), EXCLUDE_KERNEL.flags());

        // AND with disjoint flag yields zero.
        let none = EXCLUDE_KERNEL & EXCLUDE_USER;
        assert_eq!(none.flags(), 0);
    }

    #[test]
    fn test_structure_sizes_and_offsets() {
        use super::super::trace::TraceProperties;
        use crate::session::common::MAXIMUM_SESSION_NAME;
        use windows_sys::Win32::System::Diagnostics::Etw::EVENT_TRACE_PROPERTIES_V2;

        let props_size = size_of::<EVENT_TRACE_PROPERTIES_V2>();
        let name_size = size_of::<[u16; MAXIMUM_SESSION_NAME]>();
        let ext_offset = std::mem::offset_of!(TraceProperties, extension_space);

        println!("EVENT_TRACE_PROPERTIES_V2 size: {props_size}");
        println!("session_name size: {name_size}");
        println!("extension_space offset: {ext_offset}");
        println!(
            "Expected offset: {} + {} = {}",
            props_size,
            name_size,
            props_size + name_size
        );

        // The extension offset should be right after properties + session_name
        assert_eq!(ext_offset, props_size + name_size);
    }

    #[test]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_build_extensions_format() {
        let mut session =
            Trace::new("TestBuildExtensions").expect("session creation should succeed");
        session.set_events(&[PERF_PROCESS]);

        // Build extensions
        session.build_extensions();

        // Check EnableFlags
        let enable_flags = session.props_buf.properties.EnableFlags;
        println!("EnableFlags: 0x{enable_flags:08X}");
        assert_eq!(enable_flags & 0xFFFF_0000, 0x80FF_0000, "Extension marker");
        assert_eq!(
            enable_flags & 0xFFFF,
            session.extension_offset() as u32,
            "Extension offset"
        );

        // Dump extension data
        let ext = &session.props_buf.extension_space;
        println!("Extension data (first 48 bytes):");
        for (i, byte) in ext.iter().enumerate().take(48) {
            if i % 4 == 0 {
                print!("  [{i:03}]: ");
            }
            print!("{byte:02X} ");
            if i % 4 == 3 {
                println!();
            }
        }

        // Parse and verify main header
        let total_dwords = u16::from_le_bytes([ext[0], ext[1]]);
        let item_count = u16::from_le_bytes([ext[2], ext[3]]);
        println!("\nMain header: total_dwords={total_dwords}, item_count={item_count}");

        // Parse first item header
        let item1_dwords = u16::from_le_bytes([ext[4], ext[5]]);
        let item1_type = u16::from_le_bytes([ext[6], ext[7]]);
        println!("Item 1 header: dwords={item1_dwords}, type={item1_type}");

        // Verify structure
        assert_eq!(item_count, 1, "Should have 1 extension item");
        assert_eq!(
            item1_type, 1,
            "Item type should be ETW_EXT_ENABLE_FLAGS (1)"
        );
        // Group masks are 8 u32s = 8 dwords, plus 1 for header = 9 dwords
        assert_eq!(
            item1_dwords, 9,
            "Item size should be 9 dwords (1 header + 8 data)"
        );
        // Total: 1 header dword + 9 item dwords = 10 dwords
        assert_eq!(total_dwords, 10, "Total should be 10 dwords");

        // Verify first group mask (PERF_PROCESS = 0x00000001 in masks[0])
        let mask0 = u32::from_le_bytes([ext[8], ext[9], ext[10], ext[11]]);
        println!("Group mask 0: 0x{mask0:08X}");
        assert_eq!(mask0, 0x0000_0001, "PERF_PROCESS should be set");
    }

    #[test]
    #[should_panic(expected = "Cannot use both set_enable_flags() and set_events()")]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_enable_flags_and_group_masks_mutual_exclusion() {
        let mut session = Trace::new("TestExclusion").expect("session creation should succeed");
        session.set_enable_flags(0x0000_0001);
        let _ = session.set_events(&[PERF_THREAD]);
        let _ = session.start();
    }

    #[test]
    #[should_panic(expected = "Stack walks and pool tag filters require GroupMasks mode")]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_stack_walks_require_group_masks_mode() {
        let mut session = Trace::new("TestStackReq").expect("session creation should succeed");
        session.set_enable_flags(0x0000_0001);
        session.set_stack_walking(&[0x0301]).unwrap();
        let _ = session.start();
    }

    #[test]
    #[should_panic(
        expected = "update_events() cannot be called on a session started with set_enable_flags()"
    )]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_update_events_rejects_enable_flags_mode() {
        let mut session =
            Trace::new("TestUpdateEventsReject").expect("session creation should succeed");
        session.set_enable_flags(0x0000_0001);
        session.session_id = FAKE_SESSION_ID;
        let _ = session.update_events(&[PERF_PROCESS]);
    }

    #[test]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_set_stack_walking_too_many_returns_error() {
        let mut session = Trace::new("TestSWTooMany").expect("session creation should succeed");
        let ids: Vec<u16> = (0u16..257).collect();
        let err = session.set_stack_walking(&ids).unwrap_err();
        assert!(
            matches!(
                err,
                crate::Error::InvalidParameter {
                    parameter: "stack walk events",
                    problem: ParameterProblem::TooMany {
                        count: 257,
                        max: 256
                    },
                }
            ),
            "got {err:?}"
        );
        assert!(
            session.stack_events().is_empty(),
            "a rejected call must not add any hook IDs"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_set_stack_walking_duplicate_returns_error() {
        let mut session = Trace::new("TestSWDuplicate").expect("session creation should succeed");
        let err = session
            .set_stack_walking(&[0x0301, 0x0302, 0x0301])
            .unwrap_err();
        assert!(
            matches!(
                err,
                crate::Error::InvalidParameter {
                    parameter: "stack walk events",
                    problem: ParameterProblem::Duplicates,
                }
            ),
            "got {err:?}"
        );
        assert!(
            session.stack_events().is_empty(),
            "a rejected call must not add any hook IDs"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_set_pool_tag_filter_too_many_returns_error() {
        let mut session = Trace::new("TestPTTooMany").expect("session creation should succeed");
        let tags = [0x0001u32, 0x0002, 0x0003, 0x0004, 0x0005];
        let err = session.set_pool_tag_filter(&tags).unwrap_err();
        assert!(
            matches!(
                err,
                crate::Error::InvalidParameter {
                    parameter: "pool tag filter",
                    problem: ParameterProblem::TooMany { count: 5, max: 4 },
                }
            ),
            "got {err:?}"
        );
        assert!(
            session.pool_tags().is_empty(),
            "a rejected call must not add any tags"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_set_pool_tag_filter_duplicate_across_calls_returns_error() {
        let mut session = Trace::new("TestPTDuplicate").expect("session creation should succeed");
        session
            .set_pool_tag_filter(&[0x0001, 0x0002])
            .expect("distinct tags are accepted");
        let err = session.set_pool_tag_filter(&[0x0001]).unwrap_err();
        assert!(
            matches!(
                err,
                crate::Error::InvalidParameter {
                    parameter: "pool tag filter",
                    problem: ParameterProblem::Duplicates,
                }
            ),
            "got {err:?}"
        );
        assert_eq!(
            session.pool_tags(),
            &[0x0001, 0x0002],
            "a rejected call must leave the earlier tags untouched"
        );
    }

    // The post-start setters reject duplicates before any OS call, so a faked
    // session ID reaches the check without Administrator or LBR/PMC hardware.

    #[test]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_enable_object_type_filter_duplicate_returns_error() {
        let mut session = Trace::new("TestOTDuplicate").expect("session creation should succeed");
        session.session_id = FAKE_SESSION_ID;
        let err = session
            .enable_object_type_filter(&[0x0001, 0x0002, 0x0001])
            .unwrap_err();
        assert!(
            matches!(
                err,
                crate::Error::InvalidParameter {
                    parameter: "object type filter",
                    problem: ParameterProblem::Duplicates,
                }
            ),
            "got {err:?}"
        );
        assert!(session.object_type_tags().is_empty());
    }

    #[test]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_enable_lbr_duplicate_returns_error() {
        let mut session = Trace::new("TestLbrDuplicate").expect("session creation should succeed");
        session.session_id = FAKE_SESSION_ID;
        let err = session
            .enable_lbr(EXCLUDE_KERNEL, &[0x0F2E, 0x0F2E])
            .unwrap_err();
        assert!(
            matches!(
                err,
                crate::Error::InvalidParameter {
                    parameter: "LBR events",
                    problem: ParameterProblem::Duplicates,
                }
            ),
            "got {err:?}"
        );
        assert!(session.lbr_config().is_none());
        assert!(session.lbr_events().is_empty());
    }

    #[test]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_enable_pmc_duplicate_counters_and_events_return_error() {
        let mut session = Trace::new("TestPmcDuplicate").expect("session creation should succeed");
        session.session_id = FAKE_SESSION_ID;
        let counters = session.enable_pmc(
            &[
                ProfileSource::ProfileTotalIssues,
                ProfileSource::ProfileTotalIssues,
            ],
            &[0x0F2E],
        );
        let events = session.enable_pmc(&[ProfileSource::ProfileTotalIssues], &[0x0F2E, 0x0F2E]);
        for (result, parameter) in [(counters, "PMC counters"), (events, "PMC events")] {
            let err = result.unwrap_err();
            assert!(
                matches!(
                    err,
                    crate::Error::InvalidParameter {
                        parameter: p,
                        problem: ParameterProblem::Duplicates,
                    } if p == parameter
                ),
                "expected {parameter} duplicates, got {err:?}"
            );
        }
        assert!(session.pmc_counters.is_empty());
        assert!(session.pmc_events.is_empty());
    }

    // The kernel rejects an empty list only after the first call has applied the
    // configuration, and PMC lists cannot be set twice, so it must be caught first.
    #[test]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_empty_lbr_and_pmc_lists_return_error() {
        let mut session = Trace::new("TestEmptyLists").expect("session creation should succeed");
        session.session_id = FAKE_SESSION_ID;
        let results = [
            (session.enable_lbr(EXCLUDE_KERNEL, &[]), "LBR events"),
            (session.enable_pmc(&[], &[0x0F2E]), "PMC counters"),
            (
                session.enable_pmc(&[ProfileSource::ProfileTotalIssues], &[]),
                "PMC events",
            ),
        ];
        for (result, parameter) in results {
            let err = result.unwrap_err();
            assert!(
                matches!(
                    err,
                    crate::Error::InvalidParameter {
                        parameter: p,
                        problem: ParameterProblem::Empty,
                    } if p == parameter
                ),
                "expected {parameter} empty, got {err:?}"
            );
        }
        assert!(session.lbr_config().is_none());
        assert!(session.pmc_counters.is_empty());
        assert!(session.pmc_events.is_empty());
    }

    #[test]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_update_stack_walking_duplicate_returns_error() {
        let mut session = Trace::new("TestUSWDuplicate").expect("session creation should succeed");
        session.session_id = FAKE_SESSION_ID;
        let err = session
            .update_stack_walking(&[0x0301, 0x0302, 0x0301])
            .unwrap_err();
        assert!(
            matches!(
                err,
                crate::Error::InvalidParameter {
                    parameter: "stack walk events",
                    problem: ParameterProblem::Duplicates,
                }
            ),
            "got {err:?}"
        );
        assert!(session.stack_events().is_empty());
    }

    #[test]
    #[cfg_attr(miri, ignore = "ETW session creation reaches TDH (Win32)")]
    fn test_getters_return_initial_defaults() {
        let session = Trace::new("TestGetters").expect("session creation should succeed");
        assert!(session.object_type_tags().is_empty());
        assert!(session.lbr_config().is_none());
        assert!(session.lbr_events().is_empty());
    }

    #[test]
    fn test_pool_tags_display_non_empty() {
        // Printable bytes display as ASCII; non-printable display as '.'
        let tag = u32::from_le_bytes(*b"Proc");
        let non_printable = u32::from_le_bytes([0x00, 0x01, b'A', b'B']);
        let display = format!("{:?}", PoolTagsDisplay(&[tag, non_printable]));
        assert!(display.contains("\"Proc\""), "display was: {display}");
        assert!(display.contains("\"..AB\""), "display was: {display}");
    }

    #[test]
    fn test_pool_tags_display_empty() {
        let display = format!("{:?}", PoolTagsDisplay(&[]));
        assert_eq!(display, "[]");
    }

    #[test]
    fn test_lbr_config_display_all_flags() {
        let config = EXCLUDE_KERNEL
            | EXCLUDE_USER
            | EXCLUDE_JCC
            | EXCLUDE_NEAR_REL_CALL
            | EXCLUDE_NEAR_IND_CALL
            | EXCLUDE_NEAR_RET
            | EXCLUDE_NEAR_IND_JMP
            | EXCLUDE_NEAR_REL_JMP
            | EXCLUDE_FAR_BRANCH
            | CALLSTACK_ENABLE
            | SAMPLED;
        let display = format!("{:?}", LbrConfigDisplay(Some(config)));
        assert!(display.contains("EXCLUDE_KERNEL"), "display: {display}");
        assert!(display.contains("SAMPLED"), "display: {display}");
    }

    #[test]
    fn test_lbr_config_display_none() {
        assert_eq!(format!("{:?}", LbrConfigDisplay(None)), "None");
    }

    #[test]
    fn test_lbr_config_display_zero_is_capture_all() {
        let config = LbrConfig::new(0);
        let display = format!("{:?}", LbrConfigDisplay(Some(config)));
        assert_eq!(display, "NONE (capture all)");
    }

    #[test]
    fn test_lbr_config_display_unknown_bits() {
        // A raw value with no known flags set
        let config = LbrConfig::new(0x8000_0000);
        let display = format!("{:?}", LbrConfigDisplay(Some(config)));
        assert!(display.contains("0x80000000"), "display: {display}");
    }

    #[test]
    fn test_group_masks_display_non_empty() {
        let mut masks = [0u32; PERF_NUM_MASKS];
        masks[0] = 0x0000_0001; // PERF_PROCESS
        masks[3] = 0x0000_0010;
        let display = format!("{:?}", GroupMasksDisplay(&masks));
        assert!(display.contains("[0]=0x00000001"), "display: {display}");
        assert!(display.contains("[3]=0x00000010"), "display: {display}");
    }

    #[test]
    fn test_group_masks_display_all_zero() {
        let masks = [0u32; PERF_NUM_MASKS];
        assert_eq!(format!("{:?}", GroupMasksDisplay(&masks)), "[]");
    }
}
