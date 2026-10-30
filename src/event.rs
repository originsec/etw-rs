//! ETW event consumption
//!
//! This module provides wrappers around ETW event records.

use std::fmt;
use windows_sys::Win32::System::Diagnostics::Etw::{EVENT_HEADER_EXTENDED_DATA_ITEM, EVENT_RECORD};

/// A stack trace from an ETW event.
///
/// Wraps the raw `EVENT_EXTENDED_ITEM_STACK_TRACE64` data, providing access
/// to the match ID and return addresses.
#[derive(Clone, Copy)]
pub struct StackTrace<'a>(&'a [u8]);

impl<'a> StackTrace<'a> {
    /// Minimum size: 8-byte MatchId (frames are optional).
    const MIN_SIZE: usize = 8;
    /// Address size: 8-byte pointer.
    const ADDRESS_SIZE: usize = 8;
    /// Required alignment for zero-copy `u64` address access.
    const ADDRESS_ALIGNMENT: usize = std::mem::align_of::<u64>();

    /// Create from raw extended data bytes.
    #[must_use]
    pub fn from_bytes(data: &'a [u8]) -> Option<Self> {
        Self::try_from_bytes(data).ok()
    }

    /// Create from raw extended data bytes with validation errors.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - data is smaller than the 8-byte match ID
    /// - address payload is not a multiple of 8 bytes
    /// - data is not 8-byte aligned for zero-copy address access
    pub fn try_from_bytes(data: &'a [u8]) -> crate::Result<Self> {
        if data.len() < Self::MIN_SIZE {
            return Err(crate::Error::parse(format!(
                "Stack trace data too small: {} bytes, need at least {}",
                data.len(),
                Self::MIN_SIZE
            )));
        }

        let addresses_len = data.len() - Self::MIN_SIZE;
        let remainder = addresses_len % Self::ADDRESS_SIZE;
        if remainder != 0 {
            return Err(crate::Error::parse(format!(
                "Stack trace has {} trailing bytes (entry size {} bytes)",
                remainder,
                Self::ADDRESS_SIZE
            )));
        }

        let align_mask = Self::ADDRESS_ALIGNMENT - 1;
        if (data.as_ptr() as usize) & align_mask != 0 {
            return Err(crate::Error::parse(format!(
                "Stack trace data is not {}-byte aligned",
                Self::ADDRESS_ALIGNMENT
            )));
        }

        Ok(Self(data))
    }

    /// Returns the match ID used to correlate stack with its event.
    #[must_use]
    pub fn match_id(&self) -> u64 {
        #[expect(
            clippy::expect_used,
            reason = "infallible: StackTrace guarantees ≥8 bytes"
        )]
        u64::from_le_bytes(
            self.0[..8]
                .try_into()
                .expect("StackTrace guarantees at least 8 bytes"),
        )
    }

    /// Returns the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.0
    }

    /// Returns the number of addresses in the stack trace.
    #[must_use]
    pub const fn len(&self) -> usize {
        (self.0.len() - Self::MIN_SIZE) / Self::ADDRESS_SIZE
    }

    /// Returns true if the stack trace is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the address at the given index.
    #[must_use]
    pub fn address(&self, index: usize) -> Option<u64> {
        self.addresses_slice().get(index).copied()
    }

    /// Returns all addresses as a zero-copy slice.
    #[must_use]
    pub fn addresses_slice(&self) -> &[u64] {
        let entries_data = &self.0[Self::MIN_SIZE..];
        let count = entries_data.len() / Self::ADDRESS_SIZE;
        if count == 0 {
            return &[];
        }
        // SAFETY: `try_from_bytes` validated data alignment and exact entry sizing.
        unsafe { std::slice::from_raw_parts(entries_data.as_ptr().cast(), count) }
    }

    /// Returns an iterator over all addresses (zero-allocation).
    #[must_use]
    pub fn addresses_iter(&self) -> impl ExactSizeIterator<Item = u64> + '_ {
        self.addresses_slice().iter().copied()
    }

    /// Returns all addresses as a vector.
    #[must_use]
    pub fn addresses(&self) -> Vec<u64> {
        self.addresses_slice().to_vec()
    }
}

impl fmt::Debug for StackTrace<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StackTrace")
            .field("match_id", &format_args!("0x{:016X}", self.match_id()))
            .field("addresses", &self.addresses_slice())
            .finish()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Timestamp
// ═══════════════════════════════════════════════════════════════════════════════

/// ETW event timestamp.
///
/// By default, ETW converts timestamps to FILETIME format (100-nanosecond
/// intervals since January 1, 1601). When [`ProcessTraceMode::RAW_TIMESTAMP`]
/// is set, timestamps retain their original format based on [`ClockResolution`].
///
/// # Converting to SystemTime
///
/// For timestamps in FILETIME format (the default):
/// ```no_run
/// # use etw::RawEvent;
/// # fn example(event: &RawEvent) {
/// let ts = event.timestamp();
/// if let Some(system_time) = ts.to_system_time() {
///     println!("Event at: {:?}", system_time);
/// }
/// # }
/// ```
///
/// [`ProcessTraceMode::RAW_TIMESTAMP`]: crate::ProcessTraceMode::RAW_TIMESTAMP
/// [`ClockResolution`]: crate::ClockResolution
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(pub i64);

impl Timestamp {
    /// 100-nanosecond ticks per second.
    const TICKS_PER_SEC: i64 = 10_000_000;
    /// 100-nanosecond ticks per millisecond.
    const TICKS_PER_MS: i64 = 10_000;
    /// Seconds between Windows epoch (1601-01-01) and Unix epoch (1970-01-01).
    const EPOCH_DIFF_SECS: i64 = 11_644_473_600;
    /// Milliseconds between Windows epoch and Unix epoch.
    const EPOCH_DIFF_MS: i64 = 11_644_473_600_000;
    /// Nanoseconds between Windows epoch and Unix epoch.
    const EPOCH_DIFF_NANOS: i128 = 11_644_473_600_000_000_000;

    /// Creates a Timestamp from a raw i64 value.
    #[must_use]
    pub const fn new(raw: i64) -> Self {
        Self(raw)
    }

    /// Returns the raw timestamp value.
    #[must_use]
    pub const fn raw(&self) -> i64 {
        self.0
    }

    /// Returns the timestamp as 100-nanosecond ticks (FILETIME format).
    ///
    /// Only meaningful when NOT using `RAW_TIMESTAMP` mode. In RAW mode,
    /// the underlying `i64` may be negative (QPC-based), which wraps to
    /// a very large `u64` — use [`raw()`](Self::raw) instead.
    #[must_use]
    pub const fn as_ticks(&self) -> u64 {
        self.0 as u64
    }

    /// Converts to Unix timestamp in seconds.
    ///
    /// Only valid when timestamp is in FILETIME format (the default).
    #[must_use]
    pub const fn as_unix_secs(&self) -> i64 {
        self.0 / Self::TICKS_PER_SEC - Self::EPOCH_DIFF_SECS
    }

    /// Converts to Unix timestamp in milliseconds.
    ///
    /// Only valid when timestamp is in FILETIME format (the default).
    #[must_use]
    pub const fn as_unix_ms(&self) -> i64 {
        self.0 / Self::TICKS_PER_MS - Self::EPOCH_DIFF_MS
    }

    /// Converts to Unix timestamp in nanoseconds.
    ///
    /// Only valid when timestamp is in FILETIME format (the default).
    #[must_use]
    pub const fn as_unix_nanos(&self) -> i128 {
        (self.0 as i128) * 100 - Self::EPOCH_DIFF_NANOS
    }

    /// Converts to `std::time::SystemTime`.
    ///
    /// Only valid when timestamp is in FILETIME format (the default).
    /// Returns `None` if the timestamp cannot be represented as a `SystemTime`.
    #[must_use]
    pub fn to_system_time(&self) -> Option<std::time::SystemTime> {
        let unix_nanos = self.as_unix_nanos();
        if unix_nanos >= 0 {
            let nanos = u64::try_from(unix_nanos).ok()?;
            std::time::UNIX_EPOCH.checked_add(std::time::Duration::from_nanos(nanos))
        } else {
            let abs_nanos = u64::try_from(-unix_nanos).ok()?;
            std::time::UNIX_EPOCH.checked_sub(std::time::Duration::from_nanos(abs_nanos))
        }
    }
}

/// Splits days since the FILETIME epoch (1601-01-01) into a proleptic-Gregorian
/// `(year, month, day)`.
///
/// Howard Hinnant's `civil_from_days`, rebased from its 1970-01-01 epoch onto the
/// FILETIME one. FILETIME has neither leap seconds nor a Julian cut-over, so this
/// must agree with `FileTimeToSystemTime` on every input — asserted in
/// `tests/differential_filetime.rs`.
const fn civil_from_days(days: i64) -> (i64, i64, i64) {
    /// Days from 1601-01-01 to 1970-01-01.
    const DAYS_1601_TO_1970: i64 = 134_774;
    /// Days from 0000-03-01 — the era boundary the algorithm counts from, chosen so
    /// that a leap day falls last in the year — to 1970-01-01.
    const DAYS_0000_03_01_TO_1970: i64 = 719_468;
    /// Days in a 400-year Gregorian era.
    const DAYS_PER_ERA: i64 = 146_097;

    // Keeps `z` positive, so the algorithm's negative-era correction is unreachable.
    debug_assert!(days >= 0);

    let z = days - DAYS_1601_TO_1970 + DAYS_0000_03_01_TO_1970;
    let era = z / DAYS_PER_ERA;
    let day_of_era = z % DAYS_PER_ERA;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;

    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = era * 400 + year_of_era + (month <= 2) as i64;

    (year, month, day)
}

impl fmt::Display for Timestamp {
    /// Formats as ISO 8601 UTC: `YYYY-MM-DDThh:mm:ss.sssssssZ`.
    ///
    /// A negative value is not a FILETIME — under
    /// [`ProcessTraceMode::RAW_TIMESTAMP`] a QPC counter can be one — and renders as
    /// the raw `i64` instead.
    ///
    /// [`ProcessTraceMode::RAW_TIMESTAMP`]: crate::ProcessTraceMode::RAW_TIMESTAMP
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const SECS_PER_DAY: i64 = 86_400;

        if self.0 < 0 {
            return write!(f, "{}", self.0);
        }

        let secs = self.0 / Self::TICKS_PER_SEC;
        let subsec_ticks = self.0 % Self::TICKS_PER_SEC;
        let (year, month, day) = civil_from_days(secs / SECS_PER_DAY);
        let secs_of_day = secs % SECS_PER_DAY;

        write!(
            f,
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{subsec_ticks:07}Z",
            secs_of_day / 3600,
            secs_of_day / 60 % 60,
            secs_of_day % 60
        )
    }
}

/// Extended data type constants for ETW events.
///
/// These match the `EVENT_HEADER_EXT_TYPE_*` constants from the Windows SDK.
pub mod extended_data_type {
    /// Related activity ID for correlation.
    pub const RELATED_ACTIVITYID: u16 = 1;
    /// Security identifier (SID) of the user.
    pub const SID: u16 = 2;
    /// Terminal session ID.
    pub const TS_ID: u16 = 3;
    /// Instance information.
    pub const INSTANCE_INFO: u16 = 4;
    /// 32-bit stack trace.
    pub const STACK_TRACE32: u16 = 5;
    /// 64-bit stack trace.
    pub const STACK_TRACE64: u16 = 6;
    /// PEBS index.
    pub const PEBS_INDEX: u16 = 7;
    /// PMC counters.
    pub const PMC_COUNTERS: u16 = 8;
    /// PSM key.
    pub const PSM_KEY: u16 = 9;
    /// Event key.
    pub const EVENT_KEY: u16 = 10;
    /// TraceLogging event schema.
    pub const EVENT_SCHEMA_TL: u16 = 11;
    /// Provider traits.
    pub const PROV_TRAITS: u16 = 12;
    /// Process start key (uniquely identifies process lifetime).
    pub const PROCESS_START_KEY: u16 = 13;
    /// Control GUID.
    pub const CONTROL_GUID: u16 = 14;
    /// QPC delta.
    pub const QPC_DELTA: u16 = 15;
    /// Container ID.
    pub const CONTAINER_ID: u16 = 16;
    /// 32-bit stack key.
    pub const STACK_KEY32: u16 = 17;
    /// 64-bit stack key.
    pub const STACK_KEY64: u16 = 18;

    /// The constant's name for a code, so error messages name the type a log
    /// reader would otherwise have to look up.
    pub(crate) const fn name(kind: u16) -> &'static str {
        match kind {
            RELATED_ACTIVITYID => "RELATED_ACTIVITYID",
            SID => "SID",
            TS_ID => "TS_ID",
            INSTANCE_INFO => "INSTANCE_INFO",
            STACK_TRACE32 => "STACK_TRACE32",
            STACK_TRACE64 => "STACK_TRACE64",
            PEBS_INDEX => "PEBS_INDEX",
            PMC_COUNTERS => "PMC_COUNTERS",
            PSM_KEY => "PSM_KEY",
            EVENT_KEY => "EVENT_KEY",
            EVENT_SCHEMA_TL => "EVENT_SCHEMA_TL",
            PROV_TRAITS => "PROV_TRAITS",
            PROCESS_START_KEY => "PROCESS_START_KEY",
            CONTROL_GUID => "CONTROL_GUID",
            QPC_DELTA => "QPC_DELTA",
            CONTAINER_ID => "CONTAINER_ID",
            STACK_KEY32 => "STACK_KEY32",
            STACK_KEY64 => "STACK_KEY64",
            _ => "unknown",
        }
    }
}

/// An extended data item attached to an ETW event.
///
/// Extended data items provide additional context such as stack traces,
/// security identifiers (SIDs), process start keys, and more.
#[derive(Debug, Clone, Copy)]
pub struct ExtendedDataItem<'a> {
    /// The type of extended data (one of `extended_data_type::*` constants).
    pub ext_type: u16,
    /// The raw data bytes for this extended data item.
    pub data: &'a [u8],
}

/// Raw event data from ETW
///
/// Thin wrapper around `EVENT_RECORD` from Win32 API. This struct provides
/// safe access to the underlying event data without copying.
///
/// # Lifetime
///
/// The `RawEvent` is only valid for the duration of the event callback.
/// Do not store references to `RawEvent` beyond the callback scope.
#[repr(transparent)]
pub struct RawEvent {
    record: EVENT_RECORD,
}

impl RawEvent {
    /// Create a `RawEvent` from a raw `EVENT_RECORD` pointer
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - `record` is a valid, non-null pointer to an `EVENT_RECORD`
    /// - The `EVENT_RECORD` remains valid for the lifetime of the returned reference
    /// - The `UserData` pointer within the record (if non-null) points to valid memory of at least
    ///   `UserDataLength` bytes
    #[inline]
    pub const unsafe fn from_ptr<'a>(record: *const EVENT_RECORD) -> &'a Self {
        // SAFETY: RawEvent is #[repr(transparent)] over EVENT_RECORD,
        // so the pointer cast is valid. Caller guarantees pointer validity.
        unsafe { &*record.cast::<Self>() }
    }

    /// Get the provider GUID for this event
    #[inline]
    pub const fn provider_guid(&self) -> crate::Guid {
        crate::Guid::from_sys(self.record.EventHeader.ProviderId)
    }

    /// Get the event identifier (unique within a provider)
    #[inline]
    pub const fn id(&self) -> u16 {
        self.record.EventHeader.EventDescriptor.Id
    }

    /// Get the event version
    #[inline]
    pub const fn version(&self) -> u8 {
        self.record.EventHeader.EventDescriptor.Version
    }

    /// Get the event channel
    #[inline]
    pub const fn channel(&self) -> u8 {
        self.record.EventHeader.EventDescriptor.Channel
    }

    /// Get the event severity level (0=always, 1=critical, 2=error, 3=warning, 4=info, 5=verbose)
    #[inline]
    pub const fn level(&self) -> u8 {
        self.record.EventHeader.EventDescriptor.Level
    }

    /// Get the event opcode (start, stop, etc.)
    #[inline]
    pub const fn opcode(&self) -> u8 {
        self.record.EventHeader.EventDescriptor.Opcode
    }

    /// Get the event task identifier
    #[inline]
    pub const fn task(&self) -> u16 {
        self.record.EventHeader.EventDescriptor.Task
    }

    /// Get the event keyword bitmask for filtering
    #[inline]
    pub const fn keyword(&self) -> u64 {
        self.record.EventHeader.EventDescriptor.Keyword
    }

    /// Get the processor index that logged this event.
    ///
    /// This is a combined value of processor number and processor group,
    /// useful for per-CPU analysis and CSwitch correlation.
    #[inline]
    pub const fn processor_index(&self) -> u16 {
        // SAFETY: ProcessorIndex and Anonymous are union fields over the same u16.
        // ProcessorIndex is always the valid interpretation for event consumption.
        unsafe { self.record.BufferContext.Anonymous.ProcessorIndex }
    }

    /// Get the processor number (within its group) that logged this event.
    #[inline]
    pub const fn processor_number(&self) -> u8 {
        // SAFETY: Anonymous.ProcessorNumber is the low byte of the ProcessorIndex union.
        unsafe {
            self.record
                .BufferContext
                .Anonymous
                .Anonymous
                .ProcessorNumber
        }
    }

    /// Get the processor group that logged this event.
    ///
    /// On systems with fewer than 64 processors this is always 0.
    #[inline]
    pub const fn processor_group(&self) -> u8 {
        // SAFETY: Anonymous.Alignment is the high byte of the ProcessorIndex union.
        // Despite the name, this field holds the processor group number.
        unsafe { self.record.BufferContext.Anonymous.Anonymous.Alignment }
    }

    /// Returns the process ID of the thread that logged this event.
    ///
    /// This reflects the **logging context** — the process that called the ETW
    /// write API — which may differ from any process described by the event's
    /// own payload properties (e.g. a kernel event reporting on a third-party
    /// process will carry the target PID in its user data, not here).
    #[inline]
    pub const fn process_id(&self) -> u32 {
        self.record.EventHeader.ProcessId
    }

    /// Returns the thread ID of the thread that logged this event.
    ///
    /// This reflects the **logging context** — the specific thread that called
    /// the ETW write API — which may differ from any thread described by the
    /// event's own payload properties.
    #[inline]
    pub const fn thread_id(&self) -> u32 {
        self.record.EventHeader.ThreadId
    }

    /// Get the timestamp of this event.
    ///
    /// By default (without [`ProcessTraceMode::RAW_TIMESTAMP`]), this is in FILETIME
    /// format (100-nanosecond intervals since January 1, 1601).
    ///
    /// Use [`Timestamp::to_system_time()`] to convert to `std::time::SystemTime`.
    ///
    /// [`ProcessTraceMode::RAW_TIMESTAMP`]: crate::ProcessTraceMode::RAW_TIMESTAMP
    #[inline]
    pub const fn timestamp(&self) -> Timestamp {
        Timestamp(self.record.EventHeader.TimeStamp)
    }

    /// Get the raw timestamp value as `i64`.
    ///
    /// This is equivalent to `timestamp().raw()` and is provided for convenience.
    #[inline]
    pub const fn timestamp_raw(&self) -> i64 {
        self.record.EventHeader.TimeStamp
    }

    /// Get the activity ID for this event (for correlation)
    #[inline]
    pub const fn activity_id(&self) -> crate::Guid {
        crate::Guid::from_sys(self.record.EventHeader.ActivityId)
    }

    /// Get raw user data buffer
    ///
    /// Returns the event payload as a byte slice. The format of this data
    /// depends on the specific event and must be parsed according to the
    /// event's schema.
    #[inline]
    pub const fn user_data(&self) -> &[u8] {
        if self.record.UserData.is_null() || self.record.UserDataLength == 0 {
            return &[];
        }
        // SAFETY: ETW guarantees UserData points to valid memory of UserDataLength bytes
        // for the duration of the callback.
        unsafe {
            std::slice::from_raw_parts(
                self.record.UserData.cast::<u8>(),
                self.record.UserDataLength as usize,
            )
        }
    }

    /// Get the length of the user data in bytes
    #[inline]
    pub const fn user_data_length(&self) -> u16 {
        self.record.UserDataLength
    }

    /// Returns the number of extended data items attached to this event.
    ///
    /// Extended data items are only present when the provider was enabled
    /// with corresponding `EnableProperty` flags (e.g., `SID`, `STACK_TRACE`,
    /// `PROCESS_START_KEY`).
    #[inline]
    pub const fn extended_data_count(&self) -> u16 {
        self.record.ExtendedDataCount
    }

    /// Returns an iterator over the extended data items attached to this event.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use etw::RawEvent;
    /// # fn example(event: &RawEvent) {
    /// use etw::event::extended_data_type;
    ///
    /// for item in event.extended_data() {
    ///     match item.ext_type {
    ///         extended_data_type::SID => {
    ///             println!("SID data: {} bytes", item.data.len());
    ///         }
    ///         extended_data_type::STACK_TRACE64 => {
    ///             println!("Stack trace: {} bytes", item.data.len());
    ///         }
    ///         _ => {}
    ///     }
    /// }
    /// # }
    /// ```
    pub fn extended_data(&self) -> impl ExactSizeIterator<Item = ExtendedDataItem<'_>> {
        let ptr = self.record.ExtendedData;
        // Defensive: treat null pointer as empty even if ExtendedDataCount > 0
        let count = if ptr.is_null() {
            0
        } else {
            self.record.ExtendedDataCount as usize
        };

        (0..count).map(move |i| {
            // SAFETY: ETW guarantees ExtendedData points to an array of
            // ExtendedDataCount items, each valid for the callback duration.
            // The DataPtr within each item points to DataSize bytes of valid memory.
            let item: &EVENT_HEADER_EXTENDED_DATA_ITEM = unsafe { &*ptr.add(i) };
            let data = if item.DataSize > 0 && item.DataPtr != 0 {
                // DataPtr is an address the kernel hands over as a ULONGLONG, so
                // there is no pointer to derive provenance from; exposed is the
                // only model that fits.
                let data_ptr = std::ptr::with_exposed_provenance::<u8>(item.DataPtr as usize);
                // SAFETY: DataPtr is guaranteed valid for DataSize bytes during
                // the event callback lifetime.
                unsafe { std::slice::from_raw_parts(data_ptr, item.DataSize as usize) }
            } else {
                &[]
            };
            ExtendedDataItem {
                ext_type: item.ExtType,
                data,
            }
        })
    }

    /// Finds an extended data item by type.
    ///
    /// Returns `None` if no extended data of the specified type is present.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use etw::RawEvent;
    /// # fn example(event: &RawEvent) {
    /// use etw::event::extended_data_type;
    ///
    /// if let Some(sid_data) = event.find_extended_data(extended_data_type::SID) {
    ///     println!("Found SID: {} bytes", sid_data.len());
    /// }
    /// # }
    /// ```
    pub fn find_extended_data(&self, ext_type: u16) -> Option<&[u8]> {
        self.extended_data()
            .find(|item| item.ext_type == ext_type)
            .map(|item| item.data)
    }

    /// Returns the TraceLogging event-schema metadata for this event, if present.
    ///
    /// TraceLogging (self-describing) events carry their schema — the event name
    /// and field layout — inline as an
    /// [`EVENT_SCHEMA_TL`](extended_data_type::EVENT_SCHEMA_TL) extended-data
    /// item, rather than in a separately registered manifest. The presence of
    /// this item is the definitive signal that an event is a TraceLogging event;
    /// its absence means the event is manifest- or MOF-based.
    ///
    /// The returned bytes are the raw metadata blob (a size-prefixed, UTF-8 event
    /// name followed by field descriptors). Because that blob fully and uniquely
    /// describes the event's schema, it — not the event name, id, or keyword,
    /// none of which are guaranteed unique across a TraceLogging provider's
    /// events — is the sound key for caching a decoded schema.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use etw::RawEvent;
    /// # fn example(event: &RawEvent) {
    /// if event.tracelogging_metadata().is_some() {
    ///     // This event is TraceLogging (self-describing).
    /// }
    /// # }
    /// ```
    #[inline]
    pub fn tracelogging_metadata(&self) -> Option<&[u8]> {
        self.find_extended_data(extended_data_type::EVENT_SCHEMA_TL)
    }

    /// Returns the security identifier (SID) of the logging thread's user.
    ///
    /// The SID identifies the user account of the **logging thread** — the
    /// thread that called the ETW write API.  It may differ from any user or
    /// account described by the event's payload properties.
    ///
    /// Only available when the provider was enabled with `EnableProperty::SID`.
    ///
    /// # Errors
    ///
    /// Returns [`NotPresent`](crate::Error::NotPresent) if the SID extended data is absent,
    /// or [`ParseError`](crate::Error::ParseError) if the SID is malformed.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use etw::RawEvent;
    /// # fn example(event: &RawEvent) -> etw::Result<()> {
    /// let sid = event.sid()?;
    /// println!("User SID: {sid}");
    /// println!("Raw bytes: {:?}", sid.as_bytes());
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn sid(&self) -> crate::Result<crate::SidRef<'_>> {
        self.find_extended_data(extended_data_type::SID)
            .and_then(crate::SidRef::new)
            .ok_or(crate::Error::NotPresent {
                kind: extended_data_type::SID,
            })
    }

    /// Returns the process start key of the logging process.
    ///
    /// The process start key uniquely identifies a process instance across
    /// system reboots.  It identifies the **logging process** — the process
    /// that called the ETW write API — which may differ from any process
    /// described by the event's payload properties.
    ///
    /// Only available when the provider was enabled with
    /// `EnableProperty::PROCESS_START_KEY`.
    ///
    /// # Errors
    ///
    /// Returns [`NotPresent`](crate::Error::NotPresent) if the extended data is absent.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use etw::RawEvent;
    /// # fn example(event: &RawEvent) -> etw::Result<()> {
    /// let key = event.process_start_key()?;
    /// println!("Process start key: 0x{key:016X}");
    /// # Ok(())
    /// # }
    /// ```
    pub fn process_start_key(&self) -> crate::Result<u64> {
        self.find_extended_data(extended_data_type::PROCESS_START_KEY)
            .and_then(|data| data.get(..8)?.try_into().ok())
            .map(u64::from_le_bytes)
            .ok_or(crate::Error::NotPresent {
                kind: extended_data_type::PROCESS_START_KEY,
            })
    }

    /// Returns the 64-bit call stack of the logging thread.
    ///
    /// The stack trace captures the call stack of the **logging thread** — the
    /// thread that called the ETW write API — at the moment the event was
    /// written.  It does not represent the call stack of any thread described
    /// by the event's payload properties.
    ///
    /// Only available when the provider was enabled with
    /// `EnableProperty::STACK_TRACE`.  On x64 Windows the kernel stack walk is
    /// WOW64-aware and always produces `STACK_TRACE64` — `STACK_TRACE32` does
    /// not occur in practice on 64-bit systems.
    ///
    /// # Errors
    ///
    /// Returns [`NotPresent`](crate::Error::NotPresent) if no 64-bit stack trace extended data is
    /// present.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use etw::RawEvent;
    /// # fn example(event: &RawEvent) -> etw::Result<()> {
    /// let stack = event.stack_trace()?;
    /// println!("Match ID: 0x{:016X}", stack.match_id());
    /// for addr in stack.addresses() {
    ///     println!("  0x{addr:016X}");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn stack_trace(&self) -> crate::Result<StackTrace<'_>> {
        let data = self
            .find_extended_data(extended_data_type::STACK_TRACE64)
            .ok_or(crate::Error::NotPresent {
                kind: extended_data_type::STACK_TRACE64,
            })?;
        StackTrace::try_from_bytes(data)
    }

    /// Get a reference to the underlying `EVENT_RECORD`
    ///
    /// This is useful for advanced scenarios where you need direct access
    /// to the Win32 structure.
    #[inline]
    pub const fn as_raw(&self) -> &EVENT_RECORD {
        &self.record
    }
}

impl std::fmt::Display for RawEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} pid: {} tid: {} {{{}}} id: {} opcode: {}",
            self.timestamp(),
            self.process_id(),
            self.thread_id(),
            self.provider_guid(),
            self.id(),
            self.opcode(),
        )
    }
}

impl std::fmt::Debug for RawEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let alternate = f.alternate();
        let mut s = f.debug_struct("RawEvent");
        s.field("provider", &self.provider_guid())
            .field("id", &self.id())
            .field("pid", &self.process_id())
            .field("tid", &self.thread_id());
        if alternate {
            // Extra fields only when pretty-printed with {:#?}
            s.field("version", &self.version())
                .field("channel", &self.channel())
                .field("level", &self.level())
                .field("opcode", &self.opcode())
                .field("task", &self.task())
                .field("keyword", &format_args!("0x{:016X}", self.keyword()))
                .field("timestamp", &self.timestamp())
                .field("activity_id", &self.activity_id());

            // Try to show parsed properties from UserData.
            // Note: requires live TDH — will silently skip in unit tests or offline scenarios.
            if let Ok(schema) = crate::processing_context::lookup_schema(self) {
                // Create a temporary cache for debug formatting (not performance-critical)
                let mut cache = crate::parser::ParserCache::new(schema.top_level_property_count());
                let pointer_size = crate::processing_context::pointer_size_from_flags(
                    self.as_raw().EventHeader.Flags as u32,
                ) as usize;
                cache.prepopulate_fixed(&schema, pointer_size);
                {
                    let mut parser = crate::parser::EventParser::new(self, &schema, &mut cache);
                    let props = format_properties(&mut parser);
                    s.field("properties", &props);
                }
            }
        } else {
            s.field("user_data_length", &self.user_data_length())
                .field("extended_data_count", &self.extended_data_count());
        }

        s.finish()
    }
}

/// Formats event properties as an ordered list of (name, value) pairs.
///
/// Returns a `Vec` of `(name, value)` pairs in schema-defined order.
fn format_properties(parser: &mut crate::parser::EventParser<'_>) -> Vec<(String, String)> {
    use crate::types::{AnsiString, TdhInType, WideStrRef};

    // Collect property info first to avoid borrowing schema while mutating parser
    let props: Vec<_> = parser
        .schema()
        .properties()
        .map(|prop| {
            let name = prop.name().unwrap_or_else(|| "<unnamed>".to_owned());
            let in_type = TdhInType::from_raw(prop.in_type());
            let is_array = prop.count() > 1 || prop.has_param_count();
            (name, in_type, is_array)
        })
        .collect();

    let mut pairs = Vec::with_capacity(props.len());
    for (name, in_type, is_array) in props {
        if is_array {
            pairs.push((name, "<array>".to_owned()));
            continue;
        }
        // Try to format the value based on its type
        let value = match in_type {
            TdhInType::UnicodeString
            | TdhInType::NonNullTerminatedString
            | TdhInType::CountedString
            | TdhInType::ReversedCountedString
            | TdhInType::ManifestCountedString => parser
                .as_ref::<WideStrRef>(&name)
                .map_or_else(|_| "<parse error>".to_owned(), |s| s.to_string_lossy()),
            TdhInType::AnsiString
            | TdhInType::NonNullTerminatedAnsiString
            | TdhInType::CountedAnsiString
            | TdhInType::ReversedCountedAnsiString
            | TdhInType::ManifestCountedAnsiString => parser
                .get::<AnsiString>(&name)
                .map_or_else(|_| "<parse error>".to_owned(), |s| s.to_string_lossy()),
            TdhInType::UInt8 => parser
                .get::<u8>(&name)
                .map_or_else(|_| "<parse error>".to_owned(), |v| v.to_string()),
            TdhInType::Int8 => parser
                .get::<i8>(&name)
                .map_or_else(|_| "<parse error>".to_owned(), |v| v.to_string()),
            TdhInType::UInt16 => parser
                .get::<u16>(&name)
                .map_or_else(|_| "<parse error>".to_owned(), |v| v.to_string()),
            TdhInType::Int16 => parser
                .get::<i16>(&name)
                .map_or_else(|_| "<parse error>".to_owned(), |v| v.to_string()),
            TdhInType::UInt32 => parser
                .get::<u32>(&name)
                .map_or_else(|_| "<parse error>".to_owned(), |v| v.to_string()),
            TdhInType::HexInt32 => parser
                .get::<u32>(&name)
                .map_or_else(|_| "<parse error>".to_owned(), |v| format!("0x{v:X}")),
            TdhInType::Int32 => parser
                .get::<i32>(&name)
                .map_or_else(|_| "<parse error>".to_owned(), |v| v.to_string()),
            TdhInType::UInt64 => parser
                .get::<u64>(&name)
                .map_or_else(|_| "<parse error>".to_owned(), |v| v.to_string()),
            TdhInType::HexInt64 => parser
                .get::<u64>(&name)
                .map_or_else(|_| "<parse error>".to_owned(), |v| format!("0x{v:X}")),
            TdhInType::Int64 => parser
                .get::<i64>(&name)
                .map_or_else(|_| "<parse error>".to_owned(), |v| v.to_string()),
            TdhInType::Pointer | TdhInType::SizeT => parser
                .get::<usize>(&name)
                .map_or_else(|_| "<parse error>".to_owned(), |v| format!("0x{v:X}")),
            TdhInType::Boolean => parser
                .get::<bool>(&name)
                .map_or_else(|_| "<parse error>".to_owned(), |v| v.to_string()),
            TdhInType::FileTime => parser
                .get::<crate::Timestamp>(&name)
                .map_or_else(|_| "<parse error>".to_owned(), |v| v.to_string()),
            TdhInType::Guid => parser
                .get::<crate::Guid>(&name)
                .map_or_else(|_| "<parse error>".to_owned(), |v| format!("{v:?}")),
            TdhInType::Float => parser
                .get::<f32>(&name)
                .map_or_else(|_| "<parse error>".to_owned(), |v| v.to_string()),
            TdhInType::Double => parser
                .get::<f64>(&name)
                .map_or_else(|_| "<parse error>".to_owned(), |v| v.to_string()),
            _ => format!("<{in_type:?}>"),
        };

        pairs.push((name, value));
    }
    pairs
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::undocumented_unsafe_blocks,
    clippy::semicolon_if_nothing_returned,
    reason = "test-only assertions"
)]
mod tests {
    use super::*;

    struct AlignedBytes {
        words: Vec<u64>,
        len: usize,
    }

    impl AlignedBytes {
        fn new(len: usize) -> Self {
            Self {
                words: vec![0u64; len.div_ceil(8)],
                len,
            }
        }

        fn as_mut_bytes(&mut self) -> &mut [u8] {
            // SAFETY: `words` is allocated as `u64`, so base pointer is 8-byte aligned.
            // We expose exactly `len` bytes within the allocated backing storage.
            unsafe {
                std::slice::from_raw_parts_mut(self.words.as_mut_ptr().cast::<u8>(), self.len)
            }
        }

        fn as_bytes(&self) -> &[u8] {
            // SAFETY: Same reasoning as `as_mut_bytes`; this creates a read-only view.
            unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast::<u8>(), self.len) }
        }
    }

    #[test]
    fn test_timestamp_conversions() {
        // Unix epoch (1970-01-01 00:00:00 UTC) in FILETIME
        // FILETIME = (unix_secs + 11644473600) * 10_000_000
        let unix_epoch_filetime: i64 = 116_444_736_000_000_000;
        let ts = Timestamp::new(unix_epoch_filetime);

        // Verify ticks
        assert_eq!(ts.as_ticks(), unix_epoch_filetime as u64);

        // At Unix epoch, Unix timestamp should be 0
        assert_eq!(ts.as_unix_secs(), 0);
        assert_eq!(ts.as_unix_ms(), 0);
        assert_eq!(ts.as_unix_nanos(), 0);

        // SystemTime conversion should succeed
        let system_time = ts.to_system_time();
        assert!(system_time.is_some());
        assert_eq!(system_time.unwrap(), std::time::UNIX_EPOCH);
    }

    #[test]
    fn test_timestamp_one_second_after_epoch() {
        // One second after Unix epoch
        let one_sec_after: i64 = 116_444_736_000_000_000 + 10_000_000;
        let ts = Timestamp::new(one_sec_after);

        assert_eq!(ts.as_unix_secs(), 1);
        assert_eq!(ts.as_unix_ms(), 1000);
    }

    #[test]
    fn test_timestamp_display() {
        // Unix epoch: 1970-01-01 00:00:00
        let unix_epoch_filetime: i64 = 116_444_736_000_000_000;
        let ts = Timestamp::new(unix_epoch_filetime);

        let display = format!("{ts}");
        // Format: ISO 8601 YYYY-MM-DDThh:mm:ss.sssssssZ (UTC)
        assert_eq!(display, "1970-01-01T00:00:00.0000000Z");

        // One tick after epoch (100 nanoseconds)
        let ts2 = Timestamp::new(unix_epoch_filetime + 1);
        assert_eq!(format!("{ts2}"), "1970-01-01T00:00:00.0000001Z");

        // 1.5 seconds after epoch
        let ts3 = Timestamp::new(unix_epoch_filetime + 15_000_000);
        assert_eq!(format!("{ts3}"), "1970-01-01T00:00:01.5000000Z");
    }

    #[test]
    fn test_timestamp_ordering() {
        let ts1 = Timestamp::new(100);
        let ts2 = Timestamp::new(200);
        let ts3 = Timestamp::new(100);

        assert!(ts1 < ts2);
        assert!(ts2 > ts1);
        assert_eq!(ts1, ts3);
    }

    #[test]
    fn test_timestamp_zero() {
        // FILETIME 0 = January 1, 1601 (before Unix epoch)
        let ts = Timestamp::new(0);

        // Should be negative Unix time (before 1970)
        assert!(ts.as_unix_secs() < 0);
        assert!(ts.as_unix_ms() < 0);
        assert!(ts.as_unix_nanos() < 0);

        // SystemTime can represent dates before Unix epoch
        let system_time = ts.to_system_time();
        assert!(system_time.is_some());
    }

    #[test]
    fn test_stack_trace_valid_and_slice_access() {
        let mut data = AlignedBytes::new(8 + 16);
        let bytes = data.as_mut_bytes();
        bytes[..8].copy_from_slice(&0x1234_5678_9ABC_DEF0u64.to_le_bytes());
        bytes[8..16].copy_from_slice(&0x0000_7FF6_0000_1000u64.to_le_bytes());
        bytes[16..24].copy_from_slice(&0x0000_7FF6_0000_2000u64.to_le_bytes());

        let stack = StackTrace::try_from_bytes(data.as_bytes()).expect("should parse");
        assert_eq!(stack.match_id(), 0x1234_5678_9ABC_DEF0);
        assert_eq!(stack.len(), 2);
        assert_eq!(stack.addresses_slice().len(), 2);
        assert_eq!(stack.address(0), Some(0x0000_7FF6_0000_1000));
        assert_eq!(stack.address(1), Some(0x0000_7FF6_0000_2000));
        assert_eq!(stack.address(2), None);
    }

    #[test]
    fn test_stack_trace_rejects_partial_entry() {
        let data = vec![0u8; 8 + 4];
        assert!(StackTrace::try_from_bytes(&data).is_err());
        assert!(StackTrace::from_bytes(&data).is_none());
    }

    #[test]
    fn test_stack_trace_rejects_smaller_than_min_size() {
        // < 8 bytes — exercises the MIN_SIZE error path.
        let data = vec![0u8; 4];
        let err = StackTrace::try_from_bytes(&data).unwrap_err();
        // The size is the actionable detail, so pin it rather than the variant alone.
        assert!(
            matches!(&err, crate::Error::ParseError { message, .. } if message.contains("too small")),
            "got: {err:?}"
        );
        assert!(StackTrace::from_bytes(&data).is_none());

        // Empty buffer — same error.
        assert!(StackTrace::try_from_bytes(&[]).is_err());
    }

    #[test]
    fn test_stack_trace_rejects_misalignment() {
        let backing = [0u8; 8 + 16 + 8];
        let base = backing.as_ptr() as usize;
        let mut offset = 0usize;
        while offset < 8 && (base + offset).is_multiple_of(8) {
            offset += 1;
        }
        assert!(offset < 8, "failed to construct misaligned test buffer");
        let misaligned = &backing[offset..offset + 8 + 16];
        assert!(StackTrace::try_from_bytes(misaligned).is_err());
        assert!(StackTrace::from_bytes(misaligned).is_none());
    }

    #[test]
    fn test_stack_trace_is_empty_match_id_only() {
        let mut data = AlignedBytes::new(8);
        data.as_mut_bytes()
            .copy_from_slice(&0xCAFE_BABE_DEAD_BEEFu64.to_le_bytes());

        let stack = StackTrace::try_from_bytes(data.as_bytes()).expect("should parse");
        assert!(stack.is_empty());
        assert_eq!(stack.len(), 0);
        assert_eq!(stack.addresses_slice().len(), 0);
        assert_eq!(stack.addresses_iter().len(), 0);
        assert_eq!(stack.address(0), None);
        assert_eq!(stack.match_id(), 0xCAFE_BABE_DEAD_BEEF);
    }

    #[test]
    fn test_stack_trace_addresses_iter_yields_all() {
        let mut data = AlignedBytes::new(8 + 24);
        let bytes = data.as_mut_bytes();
        bytes[..8].copy_from_slice(&0u64.to_le_bytes());
        bytes[8..16].copy_from_slice(&0x0000_7FF6_0000_1000u64.to_le_bytes());
        bytes[16..24].copy_from_slice(&0x0000_7FF6_0000_2000u64.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x0000_7FF6_0000_3000u64.to_le_bytes());

        let stack = StackTrace::try_from_bytes(data.as_bytes()).expect("should parse");
        let collected: Vec<u64> = stack.addresses_iter().collect();
        assert_eq!(
            collected,
            vec![
                0x0000_7FF6_0000_1000,
                0x0000_7FF6_0000_2000,
                0x0000_7FF6_0000_3000
            ]
        );
        // ExactSizeIterator contract
        assert_eq!(stack.addresses_iter().len(), 3);
    }

    #[test]
    fn test_stack_trace_debug_format() {
        let mut data = AlignedBytes::new(8 + 16);
        let bytes = data.as_mut_bytes();
        bytes[..8].copy_from_slice(&0xDEAD_BEEF_DEAD_BEEFu64.to_le_bytes());
        bytes[8..16].copy_from_slice(&0x0000_7FF6_0000_1000u64.to_le_bytes());
        bytes[16..24].copy_from_slice(&0x0000_7FF6_0000_2000u64.to_le_bytes());

        let stack = StackTrace::try_from_bytes(data.as_bytes()).expect("should parse");
        let rendered = format!("{stack:?}");
        assert!(rendered.contains("StackTrace"));
        // match_id is rendered as 0x{:016X}
        assert!(rendered.contains("0xDEADBEEFDEADBEEF"), "got: {rendered}");
        // Addresses are rendered via the inner slice's Debug
        assert!(rendered.contains("addresses"));

        // as_bytes() returns the raw byte slice
        assert_eq!(stack.as_bytes(), data.as_bytes());

        // addresses() returns a Vec<u64> (heap-allocated copy)
        let vec_addrs = stack.addresses();
        assert_eq!(
            vec_addrs,
            vec![0x0000_7FF6_0000_1000, 0x0000_7FF6_0000_2000]
        );
    }

    /// Build a zeroed `EVENT_RECORD`. Caller fills in any required fields.
    ///
    /// `EVENT_RECORD` is a POD type — zero is a valid initialisation.
    fn zeroed_event_record() -> EVENT_RECORD {
        // SAFETY: EVENT_RECORD is plain old data; zero-init is valid.
        unsafe { std::mem::zeroed() }
    }

    #[test]
    fn test_raw_event_header_accessors() {
        let provider =
            windows_sys::core::GUID::from_u128(0x1234_5678_9ABC_DEF0_1122_3344_5566_7788);
        let activity =
            windows_sys::core::GUID::from_u128(0xAAAA_BBBB_CCCC_DDDD_EEEE_FFFF_0000_1111);

        let mut record = zeroed_event_record();
        record.EventHeader.ProviderId = provider;
        record.EventHeader.EventDescriptor.Id = 42;
        record.EventHeader.EventDescriptor.Version = 3;
        record.EventHeader.EventDescriptor.Channel = 16;
        record.EventHeader.EventDescriptor.Level = 4; // Information
        record.EventHeader.EventDescriptor.Opcode = 1; // Start
        record.EventHeader.EventDescriptor.Task = 100;
        record.EventHeader.EventDescriptor.Keyword = 0x8000_0000_0000_0001;
        record.EventHeader.ProcessId = 1234;
        record.EventHeader.ThreadId = 5678;
        record.EventHeader.TimeStamp = 116_444_736_000_000_000; // Unix epoch
        record.EventHeader.ActivityId = activity;
        // ProcessorIndex is a u16 union: low byte = ProcessorNumber, high byte = Group.
        // 0x0207 ⇒ group 2, proc 7 (little-endian byte order in the u16).
        record.BufferContext.Anonymous.ProcessorIndex = 0x0207;

        // SAFETY: `record` outlives `event` (same scope) and is a valid EVENT_RECORD.
        let event = unsafe { RawEvent::from_ptr(&raw const record) };

        assert_eq!(event.provider_guid(), crate::Guid::from_sys(provider));
        assert_eq!(event.id(), 42);
        assert_eq!(event.version(), 3);
        assert_eq!(event.channel(), 16);
        assert_eq!(event.level(), 4);
        assert_eq!(event.opcode(), 1);
        assert_eq!(event.task(), 100);
        assert_eq!(event.keyword(), 0x8000_0000_0000_0001);
        assert_eq!(event.process_id(), 1234);
        assert_eq!(event.thread_id(), 5678);
        assert_eq!(event.timestamp().raw(), 116_444_736_000_000_000);
        assert_eq!(event.timestamp_raw(), 116_444_736_000_000_000);
        assert_eq!(event.activity_id(), crate::Guid::from_sys(activity));
        assert_eq!(event.processor_index(), 0x0207);
        assert_eq!(event.processor_number(), 7);
        assert_eq!(event.processor_group(), 2);
        assert_eq!(event.user_data_length(), 0);
        assert_eq!(event.extended_data_count(), 0);
        assert!(event.user_data().is_empty());
        assert_eq!(event.extended_data().len(), 0);
    }

    #[test]
    fn test_raw_event_user_data_with_backing_buffer() {
        let mut data = AlignedBytes::new(16);
        data.as_mut_bytes()
            .copy_from_slice(b"hello world!\xDE\xAD\xBE\xEF");
        let data_ptr = data.as_bytes().as_ptr().cast_mut().cast();

        let mut record = zeroed_event_record();
        record.UserData = data_ptr;
        record.UserDataLength = 16;

        // SAFETY: `data` and `record` live for this scope; `record.UserData` points
        // into `data`'s buffer for the duration of the borrow.
        let event = unsafe { RawEvent::from_ptr(&raw const record) };

        assert_eq!(event.user_data_length(), 16);
        assert_eq!(event.user_data(), b"hello world!\xDE\xAD\xBE\xEF");
    }

    #[test]
    fn test_raw_event_user_data_empty_when_null_or_zero_length() {
        // Both fields zero (no buffer).
        let record = zeroed_event_record();
        // SAFETY: `record` outlives `event` (same scope) and is a valid EVENT_RECORD.
        let event = unsafe { RawEvent::from_ptr(&raw const record) };
        assert_eq!(event.user_data_length(), 0);
        assert!(event.user_data().is_empty());

        // Non-null pointer but zero length — should still return empty slice.
        let mut data = AlignedBytes::new(8);
        let data_ptr = data.as_mut_bytes().as_mut_ptr().cast();
        let mut record2 = zeroed_event_record();
        record2.UserData = data_ptr;
        record2.UserDataLength = 0;
        // SAFETY: `data` and `record2` live for this scope; UserDataLength is 0
        // so `user_data()` short-circuits without dereferencing the pointer.
        let event2 = unsafe { RawEvent::from_ptr(&raw const record2) };
        assert!(event2.user_data().is_empty());
    }

    #[test]
    fn test_raw_event_display_smoke() {
        let mut record = zeroed_event_record();
        record.EventHeader.EventDescriptor.Id = 42;
        record.EventHeader.EventDescriptor.Opcode = 7;
        record.EventHeader.ProcessId = 1234;
        record.EventHeader.ThreadId = 5678;
        record.EventHeader.ProviderId =
            windows_sys::core::GUID::from_u128(0x1122_3344_5566_7788_99AA_BBCC_DDEE_FF00);

        // SAFETY: `record` outlives `event` (same scope) and is a valid EVENT_RECORD.
        let event = unsafe { RawEvent::from_ptr(&raw const record) };

        let rendered = format!("{event}");
        assert!(rendered.contains("pid: 1234"), "got: {rendered}");
        assert!(rendered.contains("tid: 5678"), "got: {rendered}");
        assert!(rendered.contains("id: 42"), "got: {rendered}");
        assert!(rendered.contains("opcode: 7"), "got: {rendered}");
    }

    #[test]
    fn test_raw_event_debug_smoke() {
        let mut record = zeroed_event_record();
        record.EventHeader.EventDescriptor.Id = 99;
        record.EventHeader.ProcessId = 4321;
        record.EventHeader.ThreadId = 8765;

        // SAFETY: `record` outlives `event` (same scope) and is a valid EVENT_RECORD.
        let event = unsafe { RawEvent::from_ptr(&raw const record) };
        // Non-alternate Debug avoids any Win32 / TDH calls.
        let rendered = format!("{event:?}");
        assert!(rendered.contains("RawEvent"), "got: {rendered}");
        assert!(rendered.contains("99"), "got: {rendered}");
        assert!(rendered.contains("4321"), "got: {rendered}");
    }

    // ========================================================================
    // Extended data: extended_data(), find_extended_data(), sid(),
    // process_start_key(), stack_trace()
    // ========================================================================

    #[test]
    fn test_extended_data_sid_and_find() {
        use windows_sys::Win32::System::Diagnostics::Etw::EVENT_HEADER_EXTENDED_DATA_ITEM;

        // S-1-5-18 (LocalSystem): rev=1, subauth_count=1, authority=5, subauth[0]=18
        let sid_bytes: [u8; 12] = [
            0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00,
        ];

        // SAFETY: EVENT_HEADER_EXTENDED_DATA_ITEM is POD; zero-init valid.
        let mut item: EVENT_HEADER_EXTENDED_DATA_ITEM = unsafe { std::mem::zeroed() };
        item.ExtType = extended_data_type::SID;
        item.DataPtr = sid_bytes.as_ptr() as u64;
        item.DataSize = sid_bytes.len() as u16;

        let mut record = zeroed_event_record();
        record.ExtendedData = &raw mut item;
        record.ExtendedDataCount = 1;

        // SAFETY: record, item, and sid_bytes all live for this scope.
        let event = unsafe { RawEvent::from_ptr(&raw const record) };

        // extended_data() iterator exercises the closure
        assert_eq!(event.extended_data_count(), 1);
        assert_eq!(event.extended_data().len(), 1);
        let items: Vec<_> = event.extended_data().collect();
        assert_eq!(items[0].ext_type, extended_data_type::SID);
        assert_eq!(items[0].data, &sid_bytes[..]);

        // find_extended_data: found
        assert_eq!(
            event.find_extended_data(extended_data_type::SID),
            Some(&sid_bytes[..])
        );

        // find_extended_data: not found
        assert!(
            event
                .find_extended_data(extended_data_type::PROCESS_START_KEY)
                .is_none()
        );

        // sid() success path
        let sid = event.sid().expect("should find SID");
        assert_eq!(sid.revision(), 1);
        assert_eq!(sid.sub_authority_count(), 1);

        // process_start_key error (not present)
        assert!(event.process_start_key().is_err());

        // stack_trace error (not present)
        assert!(event.stack_trace().is_err());
    }

    #[test]
    fn test_extended_data_empty_yields_no_items() {
        let record = zeroed_event_record();
        let event = unsafe { RawEvent::from_ptr(&raw const record) };

        assert_eq!(event.extended_data().len(), 0);
        assert!(event.sid().is_err());
        assert!(event.process_start_key().is_err());
        assert!(event.stack_trace().is_err());
    }

    #[test]
    fn test_process_start_key_found() {
        use windows_sys::Win32::System::Diagnostics::Etw::EVENT_HEADER_EXTENDED_DATA_ITEM;

        let key: u64 = 0xDEAD_BEEF_CAFE_1234;
        let key_bytes = key.to_le_bytes();

        // SAFETY: EVENT_HEADER_EXTENDED_DATA_ITEM is POD; zero-init valid.
        let mut item: EVENT_HEADER_EXTENDED_DATA_ITEM = unsafe { std::mem::zeroed() };
        item.ExtType = extended_data_type::PROCESS_START_KEY;
        item.DataPtr = key_bytes.as_ptr() as u64;
        item.DataSize = 8;

        let mut record = zeroed_event_record();
        record.ExtendedData = &raw mut item;
        record.ExtendedDataCount = 1;

        // SAFETY: record, item, and key_bytes all live for this scope.
        let event = unsafe { RawEvent::from_ptr(&raw const record) };
        assert_eq!(event.process_start_key().expect("key"), key);
    }

    #[test]
    fn test_stack_trace_via_extended_data() {
        use windows_sys::Win32::System::Diagnostics::Etw::EVENT_HEADER_EXTENDED_DATA_ITEM;

        // 8-byte match_id + two 8-byte addresses = 24 bytes, must be 8-byte aligned
        let mut st_data = AlignedBytes::new(24);
        {
            let bytes = st_data.as_mut_bytes();
            bytes[..8].copy_from_slice(&0xDEAD_BEEF_1234_5678u64.to_le_bytes());
            bytes[8..16].copy_from_slice(&0x0000_7FF6_0000_1000u64.to_le_bytes());
            bytes[16..24].copy_from_slice(&0x0000_7FF6_0000_2000u64.to_le_bytes())
        };

        // SAFETY: EVENT_HEADER_EXTENDED_DATA_ITEM is POD; zero-init valid.
        let mut item: EVENT_HEADER_EXTENDED_DATA_ITEM = unsafe { std::mem::zeroed() };
        item.ExtType = extended_data_type::STACK_TRACE64;
        item.DataPtr = st_data.as_bytes().as_ptr() as u64;
        item.DataSize = 24;

        let mut record = zeroed_event_record();
        record.ExtendedData = &raw mut item;
        record.ExtendedDataCount = 1;

        // SAFETY: record, item, and st_data all live for this scope.
        let event = unsafe { RawEvent::from_ptr(&raw const record) };
        let stack = event.stack_trace().expect("should find stack trace");
        assert_eq!(stack.match_id(), 0xDEAD_BEEF_1234_5678);
        assert_eq!(stack.len(), 2);
        assert_eq!(stack.address(0), Some(0x0000_7FF6_0000_1000));
        assert_eq!(stack.address(1), Some(0x0000_7FF6_0000_2000));
    }

    // ========================================================================
    // format_properties — covers the in_type → string formatting match
    // ========================================================================

    #[test]
    fn test_format_properties_covers_all_arms() {
        use crate::{
            parser::EventParser,
            processing_context::mock::MockSchemaBuilder,
            types::{TdhInType, TdhOutType},
        };

        // Build a schema covering every explicit arm in `format_properties`,
        // plus one type (`SystemTime`) that hits the `_` catch-all.
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add("U8", TdhInType::UInt8, TdhOutType::Null)
            .add("I8", TdhInType::Int8, TdhOutType::Null)
            .add("U16", TdhInType::UInt16, TdhOutType::Null)
            .add("I16", TdhInType::Int16, TdhOutType::Null)
            .add("U32", TdhInType::UInt32, TdhOutType::Null)
            .add("Hex32", TdhInType::HexInt32, TdhOutType::Null)
            .add("I32", TdhInType::Int32, TdhOutType::Null)
            .add("U64", TdhInType::UInt64, TdhOutType::Null)
            .add("Hex64", TdhInType::HexInt64, TdhOutType::Null)
            .add("I64", TdhInType::Int64, TdhOutType::Null)
            .add("Ptr", TdhInType::Pointer, TdhOutType::Null)
            .add("Bool", TdhInType::Boolean, TdhOutType::Null)
            .add("Ft", TdhInType::FileTime, TdhOutType::Null)
            .add("Gd", TdhInType::Guid, TdhOutType::Null)
            .add("F32", TdhInType::Float, TdhOutType::Null)
            .add("F64", TdhInType::Double, TdhOutType::Null)
            .add_fixed_typed("Sysm", TdhInType::SystemTime, TdhOutType::Null, 16)
            .add("Wide", TdhInType::UnicodeString, TdhOutType::Null)
            .add("Ansi", TdhInType::AnsiString, TdhOutType::Null)
            .build_with_cache();

        let mut data = Vec::<u8>::new();
        data.push(66u8);
        data.extend_from_slice(&(-1i8).to_le_bytes());
        data.extend_from_slice(&1000u16.to_le_bytes());
        data.extend_from_slice(&(-100i16).to_le_bytes());
        data.extend_from_slice(&99u32.to_le_bytes());
        data.extend_from_slice(&0xABCDu32.to_le_bytes());
        data.extend_from_slice(&(-1i32).to_le_bytes());
        data.extend_from_slice(&1234u64.to_le_bytes());
        data.extend_from_slice(&0xCAFEu64.to_le_bytes());
        data.extend_from_slice(&(-1i64).to_le_bytes());
        data.extend_from_slice(&0x1000usize.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes()); // Boolean true
        data.extend_from_slice(&0i64.to_le_bytes()); // FileTime → 1601
        data.extend_from_slice(&[0u8; 16]); // Guid all-zero
        data.extend_from_slice(&1.5f32.to_le_bytes());
        data.extend_from_slice(&2.5f64.to_le_bytes());
        data.extend_from_slice(&[0u8; 16]); // SystemTime — bytes don't matter, hits `_`
        // UnicodeString "Hi\0" UTF-16LE (parser scans to null)
        data.extend_from_slice(&[0x48, 0x00, 0x69, 0x00, 0x00, 0x00]);
        // AnsiString — last property, parser uses remaining bytes
        data.extend_from_slice(b"Hi\0");

        let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
        let pairs = format_properties(&mut parser);

        // Build into a map for stable lookups
        let map: std::collections::HashMap<_, _> = pairs.into_iter().collect();
        assert_eq!(map["U8"], "66");
        assert_eq!(map["I8"], "-1");
        assert_eq!(map["U16"], "1000");
        assert_eq!(map["I16"], "-100");
        assert_eq!(map["U32"], "99");
        assert_eq!(map["Hex32"], "0xABCD");
        assert_eq!(map["I32"], "-1");
        assert_eq!(map["U64"], "1234");
        assert_eq!(map["Hex64"], "0xCAFE");
        assert_eq!(map["I64"], "-1");
        assert_eq!(map["Ptr"], "0x1000");
        assert_eq!(map["Bool"], "true");
        assert!(map["Ft"].contains("1601-01-01"), "got: {}", map["Ft"]);
        assert!(map["Gd"].contains("Guid"), "got: {}", map["Gd"]);
        assert_eq!(map["F32"], "1.5");
        assert_eq!(map["F64"], "2.5");
        // `_` catch-all → "<{in_type:?}>"
        assert_eq!(map["Sysm"], "<SystemTime>");
        assert_eq!(map["Wide"], "Hi");
        assert_eq!(map["Ansi"], "Hi");
    }

    #[test]
    fn test_format_properties_array_property() {
        use crate::{
            parser::EventParser,
            processing_context::mock::MockSchemaBuilder,
            types::{TdhInType, TdhOutType},
        };

        // Static count > 1 → format_properties emits "<array>" without parsing.
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add_static_array("Pids", TdhInType::UInt32, TdhOutType::Null, 4)
            .build_with_cache();
        let data = [0u8; 16];
        let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
        let pairs = format_properties(&mut parser);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, "Pids");
        assert_eq!(pairs[0].1, "<array>");
    }
}
