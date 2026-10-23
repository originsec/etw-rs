//! TDH (Trace Data Helper) APIs for dynamic event schema lookup.
//!
//! This module provides runtime schema discovery using Windows TDH APIs,
//! with caching to avoid repeated lookups for the same event types.
//!
//! # Overview
//!
//! Rather than hardcoding event schemas, this module uses `TdhGetEventInformation`
//! to retrieve schema information at runtime. Results are cached by
//! (provider GUID, discriminator, version, pointer size, classic flag) to minimise
//! overhead.
//!
//! `event_id` and `opcode` are *alternative* discriminators sharing one slot, not
//! two separate key fields:
//! - Modern manifest-based providers use `event_id` to identify events
//! - Classic kernel providers (SystemTrace) use `opcode` to identify events
//! - `EVENT_HEADER_FLAG_CLASSIC_HEADER` says which regime applies, and is itself keyed so the two
//!   cannot collide
//!
//! Pointer size is part of the key because TDH sizes `Pointer` and `SizeT`
//! properties from the bitness of the event that triggered the lookup, so a
//! schema fetched for a 64-bit event cannot be reused for a 32-bit one. See
//! `SchemaKey` for the packing and the measurements behind it.
//!
//! # Example
//!
//! ```no_run
//! use etw::processing_context::ProcessingContext;
//!
//! let mut cache = ProcessingContext::new();
//!
//! // In your event callback:
//! // let schema = cache.get_or_lookup(event);
//! // for prop in schema.properties() {
//! //     println!("{}: {:?}", prop.name(), prop.in_type());
//! // }
//! ```

use crate::{
    Error, Result,
    event::RawEvent,
    parser::{EventParser, ParserCache},
};
use rustc_hash::{FxBuildHasher, FxHashMap};
use std::hash::{Hash, Hasher};
use windows_sys::Win32::{
    Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS},
    System::Diagnostics::Etw::{
        EVENT_HEADER_FLAG_32_BIT_HEADER, EVENT_HEADER_FLAG_64_BIT_HEADER,
        EVENT_HEADER_FLAG_CLASSIC_HEADER, EVENT_PROPERTY_INFO, EVENT_RECORD, PROPERTY_FLAGS,
        PropertyParamCount, PropertyParamLength, PropertyStruct, TRACE_EVENT_INFO,
        TdhGetEventInformation,
    },
};

/// Key for caching event schemas.
///
/// `Id` and `Opcode` are *alternative* discriminators, never both load-bearing:
/// manifest events are identified by provider + Id + Version, classic MOF events
/// by opcode with Id left 0. `EVENT_HEADER_FLAG_CLASSIC_HEADER` says which regime
/// an event belongs to, straight from the header with no TDH call, so one 16-bit
/// slot carries whichever applies.
///
/// Measured over live traffic: every classic-flagged event had `Id == 0` and
/// every non-classic event `Id != 0`, with no exceptions, so collapsing the two
/// discriminators into one slot is lossless.
///
/// Channel is intentionally excluded: TDH schemas are identical regardless of
/// channel.
///
/// Pointer size IS part of the key. TDH fills in a declared length for `Pointer`
/// and `SizeT` properties based on the bitness of the event that triggered the
/// lookup, so a schema fetched for a 64-bit event describes 8-byte pointers and
/// cannot be reused for a 32-bit one. Keying on it makes a bitness-mismatched
/// offset table unrepresentable rather than something each size computation has
/// to remember to avoid.
///
/// TraceLogging is the exception to the measurement above: non-classic with
/// `Id == 0`, so its events share a slot and need a cache keyed on the schema
/// blob.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SchemaKey {
    provider_guid: crate::Guid,
    /// Packed: Discriminator(16) | Version(8) | `SCHEMA_FLAGS` at bits 24, 25 and
    /// 27. Bit 26 is unused because the masked-out `DECODE_GUID` sits between the
    /// bitness and classic flags in the source word; bits 26 and 28..31 are spare.
    event_key: u32,
}

/// The `EVENT_HEADER.Flags` bits that belong in the cache key: the two that
/// change how an event decodes, plus the one that selects its discriminator.
///
/// - `32_BIT_HEADER` / `64_BIT_HEADER` — pointer size, which sets the width of `Pointer` and
///   `SizeT` properties and therefore every offset after them. This is the distinction the key
///   previously missed. Both bits are included so the key mirrors what the header states, rather
///   than relying on the absence of one implying the other.
/// - `CLASSIC_HEADER` — manifest events are identified by provider + Id + Version, classic MOF
///   events by opcode. Measured across NT Kernel Logger, manifest, stack-trace and TraceLogging
///   sessions: every classic-flagged event had `Id == 0` and every non-classic event `Id != 0`,
///   without exception.
///
/// No other flag bit distinguishes schemas that reach this cache, so none are
/// keyed.
const SCHEMA_FLAGS: u16 = EVENT_HEADER_FLAG_32_BIT_HEADER as u16
    | EVENT_HEADER_FLAG_64_BIT_HEADER as u16
    | EVENT_HEADER_FLAG_CLASSIC_HEADER as u16;

/// Left-shift that moves [`SCHEMA_FLAGS`] clear of `Version`.
///
/// The lowest flag kept is `32_BIT_HEADER` at bit 5, so 19 lifts it to bit 24 —
/// one past the top of `Version`.
const SCHEMA_FLAGS_SHIFT: u32 = 19;

// The packing above is only sound while every SCHEMA_FLAGS bit is high enough to
// clear Version and low enough to survive the shift. Adding a flag below bit 5
// would land inside Version and silently corrupt it, so two versions of one event
// would share a cache entry; a flag at bit 13 or above would shift past bit 31 and
// be dropped, since `<<` truncates the value rather than failing. Both are checked
// here so the mask cannot be widened wrongly without the build stopping.
const _: () = {
    let shifted = (SCHEMA_FLAGS as u32) << SCHEMA_FLAGS_SHIFT;
    assert!(
        shifted.trailing_zeros() >= 24,
        "SCHEMA_FLAGS must land above bit 23; a lower flag bit would overwrite Version"
    );
    assert!(
        shifted.count_ones() == SCHEMA_FLAGS.count_ones(),
        "SCHEMA_FLAGS must not shift past bit 31"
    );
};

impl SchemaKey {
    #[inline]
    const fn from_event_record(event: &EVENT_RECORD) -> Self {
        let flags = event.EventHeader.Flags;

        // Id and Opcode are alternative discriminators, so they share one 16-bit
        // slot and `CLASSIC_HEADER` (kept in the key below) says which is in it.
        // Selected with an arithmetic mask rather than a branch: `classic_mask` is
        // all-ones for a classic record and zero otherwise, so this is a handful of
        // ALU ops with no conditional and no extra dependency — `flags` is already
        // needed for the flag bits.
        let classic_mask =
            0u16.wrapping_sub((flags & EVENT_HEADER_FLAG_CLASSIC_HEADER as u16 != 0) as u16);
        let discriminator = (event.EventHeader.EventDescriptor.Opcode as u16 & classic_mask)
            | (event.EventHeader.EventDescriptor.Id & !classic_mask);

        Self {
            provider_guid: crate::Guid::from_sys(event.EventHeader.ProviderId),
            event_key: (discriminator as u32)
                | ((event.EventHeader.EventDescriptor.Version as u32) << 16)
                // SCHEMA_FLAGS occupies bits 5, 6 and 8, so one shift lands them
                // in bits 24, 25 and 27 without packing them individually.
                | (((flags & SCHEMA_FLAGS) as u32) << SCHEMA_FLAGS_SHIFT),
        }
    }
}

/// Extracts the pointer size from `EVENT_HEADER.Flags`.
///
/// `EVENT_HEADER_FLAG_32_BIT_HEADER` (bit 5) → 4 bytes.
/// `EVENT_HEADER_FLAG_64_BIT_HEADER` (bit 6) → 8 bytes.
/// If neither is set, defaults to 8 (native 64-bit host).
pub(crate) const fn pointer_size_from_flags(flags: u32) -> u8 {
    if flags & EVENT_HEADER_FLAG_32_BIT_HEADER != 0 {
        4
    } else {
        8
    }
}

/// FxHash implementation for SchemaKey.
///
/// Hashes the GUID as u128 plus the packed event key u32.
/// Using `write_u128()` is 2x faster than `write()` with a byte slice because
/// it avoids the `hash_bytes()` compression step and uses direct bit operations.
impl Hash for SchemaKey {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Hash GUID as u128 (2x faster than write() with byte slice)
        // SAFETY: GUID is 16 bytes, repr(C), and we use read_unaligned since GUID is only 4-byte
        // aligned
        let guid_u128 =
            unsafe { std::ptr::read_unaligned((&raw const self.provider_guid).cast::<u128>()) };
        state.write_u128(guid_u128);
        state.write_u32(self.event_key);
    }
}

/// Aligned storage for TDH schema bytes.
///
/// Backed by `Vec<u64>` so the base pointer is at least 8-byte aligned.
/// `byte_len` tracks the logical byte length written by TDH.
struct AlignedSchemaBuffer {
    words: Vec<u64>,
    byte_len: usize,
}

impl AlignedSchemaBuffer {
    fn new(byte_len: usize) -> Self {
        const _: () = assert!(
            align_of::<TRACE_EVENT_INFO>() == align_of::<u64>(),
            "TRACE_EVENT_INFO alignment changed — update AlignedSchemaBuffer word type"
        );
        let word_len = byte_len.div_ceil(size_of::<u64>());
        Self {
            words: vec![0u64; word_len],
            byte_len,
        }
    }

    #[inline]
    const fn as_ptr(&self) -> *const u8 {
        self.words.as_ptr().cast::<u8>()
    }

    #[inline]
    const fn as_mut_ptr(&mut self) -> *mut u8 {
        self.words.as_mut_ptr().cast::<u8>()
    }

    #[inline]
    const fn as_bytes(&self) -> &[u8] {
        debug_assert!(self.byte_len <= self.words.len() * size_of::<u64>());
        // SAFETY: `words` is a contiguous allocation and `byte_len` never exceeds
        // its byte capacity.
        unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast::<u8>(), self.byte_len) }
    }
}

/// Cached event schema information retrieved from TDH.
pub struct EventSchema {
    /// Raw buffer containing TRACE_EVENT_INFO and property data.
    buffer: AlignedSchemaBuffer,
    /// Number of properties in the event.
    property_count: u32,
    /// Number of top-level properties (excludes struct members).
    top_level_property_count: u32,
    /// Pre-converted UTF-8 property names for efficient `&str` lookups.
    ///
    /// Populated once during schema creation by converting the UTF-16 property
    /// names from the TDH buffer. This avoids repeated UTF-16 comparisons at
    /// event parse time and allows the public API to accept `&str` instead of
    /// `&[u16]`.
    property_names: Vec<Box<str>>,
    /// Property name to index lookup map for O(1) `get()` by name.
    ///
    /// Built once at schema creation from `property_names`. Uses `FxHashMap`
    /// for fast hashing of short ASCII property names.
    name_to_index: FxHashMap<Box<str>, u32>,
}

impl EventSchema {
    /// Returns a pointer to the underlying `TRACE_EVENT_INFO`.
    #[inline]
    pub(crate) const fn info_ptr(&self) -> *const TRACE_EVENT_INFO {
        self.buffer.as_ptr().cast()
    }

    /// Returns the number of properties in this event schema.
    #[inline]
    pub const fn property_count(&self) -> u32 {
        self.property_count
    }

    /// Returns the number of top-level properties.
    #[inline]
    pub const fn top_level_property_count(&self) -> u32 {
        self.top_level_property_count
    }

    /// Returns a property by index with O(1) access.
    ///
    /// Returns `None` if index is out of bounds.
    #[inline]
    pub const fn property(&self, index: u32) -> Option<PropertyInfo<'_>> {
        if index >= self.top_level_property_count {
            return None;
        }
        // SAFETY: We validated index is within bounds above,
        // and the buffer contains valid TRACE_EVENT_INFO data from TDH.
        // Use info_ptr() (raw pointer) as the provenance source so that pointer
        // arithmetic into EventPropertyInfoArray covers the full buffer under
        // Stacked Borrows / Tree Borrows.
        let prop = unsafe {
            let info_ptr = self.info_ptr();
            let props_ptr = std::ptr::addr_of!((*info_ptr).EventPropertyInfoArray)
                .cast::<EVENT_PROPERTY_INFO>();
            &*props_ptr.add(index as usize)
        };
        Some(PropertyInfo {
            schema: self,
            property: prop,
        })
    }

    /// Returns the pre-converted UTF-8 name of a property by index.
    ///
    /// Returns `None` if the index is out of bounds.
    #[inline]
    pub fn property_name(&self, index: u32) -> Option<&str> {
        self.property_names.get(index as usize).map(|s| &**s)
    }

    /// Returns the property index for the given name via O(1) hash lookup.
    ///
    /// Returns `None` if no property with that name exists.
    #[inline]
    pub fn property_index(&self, name: &str) -> Option<u32> {
        self.name_to_index.get(name).copied()
    }

    /// Returns a property by absolute index, including struct members.
    ///
    /// Unlike `property()`, which is limited to top-level properties, this
    /// method can access struct member properties that live at indices
    /// \>= `top_level_property_count`. Bounds-checked against total
    /// `property_count`.
    pub(crate) const fn property_raw(&self, index: u32) -> Option<PropertyInfo<'_>> {
        if index >= self.property_count {
            return None;
        }
        // SAFETY: We validated index is within total property_count above,
        // and the buffer contains valid TRACE_EVENT_INFO data from TDH.
        // Use info_ptr() (raw pointer) as the provenance source so that pointer
        // arithmetic into EventPropertyInfoArray covers the full buffer under
        // Stacked Borrows / Tree Borrows.
        let prop = unsafe {
            let info_ptr = self.info_ptr();
            let props_ptr = std::ptr::addr_of!((*info_ptr).EventPropertyInfoArray)
                .cast::<EVENT_PROPERTY_INFO>();
            &*props_ptr.add(index as usize)
        };
        Some(PropertyInfo {
            schema: self,
            property: prop,
        })
    }

    /// Returns an iterator over the event properties.
    pub fn properties(&self) -> impl Iterator<Item = PropertyInfo<'_>> {
        (0..self.top_level_property_count).map(move |i| {
            #[expect(
                clippy::unwrap_used,
                reason = "i is within bounds: the range is 0..top_level_property_count"
            )]
            self.property(i).unwrap()
        })
    }

    /// Returns a reference to the underlying TRACE_EVENT_INFO.
    const fn trace_event_info(&self) -> &TRACE_EVENT_INFO {
        // SAFETY: Buffer was allocated to hold TRACE_EVENT_INFO and validated by TDH.
        unsafe { &*self.buffer.as_ptr().cast::<TRACE_EVENT_INFO>() }
    }

    /// Reads a null-terminated UTF-16 string from the buffer at the given offset.
    fn read_string_at_offset(&self, offset: u32) -> Option<String> {
        let slice = self.read_utf16_slice_at_offset(offset)?;
        String::from_utf16(slice).ok()
    }

    /// Returns a UTF-16 slice at the given offset.
    ///
    /// The returned slice does not include the null terminator.
    fn read_utf16_slice_at_offset(&self, offset: u32) -> Option<&[u16]> {
        if offset == 0 {
            return None;
        }

        let bytes = self.buffer.as_bytes();
        let start = offset as usize;
        if start >= bytes.len() || !start.is_multiple_of(2) {
            return None;
        }

        let remaining = &bytes[start..];
        let max_units = remaining.len() / 2;
        if max_units == 0 {
            return Some(&[]);
        }

        let ptr = remaining.as_ptr().cast::<u16>();
        // SAFETY: Base allocation is 8-byte aligned and start is even, so ptr is u16-aligned.
        let units = unsafe { std::slice::from_raw_parts(ptr, max_units) };
        let len = units.iter().position(|&u| u == 0).unwrap_or(max_units);
        Some(&units[..len])
    }

    /// Returns the event name if available.
    pub fn event_name(&self) -> Option<String> {
        let info = self.trace_event_info();
        // SAFETY: Accessing the union field that contains EventNameOffset.
        let offset = unsafe { info.Anonymous1.EventNameOffset };
        self.read_string_at_offset(offset)
    }

    /// Returns the provider name if available.
    pub fn provider_name(&self) -> Option<String> {
        let info = self.trace_event_info();
        self.read_string_at_offset(info.ProviderNameOffset)
    }

    /// Returns the task name if available.
    pub fn task_name(&self) -> Option<String> {
        let info = self.trace_event_info();
        self.read_string_at_offset(info.TaskNameOffset)
    }

    /// Returns the opcode name if available.
    pub fn opcode_name(&self) -> Option<String> {
        let info = self.trace_event_info();
        self.read_string_at_offset(info.OpcodeNameOffset)
    }

    /// Returns the provider GUID from TDH.
    ///
    /// For MOF (classic kernel) providers, `EventHeader.ProviderId` contains
    /// the Message GUID, not the Provider GUID. This method returns the actual
    /// provider GUID from `TRACE_EVENT_INFO.ProviderGuid`.
    pub const fn provider_guid(&self) -> crate::Guid {
        crate::Guid::from_sys(self.trace_event_info().ProviderGuid)
    }

    /// Returns the event ID (0 for classic/MOF events).
    pub const fn event_id(&self) -> u16 {
        self.trace_event_info().EventDescriptor.Id
    }

    /// Returns the event version.
    pub const fn event_version(&self) -> u8 {
        self.trace_event_info().EventDescriptor.Version
    }

    /// Returns the event opcode (0 for informational manifest events).
    pub const fn event_opcode(&self) -> u8 {
        self.trace_event_info().EventDescriptor.Opcode
    }

    /// Returns the identity of this event, for use in error messages.
    pub(crate) const fn event_context(&self) -> EventContext {
        EventContext {
            provider: self.provider_guid(),
            id: self.event_id(),
            opcode: self.event_opcode(),
            version: self.event_version(),
        }
    }
}

/// Identifies the event an error came from.
///
/// Carries the identity as data and renders it only when displayed, so an
/// error that embeds it does not pay for formatting a caller may never read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EventContext {
    provider: crate::Guid,
    id: u16,
    opcode: u8,
    version: u8,
}

impl EventContext {
    /// Builds a context from a known event identity.
    ///
    /// Exists for the `provider_schema!` codegen, which knows all four values at
    /// compile time and so builds this as a constant rather than reading them
    /// back off an event at runtime.
    #[must_use]
    pub const fn new(provider: crate::Guid, id: u16, opcode: u8, version: u8) -> Self {
        Self {
            provider,
            id,
            opcode,
            version,
        }
    }

    /// The provider that emitted the event.
    #[must_use]
    pub const fn provider(&self) -> crate::Guid {
        self.provider
    }

    /// The event ID (0 for classic/MOF events).
    #[must_use]
    pub const fn id(&self) -> u16 {
        self.id
    }

    /// The event opcode (0 for informational manifest events).
    #[must_use]
    pub const fn opcode(&self) -> u8 {
        self.opcode
    }

    /// The event version.
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.version
    }
}

impl std::fmt::Display for EventContext {
    /// Renders `provider <guid> [id:<id>] [op:<opcode>] v<version>`, omitting
    /// `id` and `op` when zero.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "provider {}", self.provider)?;
        if self.id != 0 {
            write!(f, " id:{}", self.id)?;
        }
        if self.opcode != 0 {
            write!(f, " op:{}", self.opcode)?;
        }
        write!(f, " v{}", self.version)
    }
}

impl std::fmt::Debug for EventSchema {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let info = self.trace_event_info();
        let mut s = f.debug_struct("EventSchema");
        s.field("provider_guid", &crate::Guid::from_sys(info.ProviderGuid))
            .field("event_guid", &crate::Guid::from_sys(info.EventGuid))
            .field("decoding_source", &info.DecodingSource)
            .field("provider_name", &self.provider_name())
            .field("task_name", &self.task_name())
            .field("event_name", &self.event_name())
            .field("opcode_name", &self.opcode_name())
            .field("property_count", &self.property_count)
            .field("top_level_property_count", &self.top_level_property_count);

        // Collect properties into a Vec for debug formatting
        let properties: Vec<_> = self
            .properties()
            .map(|p| PropertyDebug {
                name: p.name(),
                in_type: p.in_type(),
                in_type_name: in_type_name(p.in_type()),
                length: p.length(),
                flags: p.flags(),
            })
            .collect();
        s.field("properties", &properties);

        s.finish_non_exhaustive()
    }
}

struct PropertyDebug {
    name: Option<String>,
    in_type: u16,
    in_type_name: &'static str,
    length: u16,
    flags: i32,
}

impl std::fmt::Debug for PropertyDebug {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?}: in_type={} ({}) length={} flags={:#X}",
            self.name, self.in_type, self.in_type_name, self.length, self.flags
        )
    }
}

/// Information about a single event property.
pub struct PropertyInfo<'a> {
    schema: &'a EventSchema,
    property: &'a EVENT_PROPERTY_INFO,
}

impl std::fmt::Debug for PropertyInfo<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PropertyInfo")
            .field("name", &self.name())
            .field("in_type", &in_type_name(self.in_type()))
            .field("length", &self.length())
            .finish()
    }
}

impl PropertyInfo<'_> {
    /// Returns the property name as an allocated String.
    pub fn name(&self) -> Option<String> {
        self.schema.read_string_at_offset(self.property.NameOffset)
    }

    /// Returns the TDH input type for this property.
    ///
    /// Returns 0 (Null) for struct properties — struct properties store
    /// `StructStartIndex` in the same union field as `InType`.
    ///
    /// Pass the returned value to [`crate::TdhInType::from_raw`] to get the
    /// typed enum. See [`crate::TdhInType`] for the full list of values.
    pub const fn in_type(&self) -> u16 {
        if self.is_struct() {
            return 0; // Null — struct properties have no in_type
        }
        // SAFETY: Not a struct, so nonStructType is the active variant.
        unsafe { self.property.Anonymous1.nonStructType.InType }
    }

    /// Returns the TDH output type for this property.
    ///
    /// Returns 0 (Null) for struct properties.
    pub const fn out_type(&self) -> u16 {
        if self.is_struct() {
            return 0; // Null — struct properties have no out_type
        }
        // SAFETY: Not a struct, so nonStructType is the active variant.
        unsafe { self.property.Anonymous1.nonStructType.OutType }
    }

    /// Returns the property flags.
    pub const fn flags(&self) -> PROPERTY_FLAGS {
        self.property.Flags
    }

    /// Returns the property length in bytes, or 0 if variable-length.
    pub const fn length(&self) -> u16 {
        // SAFETY: Accessing the length union variant.
        unsafe { self.property.Anonymous3.length }
    }

    /// Returns true if this property is a structure containing nested properties.
    pub const fn is_struct(&self) -> bool {
        (self.property.Flags & PropertyStruct) != 0
    }

    /// Returns the starting index of the struct's member properties.
    ///
    /// Only valid when `is_struct()` returns true. The members occupy
    /// indices `struct_start_index()..struct_start_index() + struct_member_count()`
    /// in the schema's property array.
    pub const fn struct_start_index(&self) -> u16 {
        // SAFETY: When PropertyStruct is set, Anonymous1 contains structType.
        unsafe { self.property.Anonymous1.structType.StructStartIndex }
    }

    /// Returns the number of member properties in this struct.
    ///
    /// Only valid when `is_struct()` returns true.
    pub const fn struct_member_count(&self) -> u16 {
        // SAFETY: When PropertyStruct is set, Anonymous1 contains structType.
        unsafe { self.property.Anonymous1.structType.NumOfStructMembers }
    }

    /// Returns the raw TDH count field. A value of 0 means scalar (treat as 1);
    /// values > 1 indicate a static array. Not valid when `has_param_count()` is true.
    pub const fn count(&self) -> u16 {
        // SAFETY: Accessing the count union variant.
        unsafe { self.property.Anonymous2.count }
    }

    /// Returns true if property length is specified by another property.
    ///
    /// When true, use `length_property_index()` to get the index of the
    /// property containing the length value.
    pub const fn has_param_length(&self) -> bool {
        (self.property.Flags & PropertyParamLength) != 0
    }

    /// Returns true if property array count is specified by another property.
    ///
    /// When true, use `count_property_index()` to get the index of the
    /// property containing the count value.
    pub const fn has_param_count(&self) -> bool {
        (self.property.Flags & PropertyParamCount) != 0
    }

    /// Returns the index of the property containing this property's length.
    ///
    /// Only valid when `has_param_length()` returns true.
    pub const fn length_property_index(&self) -> u16 {
        // SAFETY: When PropertyParamLength is set, Anonymous3 contains lengthPropertyIndex.
        unsafe { self.property.Anonymous3.lengthPropertyIndex }
    }

    /// Returns the index of the property containing this property's array count.
    ///
    /// Only valid when `has_param_count()` returns true.
    pub const fn count_property_index(&self) -> u16 {
        // SAFETY: When PropertyParamCount is set, Anonymous2 contains countPropertyIndex.
        unsafe { self.property.Anonymous2.countPropertyIndex }
    }
}

/// Cache for event schemas to avoid repeated TDH lookups.
///
/// Each schema is paired with the parser cache holding its computed property
/// locations. Pointer size is part of the key, so an entry's offsets always match
/// the bitness they were built for. Since ETW callbacks are single-threaded, the
/// cache can be borrowed mutably without synchronisation.
///
/// Note: This cache is not `Sync` or `Send`. Use separate caches per thread,
/// or wrap in a mutex if shared access is required.
pub struct ProcessingContext {
    cache: FxHashMap<SchemaKey, (EventSchema, ParserCache)>,
}

impl Default for ProcessingContext {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ProcessingContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProcessingContext")
            .field("cached_schemas", &self.cache.len())
            .finish()
    }
}

impl ProcessingContext {
    /// Creates a new empty schema cache.
    ///
    /// Uses FxHash for optimal performance with trusted ETW data.
    #[inline]
    pub fn new() -> Self {
        Self {
            cache: FxHashMap::default(),
        }
    }

    /// Creates a new schema cache with pre-allocated capacity.
    ///
    /// Pre-allocating capacity can reduce reallocations during cache population.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            cache: FxHashMap::with_capacity_and_hasher(capacity, FxBuildHasher),
        }
    }

    /// Looks up or retrieves the schema for an event.
    ///
    /// If the schema is already cached, returns a reference to it.
    /// Otherwise, calls TDH to retrieve the schema and caches it.
    ///
    /// # Errors
    ///
    /// Returns error if TDH lookup fails (e.g., schema not found).
    pub fn get_or_lookup(&mut self, event: &RawEvent) -> Result<&EventSchema> {
        self.get_or_lookup_raw(event.as_raw())
    }

    /// Looks up or retrieves the schema for a raw EVENT_RECORD.
    ///
    /// # Errors
    ///
    /// Returns error if TDH lookup fails (e.g., schema not found).
    pub fn get_or_lookup_raw(&mut self, event: &EVENT_RECORD) -> Result<&EventSchema> {
        use std::collections::hash_map::Entry;

        let pointer_size = pointer_size_from_flags(event.EventHeader.Flags as u32);
        let key = SchemaKey::from_event_record(event);

        match self.cache.entry(key) {
            Entry::Occupied(entry) => Ok(&entry.into_mut().0),
            Entry::Vacant(entry) => {
                let schema = lookup_event_schema(event)?;
                let mut cache = ParserCache::new(schema.top_level_property_count());
                cache.prepopulate_fixed(&schema, pointer_size as usize);
                Ok(&entry.insert((schema, cache)).0)
            }
        }
    }

    /// Returns the number of cached entries.
    ///
    /// Pointer size is part of the cache key, so an event type seen from both a
    /// 32-bit and a 64-bit process counts twice — each bitness needs its own
    /// schema and offset table.
    #[inline]
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Returns true if the cache is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Clears all cached schemas.
    #[inline]
    pub fn clear(&mut self) {
        self.cache.clear();
    }

    /// Returns an `EventParser` for the given event.
    ///
    /// This is a convenience method that combines schema lookup and parser creation.
    /// The parser borrows both the schema and its associated parser cache from this
    /// `ProcessingContext`, enabling efficient reuse across events of the same type.
    ///
    /// The parser cache is selected (or lazily created) based on the event's
    /// pointer size (32-bit vs 64-bit), since precomputed property offsets
    /// differ for `Pointer` and `SizeT` types.
    ///
    /// # Errors
    ///
    /// Returns error if schema lookup fails.
    pub fn parser<'a>(&'a mut self, event: &'a RawEvent) -> Result<EventParser<'a>> {
        use std::collections::hash_map::Entry;

        let raw = event.as_raw();
        let pointer_size = pointer_size_from_flags(raw.EventHeader.Flags as u32);
        let key = SchemaKey::from_event_record(raw);

        let (schema, cache) = match self.cache.entry(key) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let schema = lookup_event_schema(raw)?;
                let mut cache = ParserCache::new(schema.top_level_property_count());
                cache.prepopulate_fixed(&schema, pointer_size as usize);
                entry.insert((schema, cache))
            }
        };

        Ok(EventParser::new(event, schema, cache))
    }
}

/// Looks up event schema information using TDH.
///
/// Returns the schema. The caller pairs it with a `ParserCache` built for the
/// event's pointer size, which is part of the cache key.
///
/// # Errors
///
/// Returns error if the schema cannot be found or TDH API fails.
fn lookup_event_schema(event: &EVENT_RECORD) -> Result<EventSchema> {
    let mut buffer_size: u32 = 0;

    // First call to determine required buffer size
    // SAFETY: Passing valid event pointer and size output pointer.
    // TdhGetEventInformation is a Win32 API that retrieves event metadata.
    let status = unsafe {
        TdhGetEventInformation(
            std::ptr::from_ref::<EVENT_RECORD>(event),
            0,
            std::ptr::null(),
            std::ptr::null_mut(),
            &raw mut buffer_size,
        )
    };

    if status != ERROR_INSUFFICIENT_BUFFER {
        return Err(Error::from_win32(status));
    }

    // TDH must report a buffer large enough for at least the fixed header.
    if (buffer_size as usize) < size_of::<TRACE_EVENT_INFO>() {
        return Err(Error::parse(format!(
            "TDH reported buffer size {buffer_size} is smaller than TRACE_EVENT_INFO header"
        )));
    }

    // Allocate aligned buffer.
    let mut buffer = AlignedSchemaBuffer::new(buffer_size as usize);
    let info_ptr = buffer.as_mut_ptr().cast::<TRACE_EVENT_INFO>();

    // Second call to retrieve the data
    // SAFETY: Buffer is properly sized based on the first call.
    // info_ptr points to valid, zeroed memory of the required size.
    let status = unsafe {
        TdhGetEventInformation(
            std::ptr::from_ref::<EVENT_RECORD>(event),
            0,
            std::ptr::null(),
            info_ptr,
            &raw mut buffer_size,
        )
    };

    if status != ERROR_SUCCESS {
        return Err(Error::from_win32(status));
    }

    // TDH may update buffer_size to the bytes actually written (should only decrease).
    let actual_size = buffer_size as usize;
    if actual_size > buffer.byte_len {
        return Err(Error::parse(format!(
            "TDH wrote {actual_size} bytes but buffer was only {} bytes",
            buffer.byte_len
        )));
    }
    buffer.byte_len = actual_size;

    // SAFETY: TdhGetEventInformation succeeded, so info_ptr contains valid data.
    let info = unsafe { &*info_ptr };

    // Validate that the property array fits within the allocated buffer.
    // EventPropertyInfoArray is a flexible array at the end of TRACE_EVENT_INFO.
    {
        let array_offset = std::mem::offset_of!(TRACE_EVENT_INFO, EventPropertyInfoArray);
        let prop_size = size_of::<EVENT_PROPERTY_INFO>();
        let required = array_offset + prop_size.saturating_mul(info.PropertyCount as usize);
        if required > buffer.byte_len {
            return Err(Error::parse(format!(
                "TDH PropertyCount {} exceeds buffer (need {required}, have {})",
                info.PropertyCount, buffer.byte_len
            )));
        }
    }

    // TopLevelPropertyCount must not exceed PropertyCount (top-level properties
    // are a prefix of the full property array; the remainder are struct members).
    // TDH should always satisfy this, but validate defensively.
    if info.TopLevelPropertyCount > info.PropertyCount {
        return Err(Error::parse(format!(
            "TDH TopLevelPropertyCount ({}) exceeds PropertyCount ({})",
            info.TopLevelPropertyCount, info.PropertyCount
        )));
    }

    // Pre-convert UTF-16 property names to UTF-8 for efficient &str lookups.
    // This one-time cost (typically 5-20 properties) is amortised over all
    // events sharing this schema key.
    //
    // Only top-level properties are indexed by name. Struct members are accessed
    // positionally via `struct_members()`, not by name lookup, so they are
    // intentionally excluded from `property_names` and `name_to_index`.
    let property_names = {
        let top = info.TopLevelPropertyCount;
        let mut names = Vec::with_capacity(top as usize);
        // SAFETY: info_ptr is a valid non-null pointer into the AlignedSchemaBuffer.
        // Using it as the provenance source for EventPropertyInfoArray ensures pointer
        // arithmetic covers the full allocation under Stacked Borrows / Tree Borrows.
        let props_ptr = unsafe {
            std::ptr::addr_of!((*info_ptr).EventPropertyInfoArray).cast::<EVENT_PROPERTY_INFO>()
        };
        for i in 0..top {
            // SAFETY: i is within TopLevelPropertyCount, buffer comes from TDH.
            let prop = unsafe { &*props_ptr.add(i as usize) };
            let offset = prop.NameOffset;
            let name = if offset == 0 {
                String::new()
            } else {
                let start = offset as usize;
                let bytes = buffer.as_bytes();
                if start < bytes.len() && start.is_multiple_of(2) {
                    let remaining = &bytes[start..];
                    let max_units = remaining.len() / 2;
                    if max_units == 0 {
                        String::new()
                    } else {
                        let ptr = remaining.as_ptr().cast::<u16>();
                        // SAFETY: Base allocation is 8-byte aligned and start is even.
                        let units = unsafe { std::slice::from_raw_parts(ptr, max_units) };
                        let len = units.iter().position(|&u| u == 0).unwrap_or(max_units);
                        String::from_utf16_lossy(&units[..len])
                    }
                } else {
                    String::new()
                }
            };
            names.push(name.into_boxed_str());
        }
        names
    };

    let name_to_index: FxHashMap<Box<str>, u32> = property_names
        .iter()
        .enumerate()
        .map(|(i, name)| (name.clone(), i as u32))
        .collect();

    // In the event of duplicate property names, the last index wins silently.
    // This is unusual but can occur in some MOF providers.
    debug_assert!(
        name_to_index.len() == property_names.len(),
        "Schema has duplicate property names: {} names, {} unique",
        property_names.len(),
        name_to_index.len()
    );

    let schema = EventSchema {
        buffer,
        property_count: info.PropertyCount,
        top_level_property_count: info.TopLevelPropertyCount,
        property_names,
        name_to_index,
    };

    Ok(schema)
}

/// Computes the total byte size of a struct property by summing its members.
///
/// Returns `None` if any member is variable-length (has param_length, param_count,
/// nested struct with variable members, or a variable-length type with no declared length).
///
/// # Safety
///
/// `props_ptr` must point to the schema's `EVENT_PROPERTY_INFO` array holding
/// `property_count` valid elements, as returned by a successful TDH call.
unsafe fn compute_struct_byte_size_raw(
    props_ptr: *const EVENT_PROPERTY_INFO,
    start: u16,
    count: u16,
    property_count: u32,
    pointer_size: usize,
) -> Option<u32> {
    use crate::types::TdhInType;

    // The struct's member range (StructStartIndex / NumOfStructMembers) is taken
    // verbatim from the TDH-reported schema and is not otherwise validated. Reject
    // a range that would index past the property array before dereferencing any
    // member — the dynamic path (parser::compute_struct_size via property_raw) is
    // bounds-checked the same way.
    let end = u32::from(start).checked_add(u32::from(count))?;
    if end > property_count {
        return None;
    }

    let mut total = 0u32;
    for i in (start as u32)..(start as u32 + count as u32) {
        // SAFETY: `end <= property_count` verified above, so every index in
        // `start..end` is within the `property_count`-element array.
        let member = unsafe { &*props_ptr.add(i as usize) };
        let mflags = member.Flags;

        // A fixed prefix cannot span a nested struct or a property whose length or count is
        // resolved from another property.
        if (mflags & (PropertyStruct | PropertyParamLength | PropertyParamCount)) != 0 {
            return None;
        }

        // SAFETY: Not a struct property (checked above), so nonStructType is the active variant.
        let in_type_raw = unsafe { member.Anonymous1.nonStructType.InType };
        // SAFETY: This branch is for non-param-length properties, so `length` is active.
        let length = unsafe { member.Anonymous3.length };
        let size = if length > 0 {
            length as u32
        } else {
            let in_type = TdhInType::from_raw(in_type_raw);
            in_type.fixed_size(pointer_size)? as u32
        };

        // SAFETY: This branch is for non-param-count properties, so `count` is active.
        let n = unsafe { member.Anonymous2.count };
        let n = if n == 0 { 1 } else { n as u32 };
        total = total.checked_add(size.checked_mul(n)?)?;
    }
    Some(total)
}

/// Computes the fixed prefix info for a schema.
///
/// Returns (first_variable_index, fixed_prefix_size).
///
/// A property is "fixed-size" if:
/// - It doesn't have PropertyParamLength flag (length not specified by another property)
/// - AND either has a non-zero declared length OR has a fixed-size TDH type
pub(crate) fn compute_fixed_prefix_info(
    info_ptr: *const TRACE_EVENT_INFO,
    top_level_count: u32,
    property_count: u32,
    pointer_size: usize,
) -> (u32, usize) {
    use crate::types::TdhInType;

    let mut fixed_prefix_size: usize = 0;

    for idx in 0..top_level_count {
        // SAFETY: We know idx is within bounds, and info_ptr is valid from TDH.
        let prop = unsafe {
            let props_ptr = std::ptr::addr_of!((*info_ptr).EventPropertyInfoArray)
                .cast::<EVENT_PROPERTY_INFO>();
            &*props_ptr.add(idx as usize)
        };

        let flags = prop.Flags;

        let is_struct = (flags & PropertyStruct) != 0;
        let has_param_length = (flags & PropertyParamLength) != 0;
        let has_param_count = (flags & PropertyParamCount) != 0;

        if has_param_length || has_param_count {
            // Variable size — stop here
            return (idx, fixed_prefix_size);
        }

        // Static array count: if PropertyParamCount is not set, the count union
        // field holds a static element count (0 or 1 means single element).
        // SAFETY: Accessing the count union variant.
        let static_count = unsafe { prop.Anonymous2.count } as usize;
        let multiplier = if static_count > 1 { static_count } else { 1 };

        if is_struct {
            // Compute struct size by summing member sizes.
            // SAFETY: is_struct flag checked, so structType is the active variant.
            let start = unsafe { prop.Anonymous1.structType.StructStartIndex };
            // SAFETY: is_struct flag checked, so structType is the active variant.
            let count = unsafe { prop.Anonymous1.structType.NumOfStructMembers };
            // SAFETY: info_ptr is valid from TDH, dereferencing to access the flexible array.
            let props_ptr = unsafe {
                std::ptr::addr_of!((*info_ptr).EventPropertyInfoArray).cast::<EVENT_PROPERTY_INFO>()
            };
            if let Some(size) =
                // SAFETY: props_ptr points at the schema's property_count-element
                // array; compute_struct_byte_size_raw validates start/count against
                // property_count before indexing.
                unsafe {
                    compute_struct_byte_size_raw(
                        props_ptr,
                        start,
                        count,
                        property_count,
                        pointer_size,
                    )
                }
            {
                fixed_prefix_size += size as usize * multiplier;
                continue;
            }
            // Contains variable-length members — stop here
            return (idx, fixed_prefix_size);
        }

        // SAFETY: Accessing the length union variant
        let declared_length = unsafe { prop.Anonymous3.length } as usize;
        if declared_length > 0 {
            // Fixed size via declared length (per-element size × count)
            fixed_prefix_size += declared_length * multiplier;
            continue;
        }

        // Check if the type has a fixed size
        // SAFETY: Accessing nonStructType union variant
        let in_type_raw = unsafe { prop.Anonymous1.nonStructType.InType };
        let in_type = TdhInType::from_raw(in_type_raw);

        if let Some(size) = in_type.fixed_size(pointer_size) {
            fixed_prefix_size += size * multiplier;
            continue;
        }

        // Variable length type with no declared length — stop here
        return (idx, fixed_prefix_size);
    }

    // All properties are fixed-size
    (top_level_count, fixed_prefix_size)
}

/// Looks up the schema for an event using TDH (without caching).
///
/// This is useful for debugging or one-off schema lookups. For repeated
/// lookups, use `ProcessingContext::get_or_lookup` instead.
///
/// # Errors
///
/// Returns error if the schema cannot be found or TDH API fails.
pub fn lookup_schema(event: &crate::RawEvent) -> Result<EventSchema> {
    lookup_event_schema(event.as_raw())
}

/// Returns the name of a TDH input type.
pub const fn in_type_name(in_type: u16) -> &'static str {
    match in_type {
        0 => "Null",
        1 => "UnicodeString",
        2 => "AnsiString",
        3 => "Int8",
        4 => "UInt8",
        5 => "Int16",
        6 => "UInt16",
        7 => "Int32",
        8 => "UInt32",
        9 => "Int64",
        10 => "UInt64",
        11 => "Float",
        12 => "Double",
        13 => "Boolean",
        14 => "Binary",
        15 => "GUID",
        16 => "Pointer",
        17 => "FileTime",
        18 => "SystemTime",
        19 => "SID",
        20 => "HexInt32",
        21 => "HexInt64",
        // Manifest types (22-25)
        22 => "ManifestCountedString",
        23 => "ManifestCountedAnsiString",
        24 => "Reserved24",
        25 => "ManifestCountedBinary",
        // WBEM types (300-310)
        300 => "CountedString",
        301 => "CountedAnsiString",
        302 => "ReversedCountedString",
        303 => "ReversedCountedAnsiString",
        304 => "NonNullTerminatedString",
        305 => "NonNullTerminatedAnsiString",
        306 => "UnicodeChar",
        307 => "AnsiChar",
        308 => "SizeT",
        309 => "HexDump",
        310 => "WbemSid",
        _ => "Unknown",
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::undocumented_unsafe_blocks,
    clippy::decimal_bitwise_operands,
    reason = "test-only assertions"
)]
mod tests {
    use super::*;

    #[test]
    fn test_processing_context_new() {
        let cache = ProcessingContext::new();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_in_type_name() {
        assert_eq!(in_type_name(1), "UnicodeString");
        assert_eq!(in_type_name(8), "UInt32");
        assert_eq!(in_type_name(16), "Pointer");
        // Manifest types (22-25)
        assert_eq!(in_type_name(22), "ManifestCountedString");
        assert_eq!(in_type_name(23), "ManifestCountedAnsiString");
        assert_eq!(in_type_name(25), "ManifestCountedBinary");
        // WBEM types (300-310)
        assert_eq!(in_type_name(300), "CountedString");
        assert_eq!(in_type_name(301), "CountedAnsiString");
        assert_eq!(in_type_name(310), "WbemSid");
        // Unknown types
        assert_eq!(in_type_name(99), "Unknown");
        assert_eq!(in_type_name(999), "Unknown");
    }

    #[test]
    fn test_in_type_name_all_variants() {
        // Cover every numeric branch in in_type_name() to remove uncovered arms.
        let cases: &[(u16, &str)] = &[
            (1, "UnicodeString"),
            (2, "AnsiString"),
            (3, "Int8"),
            (4, "UInt8"),
            (5, "Int16"),
            (6, "UInt16"),
            (7, "Int32"),
            (8, "UInt32"),
            (9, "Int64"),
            (10, "UInt64"),
            (11, "Float"),
            (12, "Double"),
            (13, "Boolean"),
            (14, "Binary"),
            (15, "GUID"),
            (16, "Pointer"),
            (17, "FileTime"),
            (18, "SystemTime"),
            (19, "SID"),
            (20, "HexInt32"),
            (21, "HexInt64"),
            (22, "ManifestCountedString"),
            (23, "ManifestCountedAnsiString"),
            (24, "Reserved24"),
            (25, "ManifestCountedBinary"),
            (300, "CountedString"),
            (301, "CountedAnsiString"),
            (302, "ReversedCountedString"),
            (303, "ReversedCountedAnsiString"),
            (304, "NonNullTerminatedString"),
            (305, "NonNullTerminatedAnsiString"),
            (306, "UnicodeChar"),
            (307, "AnsiChar"),
            (308, "SizeT"),
            (309, "HexDump"),
            (310, "WbemSid"),
        ];
        for &(raw, expected) in cases {
            assert_eq!(in_type_name(raw), expected, "in_type_name({raw})");
        }
    }

    #[test]
    fn test_schema_key_hash_uniqueness() {
        use std::collections::HashSet;

        // Helper to pack event_key
        let pack = |id: u16, version: u8, _opcode: u8| -> u32 {
            // Non-classic, so the discriminator is Id and no flag bits are set.
            (id as u32) | ((version as u32) << 16)
        };

        // Verify different keys produce different hash results
        let key1 = SchemaKey {
            provider_guid: crate::Guid::from_u128(0x1234),
            event_key: pack(1, 1, 2),
        };
        let key2 = SchemaKey {
            provider_guid: crate::Guid::from_u128(0x1234),
            event_key: pack(1, 2, 2), // Different version
        };
        let key3 = SchemaKey {
            provider_guid: crate::Guid::from_u128(0x5678),
            event_key: pack(1, 1, 2), // Different GUID
        };

        let mut set = HashSet::new();
        assert!(set.insert(key1));
        assert!(set.insert(key2));
        assert!(set.insert(key3));
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn test_schema_key_collision_rate() {
        use std::collections::HashSet;

        // Helper to pack event_key
        let pack = |id: u16, version: u8, _opcode: u8| -> u32 {
            // Non-classic, so the discriminator is Id and no flag bits are set.
            (id as u32) | ((version as u32) << 16)
        };

        // Generate 1000 realistic keys and check collision rate
        let keys: Vec<_> = (0..1000)
            .map(|i| SchemaKey {
                provider_guid: crate::Guid::from_u128((i as u128) * 0x123456789ABCDEF),
                event_key: pack((i % 1000) as u16, 1, ((i / 1000) % 256) as u8),
            })
            .collect();

        let unique: HashSet<_> = keys.iter().collect();
        assert_eq!(unique.len(), 1000); // No collisions in key equality
    }

    #[test]
    fn test_schema_key_equality() {
        // Helper to pack event_key
        let pack = |id: u16, version: u8, _opcode: u8| -> u32 {
            // Non-classic, so the discriminator is Id and no flag bits are set.
            (id as u32) | ((version as u32) << 16)
        };

        let key1 = SchemaKey {
            provider_guid: crate::Guid::from_u128(0x1234),
            event_key: pack(1, 1, 2),
        };
        let key2 = SchemaKey {
            provider_guid: crate::Guid::from_u128(0x1234),
            event_key: pack(1, 1, 2),
        };
        let key3 = SchemaKey {
            provider_guid: crate::Guid::from_u128(0x5678),
            event_key: pack(1, 1, 2),
        };

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    // =========================================================================
    // ProcessingContext: Default, Debug, with_capacity, clear
    // =========================================================================

    #[test]
    fn test_processing_context_default() {
        let ctx = ProcessingContext::default();
        assert!(ctx.is_empty());
    }

    #[test]
    fn test_processing_context_debug() {
        let ctx = ProcessingContext::new();
        let s = format!("{ctx:?}");
        assert!(s.contains("ProcessingContext"));
        assert!(s.contains("cached_schemas"));
    }

    #[test]
    fn test_processing_context_with_capacity() {
        let ctx = ProcessingContext::with_capacity(64);
        assert!(ctx.is_empty());
    }

    #[test]
    fn test_processing_context_clear() {
        // We can't easily insert real schemas without TDH, so use is_empty / len
        // after clear on a fresh context.
        let mut ctx = ProcessingContext::new();
        assert!(ctx.is_empty());
        ctx.clear();
        assert!(ctx.is_empty());
    }

    // =========================================================================
    // EventSchema / PropertyInfo via MockSchemaBuilder
    // =========================================================================

    #[test]
    fn test_event_schema_property_count() {
        use crate::types::{TdhInType, TdhOutType};
        let schema = mock::MockSchemaBuilder::new()
            .add("Pid", TdhInType::UInt32, TdhOutType::Null)
            .add("Name", TdhInType::UnicodeString, TdhOutType::Null)
            .build();
        assert_eq!(schema.property_count(), 2);
        assert_eq!(schema.top_level_property_count(), 2);
    }

    #[test]
    fn test_event_schema_string_accessors_return_none_for_mock() {
        // MockSchemaBuilder leaves ProviderNameOffset / EventNameOffset at 0 (no string).
        // read_string_at_offset(0) returns None, exercising the None branch.
        use crate::types::{TdhInType, TdhOutType};
        let schema = mock::MockSchemaBuilder::new()
            .add("Pid", TdhInType::UInt32, TdhOutType::Null)
            .build();
        assert!(schema.provider_name().is_none());
        assert!(schema.event_name().is_none());
        assert!(schema.task_name().is_none());
        assert!(schema.opcode_name().is_none());
    }

    #[test]
    fn test_event_schema_debug() {
        use crate::types::{TdhInType, TdhOutType};
        let schema = mock::MockSchemaBuilder::new()
            .add("Pid", TdhInType::UInt32, TdhOutType::Null)
            .build();
        // Exercises EventSchema::fmt and PropertyDebug::fmt.
        let s = format!("{schema:?}");
        assert!(s.contains("EventSchema"));
        assert!(s.contains("property_count"));
    }

    #[test]
    fn test_property_info_debug_and_flags() {
        use crate::types::{TdhInType, TdhOutType};
        let schema = mock::MockSchemaBuilder::new()
            .add("Pid", TdhInType::UInt32, TdhOutType::Null)
            .build();
        let prop = schema.property(0).expect("property 0 exists");
        // PropertyInfo::flags getter
        let _flags = prop.flags();
        // PropertyInfo Debug format
        let s = format!("{prop:?}");
        assert!(s.contains("PropertyInfo"));
    }

    #[test]
    fn test_event_schema_numeric_accessors() {
        // MockSchemaBuilder leaves TRACE_EVENT_INFO numeric fields at zero.
        // This covers event_id(), event_opcode(), event_version(), provider_guid().
        use crate::types::{TdhInType, TdhOutType};
        let schema = mock::MockSchemaBuilder::new()
            .add("Pid", TdhInType::UInt32, TdhOutType::Null)
            .build();
        assert_eq!(schema.event_id(), 0);
        assert_eq!(schema.event_opcode(), 0);
        assert_eq!(schema.event_version(), 0);
        // provider_guid returns zeroed GUID
        let zero_guid = windows_sys::core::GUID::from_u128(0);
        assert_eq!(schema.provider_guid(), crate::Guid::from_sys(zero_guid));
        // event_context renders provider guid + id/opcode/version
        let ctx = schema.event_context().to_string();
        assert!(ctx.starts_with("provider"), "got: {ctx}");
    }

    #[test]
    fn test_pointer_size_from_flags() {
        // 32-bit flag: EVENT_HEADER_FLAG_32_BIT_HEADER = 0x20
        assert_eq!(pointer_size_from_flags(0x20), 4);
        // 64-bit (no flag)
        assert_eq!(pointer_size_from_flags(0x00), 8);
        // Other flags set, no 32-bit flag
        assert_eq!(pointer_size_from_flags(0xFF & !0x20), 8);
    }

    #[test]
    fn test_event_schema_property_out_of_bounds_returns_none() {
        use crate::types::{TdhInType, TdhOutType};
        let schema = mock::MockSchemaBuilder::new()
            .add("Pid", TdhInType::UInt32, TdhOutType::Null)
            .build();
        // Index 0 is valid, index 1 is out of bounds for a 1-property schema.
        assert!(schema.property(0).is_some());
        assert!(schema.property(1).is_none());
    }

    #[test]
    fn test_event_schema_property_raw_out_of_bounds_returns_none() {
        use crate::types::{TdhInType, TdhOutType};
        let schema = mock::MockSchemaBuilder::new()
            .add("Pid", TdhInType::UInt32, TdhOutType::Null)
            .build();
        assert!(schema.property_raw(0).is_some());
        assert!(schema.property_raw(1).is_none());
    }

    #[test]
    fn test_event_schema_properties_iterator() {
        use crate::types::{TdhInType, TdhOutType};
        let schema = mock::MockSchemaBuilder::new()
            .add("Pid", TdhInType::UInt32, TdhOutType::Null)
            .add("Name", TdhInType::UnicodeString, TdhOutType::Null)
            .build();
        let names: Vec<_> = schema.properties().filter_map(|p| p.name()).collect();
        assert_eq!(names, vec!["Pid", "Name"]);
    }

    #[test]
    fn test_event_context_with_nonzero_id_and_opcode() {
        use crate::types::{TdhInType, TdhOutType};
        let schema = mock::MockSchemaBuilder::new()
            .add("Val", TdhInType::UInt32, TdhOutType::Null)
            .with_event_descriptor(42, 2, 7)
            .build();
        assert_eq!(schema.event_id(), 42);
        assert_eq!(schema.event_version(), 2);
        assert_eq!(schema.event_opcode(), 7);
        let ctx = schema.event_context().to_string();
        assert!(ctx.contains("id:42"), "got: {ctx}");
        assert!(ctx.contains("op:7"), "got: {ctx}");
        assert!(ctx.contains("v2"), "got: {ctx}");
    }

    #[test]
    fn test_property_info_in_type_struct_returns_zero() {
        use crate::types::{TdhInType, TdhOutType};
        let schema = mock::MockSchemaBuilder::new()
            .add_struct("Inner", &[("X", TdhInType::UInt32, TdhOutType::Null, 0)])
            .build();
        // The struct placeholder is top-level property 0; in_type() for a struct returns 0.
        let prop = schema.property(0).expect("struct placeholder exists");
        assert!(prop.is_struct(), "should be a struct property");
        assert_eq!(prop.in_type(), 0, "struct in_type should be 0 (Null)");
    }

    #[test]
    fn test_schema_key_from_event_record() {
        use windows_sys::Win32::System::Diagnostics::Etw::EVENT_RECORD;

        let mut record: EVENT_RECORD = unsafe { std::mem::zeroed() };
        record.EventHeader.EventDescriptor.Id = 99;
        record.EventHeader.EventDescriptor.Version = 2;
        record.EventHeader.EventDescriptor.Opcode = 5;

        // Manifest: the discriminator slot holds Id.
        let manifest = 99u32 | (2u32 << 16);
        assert_eq!(SchemaKey::from_event_record(&record).event_key, manifest);

        // Classic: the same slot holds Opcode instead, and CLASSIC lands in bit 27.
        // Proves the arithmetic select works and that the two regimes cannot share
        // a key even when one event's Id equals another's Opcode.
        record.EventHeader.Flags = EVENT_HEADER_FLAG_CLASSIC_HEADER as u16;
        let classic = SchemaKey::from_event_record(&record).event_key;
        assert_eq!(classic, 5u32 | (2u32 << 16) | (1u32 << 27));
        assert_ne!(classic, manifest);

        // Bitness bits land in 24 and 25, and do not disturb the discriminator.
        record.EventHeader.Flags = EVENT_HEADER_FLAG_32_BIT_HEADER as u16;
        assert_eq!(
            SchemaKey::from_event_record(&record).event_key,
            manifest | (1u32 << 24)
        );
        record.EventHeader.Flags = EVENT_HEADER_FLAG_64_BIT_HEADER as u16;
        assert_eq!(
            SchemaKey::from_event_record(&record).event_key,
            manifest | (1u32 << 25)
        );

        // Every other flag bit is masked out: only bitness and CLASSIC_HEADER
        // distinguish schemas in this cache.
        for bit in 0..16u16 {
            let flag = 1u16 << bit;
            if flag & SCHEMA_FLAGS != 0 {
                continue;
            }
            record.EventHeader.Flags = flag;
            assert_eq!(
                SchemaKey::from_event_record(&record).event_key,
                manifest,
                "flag 0x{flag:04X} is not schema-relevant and must be masked out"
            );
        }

        // A realistic MOF record: Opcode in the slot, classic and bitness bits set,
        // per-record and session bits dropped.
        record.EventHeader.Flags = EVENT_HEADER_FLAG_CLASSIC_HEADER as u16
            | EVENT_HEADER_FLAG_64_BIT_HEADER as u16
            | 0x0010 // NO_CPUTIME
            | 0x0001 // EXTENDED_INFO
            | 0x0200; // PROCESSOR_INDEX
        let key = SchemaKey::from_event_record(&record).event_key;
        assert_eq!(key, 5u32 | (2u32 << 16) | (1u32 << 25) | (1u32 << 27));
        assert_eq!(key >> 28, 0, "bits 28..31 must stay spare");
    }
}

// =============================================================================
// Mock schema builder for tests
// =============================================================================

#[cfg(test)]
#[expect(
    unreachable_pub,
    reason = "test-only mock module reachable within the crate"
)]
pub(crate) mod mock {
    use super::*;
    use crate::types::{TdhInType, TdhOutType};

    struct MockProperty {
        name: String,
        in_type: TdhInType,
        out_type: TdhOutType,
        length: u16,
        flags: u32,
        length_property_index: u16,
        count_property_index: u16,
        static_count: u16,
    }

    struct MockStructDef {
        /// Member definitions: (name, in_type, out_type, length, count).
        members: Vec<(String, TdhInType, TdhOutType, u16, u16)>,
    }

    /// Builds a synthetic `EventSchema` + `ParserCache` for testing without TDH.
    pub struct MockSchemaBuilder {
        properties: Vec<MockProperty>,
        /// Struct definitions, inserted into the top-level list as placeholders.
        /// The actual member properties are appended after all top-level properties.
        structs: Vec<MockStructDef>,
        /// Indices into `properties` where struct placeholders sit.
        struct_placeholder_indices: Vec<usize>,
        /// Optional EventDescriptor fields to embed in TRACE_EVENT_INFO.
        event_id: u16,
        event_version: u8,
        event_opcode: u8,
    }

    impl MockSchemaBuilder {
        pub fn new() -> Self {
            Self {
                properties: Vec::new(),
                structs: Vec::new(),
                struct_placeholder_indices: Vec::new(),
                event_id: 0,
                event_version: 0,
                event_opcode: 0,
            }
        }

        /// Sets EventDescriptor fields (id, version, opcode) in the built schema.
        pub fn with_event_descriptor(mut self, id: u16, version: u8, opcode: u8) -> Self {
            self.event_id = id;
            self.event_version = version;
            self.event_opcode = opcode;
            self
        }

        /// Adds a property whose size is determined by its `TdhInType`.
        pub fn add(mut self, name: &str, in_type: TdhInType, out_type: TdhOutType) -> Self {
            self.properties.push(MockProperty {
                name: name.to_owned(),
                in_type,
                out_type,
                length: 0,
                flags: 0,
                length_property_index: 0,
                count_property_index: 0,
                static_count: 0,
            });
            self
        }

        /// Adds a property with an explicit declared length (e.g. Binary with known size).
        pub fn add_fixed(mut self, name: &str, in_type: TdhInType, length: u16) -> Self {
            self.properties.push(MockProperty {
                name: name.to_owned(),
                in_type,
                out_type: TdhOutType::Null,
                length,
                flags: 0,
                length_property_index: 0,
                count_property_index: 0,
                static_count: 0,
            });
            self
        }

        /// Adds a property with an explicit declared length and a specific out-type.
        pub fn add_fixed_typed(
            mut self,
            name: &str,
            in_type: TdhInType,
            out_type: TdhOutType,
            length: u16,
        ) -> Self {
            self.properties.push(MockProperty {
                name: name.to_owned(),
                in_type,
                out_type,
                length,
                flags: 0,
                length_property_index: 0,
                count_property_index: 0,
                static_count: 0,
            });
            self
        }

        /// Adds a property whose array count is specified by another property (PropertyParamCount).
        pub fn add_param_count(
            mut self,
            name: &str,
            in_type: TdhInType,
            element_size: u16,
            count_prop_index: u16,
        ) -> Self {
            self.properties.push(MockProperty {
                name: name.to_owned(),
                in_type,
                out_type: TdhOutType::Null,
                length: element_size,
                flags: 0x4, // PropertyParamCount
                length_property_index: 0,
                count_property_index: count_prop_index,
                static_count: 0,
            });
            self
        }

        /// Adds a struct property with the given members.
        ///
        /// Members are stored after all top-level properties in the property array,
        /// matching the TDH layout. A length of 0 means the member's size is
        /// determined by its `TdhInType`.
        pub fn add_struct(
            mut self,
            name: &str,
            members: &[(&str, TdhInType, TdhOutType, u16)],
        ) -> Self {
            let placeholder_idx = self.properties.len();
            // Insert a placeholder top-level property — flags/union fields
            // are populated in build().
            self.properties.push(MockProperty {
                name: name.to_owned(),
                in_type: TdhInType::Null, // Unused for structs
                out_type: TdhOutType::Null,
                length: 0,
                flags: 0x1, // PropertyStruct
                length_property_index: 0,
                count_property_index: 0,
                static_count: 0,
            });
            self.struct_placeholder_indices.push(placeholder_idx);
            self.structs.push(MockStructDef {
                members: members
                    .iter()
                    .map(|(n, it, ot, len)| ((*n).to_owned(), *it, *ot, *len, 0u16))
                    .collect(),
            });
            self
        }

        /// Adds a top-level property with a static array count > 1.
        pub fn add_static_array(
            mut self,
            name: &str,
            in_type: TdhInType,
            out_type: TdhOutType,
            count: u16,
        ) -> Self {
            self.properties.push(MockProperty {
                name: name.to_owned(),
                in_type,
                out_type,
                length: 0,
                flags: 0,
                length_property_index: 0,
                count_property_index: 0,
                static_count: count,
            });
            self
        }

        /// Adds a struct with explicit member counts and/or a struct-level static array count.
        ///
        /// Members are 5-tuples: `(name, in_type, out_type, length, count)`.
        pub fn add_struct_with_count(
            mut self,
            name: &str,
            members: &[(&str, TdhInType, TdhOutType, u16, u16)],
            struct_count: u16,
        ) -> Self {
            let placeholder_idx = self.properties.len();
            self.properties.push(MockProperty {
                name: name.to_owned(),
                in_type: TdhInType::Null,
                out_type: TdhOutType::Null,
                length: 0,
                flags: 0x1, // PropertyStruct
                length_property_index: 0,
                count_property_index: 0,
                static_count: struct_count,
            });
            self.struct_placeholder_indices.push(placeholder_idx);
            self.structs.push(MockStructDef {
                members: members
                    .iter()
                    .map(|(n, it, ot, len, cnt)| ((*n).to_owned(), *it, *ot, *len, *cnt))
                    .collect(),
            });
            self
        }

        /// Builds the `EventSchema`.
        pub fn build(self) -> EventSchema {
            let top_level_count = self.properties.len() as u32;
            let total_member_count: usize = self.structs.iter().map(|s| s.members.len()).sum();
            let total_prop_count = top_level_count + total_member_count as u32;

            let epi_size = size_of::<EVENT_PROPERTY_INFO>();
            let tei_header_size = std::mem::offset_of!(TRACE_EVENT_INFO, EventPropertyInfoArray);

            // Collect all property names: top-level first, then struct members
            let mut all_names: Vec<String> =
                self.properties.iter().map(|p| p.name.clone()).collect();
            for s in &self.structs {
                for (name, _, _, _, _) in &s.members {
                    all_names.push(name.clone());
                }
            }

            // Encode each property name as null-terminated UTF-16
            let name_bytes: Vec<Vec<u8>> = all_names
                .iter()
                .map(|name| {
                    let mut encoded: Vec<u8> = Vec::new();
                    for ch in name.encode_utf16() {
                        encoded.extend_from_slice(&ch.to_le_bytes());
                    }
                    encoded.extend_from_slice(&[0u8, 0u8]);
                    encoded
                })
                .collect();

            let props_area_size = epi_size * total_prop_count as usize;
            let string_area_start = tei_header_size + props_area_size;
            let string_area_size: usize = name_bytes.iter().map(Vec::len).sum();
            let total_size = string_area_start + string_area_size;

            let mut buffer = AlignedSchemaBuffer::new(total_size);

            // SAFETY: buffer is large enough for a TRACE_EVENT_INFO + N properties + names.
            // All pointer arithmetic stays within the allocated region.
            unsafe {
                let info_ptr = buffer.as_mut_ptr().cast::<TRACE_EVENT_INFO>();
                (*info_ptr).PropertyCount = total_prop_count;
                (*info_ptr).TopLevelPropertyCount = top_level_count;
                (*info_ptr).EventDescriptor.Id = self.event_id;
                (*info_ptr).EventDescriptor.Version = self.event_version;
                (*info_ptr).EventDescriptor.Opcode = self.event_opcode;

                let props_base = std::ptr::addr_of_mut!((*info_ptr).EventPropertyInfoArray)
                    .cast::<EVENT_PROPERTY_INFO>();

                let mut string_offset = string_area_start;

                // Write top-level properties
                for (i, prop) in self.properties.iter().enumerate() {
                    let name_data = &name_bytes[i];
                    std::ptr::copy_nonoverlapping(
                        name_data.as_ptr(),
                        buffer.as_mut_ptr().add(string_offset),
                        name_data.len(),
                    );

                    let epi = &mut *props_base.add(i);
                    epi.NameOffset = string_offset as u32;
                    epi.Flags = prop.flags as i32;

                    if prop.flags & 0x1 != 0 {
                        // PropertyStruct: structType union fields are set below
                        // after we know the member start index.
                    } else {
                        epi.Anonymous1.nonStructType.InType = prop.in_type.raw_value();
                        epi.Anonymous1.nonStructType.OutType = prop.out_type.raw_value();
                    }

                    // Set the appropriate union fields based on flags
                    if prop.flags & 0x2 != 0 {
                        // PropertyParamLength: Anonymous3 holds lengthPropertyIndex
                        epi.Anonymous3.lengthPropertyIndex = prop.length_property_index;
                    } else {
                        epi.Anonymous3.length = prop.length;
                    }
                    if prop.flags & 0x4 != 0 {
                        // PropertyParamCount: Anonymous2 holds countPropertyIndex
                        epi.Anonymous2.countPropertyIndex = prop.count_property_index;
                    } else if prop.static_count > 1 {
                        epi.Anonymous2.count = prop.static_count;
                    }

                    string_offset += name_data.len();
                }

                // Write struct member properties after all top-level properties
                let mut member_idx = top_level_count as usize;
                for (struct_ordinal, s) in self.structs.iter().enumerate() {
                    let member_start = member_idx as u16;
                    let member_count = s.members.len() as u16;

                    // Set the struct parent's structType fields
                    let parent_idx = self.struct_placeholder_indices[struct_ordinal];
                    let parent_epi = &mut *props_base.add(parent_idx);
                    parent_epi.Anonymous1.structType.StructStartIndex = member_start;
                    parent_epi.Anonymous1.structType.NumOfStructMembers = member_count;

                    for (_, in_type, out_type, length, count) in &s.members {
                        let name_data = &name_bytes[member_idx];
                        std::ptr::copy_nonoverlapping(
                            name_data.as_ptr(),
                            buffer.as_mut_ptr().add(string_offset),
                            name_data.len(),
                        );

                        let epi = &mut *props_base.add(member_idx);
                        epi.NameOffset = string_offset as u32;
                        epi.Flags = 0;
                        epi.Anonymous1.nonStructType.InType = in_type.raw_value();
                        epi.Anonymous1.nonStructType.OutType = out_type.raw_value();
                        epi.Anonymous3.length = *length;
                        if *count > 1 {
                            epi.Anonymous2.count = *count;
                        }

                        string_offset += name_data.len();
                        member_idx += 1;
                    }
                }

                // Only top-level property names go into the name lookup map
                let property_names: Vec<Box<str>> = self
                    .properties
                    .iter()
                    .map(|p| p.name.clone().into_boxed_str())
                    .collect();

                let name_to_index: FxHashMap<Box<str>, u32> = property_names
                    .iter()
                    .enumerate()
                    .map(|(i, name)| (name.clone(), i as u32))
                    .collect();

                EventSchema {
                    buffer,
                    property_count: total_prop_count,
                    top_level_property_count: top_level_count,
                    property_names,
                    name_to_index,
                }
            }
        }

        /// Builds the schema and a pre-populated `ParserCache` for 8-byte pointers.
        ///
        /// Convenience for tests that need both a schema and cache.
        pub fn build_with_cache(self) -> (EventSchema, crate::parser::ParserCache) {
            let schema = self.build();
            let mut cache = crate::parser::ParserCache::new(schema.top_level_property_count());
            cache.prepopulate_fixed(&schema, 8);
            (schema, cache)
        }
    }
}
