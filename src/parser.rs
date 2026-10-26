//! Schema-aware event parser with lazy evaluation and caching.
//!
//! This module provides an `EventParser` that uses TDH schema information to
//! parse event properties by name. It lazily parses properties on demand and
//! caches their locations for efficient repeated access.
//!
//! # Property Access Methods
//!
//! The parser provides two parallel APIs for property access:
//!
//! **Owned values** (via [`FromProperty`]):
//! - `get(&str)` - lookup by name
//!
//! **Zero-copy references** (via [`FromPropertyRef`]):
//! - `as_ref(&str)` - returns `WideStrRef`, `AnsiStrRef`, `&[u8]`, `SidRef`
//!
//! ## Return type support
//!
//! | Return type      | `get`              | `as_ref`           |
//! |------------------|:------------------:|:------------------:|
//! | `String`         | yes (Unicode + ANSI via CP_ACP) | —           |
//! | `WideString`     | yes                | —                  |
//! | `AnsiString`     | yes                | —                  |
//! | `WideStrRef`     | —                  | yes                |
//! | `AnsiStrRef`     | —                  | yes                |
//! | `&[u8]`          | —                  | yes                |
//! | `SidRef`         | —                  | yes                |
//! | `Guid`           | yes                | —                  |
//! | `Sid`            | yes                | —                  |
//! | Primitives       | yes                | —                  |
//!
//! `get::<String>()` decodes an ANSI field by its TDH out-type: `Utf8`, `Json`
//! and `Xml` as UTF-8, anything else with the process active code page
//! (CP_ACP). The latter is correct for events produced on the same machine, but
//! may yield wrong results for events captured on a machine with a different
//! locale. Use [`AnsiStrRef`] and [`AnsiStrRef::decode`] to specify the code
//! page explicitly.
//!
//! # Example
//!
//! ```no_run
//! # fn example(parser: &mut etw::EventParser) -> etw::Result<()> {
//! use etw::types::WideStrRef;
//!
//! let pid: u32 = parser.get("ProcessId")?;
//! let name: String = parser.get("ImageName")?;
//!
//! // Zero-copy API
//! let name: WideStrRef = parser.as_ref("QueryName")?;
//! # Ok(())
//! # }
//! ```

use crate::{
    Error, Result,
    event::Timestamp,
    processing_context::EventSchema,
    types::{
        AnsiStrRef, AnsiString, Guid, Sid, SidRef, SystemTime, TdhInType, TdhOutType, WideStrRef,
        WideString,
    },
};
use windows_sys::Win32::{Globalization::CP_UTF8, System::SystemServices::SID_MAX_SUB_AUTHORITIES};

/// Cached information about a parsed property's location in the buffer.
///
/// One of these exists per property per event, and `get()` reads one on every
/// field access, so its width is the width of the parser's hottest lookup
/// table. Both spans are `u16` and the out-type is not stored, which takes it
/// from 24 bytes to 8 — three times more of the table per cache line.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PropertyLocation {
    /// Offset in bytes from the start of the user data buffer.
    ///
    /// `u16` because `EVENT_RECORD.UserDataLength` is a `USHORT`: an event
    /// payload cannot exceed 65535 bytes, so no offset into one can either.
    offset: u16,
    /// Total byte span of the property, including all static array elements.
    ///
    /// Saturates at `u16::MAX`. That is lossless in effect rather than merely
    /// tolerable: a span is only ever used after being clamped against the
    /// bytes remaining in the buffer, which is itself at most 65535, so a span
    /// at or past the cap selects exactly the same slice the true value would.
    /// The span is computed from counts that are attacker-influenceable, so it
    /// is the one field that can exceed the cap before clamping.
    size: u16,
    /// The TDH input type for this property.
    pub(crate) in_type: TdhInType,
}

impl PropertyLocation {
    /// Records a property's position, narrowing the spans to the buffer's own
    /// 16-bit domain.
    pub(crate) fn new(offset: usize, size: usize, in_type: TdhInType) -> Self {
        Self {
            // An offset past the buffer is already handled by the readers, which
            // return an empty slice for it; saturating keeps that behaviour
            // rather than wrapping into a valid-looking offset.
            offset: u16::try_from(offset).unwrap_or(u16::MAX),
            size: u16::try_from(size).unwrap_or(u16::MAX),
            in_type,
        }
    }

    /// Byte offset of this property within the user data buffer.
    pub(crate) const fn offset(self) -> usize {
        self.offset as usize
    }

    /// Total byte span of this property, clamped to the buffer's domain.
    pub(crate) const fn size(self) -> usize {
        self.size as usize
    }
}

// =============================================================================
// Property Iterator
// =============================================================================

/// Iterator over event properties in sequential order.
///
/// Created by [`EventParser::properties()`]. This iterator provides zero-copy
/// access to property data after all property locations have been pre-computed
/// in a single pass.
///
/// **Struct properties** yield a [`Property`] with `in_type == TdhInType::Struct`.
/// Use [`Property::is_struct()`] to detect them. Calling `.get::<T>()` on a struct
/// property returns an error — use [`EventParser::struct_members()`] instead.
///
/// The lifetime `'a` refers to the event data, `'p` refers to the parser's cache.
#[derive(Debug)]
pub struct PropertyIter<'a, 'p> {
    data: &'a [u8],
    locations: &'p [PropertyLocation],
    /// Source for each property's out-type.
    ///
    /// The out-type is read from here rather than cached in
    /// [`PropertyLocation`] because it is needed only when a `Property` is
    /// actually yielded — for display and for the public accessor — and never
    /// by `get()`. Caching it cost a quarter of every location entry on the
    /// hottest path in the parser to serve the coldest one.
    schema: &'p crate::processing_context::EventSchema,
    index: usize,
}

impl<'a> Iterator for PropertyIter<'a, '_> {
    type Item = Property<'a>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let index = self.index;
        let location = self.locations.get(index)?;
        self.index += 1;

        let prop_data = if location.offset() >= self.data.len() {
            &[]
        } else {
            let available = (self.data.len() - location.offset()).min(location.size());
            &self.data[location.offset()..location.offset() + available]
        };

        let out_type = self
            .schema
            .property(index as u32)
            .map_or(TdhOutType::Null, |prop| {
                TdhOutType::from_raw(prop.out_type())
            });

        Some(Property {
            data: prop_data,
            in_type: location.in_type,
            out_type,
        })
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.locations.len() - self.index;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for PropertyIter<'_, '_> {}

/// A property value with zero-copy access to the underlying data.
///
/// Provides typed accessor methods to interpret the raw bytes as specific types.
/// Returned by [`PropertyIter`] when iterating over event properties.
#[derive(Debug, Clone, Copy)]
pub struct Property<'a> {
    data: &'a [u8],
    in_type: TdhInType,
    out_type: TdhOutType,
}

impl<'a> Property<'a> {
    /// Returns the raw property data as a byte slice.
    #[inline]
    pub const fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Returns the TDH input type for this property.
    #[inline]
    pub const fn in_type(&self) -> TdhInType {
        self.in_type
    }

    /// Returns the TDH output type for this property.
    #[inline]
    pub const fn out_type(&self) -> TdhOutType {
        self.out_type
    }

    /// Returns `true` if this property is a struct container.
    ///
    /// Struct properties cannot be parsed directly via [`get()`](Self::get).
    /// Use [`EventParser::struct_members()`] to access their contents.
    #[inline]
    pub const fn is_struct(&self) -> bool {
        matches!(self.in_type, TdhInType::Struct)
    }

    /// Returns the property as a zero-copy UTF-16 string reference.
    #[inline]
    pub fn as_wide_str(&self) -> Result<WideStrRef<'a>> {
        WideStrRef::from_property_ref(self.data, self.in_type)
    }

    /// Returns the property as an owned UTF-16 string.
    #[inline]
    pub fn to_wide_string(&self) -> Result<WideString> {
        WideString::from_property(self.data, self.in_type, self.out_type)
    }

    /// Returns the property as a u32.
    #[inline]
    pub fn as_u32(&self) -> Result<u32> {
        u32::from_property(self.data, self.in_type, self.out_type)
    }

    /// Returns the property as a u64.
    #[inline]
    pub fn as_u64(&self) -> Result<u64> {
        u64::from_property(self.data, self.in_type, self.out_type)
    }

    /// Returns the property as a generic type implementing [`FromProperty`].
    #[inline]
    pub fn get<T: FromProperty>(&self) -> Result<T> {
        T::from_property(self.data, self.in_type, self.out_type)
    }

    /// Returns the property as a zero-copy reference type implementing [`FromPropertyRef`].
    #[inline]
    pub fn as_ref<T: FromPropertyRef<'a>>(&self) -> Result<T> {
        T::from_property_ref(self.data, self.in_type)
    }
}

impl std::fmt::Display for Property<'_> {
    #[expect(
        clippy::many_single_char_names,
        reason = "short names for scratch format values"
    )]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // When out_type is non-null it overrides the default display format.
        match self.out_type {
            TdhOutType::HexInt8 => {
                return match self.get::<u8>() {
                    Ok(v) => write!(f, "0x{v:02X}"),
                    Err(_) => write!(f, "<parse error>"),
                };
            }
            TdhOutType::HexInt16 => {
                return match self.get::<u16>() {
                    Ok(v) => write!(f, "0x{v:04X}"),
                    Err(_) => write!(f, "<parse error>"),
                };
            }
            TdhOutType::HexInt32 | TdhOutType::NtStatus | TdhOutType::HResult => {
                return match self.as_u32() {
                    Ok(v) => write!(f, "0x{v:08X}"),
                    Err(_) => write!(f, "<parse error>"),
                };
            }
            TdhOutType::HexInt64 => {
                return match self.as_u64() {
                    Ok(v) => write!(f, "0x{v:016X}"),
                    Err(_) => write!(f, "<parse error>"),
                };
            }
            TdhOutType::Pid | TdhOutType::Tid | TdhOutType::Win32Error => {
                return match self.as_u32() {
                    Ok(v) => write!(f, "{v}"),
                    Err(_) => write!(f, "<parse error>"),
                };
            }
            TdhOutType::Port => {
                // Network byte order (big-endian) u16
                return if self.data.len() >= 2 {
                    let v = u16::from_be_bytes([self.data[0], self.data[1]]);
                    write!(f, "{v}")
                } else {
                    write!(f, "<parse error>")
                };
            }
            TdhOutType::Ipv4 => {
                return if self.data.len() >= 4 {
                    write!(
                        f,
                        "{}.{}.{}.{}",
                        self.data[0], self.data[1], self.data[2], self.data[3]
                    )
                } else {
                    write!(f, "<parse error>")
                };
            }
            TdhOutType::Ipv6 => {
                return if self.data.len() >= 16 {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&self.data[..16]);
                    write!(f, "{}", std::net::Ipv6Addr::from(octets))
                } else {
                    write!(f, "<parse error>")
                };
            }
            TdhOutType::CodePointer => {
                return match self.get::<usize>() {
                    Ok(v) => write!(f, "0x{v:X}"),
                    Err(_) => write!(f, "<parse error>"),
                };
            }
            TdhOutType::Boolean => {
                // Windows BOOL is a 4-byte integer; any non-zero byte means true.
                return if self.data.is_empty() {
                    write!(f, "<parse error>")
                } else if self.data.iter().any(|&b| b != 0) {
                    write!(f, "true")
                } else {
                    write!(f, "false")
                };
            }
            TdhOutType::Guid => {
                return match self.get::<Guid>() {
                    Ok(v) => write!(f, "{v}"),
                    Err(_) => write!(f, "<parse error>"),
                };
            }
            TdhOutType::NoPrint => return Ok(()),
            // For all other out_types, fall through to in_type based formatting.
            _ => {}
        }

        // Default formatting based on in_type.
        match self.in_type {
            TdhInType::UnicodeString
            | TdhInType::CountedString
            | TdhInType::ReversedCountedString
            | TdhInType::NonNullTerminatedString
            | TdhInType::ManifestCountedString => match self.as_wide_str() {
                Ok(s) => write!(f, "{}", s.to_string_lossy()),
                Err(_) => write!(f, "<parse error>"),
            },
            TdhInType::AnsiString
            | TdhInType::CountedAnsiString
            | TdhInType::ReversedCountedAnsiString
            | TdhInType::NonNullTerminatedAnsiString
            | TdhInType::ManifestCountedAnsiString => match self.get::<AnsiString>() {
                Ok(s) if self.out_type.ansi_code_page() == CP_UTF8 => {
                    write!(f, "{}", String::from_utf8_lossy(s.as_bytes()))
                }
                Ok(s) => write!(f, "{s}"),
                Err(_) => write!(f, "<parse error>"),
            },
            TdhInType::Int8 => match self.get::<i8>() {
                Ok(v) => write!(f, "{v}"),
                Err(_) => write!(f, "<parse error>"),
            },
            TdhInType::UInt8 => match self.get::<u8>() {
                Ok(v) => write!(f, "{v}"),
                Err(_) => write!(f, "<parse error>"),
            },
            TdhInType::Int16 => match self.get::<i16>() {
                Ok(v) => write!(f, "{v}"),
                Err(_) => write!(f, "<parse error>"),
            },
            // A fixed-length WCHAR array is one UnicodeChar property, so decode
            // every code unit rather than reading a single u16.
            TdhInType::UnicodeChar => write!(f, "{}", WideStrRef::new(self.data).to_string_lossy()),
            TdhInType::UInt16 => match self.get::<u16>() {
                Ok(v) => write!(f, "{v}"),
                Err(_) => write!(f, "<parse error>"),
            },
            TdhInType::Int32 => match self.get::<i32>() {
                Ok(v) => write!(f, "{v}"),
                Err(_) => write!(f, "<parse error>"),
            },
            TdhInType::UInt32 => match self.as_u32() {
                Ok(v) => write!(f, "{v}"),
                Err(_) => write!(f, "<parse error>"),
            },
            TdhInType::Int64 => match self.get::<i64>() {
                Ok(v) => write!(f, "{v}"),
                Err(_) => write!(f, "<parse error>"),
            },
            TdhInType::UInt64 => match self.as_u64() {
                Ok(v) => write!(f, "{v}"),
                Err(_) => write!(f, "<parse error>"),
            },
            TdhInType::FileTime => match self.get::<Timestamp>() {
                Ok(v) => write!(f, "{v}"),
                Err(_) => write!(f, "<parse error>"),
            },
            TdhInType::SystemTime => {
                if self.data.len() >= 16 {
                    let y = u16::from_le_bytes([self.data[0], self.data[1]]);
                    let mo = u16::from_le_bytes([self.data[2], self.data[3]]);
                    let d = u16::from_le_bytes([self.data[6], self.data[7]]);
                    let h = u16::from_le_bytes([self.data[8], self.data[9]]);
                    let mi = u16::from_le_bytes([self.data[10], self.data[11]]);
                    let s = u16::from_le_bytes([self.data[12], self.data[13]]);
                    let ms = u16::from_le_bytes([self.data[14], self.data[15]]);
                    write!(f, "{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{ms:03}0000")
                } else {
                    write!(f, "<parse error>")
                }
            }
            TdhInType::HexInt32 => match self.as_u32() {
                Ok(v) => write!(f, "0x{v:X}"),
                Err(_) => write!(f, "<parse error>"),
            },
            TdhInType::HexInt64 => match self.as_u64() {
                Ok(v) => write!(f, "0x{v:X}"),
                Err(_) => write!(f, "<parse error>"),
            },
            TdhInType::Pointer | TdhInType::SizeT => match self.get::<usize>() {
                Ok(v) => write!(f, "0x{v:X}"),
                Err(_) => write!(f, "<parse error>"),
            },
            TdhInType::Float => match self.get::<f32>() {
                Ok(v) => write!(f, "{v}"),
                Err(_) => write!(f, "<parse error>"),
            },
            TdhInType::Double => match self.get::<f64>() {
                Ok(v) => write!(f, "{v}"),
                Err(_) => write!(f, "<parse error>"),
            },
            TdhInType::Boolean => match self.get::<bool>() {
                Ok(v) => write!(f, "{v}"),
                Err(_) => write!(f, "<parse error>"),
            },
            TdhInType::Guid => match self.get::<Guid>() {
                Ok(v) => write!(f, "{v}"),
                Err(_) => write!(f, "<parse error>"),
            },
            TdhInType::Sid => match SidRef::new(self.data) {
                Some(sid) => write!(f, "{sid}"),
                None => write!(f, "<parse error>"),
            },
            TdhInType::WbemSid => {
                // See token_user_size() for the pointer-size caveat.
                let hdr = token_user_size(size_of::<usize>());
                if self.data.len() > hdr {
                    match SidRef::new(&self.data[hdr..]) {
                        Some(sid) => write!(f, "{sid}"),
                        None => write!(f, "<parse error>"),
                    }
                } else {
                    write!(f, "<parse error>")
                }
            }
            _ => {
                // Binary, HexDump, etc. — show as hex bytes
                write!(f, "[")?;
                for (i, b) in self.data.iter().enumerate() {
                    if i > 0 {
                        write!(f, " ")?;
                    }
                    write!(f, "{b:02X}")?;
                }
                write!(f, "]")
            }
        }
    }
}

/// Schema-aware event parser with lazy evaluation and index hints.
///
/// This parser uses TDH schema information to parse event properties by name.
/// Properties are parsed lazily on first access and their locations are cached
/// for efficient repeated access.
///
/// # Parser Reuse
///
/// When created via
/// [`ProcessingContext::parser()`](crate::processing_context::ProcessingContext::parser),
/// the parser automatically reuses a cached location buffer stored with the schema.
/// This eliminates per-event allocation overhead for high-throughput processing.
///
/// # Index Hints
///
/// When you know the expected index of a property in the schema, you can provide
/// it as a hint to avoid O(n) name comparisons. If the hint is wrong, the parser
/// falls back silently to hash lookup by name.
///
/// # Thread Safety
///
/// `EventParser` is not thread-safe. ETW guarantees single-threaded callback
/// execution per session, so no synchronisation is needed.
pub struct EventParser<'a> {
    /// Raw event user data buffer.
    data: &'a [u8],
    /// TDH schema for this event.
    schema: &'a EventSchema,
    /// Cache of property locations, borrowed from the schema.
    cache: &'a mut ParserCache,
    /// Pointer size of the emitting process (4 for 32-bit, 8 for 64-bit).
    pointer_size: usize,
    /// How many properties `get`/`as_ref` have resolved on this event so far.
    ///
    /// Indexes [`ParserCache::learned_hints`], which records what each call
    /// position resolved to on earlier events. Starts at zero for every event:
    /// the hint is keyed on a call's position within the event, not on the index
    /// the previous call landed at.
    position: u32,
}

/// Cache state for the parser, storing computed property locations.
///
/// This is stored alongside `EventSchema` to enable parser reuse across events
/// of the same type without re-allocating the location vector.
///
/// Each cache is pointer-size-specific because `Pointer` and `SizeT` types
/// differ between 32-bit (4 bytes) and 64-bit (8 bytes) processes.
pub(crate) struct ParserCache {
    /// Property locations in index order (indices are always 0..N contiguous).
    pub(crate) locations: Vec<PropertyLocation>,
    /// Per-event memoised decoded values for length/count properties.
    pub(crate) decoded_lengths: Vec<Option<u16>>,
    /// Current offset in the buffer where the next unparsed property starts.
    pub(crate) current_offset: usize,
    /// Index of first variable-length property for this pointer size.
    first_variable_index: u32,
    /// Total size in bytes of the fixed-length prefix for this pointer size.
    fixed_prefix_size: usize,
    /// For each call position within an event, the property index that position
    /// resolved to previously.
    ///
    /// Consumers overwhelmingly read the same properties in the same order on
    /// every event of a type — a generated parser always does, and a hand-written
    /// one is a struct literal built the same way each time. This records that
    /// shape, so the Nth `get` on the next event goes straight to the index the
    /// Nth `get` wanted last time instead of hashing the name.
    ///
    /// Deliberately *not* cleared by [`reset`](Self::reset): surviving between
    /// events is the whole point. It lives here rather than on the parser for the
    /// same reason — the parser is rebuilt per event.
    ///
    /// Every use is verified against the property's actual name, so an entry that
    /// is stale, or shared by two callers reading different orders, costs one
    /// failed comparison and can never yield the wrong property.
    learned_hints: Vec<u32>,
}

impl ParserCache {
    /// Creates a new cache with capacity for the given number of properties.
    pub(crate) fn new(property_count: u32) -> Self {
        Self {
            locations: Vec::with_capacity(property_count as usize),
            decoded_lengths: Vec::with_capacity(property_count as usize),
            current_offset: 0,
            first_variable_index: 0,
            fixed_prefix_size: 0,
            // Seeded with the identity mapping: position N guesses index N. That
            // is already right for a caller reading every property in order, and
            // wrong guesses are corrected on first use.
            learned_hints: (0..property_count).collect(),
        }
    }

    /// Pre-populates the cache with fixed-offset property locations.
    ///
    /// Computes `first_variable_index` and `fixed_prefix_size` for this
    /// pointer size, then fills in property locations for all fixed-offset
    /// properties. These locations are reused across events of the same schema.
    #[expect(
        clippy::expect_used,
        reason = "invariants guaranteed by compute_fixed_prefix_info"
    )]
    pub(crate) fn prepopulate_fixed(&mut self, schema: &EventSchema, pointer_size: usize) {
        let (first_var_idx, fixed_size) = crate::processing_context::compute_fixed_prefix_info(
            schema.info_ptr(),
            schema.top_level_property_count(),
            schema.property_count(),
            pointer_size,
        );
        self.first_variable_index = first_var_idx;
        self.fixed_prefix_size = fixed_size;

        // Compute fixed property locations using known sizes
        let mut offset = 0usize;
        for idx in 0..first_var_idx {
            let prop = schema.property(idx).expect("valid index");

            let (in_type, size) = if prop.is_struct() {
                // Struct properties: compute size by summing members.
                // compute_fixed_prefix_info guarantees all members are fixed-size.
                let start = prop.struct_start_index() as u32;
                let count = prop.struct_member_count() as u32;
                let mut struct_size = 0usize;
                for m in start..start + count {
                    let member = schema.property_raw(m).expect("valid member index");
                    // Nested structs can't reach here — compute_struct_byte_size_raw
                    // returns None for nested structs, which stops
                    // compute_fixed_prefix_info from including the parent struct.
                    debug_assert!(!member.is_struct(), "nested struct in fixed prefix");
                    let member_len = member.length() as usize;
                    let member_size = if member_len > 0 {
                        member_len
                    } else {
                        TdhInType::from_raw(member.in_type())
                            .fixed_size(pointer_size)
                            .expect("fixed member type")
                    };
                    struct_size += member_size * member.count().max(1) as usize;
                }
                (TdhInType::Struct, struct_size)
            } else {
                let in_type = TdhInType::from_raw(prop.in_type());
                let declared_len = prop.length() as usize;
                let size = if declared_len > 0 {
                    declared_len
                } else {
                    // Must be a fixed-size type (guaranteed by compute_fixed_prefix_info)
                    in_type.fixed_size(pointer_size).expect("fixed type")
                };
                (in_type, size)
            };

            let total_size = size * prop.count().max(1) as usize;
            self.locations
                .push(PropertyLocation::new(offset, total_size, in_type));
            self.decoded_lengths.push(None);
            offset += total_size;
        }

        self.current_offset = offset;
        debug_assert_eq!(offset, self.fixed_prefix_size);
    }

    /// Resets the cache for a new event with the same schema.
    ///
    /// Preserves fixed property locations and clears variable-length ones.
    pub(crate) fn reset(&mut self) {
        let first_var = self.first_variable_index as usize;
        self.locations.truncate(first_var);
        self.decoded_lengths.clear();
        self.decoded_lengths.resize(self.locations.len(), None);
        self.current_offset = self.fixed_prefix_size;
    }
}

impl std::fmt::Debug for ParserCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParserCache")
            .field("parsed_count", &self.locations.len())
            .field("cached_lengths", &self.decoded_lengths.len())
            .field("current_offset", &self.current_offset)
            .field("first_variable_index", &self.first_variable_index)
            .field("fixed_prefix_size", &self.fixed_prefix_size)
            // Printed in full, unlike the other vectors: it is short, and the
            // mapping itself is the diagnostic content — it shows which property
            // each call position has settled on.
            .field("learned_hints", &self.learned_hints)
            .finish()
    }
}

/// True when `lhs` and `rhs` are equal, comparing `W` bytes from each end.
///
/// The two reads overlap in the middle rather than tiling it, which covers every
/// byte without a loop: with `W <= len <= 2 * W` the ranges `[..W]` and
/// `[len - W..]` overlap whenever `len < 2 * W` and abut when `len == 2 * W`.
/// Callers must satisfy that bound; the `else` arm is a correctness backstop,
/// not an expected path.
///
/// `W` is a const parameter so each comparison is a fixed-size array equality,
/// which LLVM lowers inline instead of calling `memcmp`: an integer compare up to
/// `W == 8`, and a single SIMD compare at `W == 16` (measured at roughly 0.4ns).
#[inline]
fn ends_equal<const W: usize>(lhs: &[u8], rhs: &[u8]) -> bool {
    let (Some(left_head), Some(left_tail), Some(right_head), Some(right_tail)) = (
        lhs.first_chunk::<W>(),
        lhs.last_chunk::<W>(),
        rhs.first_chunk::<W>(),
        rhs.last_chunk::<W>(),
    ) else {
        return lhs == rhs;
    };
    left_head == right_head && left_tail == right_tail
}

/// Compares two property names for equality.
///
/// Same result as `lhs == rhs`, and a full comparison -- no prefix shortcut, so
/// a name differing only in its last byte still compares unequal.
///
/// Exists because `str` equality lowers to a `memcmp` libcall. LLVM inlines
/// `memcmp` only when the length is a compile-time constant, and these lengths
/// are not, so on MSVC the comparison becomes an indirect call into
/// `vcruntime140.dll` through the import table. Property names are short enough
/// that the call costs more than the bytes it compares: measured over real ETW
/// names, 4.4ns for `==` against 1.5ns for this.
///
/// The arms cover 0..=32 bytes, which is every name observed across the
/// generated schemas in this repository -- 52 distinct names spanning 3 to 27
/// bytes, none longer. Anything past that keeps the libcall.
///
/// The 17..=32 arm is not optional padding. Without it, a name in that range
/// pays the length dispatch *and then* the libcall anyway, which measured 7.1ns
/// against 5.9ns for plain `==` -- slower than not optimising at all. 21% of the
/// observed names fall in that range, `ParentProcessSequenceNumber` and
/// `ProcessTokenElevationType` among them, so the arm converts a regression on a
/// fifth of all lookups into a 3x gain. Its 16-byte chunks compare as one SSE
/// operation (~0.4ns measured), and adding it cost the shorter names nothing.
#[inline]
fn names_equal(lhs: &str, rhs: &str) -> bool {
    let (left, right) = (lhs.as_bytes(), rhs.as_bytes());
    if left.len() != right.len() {
        return false;
    }
    match left.len() {
        0 => true,
        1 => left[0] == right[0],
        2..=3 => ends_equal::<2>(left, right),
        4..=7 => ends_equal::<4>(left, right),
        8..=16 => ends_equal::<8>(left, right),
        17..=32 => ends_equal::<16>(left, right),
        _ => left == right,
    }
}

impl<'a> EventParser<'a> {
    /// Creates a new schema parser for an event.
    ///
    /// The parser borrows both the schema and a cache from the caller.
    /// Fixed-size property locations are preserved in the cache from previous
    /// uses, eliminating redundant computation.
    ///
    /// For typical usage, prefer
    /// [`ProcessingContext::parser()`](crate::processing_context::ProcessingContext::parser) which
    /// handles cache management automatically.
    pub(crate) fn new(
        event: &'a crate::event::RawEvent,
        schema: &'a EventSchema,
        cache: &'a mut ParserCache,
    ) -> Self {
        let flags = event.as_raw().EventHeader.Flags as u32;
        let pointer_size = crate::processing_context::pointer_size_from_flags(flags) as usize;

        // Reset variable-length locations while preserving fixed locations
        cache.reset();

        Self {
            data: event.user_data(),
            schema,
            cache,
            pointer_size,
            position: 0,
        }
    }

    /// Attaches the event and property as fields. `PropertyNotFound` passes
    /// through untouched: `find_property_by_name` already builds it with the
    /// same context, and `at_property` only fills in a `ParseError`.
    ///
    /// Kept out of line deliberately. `get`, `get_hinted`, `as_ref` and
    /// `as_ref_hinted` each call this from three `map_err` sites, and it is
    /// unreachable unless a property is missing or malformed. Inlined, the
    /// context construction and error rewrite land in the hot accessor three
    /// times over and cost enough to show up in the dynamic-parser benchmarks.
    #[cold]
    #[inline(never)]
    fn property_error(&self, name: &str, e: Error) -> Error {
        e.at_property(self.schema.event_context(), name)
    }

    /// Gets a property by name, returning an owned value.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn example(parser: &mut etw::EventParser) -> etw::Result<()> {
    /// let pid: u32 = parser.get("ProcessId")?;
    /// let name: String = parser.get("ImageName")?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns error if the property is not found or cannot be parsed.
    pub fn get<T: FromProperty>(&mut self, name: &str) -> Result<T> {
        match self.get_undecorated(name) {
            Ok(value) => Ok(value),
            Err(e) => Err(self.property_error(name, e)),
        }
    }

    /// The `get` hot path, with no error decoration.
    ///
    /// Split out so the `?` chain stays free of `map_err` at every step: the
    /// decoration is unreachable on success, but folding it into each step put
    /// it inline in the middle of the accessor and cost measurably more than the
    /// single call [`get`](Self::get) makes on the way out.
    fn get_undecorated<T: FromProperty>(&mut self, name: &str) -> Result<T> {
        let index = self.find_property_at_learned_hint(name)?;
        let (prop_data, in_type) = self.get_raw_property_at(index)?;
        T::from_property(prop_data, in_type, self.out_type_for::<T>(index, in_type))
    }

    /// Gets a property by name with an index hint for O(1) lookup.
    ///
    /// Used by macro-generated dynamic parsers. Prefer [`get`](Self::get) in hand-written code.
    #[doc(hidden)]
    pub fn get_hinted<T: FromProperty>(&mut self, name: &str, hint: u32) -> Result<T> {
        match self.get_hinted_undecorated(name, hint) {
            Ok(value) => Ok(value),
            Err(e) => Err(self.property_error(name, e)),
        }
    }

    /// The `get_hinted` hot path, with no error decoration. See
    /// [`get_undecorated`](Self::get_undecorated).
    fn get_hinted_undecorated<T: FromProperty>(&mut self, name: &str, hint: u32) -> Result<T> {
        let index = self.find_property_by_hint(name, hint)?;
        let target = index as usize;

        // Ensure property location is cached
        if target >= self.cache.locations.len() {
            self.compute_locations_up_to(index)?;
        }
        let location =
            self.cache.locations.get(target).ok_or_else(|| {
                Error::parse(format!("location {target} not in cache after compute"))
            })?;

        T::from_property(
            self.slice_property(*location),
            location.in_type,
            self.out_type_for::<T>(index, location.in_type),
        )
    }

    // =========================================================================
    // Zero-Copy Access (FromPropertyRef)
    // =========================================================================

    /// Borrows a property by name as a zero-copy reference.
    ///
    /// Returns types that borrow directly from the event buffer without copying:
    /// - `WideStrRef<'a>` - UTF-16 string
    /// - `AnsiStrRef<'a>` - ANSI string
    /// - `&'a [u8]` - Binary data
    /// - `SidRef<'a>` - Security identifier
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn example(parser: &mut etw::EventParser) -> etw::Result<()> {
    /// use etw::types::{SidRef, WideStrRef};
    ///
    /// let name: WideStrRef = parser.as_ref("QueryName")?;
    /// let data: &[u8] = parser.as_ref("BinaryData")?;
    /// let sid: SidRef = parser.as_ref("UserSid")?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns error if the property is not found or has incompatible type.
    pub fn as_ref<T: FromPropertyRef<'a>>(&mut self, name: &str) -> Result<T> {
        match self.as_ref_undecorated(name) {
            Ok(value) => Ok(value),
            Err(e) => Err(self.property_error(name, e)),
        }
    }

    /// The `as_ref` hot path, with no error decoration. See
    /// [`get_undecorated`](Self::get_undecorated).
    fn as_ref_undecorated<T: FromPropertyRef<'a>>(&mut self, name: &str) -> Result<T> {
        let index = self.find_property_at_learned_hint(name)?;
        let (prop_data, in_type) = self.get_raw_property_at(index)?;
        T::from_property_ref(prop_data, in_type)
    }

    /// Borrows a property by name with an index hint as a zero-copy reference.
    ///
    /// Used by macro-generated dynamic parsers. Prefer [`as_ref`](Self::as_ref) in hand-written
    /// code.
    #[doc(hidden)]
    pub fn as_ref_hinted<T: FromPropertyRef<'a>>(&mut self, name: &str, hint: u32) -> Result<T> {
        match self.as_ref_hinted_undecorated(name, hint) {
            Ok(value) => Ok(value),
            Err(e) => Err(self.property_error(name, e)),
        }
    }

    /// The `as_ref_hinted` hot path, with no error decoration. See
    /// [`get_undecorated`](Self::get_undecorated).
    fn as_ref_hinted_undecorated<T: FromPropertyRef<'a>>(
        &mut self,
        name: &str,
        hint: u32,
    ) -> Result<T> {
        let index = self.find_property_by_hint(name, hint)?;
        let (prop_data, in_type) = self.get_raw_property_at(index)?;
        T::from_property_ref(prop_data, in_type)
    }

    // =========================================================================
    // Property Iteration
    // =========================================================================

    /// Returns an iterator over all properties in sequential order.
    ///
    /// This is the most efficient way to access multiple properties sequentially.
    /// All property locations are computed in a single pass, then iteration
    /// proceeds with zero-copy access to property data.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn example(parser: &mut etw::EventParser) -> etw::Result<()> {
    /// use etw::types::WideStrRef;
    ///
    /// for prop in parser.properties()? {
    ///     println!("Type: {:?}, Size: {}", prop.in_type(), prop.data().len());
    ///
    ///     // Zero-copy string access
    ///     if let Ok(s) = prop.as_wide_str() {
    ///         println!("  Value: {}", s.to_string_lossy());
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns error if property locations cannot be computed (e.g., malformed event data).
    pub fn properties(&mut self) -> Result<PropertyIter<'a, '_>> {
        // Pre-compute all property locations in one pass
        let count = self.schema.top_level_property_count();
        if count > 0 {
            self.compute_locations_up_to(count - 1)?;
        }

        Ok(PropertyIter {
            data: self.data,
            locations: &self.cache.locations,
            schema: self.schema,
            index: 0,
        })
    }

    /// Returns all properties paired with their schema names.
    ///
    /// Convenience method that zips schema property names with parsed values.
    /// Collects names from the schema first, then resolves all property locations
    /// in a single pass.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn example(parser: &mut etw::EventParser) -> etw::Result<()> {
    /// for (name, prop) in parser.named_properties()? {
    ///     println!("{name}: {prop}");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    // Collect is needed: names must be collected before properties() borrows self mutably.
    pub fn named_properties(&mut self) -> Result<Vec<(String, Property<'a>)>> {
        let names: Vec<_> = self
            .schema
            .properties()
            .map(|p| p.name().unwrap_or_else(|| "<unnamed>".to_owned()))
            .collect();
        let props = self.properties()?;
        Ok(names.into_iter().zip(props).collect())
    }

    /// Formats the event as `"EventName { field: value, field: value, ... }"`.
    ///
    /// Uses [`std::fmt::Display`] on each [`Property`] for value formatting.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn example(parser: &mut etw::EventParser) -> etw::Result<()> {
    /// println!("{}", parser.format_event()?);
    /// // Output: "ProcessStop { ProcessID: 1234, ExitCode: 0, ImageName: notepad.exe }"
    /// # Ok(())
    /// # }
    /// ```
    pub fn format_event(&mut self) -> Result<String> {
        let event_name = self
            .schema
            .event_name()
            .or_else(|| self.schema.task_name())
            .or_else(|| self.schema.opcode_name())
            .unwrap_or_else(|| "Unknown".to_owned());
        let pairs = self.named_properties()?;
        let fields: Vec<_> = pairs
            .iter()
            .map(|(name, prop)| format!("{name}: {prop}"))
            .collect();
        Ok(format!("{event_name} {{ {} }}", fields.join(", ")))
    }

    /// Slices the event data for a cached property location.
    ///
    /// Handles ETW trailing zero truncation: fields may be partially or entirely
    /// missing when their values would be zero. Returns available data (may be
    /// empty or truncated).
    #[inline]
    fn slice_property(&self, location: PropertyLocation) -> &'a [u8] {
        if location.offset() >= self.data.len() {
            &[]
        } else {
            let available = (self.data.len() - location.offset()).min(location.size());
            &self.data[location.offset()..location.offset() + available]
        }
    }

    /// The out-type `T` is parsed with: the schema's, if `T` reads it for this
    /// in-type, else `Null`.
    ///
    /// Gated on [`FromProperty::reads_out_type`] so that the lookup — a read from
    /// the schema's `EVENT_PROPERTY_INFO`, outside the location cache — stays off
    /// the `get()` path of every property that does not need it.
    #[inline]
    fn out_type_for<T: FromProperty>(&self, index: u32, in_type: TdhInType) -> TdhOutType {
        if T::reads_out_type(in_type) {
            self.schema
                .property(index)
                .map_or(TdhOutType::Null, |prop| {
                    TdhOutType::from_raw(prop.out_type())
                })
        } else {
            TdhOutType::Null
        }
    }

    /// Gets the raw property data and type for a given property index.
    #[inline]
    fn get_raw_property_at(&mut self, index: u32) -> Result<(&'a [u8], TdhInType)> {
        let target = index as usize;

        // Ensure property location is cached
        if target >= self.cache.locations.len() {
            // Cold path: compute locations up to target
            self.compute_locations_up_to(index)?;
        }
        let location = self.cache.locations.get(target).ok_or_else(|| {
            Error::parse(format!(
                "Property location {target} not in cache after compute"
            ))
        })?;

        Ok((self.slice_property(*location), location.in_type))
    }

    /// Finds a property by name via O(1) hash lookup.
    #[inline]
    fn find_property_by_name(&self, name: &str) -> Result<u32> {
        self.schema
            .property_index(name)
            .ok_or_else(|| Error::PropertyNotFound {
                name: name.to_owned(),
                context: self.schema.event_context(),
            })
    }

    /// Finds a property by name, trying what this call position resolved to
    /// previously.
    ///
    /// The unhinted accessors' equivalent of [`find_property_by_hint`]: it
    /// supplies the hint itself, from [`ParserCache::learned_hints`], so callers
    /// get the hinted path's cost without having to know schema indices. On a
    /// miss it falls through to the same hash lookup and records the answer, so
    /// that call position is right from then on. The result is identical either
    /// way — only the cost differs.
    ///
    /// Predicting by *call position*, rather than by "the index after the last
    /// one", is what lets this serve a caller reading a subset: positions 0, 1, 2
    /// mapping to indices 0, 1, 6 is learned exactly as readily as 0, 1, 2.
    ///
    /// [`find_property_by_hint`]: Self::find_property_by_hint
    #[inline]
    fn find_property_at_learned_hint(&mut self, name: &str) -> Result<u32> {
        let position = self.position as usize;
        self.position = self.position.saturating_add(1);

        // Positions past the table belong to callers reading more properties than
        // the schema has — re-reads, mostly. They keep working, just unhinted.
        let Some(&hint) = self.cache.learned_hints.get(position) else {
            return self.find_property_by_name(name);
        };

        if self
            .schema
            .property_name(hint)
            .is_some_and(|candidate| names_equal(candidate, name))
        {
            return Ok(hint);
        }

        let index = self.find_property_by_name(name)?;
        if let Some(slot) = self.cache.learned_hints.get_mut(position) {
            *slot = index;
        }
        Ok(index)
    }

    /// Finds a property by name, trying the caller's hint index first.
    ///
    /// Checks the hinted index directly, a single string comparison, and falls
    /// back to the hash lookup if the hint is wrong. Use
    /// [`validate_all_schemas()`] at startup to detect stale hints.
    fn find_property_by_hint(&self, name: &str, hint: u32) -> Result<u32> {
        if self
            .schema
            .property_name(hint)
            .is_some_and(|n| names_equal(n, name))
        {
            return Ok(hint);
        }

        // Hint was wrong — silently fall back to hash lookup.
        self.find_property_by_name(name)
    }

    /// Computes and caches property locations up to (and including) the target index.
    ///
    /// This is the cold path for property access. After calling this, the location
    /// at `target_index` is guaranteed to be in the cache.
    fn compute_locations_up_to(&mut self, target_index: u32) -> Result<()> {
        let target = target_index as usize;

        while self.cache.locations.len() <= target {
            let idx = self.cache.locations.len() as u32;
            let prop = self
                .schema
                .property(idx)
                .ok_or_else(|| Error::parse(format!("Property index {idx} out of bounds")))?;

            let offset = self.cache.current_offset;
            let in_type = if prop.is_struct() {
                TdhInType::Struct
            } else {
                TdhInType::from_raw(prop.in_type())
            };
            let is_last = idx == self.schema.top_level_property_count() - 1;
            let size = self.compute_property_size(&prop, offset, is_last)?;

            self.cache
                .locations
                .push(PropertyLocation::new(offset, size, in_type));
            self.cache.decoded_lengths.push(None);
            self.cache.current_offset =
                self.cache.current_offset.checked_add(size).ok_or_else(|| {
                    Error::parse(format!("Property offset overflow at index {idx}"))
                })?;
        }

        Ok(())
    }

    /// Reads the length value from a previously-parsed property.
    /// Read a dynamic length/count value from a property in the event data.
    ///
    /// Returns `u16` because ETW events are at most 64 KB, so no property
    /// length or count can exceed `u16::MAX`. Values from wider backing
    /// fields (u32, u64) are truncated to u16.
    fn get_length_from_property(&mut self, length_prop_index: u16) -> Result<u16> {
        let index = length_prop_index as usize;
        if let Some(Some(cached)) = self.cache.decoded_lengths.get(index) {
            return Ok(*cached);
        }

        let location = *self.cache.locations.get(index).ok_or_else(|| {
            Error::parse(format!(
                "Length/count property index {length_prop_index} out of range"
            ))
        })?;

        let mut buf = [0u8; 8];
        if location.offset() < self.data.len() {
            let available = (self.data.len() - location.offset()).min(location.size().min(8));
            let src = &self.data[location.offset()..location.offset() + available];
            buf[..available].copy_from_slice(src);
        }

        // Read as appropriate integer type based on declared size.
        // Assumes the length/count property is a scalar (count <= 1), so
        // location.size() equals the element size. ETW length/count properties
        // are always scalar in practice.
        debug_assert!(
            matches!(location.size(), 1 | 2 | 4 | 8),
            "length/count property has unexpected size {} (expected scalar 1/2/4/8)",
            location.size()
        );
        // Property lengths/counts are u16 (ETW events are ≤64 KB). A wider backing
        // field is a TDH schema artefact, but its *value* is read from the untrusted
        // event buffer — a hostile provider can place a value > u16::MAX there. Reject
        // it rather than silently truncating (a wrap desynchronises every following
        // property offset).
        let value = match location.size() {
            1 => Ok(u16::from(buf[0])),
            2 => Ok(u16::from_le_bytes([buf[0], buf[1]])),
            4 => {
                let raw = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
                u16::try_from(raw)
                    .map_err(|_| Error::parse(format!("Length/count value {raw} exceeds u16::MAX")))
            }
            8 => {
                let raw = u64::from_le_bytes(buf);
                u16::try_from(raw)
                    .map_err(|_| Error::parse(format!("Length/count value {raw} exceeds u16::MAX")))
            }
            _ => Err(Error::parse(format!(
                "Invalid length property size: {}",
                location.size()
            ))),
        }?;

        if let Some(slot) = self.cache.decoded_lengths.get_mut(index) {
            *slot = Some(value);
        }

        Ok(value)
    }

    /// Computes the size of a struct property by summing its member sizes.
    ///
    /// Iterates member properties from `struct_start_index()` for
    /// `struct_member_count()` entries, using `schema.property_raw()` to access
    /// each member. Supports nested structs via recursion.
    fn compute_struct_size(
        &mut self,
        prop: &crate::processing_context::PropertyInfo<'_>,
        offset: usize,
    ) -> Result<usize> {
        let start = prop.struct_start_index() as u32;
        let count = prop.struct_member_count() as u32;
        let mut total = 0usize;

        for i in start..start + count {
            let member = self
                .schema
                .property_raw(i)
                .ok_or_else(|| Error::parse(format!("Struct member index {i} out of bounds")))?;

            // Struct members with PropertyParamCount or PropertyParamLength use
            // union fields differently — count()/length() return property indices
            // instead of actual values. Bail rather than silently miscomputing.
            if member.has_param_count() || member.has_param_length() {
                return Err(Error::parse(format!(
                    "Struct member {i} has parameterised count/length (not supported)"
                )));
            }

            let member_offset = offset + total;
            let member_size = if member.is_struct() {
                // Nested struct — recurse
                self.compute_struct_size(&member, member_offset)?
            } else {
                let declared_len = member.length() as usize;
                if declared_len > 0 {
                    declared_len
                } else {
                    let in_type = TdhInType::from_raw(member.in_type());
                    if let Some(size) = in_type.fixed_size(self.pointer_size) {
                        size
                    } else {
                        // Variable-length member — scan
                        let remaining = self.data.get(member_offset..).ok_or_else(|| {
                            Error::parse(format!(
                                "Struct member data truncated at offset {member_offset}"
                            ))
                        })?;
                        Self::compute_variable_element_size(remaining, in_type, self.pointer_size)?
                    }
                }
            };

            total += member_size * member.count().max(1) as usize;
        }

        Ok(total)
    }

    /// Computes the size of a property in the buffer.
    ///
    /// When `is_last` is true and the property is a NULL-terminated string,
    /// the remaining buffer bytes are used directly instead of scanning for
    /// a NULL terminator. ETW can sometimes drop the trailing NULL on the
    /// last property, so scanning would fail on valid events.
    fn compute_property_size(
        &mut self,
        prop: &crate::processing_context::PropertyInfo<'_>,
        offset: usize,
        is_last: bool,
    ) -> Result<usize> {
        // PropertyStruct — size is sum of member sizes, multiplied by static array count.
        if prop.is_struct() {
            let struct_size = self.compute_struct_size(prop, offset)?;
            return Ok(struct_size * prop.count().max(1) as usize);
        }

        // Check PropertyParamLength flag — length is stored in another property
        if prop.has_param_length() {
            let len = self.get_length_from_property(prop.length_property_index())? as usize;
            // The length is per element, whether the count is static or
            // PropertyParamCount — TDH multiplies either way.
            let count = if prop.has_param_count() {
                self.get_length_from_property(prop.count_property_index())? as usize
            } else {
                prop.count().max(1) as usize
            };
            // Both values are u16, so u16 × u16 ≤ 4 GB — cannot overflow usize on 64-bit.
            return Ok(len * count);
        }

        // Determine element count: dynamic (PropertyParamCount) or static.
        // Both paths yield a value bounded by u16.
        let array_count = if prop.has_param_count() {
            self.get_length_from_property(prop.count_property_index())? as usize
        } else {
            let static_count = prop.count() as usize;
            if static_count > 1 { static_count } else { 1 }
        };

        let declared_length = prop.length() as usize;

        // If declared length is non-zero, use it (it's the per-element size).
        // declared_length is u16, array_count is u16 — cannot overflow usize on 64-bit.
        if declared_length > 0 {
            return declared_length.checked_mul(array_count).ok_or_else(|| {
                Error::parse(format!(
                    "Property size overflow: {declared_length} × {array_count}"
                ))
            });
        }

        let in_type = TdhInType::from_raw(prop.in_type());

        // Check for fixed-size types.
        // fixed_size() returns ≤8, array_count is u16 — cannot overflow usize on 64-bit.
        if let Some(size) = in_type.fixed_size(self.pointer_size) {
            return size.checked_mul(array_count).ok_or_else(|| {
                Error::parse(format!("Property size overflow: {size} × {array_count}"))
            });
        }

        // Variable-length types — scan each array element sequentially.
        // For non-array properties, array_count is 1.
        let mut total_size = 0;
        for i in 0..array_count {
            let element_offset = offset + total_size;
            let Some(remaining) = self.data.get(element_offset..) else {
                return Err(Error::parse(format!(
                    "Property data truncated at offset {element_offset}"
                )));
            };

            // For the last element of the last property, use remaining buffer
            // bytes instead of scanning for NULL. ETW can drop the trailing
            // NULL on the last property, which would cause a scan failure.
            let is_last_element = is_last && i == array_count - 1;
            if is_last_element
                && matches!(in_type, TdhInType::UnicodeString | TdhInType::AnsiString)
            {
                total_size += remaining.len();
            } else {
                total_size +=
                    Self::compute_variable_element_size(remaining, in_type, self.pointer_size)?;
            }
        }
        Ok(total_size)
    }

    /// Computes the size of a single variable-length element in the buffer.
    fn compute_variable_element_size(
        remaining: &[u8],
        in_type: TdhInType,
        pointer_size: usize,
    ) -> Result<usize> {
        match in_type {
            // A Binary property reaches this point only when it declared neither a
            // length nor a PropertyParamLength, which leaves nothing to size it by.
            //
            // <tdh.h> implies an IPv6 out-type means 16 bytes, but no registered
            // manifest (25H2) has a property that reaches here, so honouring it would
            // cost every caller an out-type lookup for nothing.
            TdhInType::Binary => Err(Error::parse(
                "Binary property has no declared length and no PropertyParamLength; \
                 cannot determine its size",
            )),
            TdhInType::UnicodeString => {
                // Null-terminated UTF-16 string — uses aligned fast path when possible.
                crate::types::WideStrRef::find_null_terminator(remaining)
                    .map(|pos| pos + 2) // Include null terminator in size
                    .ok_or_else(|| {
                        Error::parse("No null terminator found for UnicodeString")
                    })
            }
            TdhInType::AnsiString => {
                // Null-terminated ANSI string
                remaining
                    .iter()
                    .position(|&b| b == 0)
                    .map(|pos| pos + 1) // Include null terminator
                    .ok_or_else(|| {
                        Error::parse("No null terminator found for AnsiString")
                    })
            }
            TdhInType::Sid => {
                if remaining.len() < 8 {
                    return Err(Error::parse("Insufficient data for SID"));
                }
                let sub_auth_count = remaining[1] as usize;
                if sub_auth_count > SID_MAX_SUB_AUTHORITIES as usize {
                    return Err(Error::parse(format!(
                        "SID sub-authority count {sub_auth_count} exceeds maximum of {SID_MAX_SUB_AUTHORITIES}"
                    )));
                }
                Ok(8 + sub_auth_count * 4)
            }
            TdhInType::CountedString | TdhInType::ReversedCountedString => {
                if remaining.len() < 2 {
                    return Err(Error::parse("Insufficient data for CountedString"));
                }
                // TDH_INTYPE_COUNTEDSTRING: the 2-byte prefix is a *byte* count of
                // the UTF-16 payload that follows (not a character count), so it
                // must be even. See the TDH_INTYPE_COUNTEDSTRING definition in
                // <tdh.h>.
                let byte_count = counted_string_len(remaining, in_type) as usize;
                if byte_count & 1 != 0 {
                    return Err(Error::parse(format!(
                        "CountedString has odd byte count ({byte_count})"
                    )));
                }
                let total = 2 + byte_count;
                if total > remaining.len() {
                    return Err(Error::parse(format!(
                        "CountedString declares {byte_count} bytes but only {} available",
                        remaining.len() - 2
                    )));
                }
                Ok(total)
            }
            TdhInType::CountedAnsiString | TdhInType::ReversedCountedAnsiString => {
                if remaining.len() < 2 {
                    return Err(Error::parse("Insufficient data for CountedAnsiString"));
                }
                let byte_count = counted_string_len(remaining, in_type) as usize;
                let total = 2 + byte_count;
                if total > remaining.len() {
                    return Err(Error::parse(format!(
                        "CountedAnsiString declares {byte_count} bytes but only {} available",
                        remaining.len() - 2
                    )));
                }
                Ok(total)
            }
            TdhInType::ManifestCountedString
            | TdhInType::ManifestCountedAnsiString
            | TdhInType::ManifestCountedBinary => {
                // 2-byte LE bytecount prefix followed by payload bytes.
                if remaining.len() < 2 {
                    return Err(Error::parse("Insufficient data for ManifestCounted prefix"));
                }
                let byte_count = u16::from_le_bytes([remaining[0], remaining[1]]) as usize;
                let total = 2 + byte_count;
                if total > remaining.len() {
                    return Err(Error::parse(format!(
                        "ManifestCounted field declares {byte_count} bytes but only {} available",
                        remaining.len() - 2
                    )));
                }
                Ok(total)
            }
            TdhInType::WbemSid => {
                let hdr = token_user_size(pointer_size);
                if remaining.len() < hdr + 8 {
                    return Err(Error::parse("Insufficient data for WbemSid"));
                }
                let sub_auth_count = remaining[hdr + 1] as usize;
                if sub_auth_count > SID_MAX_SUB_AUTHORITIES as usize {
                    return Err(Error::parse(format!(
                        "WbemSid sub-authority count {sub_auth_count} exceeds maximum of {SID_MAX_SUB_AUTHORITIES}"
                    )));
                }
                let sid_size = 8 + sub_auth_count * 4;
                Ok(hdr + sid_size)
            }
            _ => Err(Error::parse(format!(
                "Cannot determine size for type {in_type:?}"
            ))),
        }
    }

    /// Returns the individual member properties of a struct property.
    ///
    /// Each returned [`Property`] contains the member's data slice, `in_type`,
    /// and `out_type`. Member offsets are computed sequentially within the
    /// struct's data region.
    ///
    /// Note: when the struct property has a static array count > 1, this method
    /// returns the members of the **first instance only**. To iterate subsequent
    /// instances, advance manually using the total byte size of the struct.
    ///
    /// # Errors
    ///
    /// Returns error if the property is not found, is not a struct, or if
    /// member data cannot be parsed.
    pub fn struct_members(&mut self, name: &str) -> Result<Vec<Property<'a>>> {
        let index = self.find_property_by_name(name)?;

        let prop = self
            .schema
            .property(index)
            .ok_or_else(|| Error::parse(format!("Property index {index} out of bounds")))?;

        if !prop.is_struct() {
            return Err(Error::parse(format!("Property '{name}' is not a struct")));
        }

        // Ensure the struct property location is cached
        if index as usize >= self.cache.locations.len() {
            self.compute_locations_up_to(index)?;
        }
        let struct_location = self.cache.locations[index as usize];

        let start = prop.struct_start_index() as u32;
        let count = prop.struct_member_count() as u32;
        let mut members = Vec::with_capacity(count as usize);
        let mut member_offset = struct_location.offset();

        for i in start..start + count {
            let member = self
                .schema
                .property_raw(i)
                .ok_or_else(|| Error::parse(format!("Struct member index {i} out of bounds")))?;

            if member.has_param_count() || member.has_param_length() {
                return Err(Error::parse(format!(
                    "Struct member {i} has parameterised count/length (not supported)"
                )));
            }

            let in_type = TdhInType::from_raw(member.in_type());
            let out_type = TdhOutType::from_raw(member.out_type());

            let member_size = if member.is_struct() {
                self.compute_struct_size(&member, member_offset)?
            } else {
                let declared_len = member.length() as usize;
                if declared_len > 0 {
                    declared_len
                } else if let Some(size) = in_type.fixed_size(self.pointer_size) {
                    size
                } else {
                    let remaining = self.data.get(member_offset..).ok_or_else(|| {
                        Error::parse(format!(
                            "Struct member data truncated at offset {member_offset}"
                        ))
                    })?;
                    Self::compute_variable_element_size(remaining, in_type, self.pointer_size)?
                }
            };

            let total_member_size = member_size * member.count().max(1) as usize;
            let member_data = if member_offset >= self.data.len() {
                &[]
            } else {
                let available = (self.data.len() - member_offset).min(total_member_size);
                &self.data[member_offset..member_offset + available]
            };

            members.push(Property {
                data: member_data,
                in_type,
                out_type,
            });

            member_offset += total_member_size;
        }

        Ok(members)
    }

    /// Returns the individual elements of an array property.
    ///
    /// For fixed-size elements, each element is sliced from the total data.
    /// For variable-size elements, each is scanned sequentially.
    ///
    /// Note: struct array properties (where `is_struct()` is true and `count > 1`)
    /// are not supported — this method returns an error for them. Use
    /// [`struct_members()`](Self::struct_members) to access a single struct
    /// instance, then advance manually for subsequent instances.
    ///
    /// # Errors
    ///
    /// Returns error if the property is not found, is not an array, is a struct
    /// array, or if element data cannot be parsed.
    pub fn array_elements(&mut self, name: &str) -> Result<Vec<Property<'a>>> {
        let index = self.find_property_by_name(name)?;

        let prop = self
            .schema
            .property(index)
            .ok_or_else(|| Error::parse(format!("Property index {index} out of bounds")))?;

        if prop.is_struct() {
            return Err(Error::parse(format!(
                "Property '{name}' is a struct array; use struct_members() for a single instance"
            )));
        }

        // Determine array count
        let array_count = if prop.has_param_count() {
            let count = self.get_length_from_property(prop.count_property_index())? as usize;
            if count == 0 {
                return Ok(Vec::new());
            }
            count
        } else {
            let count = prop.count() as usize;
            // count == 0 means scalar (not an array)
            if count == 0 {
                return Err(Error::parse(format!(
                    "Property '{name}' is not an array (count == 0)"
                )));
            }
            count
        };

        // Ensure the array property location is cached
        if index as usize >= self.cache.locations.len() {
            self.compute_locations_up_to(index)?;
        }
        let location = self.cache.locations[index as usize];
        let in_type = location.in_type;
        let out_type = TdhOutType::from_raw(prop.out_type());

        // When has_param_length is set, prop.length() returns a property index
        // (lengthPropertyIndex), not an actual byte count. Element iteration with
        // per-element dynamic lengths is not supported.
        if prop.has_param_length() {
            return Err(Error::parse(format!(
                "Property '{name}' uses PropertyParamLength; element iteration not supported"
            )));
        }

        let mut elements = Vec::with_capacity(array_count);
        let declared_length = prop.length() as usize;

        if declared_length > 0 || in_type.fixed_size(self.pointer_size).is_some() {
            // Fixed-size elements
            let element_size = if declared_length > 0 {
                declared_length
            } else {
                in_type.fixed_size(self.pointer_size).unwrap_or(0)
            };

            for i in 0..array_count {
                // i and element_size are u16-bounded, location.offset() is within
                // a ≤64 KB ETW buffer — cannot overflow usize on 64-bit.
                let elem_offset = location.offset() + i * element_size;
                let elem_data = if elem_offset >= self.data.len() {
                    &[]
                } else {
                    let available = (self.data.len() - elem_offset).min(element_size);
                    &self.data[elem_offset..elem_offset + available]
                };
                elements.push(Property {
                    data: elem_data,
                    in_type,
                    out_type,
                });
            }
        } else {
            // Variable-size elements — scan sequentially
            let mut elem_offset = location.offset();
            for _ in 0..array_count {
                let remaining = self.data.get(elem_offset..).ok_or_else(|| {
                    Error::parse(format!(
                        "Array element data truncated at offset {elem_offset}"
                    ))
                })?;
                let elem_size =
                    Self::compute_variable_element_size(remaining, in_type, self.pointer_size)?;
                let elem_data = &self.data[elem_offset..elem_offset + elem_size];
                elements.push(Property {
                    data: elem_data,
                    in_type,
                    out_type,
                });
                elem_offset += elem_size;
            }
        }

        Ok(elements)
    }

    /// Returns a reference to the event schema.
    ///
    /// Use this to inspect available properties and their types.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn example(parser: &etw::EventParser) {
    /// for prop in parser.schema().properties() {
    ///     println!(
    ///         "  {}: {:?}",
    ///         prop.name().unwrap_or_default(),
    ///         prop.in_type()
    ///     );
    /// }
    /// # }
    /// ```
    #[must_use]
    pub const fn schema(&self) -> &EventSchema {
        self.schema
    }

    /// Creates an `EventParser` from raw parts for testing.
    ///
    /// Takes a raw data slice, schema, and cache directly without requiring
    /// a `RawEvent`. Defaults to 64-bit pointer size.
    #[cfg(test)]
    pub(crate) fn from_raw_parts(
        data: &'a [u8],
        schema: &'a EventSchema,
        cache: &'a mut ParserCache,
    ) -> Self {
        cache.reset();
        Self {
            data,
            schema,
            cache,
            pointer_size: 8,
            position: 0,
        }
    }
}

impl std::fmt::Debug for EventParser<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventParser")
            .field("data_len", &self.data.len())
            .field("cache", &self.cache)
            .finish()
    }
}

/// Trait for types that can be parsed from a property buffer.
///
/// Implemented by all types that [`EventParser::get`] and [`EventParser::get_hinted`]
/// can return, including primitives, [`WideString`], [`AnsiString`], `OsString`
/// and `String`.
///
/// Assumes 64-bit event data (this crate supports only x86_64 and aarch64).
pub trait FromProperty: Sized {
    /// Whether [`from_property`](Self::from_property) reads its `out_type` for a
    /// property of this `in_type`.
    ///
    /// [`EventParser::get`] looks the out-type up only when this returns `true`,
    /// and passes [`TdhOutType::Null`] otherwise: the lookup reads the schema, and
    /// almost no property needs it. An impl that does consult `out_type` must
    /// override this, or it will only ever see `Null` from the parser.
    #[must_use]
    fn reads_out_type(in_type: TdhInType) -> bool {
        let _ = in_type;
        false
    }

    /// Parses `Self` from `data`, laid out according to `in_type`.
    ///
    /// `out_type` is the property's declared output type. Most types ignore it;
    /// `String` uses it to pick the code page of an ANSI string
    /// ([`TdhOutType::ansi_code_page`]).
    fn from_property(data: &[u8], in_type: TdhInType, out_type: TdhOutType) -> Result<Self>;
}

/// Trait for types that can be borrowed from a property buffer without copying.
///
/// Unlike `FromProperty` which returns owned types, this trait returns references
/// into the event buffer, enabling zero-copy access to string and binary data.
///
/// # Example
///
/// ```no_run
/// # fn example(parser: &mut etw::EventParser) -> etw::Result<()> {
/// use etw::{
///     parser::FromPropertyRef,
///     types::{AnsiStrRef, SidRef, WideStrRef},
/// };
///
/// let wide: WideStrRef = parser.as_ref("QueryName")?;
/// let ansi: AnsiStrRef = parser.as_ref("ProcessName")?;
/// let data: &[u8] = parser.as_ref("BinaryData")?;
/// let sid: SidRef = parser.as_ref("UserSid")?;
/// # Ok(())
/// # }
/// ```
pub trait FromPropertyRef<'a>: Sized {
    /// Borrows `Self` from `data`, interpreting it according to `in_type`.
    fn from_property_ref(data: &'a [u8], in_type: TdhInType) -> Result<Self>;
}

// =============================================================================
// FromProperty Implementations (Native Types)
// =============================================================================

/// Slices the UTF-16 payload out of a wide-string property.
///
/// Applies the counted-prefix rules only; null-terminator handling is left to
/// the caller because the owned and borrowing decoders express it differently.
///
/// Shared by `FromProperty for WideString` and `FromProperty for String` so the
/// two cannot drift. That matters most for malformed input: a truncated or
/// odd-length counted prefix must stay an error in both, not become a silently
/// empty string.
fn wide_string_payload(data: &[u8], in_type: TdhInType) -> Result<&[u8]> {
    match in_type {
        TdhInType::UnicodeString | TdhInType::NonNullTerminatedString => Ok(data),
        TdhInType::CountedString | TdhInType::ReversedCountedString => {
            if data.len() < 2 {
                return Err(Error::parse("CountedString too short"));
            }
            // The 2-byte prefix is a byte count of the UTF-16 payload.
            let byte_count = counted_string_len(data, in_type) as usize;
            if byte_count & 1 != 0 {
                return Err(Error::parse(format!(
                    "CountedString has odd byte count ({byte_count})"
                )));
            }
            let end = (2 + byte_count).min(data.len());
            Ok(&data[2..end])
        }
        TdhInType::ManifestCountedString => {
            if data.len() < 2 {
                return Err(Error::parse("ManifestCountedString too short"));
            }
            let byte_count = u16::from_le_bytes([data[0], data[1]]) as usize;
            if byte_count & 1 != 0 {
                return Err(Error::parse(format!(
                    "ManifestCountedString has odd byte count ({byte_count})"
                )));
            }
            let end = (2 + byte_count).min(data.len());
            Ok(&data[2..end])
        }
        _ => Err(Error::parse(format!(
            "Cannot parse WideString from {in_type:?}"
        ))),
    }
}

impl FromProperty for WideString {
    fn from_property(data: &[u8], in_type: TdhInType, _: TdhOutType) -> Result<Self> {
        Ok(Self::from_bytes(wide_string_payload(data, in_type)?))
    }
}

impl FromProperty for AnsiString {
    fn from_property(data: &[u8], in_type: TdhInType, _: TdhOutType) -> Result<Self> {
        match in_type {
            TdhInType::AnsiString | TdhInType::NonNullTerminatedAnsiString => {
                Ok(Self::from_bytes(data))
            }
            TdhInType::CountedAnsiString | TdhInType::ReversedCountedAnsiString => {
                if data.len() < 2 {
                    return Err(Error::parse("CountedAnsiString too short"));
                }
                let byte_count = counted_string_len(data, in_type) as usize;
                let str_data = &data[2..];
                let end = byte_count.min(str_data.len());
                Ok(Self::from_vec(str_data[..end].to_vec()))
            }
            TdhInType::ManifestCountedAnsiString => {
                if data.len() < 2 {
                    return Err(Error::parse("ManifestCountedAnsiString too short"));
                }
                let byte_count = u16::from_le_bytes([data[0], data[1]]) as usize;
                let end = (2 + byte_count).min(data.len());
                Ok(Self::from_vec(data[2..end].to_vec()))
            }
            _ => Err(Error::parse(format!(
                "Cannot parse AnsiString from {in_type:?}"
            ))),
        }
    }
}

impl FromProperty for std::ffi::OsString {
    fn from_property(data: &[u8], in_type: TdhInType, out_type: TdhOutType) -> Result<Self> {
        match in_type {
            TdhInType::UnicodeString
            | TdhInType::NonNullTerminatedString
            | TdhInType::CountedString
            | TdhInType::ReversedCountedString
            | TdhInType::ManifestCountedString => {
                Ok(WideString::from_property(data, in_type, out_type)?.to_os_string())
            }
            _ => Err(Error::parse(format!(
                "Cannot parse OsString from {in_type:?}"
            ))),
        }
    }
}

impl FromProperty for String {
    fn reads_out_type(in_type: TdhInType) -> bool {
        matches!(
            in_type,
            TdhInType::AnsiString
                | TdhInType::NonNullTerminatedAnsiString
                | TdhInType::CountedAnsiString
                | TdhInType::ReversedCountedAnsiString
                | TdhInType::ManifestCountedAnsiString
        )
    }

    fn from_property(data: &[u8], in_type: TdhInType, out_type: TdhOutType) -> Result<Self> {
        match in_type {
            TdhInType::UnicodeString
            | TdhInType::NonNullTerminatedString
            | TdhInType::CountedString
            | TdhInType::ReversedCountedString
            | TdhInType::ManifestCountedString => {
                // Decode straight out of the event buffer. Going via
                // `WideString` copies the UTF-16 payload into a `Vec<u16>`
                // purely to decode it, and `WideStrRef::decode_utf16` also
                // takes an aligned fast path the owned form cannot. Mirrors
                // what the AnsiString arm below already does.
                //
                // Slicing comes from the same `wide_string_payload` the owned
                // impl uses, and `null_terminated_len` applies the terminator
                // rule `WideString::from_bytes` does, so this is a pure
                // allocation saving: same output, and the same errors on
                // malformed input. Both decode via the strict
                // `String::from_utf16`, so a lone surrogate still errors rather
                // than being replaced.
                let payload = wide_string_payload(data, in_type)?;
                let end = WideStrRef::null_terminated_len(payload);
                WideStrRef::new(&payload[..end]).decode_utf16()
            }
            // Borrow via AnsiStrRef to avoid copying the bytes into an owned
            // AnsiString before decoding.
            TdhInType::AnsiString
            | TdhInType::NonNullTerminatedAnsiString
            | TdhInType::CountedAnsiString
            | TdhInType::ReversedCountedAnsiString
            | TdhInType::ManifestCountedAnsiString => {
                AnsiStrRef::from_property_ref(data, in_type)?.decode(out_type.ansi_code_page())
            }
            _ => Err(Error::parse(format!(
                "Cannot parse String from {in_type:?}"
            ))),
        }
    }
}

macro_rules! impl_from_property_primitive {
    ($t:ty, $size:expr, $($variant:pat),+) => {
        impl FromProperty for $t {
            fn from_property(data: &[u8], in_type: TdhInType, _: TdhOutType) -> Result<Self> {
                match in_type {
                    $($variant)|+ => {
                        // Fast path: data is exactly the right size (common case)
                        if data.len() == $size {
                            // Length was just checked, so try_into always succeeds.
                            return Ok(<$t>::from_le_bytes(data.try_into().unwrap()));
                        }
                        // Slow path: zero-extend truncated data (ETW may truncate trailing zeros)
                        debug_assert!(
                            data.len() <= $size,
                            "data longer than expected for {}: {} > {}",
                            stringify!($t), data.len(), $size,
                        );
                        let mut arr = [0u8; $size];
                        let copy_len = data.len().min($size);
                        arr[..copy_len].copy_from_slice(&data[..copy_len]);
                        Ok(<$t>::from_le_bytes(arr))
                    }
                    _ => Err(Error::parse(format!(
                        "Cannot parse {} from {:?}",
                        stringify!($t), in_type
                    ))),
                }
            }
        }
    };
}

// Strict type matching: each Rust type accepts only the TDH types with matching
// signedness and width. HexInt* are unsigned (flags, handles, status codes).
// Pointer/SizeT are variable-width (4 bytes on 32-bit events, 8 on 64-bit).
// u64 accepts them and zero-extends 32-bit values; prefer usize for pointer
// arithmetic. u32 does NOT accept Pointer/SizeT — on 64-bit events the 8-byte
// slice would exceed the 4-byte buffer in the macro's slow path.
impl_from_property_primitive!(u8, 1, TdhInType::UInt8);
impl_from_property_primitive!(i8, 1, TdhInType::Int8);
impl_from_property_primitive!(u16, 2, TdhInType::UInt16);
impl_from_property_primitive!(i16, 2, TdhInType::Int16);
impl_from_property_primitive!(u32, 4, TdhInType::UInt32, TdhInType::HexInt32);
impl_from_property_primitive!(i32, 4, TdhInType::Int32);
impl_from_property_primitive!(
    u64,
    8,
    TdhInType::UInt64,
    TdhInType::HexInt64,
    TdhInType::Pointer,
    TdhInType::SizeT
);
impl_from_property_primitive!(i64, 8, TdhInType::Int64);
impl_from_property_primitive!(f32, 4, TdhInType::Float);
impl_from_property_primitive!(f64, 8, TdhInType::Double);

impl FromProperty for bool {
    fn from_property(data: &[u8], in_type: TdhInType, _: TdhOutType) -> Result<Self> {
        match in_type {
            TdhInType::Boolean => {
                // Any non-zero byte is truthy — consistent with Property::fmt.
                // Handles Win32 BOOL (4 bytes) and BOOLEAN (1 byte).
                Ok(data.iter().any(|&b| b != 0))
            }
            _ => Err(Error::parse(format!("Cannot parse bool from {in_type:?}"))),
        }
    }
}

impl FromProperty for usize {
    fn from_property(data: &[u8], in_type: TdhInType, _: TdhOutType) -> Result<Self> {
        match in_type {
            TdhInType::Pointer | TdhInType::SizeT => {
                // Pointer/SizeT is 4 or 8 bytes (or fewer when ETW truncates trailing zeros)
                debug_assert!(
                    data.len() <= 8,
                    "Pointer/SizeT must be at most 8 bytes, got {}",
                    data.len()
                );
                let mut buf = [0u8; 8];
                let copy_len = data.len().min(8);
                buf[..copy_len].copy_from_slice(&data[..copy_len]);
                Ok(u64::from_le_bytes(buf) as Self)
            }
            _ => Err(Error::parse(format!(
                "Cannot parse pointer from {in_type:?}"
            ))),
        }
    }
}

impl FromProperty for Vec<u8> {
    fn from_property(data: &[u8], in_type: TdhInType, _: TdhOutType) -> Result<Self> {
        match in_type {
            TdhInType::Binary => Ok(data.to_vec()),
            _ => Err(Error::parse(format!(
                "Cannot parse Vec<u8> from {in_type:?}"
            ))),
        }
    }
}

/// Address family constant for IPv4.
const AF_INET: u16 = 2;
/// Address family constant for IPv6.
const AF_INET6: u16 = 23;

/// Parse a Windows SOCKADDR structure from raw bytes.
///
/// Supports both IPv4 (`SOCKADDR_IN`) and IPv6 (`SOCKADDR_IN6`) addresses.
pub fn parse_sockaddr(data: &[u8]) -> Result<std::net::SocketAddr> {
    if data.len() < 2 {
        return Err(Error::parse("Insufficient data for SOCKADDR"));
    }

    let family = u16::from_le_bytes([data[0], data[1]]);
    match family {
        AF_INET => parse_sockaddr_v4(data),
        AF_INET6 => parse_sockaddr_v6(data),
        _ => Err(Error::parse(format!("Unknown address family: {family}"))),
    }
}

fn parse_sockaddr_v4(data: &[u8]) -> Result<std::net::SocketAddr> {
    if data.len() < 8 {
        return Err(Error::parse("Insufficient data for SOCKADDR_IN"));
    }
    // Port is in network byte order (big-endian)
    let port = u16::from_be_bytes([data[2], data[3]]);
    let ip = std::net::Ipv4Addr::new(data[4], data[5], data[6], data[7]);
    Ok(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
        ip, port,
    )))
}

fn parse_sockaddr_v6(data: &[u8]) -> Result<std::net::SocketAddr> {
    if data.len() < 24 {
        return Err(Error::parse("Insufficient data for SOCKADDR_IN6"));
    }
    // Port is in network byte order (big-endian)
    let port = u16::from_be_bytes([data[2], data[3]]);
    let mut addr = [0u8; 16];
    addr.copy_from_slice(&data[8..24]);
    let ip = std::net::Ipv6Addr::from(addr);
    // flow_info (bytes 4-7) and scope_id (bytes 24-27) from SOCKADDR_IN6 are
    // discarded — std::net::SocketAddrV6 supports them but they are rarely
    // meaningful in ETW event payloads.
    Ok(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
        ip, port, 0, 0,
    )))
}

impl FromProperty for std::net::SocketAddr {
    fn from_property(data: &[u8], in_type: TdhInType, _: TdhOutType) -> Result<Self> {
        match in_type {
            TdhInType::Binary => parse_sockaddr(data),
            _ => Err(Error::parse(format!(
                "Cannot parse SocketAddr from {in_type:?}"
            ))),
        }
    }
}

impl FromProperty for std::net::Ipv4Addr {
    fn from_property(data: &[u8], in_type: TdhInType, _: TdhOutType) -> Result<Self> {
        match in_type {
            // Binary / UInt32 — exactly 4 bytes in network byte order.
            // Exact length match prevents confusion with SOCKADDR_IN (8+ bytes).
            TdhInType::Binary | TdhInType::UInt32 | TdhInType::Int32 | TdhInType::HexInt32 => {
                if data.len() != 4 {
                    return Err(Error::parse(format!(
                        "Ipv4Addr requires exactly 4 bytes, got {}",
                        data.len()
                    )));
                }
                Ok(Self::new(data[0], data[1], data[2], data[3]))
            }
            _ => Err(Error::parse(format!(
                "Cannot parse Ipv4Addr from {in_type:?}"
            ))),
        }
    }
}

impl FromProperty for std::net::Ipv6Addr {
    fn from_property(data: &[u8], in_type: TdhInType, _: TdhOutType) -> Result<Self> {
        match in_type {
            // Binary / Guid — exactly 16 bytes in network byte order.
            // Exact length match prevents confusion with SOCKADDR_IN6 (24+ bytes).
            TdhInType::Binary | TdhInType::Guid => {
                if data.len() != 16 {
                    return Err(Error::parse(format!(
                        "Ipv6Addr requires exactly 16 bytes, got {}",
                        data.len()
                    )));
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[..16]);
                Ok(Self::from(octets))
            }
            _ => Err(Error::parse(format!(
                "Cannot parse Ipv6Addr from {in_type:?}"
            ))),
        }
    }
}

impl FromProperty for SystemTime {
    fn from_property(data: &[u8], in_type: TdhInType, _: TdhOutType) -> Result<Self> {
        match in_type {
            TdhInType::SystemTime => {
                if data.len() < 16 {
                    return Err(Error::parse("Insufficient data for SystemTime"));
                }
                Ok(Self {
                    year: u16::from_le_bytes([data[0], data[1]]),
                    month: u16::from_le_bytes([data[2], data[3]]),
                    day_of_week: u16::from_le_bytes([data[4], data[5]]),
                    day: u16::from_le_bytes([data[6], data[7]]),
                    hour: u16::from_le_bytes([data[8], data[9]]),
                    minute: u16::from_le_bytes([data[10], data[11]]),
                    second: u16::from_le_bytes([data[12], data[13]]),
                    milliseconds: u16::from_le_bytes([data[14], data[15]]),
                })
            }
            _ => Err(Error::parse(format!(
                "Cannot parse SystemTime from {in_type:?}"
            ))),
        }
    }
}

impl FromProperty for Timestamp {
    fn from_property(data: &[u8], in_type: TdhInType, _: TdhOutType) -> Result<Self> {
        match in_type {
            TdhInType::FileTime => {
                // Zero-extend truncated data (ETW may truncate trailing zeros)
                let mut arr = [0u8; 8];
                let len = data.len().min(8);
                arr[..len].copy_from_slice(&data[..len]);
                Ok(Self(i64::from_le_bytes(arr)))
            }
            _ => Err(Error::parse(format!(
                "Cannot parse Timestamp from {in_type:?}"
            ))),
        }
    }
}

impl FromProperty for Guid {
    fn from_property(data: &[u8], in_type: TdhInType, _: TdhOutType) -> Result<Self> {
        match in_type {
            TdhInType::Guid => {
                if data.len() < 16 {
                    return Err(Error::parse("Insufficient data for GUID"));
                }

                // SAFETY: This is Windows-only code. GUID bytes from ETW are already in
                // Windows native memory layout (data1/data2/data3 as little-endian integers,
                // data4 as raw bytes). We can directly copy the 16 bytes without conversion.
                // The pointer is valid because we've verified data.len() >= 16 above.
                // ETW UserData is 8-byte aligned, so GUIDs at offset 0 are naturally aligned.
                // Using read_unaligned for safety: GUIDs at arbitrary field offsets may not be
                // 4-byte aligned (e.g., a GUID following a u16 field at offset 2).
                let guid = unsafe { std::ptr::read_unaligned(data.as_ptr().cast::<Self>()) };
                Ok(guid)
            }
            _ => Err(Error::parse(format!("Cannot parse GUID from {in_type:?}"))),
        }
    }
}

/// Returns the size of the `TOKEN_USER` header for the given pointer size.
///
/// `TOKEN_USER` wraps `SID_AND_ATTRIBUTES { Sid: *SID, Attributes: DWORD }`.
/// On a 64-bit process: pointer(8) + DWORD(4) + padding(4) = 16 bytes.
/// On a 32-bit process: pointer(4) + DWORD(4) = 8 bytes.
const fn token_user_size(pointer_size: usize) -> usize {
    if pointer_size == 8 { 16 } else { 8 }
}

/// Reads the 2-byte byte-count prefix from a counted string field.
///
/// All four counted variants count *bytes*, not characters — including the wide
/// ones, whose payload is therefore half this many UTF-16 code units.
///
/// `ReversedCountedString`/`ReversedCountedAnsiString` use big-endian byte order;
/// `CountedString`/`CountedAnsiString` use little-endian.
/// Caller must ensure `data.len() >= 2`.
const fn counted_string_len(data: &[u8], in_type: TdhInType) -> u16 {
    match in_type {
        TdhInType::ReversedCountedString | TdhInType::ReversedCountedAnsiString => {
            u16::from_be_bytes([data[0], data[1]])
        }
        _ => u16::from_le_bytes([data[0], data[1]]),
    }
}

impl FromProperty for Sid {
    fn from_property(data: &[u8], in_type: TdhInType, _: TdhOutType) -> Result<Self> {
        match in_type {
            TdhInType::WbemSid => {
                // Skip TOKEN_USER header to reach the SID.
                // See token_user_size() for the pointer-size caveat.
                let hdr = token_user_size(size_of::<usize>());
                if data.len() <= hdr {
                    return Err(Error::parse("Insufficient data for WbemSid"));
                }
                Self::from_property(&data[hdr..], TdhInType::Sid, TdhOutType::Null)
            }
            TdhInType::Sid => {
                if data.len() < 8 {
                    return Err(Error::parse("Insufficient data for SID"));
                }
                let revision = data[0];
                // SID_REVISION (1) is the only valid revision per the Windows SDK.
                if revision != 1 {
                    return Err(Error::parse(format!(
                        "Invalid SID revision {revision} (expected 1)"
                    )));
                }
                let sub_auth_count = data[1] as usize;
                if sub_auth_count > SID_MAX_SUB_AUTHORITIES as usize {
                    return Err(Error::parse(format!(
                        "SID sub-authority count {sub_auth_count} exceeds maximum of {SID_MAX_SUB_AUTHORITIES}"
                    )));
                }
                let mut authority = [0u8; 6];
                authority.copy_from_slice(&data[2..8]);

                let expected_len = 8 + sub_auth_count * 4;
                if data.len() < expected_len {
                    return Err(Error::parse(format!(
                        "Insufficient data for SID: need {} bytes, have {}",
                        expected_len,
                        data.len()
                    )));
                }

                let mut sub_authorities = Vec::with_capacity(sub_auth_count);
                for i in 0..sub_auth_count {
                    let offset = 8 + i * 4;
                    sub_authorities.push(u32::from_le_bytes([
                        data[offset],
                        data[offset + 1],
                        data[offset + 2],
                        data[offset + 3],
                    ]));
                }

                Ok(Self {
                    revision,
                    authority,
                    sub_authorities,
                })
            }
            _ => Err(Error::parse(format!("Cannot parse Sid from {in_type:?}"))),
        }
    }
}

// =============================================================================
// FromPropertyRef Implementations (Zero-Copy)
// =============================================================================

impl<'a> FromPropertyRef<'a> for WideStrRef<'a> {
    fn from_property_ref(data: &'a [u8], in_type: TdhInType) -> Result<Self> {
        match in_type {
            TdhInType::UnicodeString => {
                Ok(WideStrRef::new(&data[..Self::null_terminated_len(data)]))
            }
            TdhInType::NonNullTerminatedString => {
                // No null terminator to strip — data slice is the full content.
                Ok(WideStrRef::new(data))
            }
            TdhInType::CountedString | TdhInType::ReversedCountedString => {
                if data.len() < 2 {
                    return Ok(WideStrRef::new(&[]));
                }
                // The 2-byte prefix is a byte count of the UTF-16 payload.
                let byte_count = counted_string_len(data, in_type) as usize;
                if byte_count & 1 != 0 {
                    return Err(Error::parse(format!(
                        "CountedString has odd byte count ({byte_count})"
                    )));
                }
                let end = (2 + byte_count).min(data.len());
                Ok(WideStrRef::new(&data[2..end]))
            }
            TdhInType::ManifestCountedString => {
                if data.len() < 2 {
                    return Ok(WideStrRef::new(&[]));
                }
                // The 2-byte prefix is a byte count of the UTF-16 payload.
                let byte_count = u16::from_le_bytes([data[0], data[1]]) as usize;
                if byte_count & 1 != 0 {
                    return Err(Error::parse(format!(
                        "ManifestCountedString has odd byte count ({byte_count})"
                    )));
                }
                let end = (2 + byte_count).min(data.len());
                Ok(WideStrRef::new(&data[2..end]))
            }
            _ => Err(Error::parse(format!(
                "Cannot borrow WideStrRef from {in_type:?} (expected UnicodeString, NonNullTerminatedString, CountedString, or ManifestCountedString)"
            ))),
        }
    }
}

impl<'a> FromPropertyRef<'a> for AnsiStrRef<'a> {
    fn from_property_ref(data: &'a [u8], in_type: TdhInType) -> Result<Self> {
        match in_type {
            TdhInType::AnsiString => Ok(AnsiStrRef::from_raw_with_null(data)),
            TdhInType::NonNullTerminatedAnsiString => {
                // No null terminator to strip — data slice is the full content.
                Ok(AnsiStrRef::new(data))
            }
            TdhInType::CountedAnsiString | TdhInType::ReversedCountedAnsiString => {
                if data.len() < 2 {
                    return Ok(AnsiStrRef::new(&[]));
                }
                let byte_count = counted_string_len(data, in_type) as usize;
                let end = (2 + byte_count).min(data.len());
                Ok(AnsiStrRef::new(&data[2..end]))
            }
            TdhInType::ManifestCountedAnsiString => {
                if data.len() < 2 {
                    return Ok(AnsiStrRef::new(&[]));
                }
                let byte_count = u16::from_le_bytes([data[0], data[1]]) as usize;
                let end = (2 + byte_count).min(data.len());
                Ok(AnsiStrRef::new(&data[2..end]))
            }
            _ => Err(Error::parse(format!(
                "Cannot borrow AnsiStrRef from {in_type:?} (expected AnsiString, NonNullTerminatedAnsiString, CountedAnsiString, or ManifestCountedAnsiString)"
            ))),
        }
    }
}

impl<'a> FromPropertyRef<'a> for &'a [u8] {
    fn from_property_ref(data: &'a [u8], in_type: TdhInType) -> Result<Self> {
        match in_type {
            TdhInType::Binary => Ok(data),
            TdhInType::ManifestCountedBinary => {
                // Skip the 2-byte LE bytecount prefix.
                if data.len() < 2 {
                    return Ok(&[]);
                }
                let byte_count = u16::from_le_bytes([data[0], data[1]]) as usize;
                let end = (2 + byte_count).min(data.len());
                Ok(&data[2..end])
            }
            _ => Err(Error::parse(format!(
                "Cannot borrow &[u8] from {in_type:?} (expected Binary or ManifestCountedBinary)"
            ))),
        }
    }
}

impl<'a> FromPropertyRef<'a> for SidRef<'a> {
    fn from_property_ref(data: &'a [u8], in_type: TdhInType) -> Result<Self> {
        match in_type {
            TdhInType::WbemSid => {
                // TOKEN_USER size depends on the emitting process's pointer size.
                // etw-rs requires a 64-bit host, so pointer_size is unavailable
                // here; we assume 64-bit (16 bytes). 32-bit (WOW64) emitters
                // would produce an 8-byte header and are not handled by this trait.
                let hdr = token_user_size(size_of::<usize>());
                if data.len() <= hdr {
                    return Err(Error::parse("Insufficient data for WbemSid"));
                }
                SidRef::new(&data[hdr..])
                    .ok_or_else(|| Error::parse("Invalid SID in WbemSid payload"))
            }
            TdhInType::Sid => {
                SidRef::new(data).ok_or_else(|| Error::parse("Invalid SID: data too short"))
            }
            _ => Err(Error::parse(format!(
                "Cannot borrow SidRef from {in_type:?} (expected Sid)"
            ))),
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test-only assertions"
)]
mod tests {
    use super::*;
    use crate::types::decode_cp1252;

    /// `String` decodes wide properties from a borrow of the event buffer while
    /// `WideString` copies first. That is meant to be an allocation saving and
    /// nothing more, so the two must agree on every wide `in_type` -- including
    /// the null-terminator rule, which differs between the borrowing and owned
    /// constructors and is easy to get wrong.
    #[test]
    fn string_matches_widestring_on_wellformed_wide_input() {
        let wide = |s: &str| -> Vec<u8> { s.encode_utf16().flat_map(u16::to_le_bytes).collect() };
        let cases: [(TdhInType, Vec<u8>); 5] = [
            // Trailing null: both must strip exactly one code unit.
            (TdhInType::UnicodeString, wide("Hi\0")),
            // No terminator at all.
            (TdhInType::NonNullTerminatedString, wide("Hi")),
            // Terminator present on a type that claims not to have one.
            (TdhInType::NonNullTerminatedString, wide("Hi\0")),
            // Counted: 2-byte payload length prefix, then the payload.
            (TdhInType::CountedString, {
                let mut v = 4_u16.to_le_bytes().to_vec();
                v.extend_from_slice(&wide("Hi"));
                v
            }),
            (TdhInType::ManifestCountedString, {
                let mut v = 4_u16.to_le_bytes().to_vec();
                v.extend_from_slice(&wide("Hi"));
                v
            }),
        ];
        for (in_type, data) in cases {
            let borrowed = String::from_property(&data, in_type, TdhOutType::Null);
            let owned = WideString::from_property(&data, in_type, TdhOutType::Null)
                .and_then(|w| w.decode_utf16());
            assert_eq!(
                borrowed.as_deref().ok(),
                owned.as_deref().ok(),
                "{in_type:?}: borrowed String disagrees with owned WideString"
            );
        }
    }

    /// An odd byte length leaves a stray byte after the last code unit, so the
    /// final two bytes straddle a character and cannot be a terminator. A
    /// declared or truncated length can be odd, and reading such a pair as a null
    /// drops the character before it.
    #[test]
    fn string_matches_widestring_on_odd_length_wide_input() {
        let cases: [(&[u8], &str); 4] = [
            (&[0x41, 0x00, 0x00], "A"),
            (&[0x41, 0x00, 0x42, 0x00, 0x00], "AB"),
            (&[0x41, 0x00, 0x42], "A"),
            // An embedded null still truncates, as it does on even input.
            (&[0x41, 0x00, 0x00, 0x00, 0x42, 0x00, 0x00, 0x00, 0xFF], "A"),
        ];
        for in_type in [TdhInType::UnicodeString, TdhInType::NonNullTerminatedString] {
            for (data, expected) in cases {
                let owned = WideString::from_property(data, in_type, TdhOutType::Null)
                    .and_then(|w| w.decode_utf16());
                assert_eq!(
                    owned.as_deref().ok(),
                    Some(expected),
                    "{in_type:?} {data:02X?}"
                );
                let borrowed = String::from_property(data, in_type, TdhOutType::Null);
                assert_eq!(
                    borrowed.as_deref().ok(),
                    Some(expected),
                    "{in_type:?} {data:02X?}"
                );
            }
        }
        for (data, expected) in cases {
            let wide = WideStrRef::from_property_ref(data, TdhInType::UnicodeString).unwrap();
            assert_eq!(wide.decode_utf16().unwrap(), expected, "{data:02X?}");
        }
    }

    /// The malformed cases matter more than the well-formed ones: event payloads
    /// are attacker-influenceable, and the borrowing constructors answer a
    /// truncated counted prefix with an empty string where the owned ones return
    /// an error. Decoding `String` through the borrow must keep the error.
    #[test]
    fn string_rejects_malformed_counted_wide_input_like_widestring() {
        let cases: [(TdhInType, Vec<u8>); 4] = [
            // Counted prefix truncated away entirely.
            (TdhInType::CountedString, vec![0x41]),
            (TdhInType::ManifestCountedString, vec![0x41]),
            // Odd payload byte count cannot be UTF-16.
            (TdhInType::CountedString, vec![0x03, 0x00, 0x41, 0x00, 0x42]),
            (
                TdhInType::ManifestCountedString,
                vec![0x03, 0x00, 0x41, 0x00, 0x42],
            ),
        ];
        for (in_type, data) in cases {
            assert!(
                String::from_property(&data, in_type, TdhOutType::Null).is_err(),
                "{in_type:?}: malformed input must not decode to a String"
            );
            assert!(
                WideString::from_property(&data, in_type, TdhOutType::Null).is_err(),
                "{in_type:?}: owned path must also reject it (invariant both share)"
            );
        }
    }

    /// A property's span is computed from counts the event itself supplies, so it
    /// can exceed the 16-bit domain before anything clamps it. Saturating is what
    /// makes narrowing safe: wrapping would turn an oversized span into a tiny
    /// one and silently truncate the property, where saturating leaves it at or
    /// past the buffer length and every reader clamps it to the same slice the
    /// unnarrowed value would have selected.
    #[test]
    fn property_location_saturates_an_oversized_span() {
        let oversized = usize::from(u16::MAX) + 100;
        let loc = PropertyLocation::new(0, oversized, TdhInType::Binary);

        assert_eq!(
            loc.size(),
            usize::from(u16::MAX),
            "an oversized span must saturate at the buffer domain"
        );
        // Had it wrapped, the span would be 99 -- smaller than the real data.
        assert_ne!(loc.size(), oversized as u16 as usize);
    }

    #[test]
    fn test_tdh_in_type_fixed_sizes() {
        assert_eq!(TdhInType::UInt8.fixed_size(8), Some(1));
        assert_eq!(TdhInType::UInt16.fixed_size(8), Some(2));
        assert_eq!(TdhInType::UInt32.fixed_size(8), Some(4));
        assert_eq!(TdhInType::UInt64.fixed_size(8), Some(8));
        assert_eq!(TdhInType::Pointer.fixed_size(8), Some(8));
        assert_eq!(TdhInType::Pointer.fixed_size(4), Some(4));
        assert_eq!(TdhInType::SizeT.fixed_size(4), Some(4));
        assert_eq!(TdhInType::UnicodeString.fixed_size(8), None);
    }

    #[test]
    fn test_tdh_in_type_from_raw() {
        assert_eq!(TdhInType::from_raw(1), TdhInType::UnicodeString);
        assert_eq!(TdhInType::from_raw(8), TdhInType::UInt32);
        assert_eq!(TdhInType::from_raw(999), TdhInType::Unknown(999));
        assert_eq!(TdhInType::from_raw(0), TdhInType::Null);
    }

    // ========================================================================
    // FromProperty unit tests - covers all TDH types
    // ========================================================================

    #[test]
    fn test_from_property_int8() {
        let data = [0xFE]; // -2 as i8
        let result = i8::from_property(&data, TdhInType::Int8, TdhOutType::Null)
            .expect("parse should succeed");
        assert_eq!(result, -2);
    }

    #[test]
    fn test_from_property_uint8() {
        let data = [0x42];
        let result = u8::from_property(&data, TdhInType::UInt8, TdhOutType::Null)
            .expect("parse should succeed");
        assert_eq!(result, 0x42);
    }

    #[test]
    fn test_from_property_int16() {
        let data = [0xFE, 0xFF]; // -2 as i16 (little-endian)
        let result = i16::from_property(&data, TdhInType::Int16, TdhOutType::Null)
            .expect("parse should succeed");
        assert_eq!(result, -2);
    }

    #[test]
    fn test_from_property_uint16() {
        let data = [0x34, 0x12]; // 0x1234
        let result = u16::from_property(&data, TdhInType::UInt16, TdhOutType::Null)
            .expect("parse should succeed");
        assert_eq!(result, 0x1234);
    }

    #[test]
    fn test_from_property_int32() {
        let data = [0xFE, 0xFF, 0xFF, 0xFF]; // -2 as i32
        let result = i32::from_property(&data, TdhInType::Int32, TdhOutType::Null)
            .expect("parse should succeed");
        assert_eq!(result, -2);
    }

    #[test]
    fn test_from_property_uint32() {
        let data = [0x78, 0x56, 0x34, 0x12]; // 0x12345678
        let result = u32::from_property(&data, TdhInType::UInt32, TdhOutType::Null)
            .expect("parse should succeed");
        assert_eq!(result, 0x12345678);
    }

    #[test]
    fn test_from_property_hexint32() {
        let data = [0xEF, 0xBE, 0xAD, 0xDE]; // 0xDEADBEEF
        let result = u32::from_property(&data, TdhInType::HexInt32, TdhOutType::Null)
            .expect("parse should succeed");
        assert_eq!(result, 0xDEADBEEF);
    }

    #[test]
    fn test_from_property_int64() {
        let data = [0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]; // -2 as i64
        let result = i64::from_property(&data, TdhInType::Int64, TdhOutType::Null)
            .expect("parse should succeed");
        assert_eq!(result, -2);
    }

    #[test]
    fn test_from_property_uint64() {
        let data = [0xEF, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12];
        let result = u64::from_property(&data, TdhInType::UInt64, TdhOutType::Null)
            .expect("parse should succeed");
        assert_eq!(result, 0x1234567890ABCDEF);
    }

    #[test]
    fn test_from_property_hexint64() {
        let data = [0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE];
        let result = u64::from_property(&data, TdhInType::HexInt64, TdhOutType::Null)
            .expect("parse should succeed");
        assert_eq!(result, 0xDEADBEEFDEADBEEF);
    }

    #[test]
    fn test_from_property_float() {
        let data = 1.5f32.to_le_bytes();
        let result = f32::from_property(&data, TdhInType::Float, TdhOutType::Null)
            .expect("parse should succeed");
        assert!((result - 1.5).abs() < 0.001);
    }

    #[test]
    fn test_from_property_double() {
        let data = 123.456789012345f64.to_le_bytes();
        let result = f64::from_property(&data, TdhInType::Double, TdhOutType::Null)
            .expect("parse should succeed");
        assert!((result - 123.456789012345).abs() < 0.0000001);
    }

    #[test]
    fn test_from_property_bool_1byte() {
        assert!(
            !bool::from_property(&[0], TdhInType::Boolean, TdhOutType::Null)
                .expect("parse should succeed")
        );
        assert!(
            bool::from_property(&[1], TdhInType::Boolean, TdhOutType::Null)
                .expect("parse should succeed")
        );
        assert!(
            bool::from_property(&[0xFF], TdhInType::Boolean, TdhOutType::Null)
                .expect("parse should succeed")
        );
    }

    #[test]
    fn test_from_property_bool_4byte() {
        assert!(
            !bool::from_property(&[0, 0, 0, 0], TdhInType::Boolean, TdhOutType::Null)
                .expect("parse should succeed")
        );
        assert!(
            bool::from_property(&[1, 0, 0, 0], TdhInType::Boolean, TdhOutType::Null)
                .expect("parse should succeed")
        );
    }

    #[test]
    fn test_from_property_pointer() {
        let data = [0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70];
        let result = usize::from_property(&data, TdhInType::Pointer, TdhOutType::Null)
            .expect("parse should succeed");
        assert_eq!(result, 0x7060504030201000usize);
    }

    #[test]
    fn test_from_property_guid() {
        // {12345678-1234-5678-ABCD-EF1234567890}
        let data = [
            0x78, 0x56, 0x34, 0x12, // data1
            0x34, 0x12, // data2
            0x78, 0x56, // data3
            0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, // data4
        ];
        let result = Guid::from_property(&data, TdhInType::Guid, TdhOutType::Null)
            .expect("parse should succeed");
        let expected = Guid::from_u128(0x12345678_1234_5678_abcd_ef1234567890);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_guid_wrapper() {
        let data = [
            0x78, 0x56, 0x34, 0x12, // data1
            0x34, 0x12, // data2
            0x78, 0x56, // data3
            0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, // data4
        ];
        let guid = Guid::from_property(&data, TdhInType::Guid, TdhOutType::Null)
            .expect("parse should succeed");

        // Test Display
        assert_eq!(guid.to_string(), "12345678-1234-5678-abcd-ef1234567890");

        // Test the u128 interop escape hatch round-trips losslessly
        assert_eq!(guid.to_u128(), 0x12345678_1234_5678_abcd_ef1234567890);
        assert_eq!(Guid::from_u128(guid.to_u128()), guid);
    }

    #[test]
    fn test_from_property_timestamp() {
        // Windows epoch: Jan 1, 1601. Unix epoch: Jan 1, 1970.
        // 116444736000000000 = 100ns ticks between epochs
        let ticks: i64 = 116444736000000000 + 10_000_000; // +1 second after Unix epoch
        let data = ticks.to_le_bytes();

        // Test with FileTime type
        let result = Timestamp::from_property(&data, TdhInType::FileTime, TdhOutType::Null)
            .expect("parse should succeed");
        assert_eq!(result.raw(), ticks);
        assert_eq!(result.as_unix_ms(), 1000); // 1 second = 1000ms

        // UInt64 is no longer accepted — use FileTime explicitly
        assert!(Timestamp::from_property(&data, TdhInType::UInt64, TdhOutType::Null).is_err());
    }

    #[test]
    fn test_from_property_systemtime() {
        // SYSTEMTIME: 2024-06-15 14:30:45.123
        let data = [
            0xE8, 0x07, // year: 2024
            0x06, 0x00, // month: 6
            0x06, 0x00, // day of week: Saturday
            0x0F, 0x00, // day: 15
            0x0E, 0x00, // hour: 14
            0x1E, 0x00, // minute: 30
            0x2D, 0x00, // second: 45
            0x7B, 0x00, // milliseconds: 123
        ];
        let result = SystemTime::from_property(&data, TdhInType::SystemTime, TdhOutType::Null)
            .expect("parse should succeed");
        assert_eq!(result.year, 2024);
        assert_eq!(result.month, 6);
        assert_eq!(result.day, 15);
        assert_eq!(result.hour, 14);
        assert_eq!(result.minute, 30);
        assert_eq!(result.second, 45);
        assert_eq!(result.milliseconds, 123);
    }

    #[test]
    fn test_from_property_sid() {
        // S-1-5-21-1234567890-... (simplified SID with 2 sub-authorities)
        let data = [
            0x01, // revision: 1
            0x02, // sub-authority count: 2
            0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // authority: 5 (NT Authority)
            0x15, 0x00, 0x00, 0x00, // sub-auth[0]: 21 (BUILTIN_DOMAIN)
            0xD2, 0x02, 0x96, 0x49, // sub-auth[1]: 1234567890
        ];
        let result = Sid::from_property(&data, TdhInType::Sid, TdhOutType::Null)
            .expect("parse should succeed");
        assert_eq!(result.revision, 1);
        assert_eq!(result.sub_authorities.len(), 2);
        assert_eq!(result.sub_authorities[0], 21);
        assert_eq!(result.sub_authorities[1], 1234567890);
        assert_eq!(result.to_string(), "S-1-5-21-1234567890");
    }

    #[test]
    fn test_from_property_binary() {
        let data = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        let result = Vec::<u8>::from_property(&data, TdhInType::Binary, TdhOutType::Null)
            .expect("parse should succeed");
        assert_eq!(result, vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]);
    }

    #[test]
    fn test_from_property_unicode_string() {
        // "Test" in UTF-16LE with null terminator
        let data = [0x54, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00, 0x00, 0x00];
        let result = String::from_property(&data, TdhInType::UnicodeString, TdhOutType::Null)
            .expect("parse should succeed");
        assert_eq!(result, "Test");
    }

    #[test]
    fn test_from_property_ansi_string() {
        let data = b"Hello\0";
        let result = AnsiString::from_property(data, TdhInType::AnsiString, TdhOutType::Null)
            .expect("parse should succeed")
            .to_string_lossy();
        assert_eq!(result, "Hello");
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls MultiByteToWideChar (Win32)")]
    fn test_string_accepts_ansi_string() {
        let data = b"Hello\0";
        let result = String::from_property(data, TdhInType::AnsiString, TdhOutType::Null)
            .expect("String::from_property should accept AnsiString via CP_ACP");
        assert_eq!(result, "Hello");
    }

    #[test]
    fn test_from_property_counted_string() {
        // Byte count = 8 (4 chars × 2), "Test" in UTF-16LE
        let data = [0x08, 0x00, 0x54, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00];
        let result = String::from_property(&data, TdhInType::CountedString, TdhOutType::Null)
            .expect("parse should succeed");
        assert_eq!(result, "Test");
    }

    #[test]
    fn counted_string_prefix_is_byte_count_not_char_count() {
        // Regression: TDH_INTYPE_COUNTEDSTRING's 2-byte prefix is a *byte* count,
        // not a character count. Modelled on the real ImageFileName field from
        // Microsoft's kernel `KernelProcess` `ProcessStarted` event: a 48-char
        // path carries a prefix of 96 (= 48 × 2 bytes). Treating it as a char
        // count over-reads the field, appending garbage and drifting every
        // subsequent field's offset.
        let path = r"\Device\HarddiskVolume3\Windows\System32\cmd.exe";
        let chars: Vec<u16> = path.encode_utf16().collect();
        assert_eq!(chars.len(), 48, "test path should be 48 UTF-16 code units");

        let mut field = Vec::new();
        field.extend_from_slice(&96u16.to_le_bytes()); // byte count, not char count
        for c in &chars {
            field.extend_from_slice(&c.to_le_bytes());
        }

        // The value decodes exactly, with no trailing garbage.
        let decoded = String::from_property(&field, TdhInType::CountedString, TdhOutType::Null)
            .expect("should decode");
        assert_eq!(decoded, path);

        // The length consumes exactly prefix + byte_count and no more — appending
        // a sentinel "next field" must not be swallowed.
        let mut with_next = field.clone();
        with_next.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let size =
            EventParser::compute_variable_element_size(&with_next, TdhInType::CountedString, 8)
                .expect("length should compute");
        assert_eq!(
            size,
            2 + 96,
            "CountedString must consume exactly its 2-byte prefix plus byte_count"
        );
    }

    #[test]
    fn counted_string_rejects_odd_byte_count() {
        // A UTF-16 payload cannot occupy an odd number of bytes, so an odd
        // prefix means the field is malformed and its declared length cannot be
        // trusted to position the following properties. Enough payload follows
        // that the only thing wrong here is the parity.
        let data = [0x05u8, 0x00, 0x48, 0x00, 0x69, 0x00, 0x21, 0x00];

        // Assert on the message, not just `is_err`: all three paths guard the
        // same input, so a future length or buffer check could otherwise
        // satisfy these assertions without the parity rule existing at all.
        fn assert_rejects_parity<T>(result: Result<T>, path: &str) {
            match result {
                Ok(_) => panic!("{path} accepted an odd byte count"),
                Err(e) => {
                    let msg = e.to_string();
                    assert!(
                        msg.contains("odd byte count"),
                        "{path} failed for the wrong reason: {msg}"
                    );
                }
            }
        }

        assert_rejects_parity(
            EventParser::compute_variable_element_size(&data, TdhInType::CountedString, 8),
            "length calc",
        );
        assert_rejects_parity(
            String::from_property(&data, TdhInType::CountedString, TdhOutType::Null),
            "owned decoder",
        );
        assert_rejects_parity(
            <crate::types::WideStrRef<'_> as FromPropertyRef<'_>>::from_property_ref(
                &data,
                TdhInType::CountedString,
            ),
            "borrowing decoder",
        );

        // Big-endian prefix — same parity rule applies to ReversedCountedString.
        let reversed = [0x00u8, 0x05, 0x48, 0x00, 0x69, 0x00, 0x21, 0x00];
        assert_rejects_parity(
            EventParser::compute_variable_element_size(
                &reversed,
                TdhInType::ReversedCountedString,
                8,
            ),
            "ReversedCountedString length calc",
        );
    }

    #[test]
    fn test_from_property_counted_ansi_string() {
        // Length: 5 bytes, "Hello"
        let data = [0x05, 0x00, b'H', b'e', b'l', b'l', b'o'];
        let result =
            AnsiString::from_property(&data, TdhInType::CountedAnsiString, TdhOutType::Null)
                .expect("parse should succeed")
                .to_string_lossy();
        assert_eq!(result, "Hello");
    }

    // ========================================================================
    // ETW Trailing Zero Truncation Tests
    // ETW drops trailing zeros from UserData, so parsers must zero-extend.
    // ========================================================================

    #[test]
    fn test_truncated_u32_from_0_bytes() {
        // Entirely missing field - should return 0
        let data: [u8; 0] = [];
        let result = u32::from_property(&data, TdhInType::UInt32, TdhOutType::Null)
            .expect("parse should succeed");
        assert_eq!(result, 0);
    }

    #[test]
    fn test_truncated_u32_from_1_byte() {
        // Only lowest byte present
        let data = [0x42];
        let result = u32::from_property(&data, TdhInType::UInt32, TdhOutType::Null)
            .expect("parse should succeed");
        assert_eq!(result, 0x42);
    }

    #[test]
    fn test_truncated_u32_from_2_bytes() {
        let data = [0x34, 0x12];
        let result = u32::from_property(&data, TdhInType::UInt32, TdhOutType::Null)
            .expect("parse should succeed");
        assert_eq!(result, 0x1234);
    }

    #[test]
    fn test_truncated_u32_from_3_bytes() {
        let data = [0x56, 0x34, 0x12];
        let result = u32::from_property(&data, TdhInType::UInt32, TdhOutType::Null)
            .expect("parse should succeed");
        assert_eq!(result, 0x123456);
    }

    #[test]
    fn test_truncated_u64_from_partial() {
        // Only 4 bytes present for a u64
        let data = [0x78, 0x56, 0x34, 0x12];
        let result = u64::from_property(&data, TdhInType::UInt64, TdhOutType::Null)
            .expect("parse should succeed");
        assert_eq!(result, 0x12345678);
    }

    #[test]
    fn test_truncated_bool_from_0_bytes() {
        // Empty data = false
        let data: [u8; 0] = [];
        let result = bool::from_property(&data, TdhInType::Boolean, TdhOutType::Null)
            .expect("parse should succeed");
        assert!(!result);
    }

    #[test]
    fn test_truncated_bool_from_1_byte() {
        // Single byte TRUE
        let data = [1];
        let result = bool::from_property(&data, TdhInType::Boolean, TdhOutType::Null)
            .expect("parse should succeed");
        assert!(result);
    }

    #[test]
    fn test_truncated_pointer_from_0_bytes() {
        // Empty data = null pointer
        let data: [u8; 0] = [];
        let result = usize::from_property(&data, TdhInType::Pointer, TdhOutType::Null)
            .expect("parse should succeed");
        assert_eq!(result, 0);
    }

    #[test]
    fn test_truncated_pointer_from_4_bytes() {
        // Lower 4 bytes of pointer
        let data = [0x78, 0x56, 0x34, 0x12];
        let result = usize::from_property(&data, TdhInType::Pointer, TdhOutType::Null)
            .expect("parse should succeed");
        assert_eq!(result, 0x12345678);
    }

    #[test]
    fn test_truncated_string_from_0_bytes() {
        // Empty data = empty string
        let data: [u8; 0] = [];
        let result = String::from_property(&data, TdhInType::UnicodeString, TdhOutType::Null)
            .expect("parse should succeed");
        assert_eq!(result, "");
    }

    #[test]
    fn test_string_without_null_terminator() {
        // "Hi" in UTF-16LE without null terminator (ETW truncated it)
        let data = [0x48, 0x00, 0x69, 0x00];
        let result = String::from_property(&data, TdhInType::UnicodeString, TdhOutType::Null)
            .expect("parse should succeed");
        assert_eq!(result, "Hi");
    }

    #[test]
    fn test_os_string_from_property_keeps_lone_surrogate() {
        use std::os::windows::ffi::OsStrExt;
        // "H", lone high surrogate, null terminator
        let data = [0x48, 0x00, 0x00, 0xD8, 0x00, 0x00];
        assert!(String::from_property(&data, TdhInType::UnicodeString, TdhOutType::Null).is_err());
        let result =
            std::ffi::OsString::from_property(&data, TdhInType::UnicodeString, TdhOutType::Null)
                .expect("parse should succeed");
        assert_eq!(result.encode_wide().collect::<Vec<_>>(), [0x48, 0xD800]);
    }

    #[test]
    fn test_os_string_from_property_counted() {
        // byte count 4, then "Hi"
        let data = [0x04, 0x00, 0x48, 0x00, 0x69, 0x00];
        for in_type in [TdhInType::CountedString, TdhInType::ManifestCountedString] {
            let result = std::ffi::OsString::from_property(&data, in_type, TdhOutType::Null)
                .expect("parse should succeed");
            assert_eq!(result, "Hi");
        }
    }

    #[test]
    fn test_os_string_from_property_rejects_ansi() {
        assert!(
            std::ffi::OsString::from_property(b"Hi\0", TdhInType::AnsiString, TdhOutType::Null)
                .is_err()
        );
    }

    #[test]
    fn test_ansi_string_without_null_terminator() {
        // "Hi" without null terminator
        let data = b"Hi";
        let result = AnsiString::from_property(data, TdhInType::AnsiString, TdhOutType::Null)
            .expect("parse should succeed")
            .to_string_lossy();
        assert_eq!(result, "Hi");
    }

    // ========================================================================
    // Strict type matching tests
    // Verify that cross-signedness parsing is rejected.
    // ========================================================================

    #[test]
    fn test_strict_u32_rejects_int32() {
        let data = [0xFF, 0xFF, 0xFF, 0xFF];
        assert!(u32::from_property(&data, TdhInType::Int32, TdhOutType::Null).is_err());
    }

    #[test]
    fn test_strict_i32_rejects_uint32() {
        let data = [0xFF, 0xFF, 0xFF, 0xFF];
        assert!(i32::from_property(&data, TdhInType::UInt32, TdhOutType::Null).is_err());
    }

    #[test]
    fn test_strict_u64_rejects_int64() {
        let data = [0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        assert!(u64::from_property(&data, TdhInType::Int64, TdhOutType::Null).is_err());
    }

    #[test]
    fn test_strict_i64_rejects_uint64() {
        let data = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80];
        assert!(i64::from_property(&data, TdhInType::UInt64, TdhOutType::Null).is_err());
    }

    #[test]
    fn test_strict_i32_rejects_hexint32() {
        let data = [0xEF, 0xBE, 0xAD, 0xDE];
        assert!(i32::from_property(&data, TdhInType::HexInt32, TdhOutType::Null).is_err());
    }

    #[test]
    fn test_strict_u16_rejects_int16() {
        let data = [0xFE, 0xFF];
        assert!(u16::from_property(&data, TdhInType::Int16, TdhOutType::Null).is_err());
    }

    #[test]
    fn test_strict_i8_rejects_uint8() {
        let data = [0x80];
        assert!(i8::from_property(&data, TdhInType::UInt8, TdhOutType::Null).is_err());
    }

    #[test]
    fn test_u32_accepts_hexint32() {
        let data = [0xEF, 0xBE, 0xAD, 0xDE];
        let result = u32::from_property(&data, TdhInType::HexInt32, TdhOutType::Null)
            .expect("should succeed");
        assert_eq!(result, 0xDEADBEEF);
    }

    #[test]
    fn test_u64_accepts_hexint64() {
        let data = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80];
        let result = u64::from_property(&data, TdhInType::HexInt64, TdhOutType::Null)
            .expect("should succeed");
        assert_eq!(result, 0x8000_0000_0000_0001);
    }

    // ========================================================================
    // Windows-1252 (CP1252) Decoding Tests
    // ========================================================================

    #[test]
    fn test_cp1252_ascii() {
        // ASCII bytes should pass through unchanged
        let data = b"Hello, World!";
        let result = decode_cp1252(data);
        assert_eq!(result, "Hello, World!");
    }

    #[test]
    fn test_cp1252_special_chars() {
        // Test the special 0x80-0x9F range
        let data = [
            0x80, // € Euro
            0x85, // … Ellipsis
            0x86, // † Dagger
            0x99, // ™ Trademark
        ];
        let result = decode_cp1252(&data);
        assert_eq!(result, "€…†™");
    }

    #[test]
    fn test_cp1252_latin1_supplement() {
        // Latin-1 supplement (0xA0-0xFF) should pass through
        let data = [0xA0, 0xA9, 0xAE, 0xB0, 0xE9]; // NBSP, ©, ®, °, é
        let result = decode_cp1252(&data);
        assert_eq!(result, "\u{A0}©®°é");
    }

    #[test]
    fn test_cp1252_undefined_bytes() {
        // Undefined bytes (0x81, 0x8D, 0x8F, 0x90, 0x9D) should become U+FFFD
        let data = [0x81];
        let result = decode_cp1252(&data);
        assert_eq!(result, "\u{FFFD}");
    }

    // ========================================================================
    // WideStrRef Tests
    // ========================================================================

    #[test]
    fn test_widestr_empty() {
        let ws = WideStrRef::new(&[]);
        assert!(ws.is_empty());
        assert_eq!(ws.len(), 0);
        assert_eq!(ws.decode_utf16().unwrap(), "");
    }

    #[test]
    fn test_widestr_ascii() {
        // "Test" in UTF-16LE
        let data = [0x54, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00];
        let ws = WideStrRef::new(&data);
        assert_eq!(ws.len(), 4);
        assert_eq!(ws.decode_utf16().unwrap(), "Test");
    }

    #[test]
    fn test_widestr_with_null() {
        // "Hi" + null in UTF-16LE
        let data = [0x48, 0x00, 0x69, 0x00, 0x00, 0x00, 0x58, 0x00];
        let ws = WideStrRef::from_raw_with_null(&data);
        assert_eq!(ws.len(), 2);
        assert_eq!(ws.decode_utf16().unwrap(), "Hi");
    }

    #[test]
    fn test_widestr_eq_ascii() {
        let data = [0x54, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00];
        let ws = WideStrRef::new(&data);
        assert!(ws.eq_ascii("Test"));
        assert!(!ws.eq_ascii("test"));
        assert!(!ws.eq_ascii("Tests"));
        assert!(!ws.eq_ascii("Tes"));
    }

    #[test]
    fn test_widestr_eq_ascii_ignore_case() {
        let data = [0x54, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00];
        let ws = WideStrRef::new(&data);
        assert!(ws.eq_ascii_ignore_case("Test"));
        assert!(ws.eq_ascii_ignore_case("test"));
        assert!(ws.eq_ascii_ignore_case("TEST"));
        assert!(!ws.eq_ascii_ignore_case("Tests"));
    }

    #[test]
    fn test_widestr_starts_with() {
        let data = [0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00]; // "Hello"
        let ws = WideStrRef::new(&data);
        assert!(ws.starts_with_ascii("He"));
        assert!(ws.starts_with_ascii("Hello"));
        assert!(!ws.starts_with_ascii("he"));
        assert!(!ws.starts_with_ascii("HelloWorld"));
    }

    #[test]
    fn test_widestr_ends_with() {
        let data = [0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00]; // "Hello"
        let ws = WideStrRef::new(&data);
        assert!(ws.ends_with_ascii("lo"));
        assert!(ws.ends_with_ascii("Hello"));
        assert!(!ws.ends_with_ascii("LO"));
    }

    #[test]
    fn test_widestr_contains() {
        let data = [0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00]; // "Hello"
        let ws = WideStrRef::new(&data);
        assert!(ws.contains_ascii("ell"));
        assert!(ws.contains_ascii("Hello"));
        assert!(ws.contains_ascii("o"));
        assert!(!ws.contains_ascii("world"));
    }

    #[test]
    fn test_widestr_partial_eq_str() {
        let data = [0x54, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00];
        let ws = WideStrRef::new(&data);
        assert_eq!(ws, "Test");
        assert!(ws != "test");
    }

    // ========================================================================
    // AnsiStrRef Tests
    // ========================================================================

    #[test]
    fn test_ansistr_empty() {
        let ans = AnsiStrRef::new(&[]);
        assert!(ans.is_empty());
        assert_eq!(ans.len(), 0);
        assert_eq!(ans.to_string_lossy(), "");
    }

    #[test]
    fn test_ansistr_ascii() {
        let data = b"Hello";
        let ans = AnsiStrRef::new(data);
        assert!(ans.is_ascii());
        assert_eq!(ans.to_string_ascii(), Some("Hello".to_owned()));
        assert_eq!(ans.to_string_cp1252(), "Hello");
        assert_eq!(ans.to_string_lossy(), "Hello");
    }

    #[test]
    fn test_ansistr_with_null() {
        let data = b"Hi\0extra";
        let ans = AnsiStrRef::from_raw_with_null(data);
        assert_eq!(ans.len(), 2);
        assert_eq!(ans.to_string_lossy(), "Hi");
    }

    #[test]
    fn test_ansistr_cp1252() {
        // Test CP1252-specific characters
        let data = [0x80, 0x99]; // € and ™
        let ans = AnsiStrRef::new(&data);
        assert!(!ans.is_ascii());
        assert_eq!(ans.to_string_ascii(), None);
        assert_eq!(ans.to_string_cp1252(), "€™");
    }

    #[test]
    fn test_ansistr_utf8_fallback() {
        // UTF-8 encoded "café" - the 'é' is 0xC3 0xA9 in UTF-8
        let data = b"caf\xc3\xa9";
        let ans = AnsiStrRef::new(data);
        // to_string_lossy should detect valid UTF-8 and use it
        assert_eq!(ans.to_string_lossy(), "café");
    }

    #[test]
    fn test_ansistr_eq_ascii() {
        let data = b"test";
        let ans = AnsiStrRef::new(data);
        assert!(ans.eq_ascii("test"));
        assert!(!ans.eq_ascii("Test"));
        assert!(!ans.eq_ascii("tests"));
    }

    #[test]
    fn test_ansistr_eq_ascii_ignore_case() {
        let data = b"Test";
        let ans = AnsiStrRef::new(data);
        assert!(ans.eq_ascii_ignore_case("test"));
        assert!(ans.eq_ascii_ignore_case("TEST"));
        assert!(ans.eq_ascii_ignore_case("Test"));
    }

    #[test]
    fn test_ansistr_partial_eq_str() {
        let data = b"Hello";
        let ans = AnsiStrRef::new(data);
        assert_eq!(ans, "Hello");
        assert!(ans != "hello");
    }

    // ========================================================================
    // AnsiString::to_string_lossy CP1252 Tests
    // ========================================================================

    #[test]
    fn test_ansi_string_to_string_lossy_cp1252() {
        let data = [0x80, 0x99, 0x00]; // €™ + null
        let result = AnsiString::from_property(&data, TdhInType::AnsiString, TdhOutType::Null)
            .expect("parse should succeed")
            .to_string_lossy();
        assert_eq!(result, "€™");
    }

    #[test]
    fn test_ansi_string_to_string_lossy_ascii() {
        let data = b"Hello\0";
        let result = AnsiString::from_property(data, TdhInType::AnsiString, TdhOutType::Null)
            .expect("parse should succeed")
            .to_string_lossy();
        assert_eq!(result, "Hello");
    }

    // ========================================================================
    // compute_variable_element_size — NULL terminator scanning
    // ========================================================================

    #[test]
    fn test_variable_size_unicode_with_null() {
        // "Hi" in UTF-16 LE with null terminator
        let data = [0x48, 0x00, 0x69, 0x00, 0x00, 0x00];
        let size = EventParser::compute_variable_element_size(&data, TdhInType::UnicodeString, 8)
            .expect("should find null");
        assert_eq!(size, 6); // 4 content + 2 null
    }

    #[test]
    fn test_variable_size_unicode_without_null() {
        // "Hi" in UTF-16 LE without null — non-last properties must error
        let data = [0x48, 0x00, 0x69, 0x00];
        let result = EventParser::compute_variable_element_size(&data, TdhInType::UnicodeString, 8);
        assert!(result.is_err());
    }

    #[test]
    fn test_variable_size_ansi_with_null() {
        let data = b"Hello\0";
        let size = EventParser::compute_variable_element_size(data, TdhInType::AnsiString, 8)
            .expect("should find null");
        assert_eq!(size, 6); // 5 content + 1 null
    }

    #[test]
    fn test_variable_size_ansi_without_null() {
        // No null — non-last properties must error
        let data = b"Hello";
        let result = EventParser::compute_variable_element_size(data, TdhInType::AnsiString, 8);
        assert!(result.is_err());
    }

    // ========================================================================
    // compute_variable_element_size — error paths for counted/manifest types
    // ========================================================================

    #[test]
    fn test_variable_size_counted_string_too_short_for_prefix() {
        let data = [0x01u8]; // < 2 bytes for the count prefix
        let r = EventParser::compute_variable_element_size(&data, TdhInType::CountedString, 8);
        assert!(r.is_err());
    }

    #[test]
    fn test_variable_size_counted_string_declares_more_than_available() {
        // byte_count = 10 (LE), but only 4 bytes follow → error
        let data = [0x0Au8, 0x00, 0x00, 0x00, 0x00, 0x00];
        let r = EventParser::compute_variable_element_size(&data, TdhInType::CountedString, 8);
        assert!(r.is_err());
    }

    #[test]
    fn test_variable_size_counted_ansi_string_too_short_for_prefix() {
        let data = [0x01u8];
        let r = EventParser::compute_variable_element_size(&data, TdhInType::CountedAnsiString, 8);
        assert!(r.is_err());
    }

    #[test]
    fn test_variable_size_counted_ansi_string_declares_more_than_available() {
        // byte_count = 100, only 2 bytes total
        let data = [0x64u8, 0x00];
        let r = EventParser::compute_variable_element_size(&data, TdhInType::CountedAnsiString, 8);
        assert!(r.is_err());
    }

    #[test]
    fn test_variable_size_manifest_counted_too_short_for_prefix() {
        let data = [0x01u8];
        let r =
            EventParser::compute_variable_element_size(&data, TdhInType::ManifestCountedString, 8);
        assert!(r.is_err());
    }

    #[test]
    fn test_variable_size_manifest_counted_declares_more_than_available() {
        // byte_count = 100, only the 2-byte prefix present
        let data = [0x64u8, 0x00];
        let r =
            EventParser::compute_variable_element_size(&data, TdhInType::ManifestCountedBinary, 8);
        assert!(r.is_err());
    }

    #[test]
    fn test_variable_size_wbem_sid_too_short() {
        // hdr is 16 (64-bit pointer_size). Need hdr + 8 = 24 bytes minimum.
        let data = [0u8; 20];
        let r = EventParser::compute_variable_element_size(&data, TdhInType::WbemSid, 8);
        assert!(r.is_err());
    }

    #[test]
    fn test_variable_size_wbem_sid_subauth_count_too_large() {
        // 16-byte header + SID with sub_auth_count = 16 (> 15 max)
        let mut data = vec![0u8; 24];
        data[16] = 0x01; // revision
        data[17] = 0x10; // sub_auth_count = 16 (out of range)
        let r = EventParser::compute_variable_element_size(&data, TdhInType::WbemSid, 8);
        assert!(r.is_err());
    }

    #[test]
    fn test_variable_size_wbem_sid_valid() {
        // 16-byte header + 12-byte SID (1 sub-auth)
        let mut data = vec![0u8; 28];
        data[16] = 0x01; // revision
        data[17] = 0x01; // sub_auth_count = 1
        let size =
            EventParser::compute_variable_element_size(&data, TdhInType::WbemSid, 8).unwrap();
        assert_eq!(size, 16 + 12);
    }

    #[test]
    fn test_variable_size_unsupported_type_errors() {
        let data = [0u8; 8];
        let r = EventParser::compute_variable_element_size(&data, TdhInType::UInt32, 8);
        assert!(r.is_err());
    }

    // ========================================================================
    // WideString / AnsiString / String FromProperty — error paths
    // ========================================================================

    #[test]
    fn test_wide_string_manifest_counted_too_short() {
        let r = crate::types::WideString::from_property(
            &[0x01u8],
            TdhInType::ManifestCountedString,
            TdhOutType::Null,
        );
        assert!(r.is_err());
    }

    #[test]
    fn test_wide_string_manifest_counted_odd_byte_count() {
        // byte_count = 3 (odd) → not valid for UTF-16
        let r = crate::types::WideString::from_property(
            &[0x03u8, 0x00, 0x48, 0x00, 0x69],
            TdhInType::ManifestCountedString,
            TdhOutType::Null,
        );
        assert!(r.is_err());
    }

    #[test]
    fn test_wide_string_manifest_counted_valid() {
        // byte_count = 4, "Hi" UTF-16LE
        let s = crate::types::WideString::from_property(
            &[0x04u8, 0x00, 0x48, 0x00, 0x69, 0x00],
            TdhInType::ManifestCountedString,
            TdhOutType::Null,
        )
        .unwrap();
        assert_eq!(s.to_string_lossy(), "Hi");
    }

    #[test]
    fn test_ansi_string_manifest_counted_too_short() {
        let r = crate::types::AnsiString::from_property(
            &[0x01u8],
            TdhInType::ManifestCountedAnsiString,
            TdhOutType::Null,
        );
        assert!(r.is_err());
    }

    #[test]
    fn test_ansi_string_manifest_counted_valid() {
        let s = crate::types::AnsiString::from_property(
            &[0x02u8, 0x00, 0x48, 0x69],
            TdhInType::ManifestCountedAnsiString,
            TdhOutType::Null,
        )
        .unwrap();
        assert_eq!(s.to_string_lossy(), "Hi");
    }

    #[test]
    fn test_ansi_string_unsupported_type() {
        let r =
            crate::types::AnsiString::from_property(&[0u8; 4], TdhInType::UInt32, TdhOutType::Null);
        assert!(r.is_err());
    }

    // ========================================================================
    // FromProperty for primitives — slow-path zero-extension and unsupported
    // ========================================================================

    #[test]
    fn test_u32_from_property_zero_extends_truncated_data() {
        // Only 2 bytes provided for a UInt32 — the slow path zero-extends.
        // Bytes [0x42, 0x00] → 0x00000042 = 66 after zero-extension.
        let v = u32::from_property(&[0x42u8, 0x00], TdhInType::UInt32, TdhOutType::Null).unwrap();
        assert_eq!(v, 0x42);
    }

    #[test]
    fn test_u32_from_property_unsupported_type_errors() {
        let r = u32::from_property(&[0u8; 4], TdhInType::UnicodeString, TdhOutType::Null);
        assert!(r.is_err());
    }

    #[test]
    fn test_u64_from_property_zero_extends_truncated_data() {
        let v = u64::from_property(&[0xAAu8, 0xBB], TdhInType::UInt64, TdhOutType::Null).unwrap();
        assert_eq!(v, 0xBBAA);
    }
}

// =============================================================================
// Parser tests using MockSchemaBuilder
//
// A `MockSchemaBuilder` schema and a hand-encoded payload are written from one
// understanding of the wire format, so a test asserting the two against each other
// cannot fail when that understanding is wrong. That is how the `CountedString`
// byte-count bug survived a green suite. The property-offset claims that used to
// live here are now made against real TDH schemas in
// `tests/differential_offline.rs`, where TDH supplies the expected answer and a
// trailing sentinel catches drift.
//
// What remains is deliberate, in four groups:
//
//   * Hostile input — truncation, odd byte counts, malformed SIDs, unsupported type combinations.
//     No real provider emits these, so no oracle can produce them; they assert *rejection*, not a
//     decoded value.
//   * etw-rs mechanism — index-hint fallback, the static-array fast paths, the parser cache,
//     `Display` rendering. The behaviour under test is ours, so the expected value is legitimately
//     ours too.
//   * API surface — `struct_members()`, `array_elements()`, the borrowed `*_ref` decoders, iterator
//     plumbing.
//   * Types no oracle can reach — `WbemSid` and `ReversedCountedString`. These arrive only via MOF
//     or via constructs a manifest cannot declare, and TraceLogging does not emit them either. They
//     keep the weaker self-referential form for want of anything better; a corpus of captured
//     classic-kernel events is what would give them a real oracle.
// =============================================================================

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test-only assertions"
)]
mod position_tests {
    use super::*;
    use crate::processing_context::mock::MockSchemaBuilder;

    // =========================================================================
    // Buffer helpers
    // =========================================================================

    fn wide_str_bytes(s: &str) -> Vec<u8> {
        let mut v = Vec::new();
        for ch in s.encode_utf16() {
            v.extend_from_slice(&ch.to_le_bytes());
        }
        v.extend_from_slice(&[0u8, 0u8]);
        v
    }

    fn ansi_str_bytes(s: &str) -> Vec<u8> {
        let mut v: Vec<u8> = s.as_bytes().to_vec();
        v.push(0);
        v
    }

    fn sid_bytes(sub_auth_count: u8, sub_auths: &[u32]) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(1); // revision
        v.push(sub_auth_count);
        v.extend_from_slice(&[0, 0, 0, 0, 0, 5]); // NT Authority
        for &sa in sub_auths {
            v.extend_from_slice(&sa.to_le_bytes());
        }
        v
    }

    // =========================================================================
    // Fixed types at first position (offset 0)
    // =========================================================================

    #[test]
    fn dynamic_boolean_non_first_byte_truthy() {
        // Windows BOOL 0x00000100 — first byte is zero but the value is truthy.
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add("Target", TdhInType::Boolean, TdhOutType::Null)
            .build_with_cache();
        let data = 0x00_00_01_00u32.to_le_bytes(); // [0x00, 0x01, 0x00, 0x00]
        let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
        let val: bool = parser.get("Target").unwrap();
        assert!(val);
    }

    // =========================================================================
    // Variable types at first position
    // =========================================================================

    // =========================================================================
    // Fixed types after fixed prefix (odd and even offsets)
    // =========================================================================

    // =========================================================================
    // Fixed types after variable field
    // =========================================================================

    // =========================================================================
    // Variable types after fixed prefix
    // =========================================================================

    // =========================================================================
    // Variable types after variable prefix
    // =========================================================================

    // =========================================================================
    // Types as last field
    // =========================================================================

    // =========================================================================
    // Binary with declared length
    // =========================================================================

    /// A Binary property that declares neither a length nor a PropertyParamLength
    /// cannot be sized, whatever its out-type, and must be rejected rather than
    /// guessed at — mis-sizing it displaces every property after it.
    #[test]
    fn dynamic_binary_without_declared_length_is_rejected() {
        // Ipv6 included: <tdh.h> implies it means 16 bytes, which etw-rs does not honour.
        for out_type in [TdhOutType::Null, TdhOutType::Ipv6] {
            let (schema, mut cache) = MockSchemaBuilder::new()
                .add("Target", TdhInType::Binary, out_type)
                .build_with_cache();
            let data = [0u8; 20];
            let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
            assert!(
                parser.get::<Vec<u8>>("Target").is_err(),
                "an unsized Binary with out-type {out_type:?} must be rejected, not sized"
            );
        }
    }

    // =========================================================================
    // Zero-copy reference API (as_ref)
    // =========================================================================

    #[test]
    fn dynamic_wide_str_ref_first() {
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add("Target", TdhInType::UnicodeString, TdhOutType::Null)
            .build_with_cache();
        let data = wide_str_bytes("RefTest");
        let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
        let val: WideStrRef = parser.as_ref("Target").unwrap();
        assert_eq!(val.decode_utf16().unwrap(), "RefTest");
    }

    #[test]
    fn dynamic_ansi_str_ref_after_u32() {
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add("Prefix", TdhInType::UInt32, TdhOutType::Null)
            .add("Target", TdhInType::AnsiString, TdhOutType::Null)
            .build_with_cache();
        let mut data = 0u32.to_le_bytes().to_vec();
        data.extend_from_slice(&ansi_str_bytes("reftest"));
        let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
        let val: AnsiStrRef = parser.as_ref("Target").unwrap();
        assert_eq!(val.to_string_lossy(), "reftest");
    }

    /// "café" in UTF-8, null-terminated. Any ANSI code page reads the last two
    /// bytes as something other than "é", so only a UTF-8 decode yields "café".
    const UTF8_CAFE: &[u8] = &[0x63, 0x61, 0x66, 0xC3, 0xA9, 0x00];

    #[test]
    fn dynamic_ansi_string_decodes_by_out_type() {
        for out_type in [TdhOutType::Utf8, TdhOutType::Json, TdhOutType::Xml] {
            let (schema, mut cache) = MockSchemaBuilder::new()
                .add("Prefix", TdhInType::UInt32, TdhOutType::Null)
                .add("Target", TdhInType::AnsiString, out_type)
                .build_with_cache();
            let mut data = 0u32.to_le_bytes().to_vec();
            data.extend_from_slice(UTF8_CAFE);

            let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
            let via_get: String = parser.get("Target").unwrap();
            assert_eq!(via_get, "café", "get, out-type {out_type:?}");

            let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
            let via_hint: String = parser.get_hinted("Target", 1).unwrap();
            assert_eq!(via_hint, "café", "get_hinted, out-type {out_type:?}");

            let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
            let target = parser.properties().unwrap().nth(1).unwrap();
            assert_eq!(target.out_type(), out_type);
            assert_eq!(target.to_string(), "café", "Display, out-type {out_type:?}");
        }
    }

    #[test]
    fn utf8_out_type_rejects_invalid_utf8() {
        // 0xE9 is "é" in Windows-1252 but a truncated sequence in UTF-8.
        let data = [0x63, 0x61, 0x66, 0xE9, 0x00];
        assert!(String::from_property(&data, TdhInType::AnsiString, TdhOutType::Utf8).is_err());
    }

    #[test]
    fn dynamic_sid_ref_after_unicode() {
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add("Prefix", TdhInType::UnicodeString, TdhOutType::Null)
            .add("Target", TdhInType::Sid, TdhOutType::Null)
            .build_with_cache();
        let mut data = wide_str_bytes("A");
        data.extend_from_slice(&sid_bytes(2, &[10, 20]));
        let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
        let val: SidRef = parser.as_ref("Target").unwrap();
        assert_eq!(val.sub_authority(0), Some(10));
        assert_eq!(val.sub_authority(1), Some(20));
    }

    #[test]
    fn dynamic_binary_ref_fixed_length() {
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add_fixed("Target", TdhInType::Binary, 5)
            .build_with_cache();
        let data = vec![1, 2, 3, 4, 5];
        let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
        let val: &[u8] = parser.as_ref("Target").unwrap();
        assert_eq!(val, &[1, 2, 3, 4, 5]);
    }

    // =========================================================================
    // Complex multi-field schema
    // =========================================================================

    // =========================================================================
    // WbemSid (TOKEN_USER + SID)
    // =========================================================================

    #[test]
    fn dynamic_wbem_sid_first() {
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add("Target", TdhInType::WbemSid, TdhOutType::Null)
            .add("Sentinel", TdhInType::UInt32, TdhOutType::Null)
            .build_with_cache();

        let mut data = Vec::new();
        // TOKEN_USER header: 16 bytes
        data.extend_from_slice(&[0u8; 16]);
        // SID: S-1-5-21
        data.extend_from_slice(&sid_bytes(1, &[21]));
        // Sentinel
        data.extend_from_slice(&0xABCDu32.to_le_bytes());

        let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
        let val: Sid = parser.get("Target").unwrap();
        assert_eq!(val.sub_authorities[0], 21);
        let sentinel: u32 = parser.get("Sentinel").unwrap();
        assert_eq!(sentinel, 0xABCD);
    }

    #[test]
    fn dynamic_wbem_sid_after_u32() {
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add("Prefix", TdhInType::UInt32, TdhOutType::Null)
            .add("Target", TdhInType::WbemSid, TdhOutType::Null)
            .add("Sentinel", TdhInType::UInt32, TdhOutType::Null)
            .build_with_cache();

        let mut data = 0xAAAAu32.to_le_bytes().to_vec();
        data.extend_from_slice(&[0u8; 16]); // TOKEN_USER
        data.extend_from_slice(&sid_bytes(2, &[10, 20]));
        data.extend_from_slice(&0xBBBBu32.to_le_bytes());

        let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
        let val: Sid = parser.get("Target").unwrap();
        assert_eq!(val.sub_authorities, vec![10, 20]);
        let sentinel: u32 = parser.get("Sentinel").unwrap();
        assert_eq!(sentinel, 0xBBBB);
    }

    // =========================================================================
    // Property iteration
    // =========================================================================

    #[test]
    fn dynamic_property_iteration() {
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add("A", TdhInType::UInt32, TdhOutType::Null)
            .add("B", TdhInType::UnicodeString, TdhOutType::Null)
            .add("C", TdhInType::UInt64, TdhOutType::Null)
            .build_with_cache();

        let mut data = Vec::new();
        data.extend_from_slice(&42u32.to_le_bytes());
        data.extend_from_slice(&wide_str_bytes("iter"));
        data.extend_from_slice(&99u64.to_le_bytes());

        let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
        let props: Vec<_> = parser.properties().unwrap().collect();
        assert_eq!(props.len(), 3);
        assert_eq!(props[0].as_u32().unwrap(), 42);
        assert_eq!(
            props[1].as_wide_str().unwrap().decode_utf16().unwrap(),
            "iter"
        );
        assert_eq!(props[2].as_u64().unwrap(), 99);
    }

    // =========================================================================
    // CountedString / ReversedCountedString / CountedAnsiString
    // =========================================================================

    /// Builds a ReversedCountedString payload: 2-byte BE *byte* count + UTF-16 data.
    fn reversed_counted_wide_str_bytes(s: &str) -> Vec<u8> {
        let chars: Vec<u16> = s.encode_utf16().collect();
        let mut v = Vec::new();
        v.extend_from_slice(&((chars.len() * 2) as u16).to_be_bytes());
        for ch in &chars {
            v.extend_from_slice(&ch.to_le_bytes());
        }
        v
    }

    /// Builds a ReversedCountedAnsiString payload: 2-byte BE byte count + ANSI data.
    fn reversed_counted_ansi_str_bytes(s: &str) -> Vec<u8> {
        let bytes = s.as_bytes();
        let mut v = Vec::new();
        v.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        v.extend_from_slice(bytes);
        v
    }

    #[test]
    fn dynamic_reversed_counted_string_first() {
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add("Target", TdhInType::ReversedCountedString, TdhOutType::Null)
            .add("Sentinel", TdhInType::UInt32, TdhOutType::Null)
            .build_with_cache();
        let mut data = reversed_counted_wide_str_bytes("Rev");
        data.extend_from_slice(&0xFACEu32.to_le_bytes());
        let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
        let val: WideString = parser.get("Target").unwrap();
        assert_eq!(val.to_string_lossy(), "Rev");
        let sentinel: u32 = parser.get("Sentinel").unwrap();
        assert_eq!(sentinel, 0xFACE);
    }

    #[test]
    fn dynamic_reversed_counted_ansi_after_u8() {
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add("Prefix", TdhInType::UInt8, TdhOutType::Null)
            .add(
                "Target",
                TdhInType::ReversedCountedAnsiString,
                TdhOutType::Null,
            )
            .add("Sentinel", TdhInType::UInt32, TdhOutType::Null)
            .build_with_cache();
        let mut data = vec![0xFFu8];
        data.extend_from_slice(&reversed_counted_ansi_str_bytes("rev"));
        data.extend_from_slice(&0x5678u32.to_le_bytes());
        let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
        let val: AnsiString = parser.get("Target").unwrap();
        assert_eq!(val.to_string_lossy(), "rev");
        let sentinel: u32 = parser.get("Sentinel").unwrap();
        assert_eq!(sentinel, 0x5678);
    }

    // =========================================================================
    // PropertyParamLength
    // =========================================================================

    // =========================================================================
    // PropertyParamCount
    // =========================================================================

    // =========================================================================
    // Struct properties
    // =========================================================================

    // =========================================================================
    // Struct member access
    // =========================================================================

    #[test]
    fn dynamic_struct_members_access() {
        // Schema: [MyStruct{u32, u16}, Sentinel: u32]
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add_struct(
                "MyStruct",
                &[
                    ("FieldA", TdhInType::UInt32, TdhOutType::Null, 0),
                    ("FieldB", TdhInType::UInt16, TdhOutType::Null, 0),
                ],
            )
            .add("Sentinel", TdhInType::UInt32, TdhOutType::Null)
            .build_with_cache();

        let mut data = Vec::new();
        data.extend_from_slice(&0xAABBCCDDu32.to_le_bytes()); // FieldA
        data.extend_from_slice(&0x1234u16.to_le_bytes()); // FieldB
        data.extend_from_slice(&0xDEADu32.to_le_bytes()); // Sentinel

        let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
        let members = parser.struct_members("MyStruct").unwrap();
        assert_eq!(members.len(), 2);

        let field_a: u32 = members[0].get().unwrap();
        assert_eq!(field_a, 0xAABBCCDD);

        let field_b: u16 = members[1].get().unwrap();
        assert_eq!(field_b, 0x1234);
    }

    #[test]
    fn dynamic_struct_members_with_string() {
        // Schema: [Prefix: u32, MyStruct{UnicodeString, u32}]
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add("Prefix", TdhInType::UInt32, TdhOutType::Null)
            .add_struct(
                "MyStruct",
                &[
                    ("Name", TdhInType::UnicodeString, TdhOutType::Null, 0),
                    ("Value", TdhInType::UInt32, TdhOutType::Null, 0),
                ],
            )
            .build_with_cache();

        let mut data = Vec::new();
        data.extend_from_slice(&42u32.to_le_bytes()); // Prefix
        data.extend(wide_str_bytes("hello")); // Name
        data.extend_from_slice(&777u32.to_le_bytes()); // Value

        let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
        let members = parser.struct_members("MyStruct").unwrap();
        assert_eq!(members.len(), 2);

        let name = members[0].to_wide_string().unwrap();
        assert_eq!(name.decode_utf16().unwrap(), "hello");

        let value: u32 = members[1].get().unwrap();
        assert_eq!(value, 777);
    }

    // =========================================================================
    // Array element access
    // =========================================================================

    #[test]
    fn dynamic_array_elements_fixed() {
        // Schema: [CountField: u16, Items: u32{param_count=0, element_size=4}, Sentinel: u32]
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add("CountField", TdhInType::UInt16, TdhOutType::Null)
            .add_param_count("Items", TdhInType::UInt32, 4, 0)
            .add("Sentinel", TdhInType::UInt32, TdhOutType::Null)
            .build_with_cache();

        let mut data = Vec::new();
        data.extend_from_slice(&3u16.to_le_bytes()); // CountField = 3
        data.extend_from_slice(&10u32.to_le_bytes()); // Items[0]
        data.extend_from_slice(&20u32.to_le_bytes()); // Items[1]
        data.extend_from_slice(&30u32.to_le_bytes()); // Items[2]
        data.extend_from_slice(&0xCAFEu32.to_le_bytes()); // Sentinel

        let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
        let elements = parser.array_elements("Items").unwrap();
        assert_eq!(elements.len(), 3);

        let v0: u32 = elements[0].get().unwrap();
        let v1: u32 = elements[1].get().unwrap();
        let v2: u32 = elements[2].get().unwrap();
        assert_eq!(v0, 10);
        assert_eq!(v1, 20);
        assert_eq!(v2, 30);
    }

    #[test]
    fn dynamic_array_elements_variable() {
        // Schema: [CountField: u16, Strings: UnicodeString{param_count=0, element_size=0}]
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add("CountField", TdhInType::UInt16, TdhOutType::Null)
            .add_param_count("Strings", TdhInType::UnicodeString, 0, 0)
            .build_with_cache();

        let mut data = Vec::new();
        data.extend_from_slice(&2u16.to_le_bytes()); // CountField = 2
        data.extend(wide_str_bytes("abc")); // Strings[0]
        data.extend(wide_str_bytes("xy")); // Strings[1]

        let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
        let elements = parser.array_elements("Strings").unwrap();
        assert_eq!(elements.len(), 2);

        let s0 = elements[0].to_wide_string().unwrap();
        let s1 = elements[1].to_wide_string().unwrap();
        assert_eq!(s0.decode_utf16().unwrap(), "abc");
        assert_eq!(s1.decode_utf16().unwrap(), "xy");
    }

    // =========================================================================
    // Fast name comparison
    // =========================================================================

    #[test]
    fn names_equal_agrees_with_str_eq_at_every_length_and_difference_position() {
        // `names_equal` reads a word from each end of the slice and relies on the
        // two reads overlapping to cover the middle. If that overlap were ever
        // wrong there would be bytes it never looks at, and a name differing only
        // in those bytes would compare equal -- returning the wrong property with
        // no error. This walks every length across all five arms and their
        // boundaries, flipping each byte in turn, and requires agreement with
        // `str` equality every time.
        //
        // The range runs past 32 so the widest arm is covered along with both of
        // its edges: 16/17, where 8-byte chunks give way to 16-byte ones, and
        // 32/33, where the fast path gives way to the libcall. A shorter range
        // would leave the 16-byte arm's overlap untested, and that arm is the one
        // whose ranges abut exactly at len == 32.
        for n in 0..=40usize {
            let base: String = (0..n).map(|i| (b'a' + (i % 26) as u8) as char).collect();
            assert!(
                names_equal(&base, &base),
                "len {n}: a name compared unequal to itself"
            );
            for pos in 0..n {
                let mut bytes = base.clone().into_bytes();
                bytes[pos] ^= 0x20; // flip case: still ASCII, still one byte
                let other = String::from_utf8(bytes).unwrap();
                assert_eq!(
                    names_equal(&base, &other),
                    base == other,
                    "len {n}, byte {pos}: disagreed with str equality"
                );
                assert!(
                    !names_equal(&base, &other),
                    "len {n}: a difference at byte {pos} went undetected"
                );
            }
        }
    }

    #[test]
    fn names_equal_rejects_names_of_different_length() {
        // A prefix must not compare equal to the longer name it prefixes: the
        // length check has to run before any word comparison, since the word
        // reads alone would examine overlapping bytes of two different lengths.
        for (a, b) in [
            ("", "a"),
            ("Stack", "StackBase"),
            ("StackBase", "StackBases"),
            ("TebBase", "TebBase2"),
            ("Win32StartAddr", "Win32StartAdd"),
        ] {
            assert!(!names_equal(a, b), "{a:?} vs {b:?} compared equal");
            assert!(!names_equal(b, a), "{b:?} vs {a:?} compared equal");
        }
    }

    #[test]
    fn names_equal_handles_real_thread_start_names() {
        // The set the benchmarks use, including the same-length pair that makes a
        // hint miss expensive (`StackBase` / `StartAddr`, both nine bytes).
        const NAMES: [&str; 10] = [
            "ProcessID",
            "ThreadID",
            "StackBase",
            "StackLimit",
            "UserStackBase",
            "UserStackLimit",
            "StartAddr",
            "Win32StartAddr",
            "TebBase",
            "SubProcessTag",
        ];
        for (i, a) in NAMES.iter().enumerate() {
            for (j, b) in NAMES.iter().enumerate() {
                assert_eq!(names_equal(a, b), i == j, "{a:?} vs {b:?}");
            }
        }
        assert_eq!("StackBase".len(), "StartAddr".len());
    }

    // =========================================================================
    // Bad hint fallback
    // =========================================================================

    #[test]
    fn learned_hints_record_what_each_call_position_resolved_to() {
        // This is the behaviour that a "next index" cursor cannot provide, and the
        // reason for keying on call position: a caller reading a fixed subset out
        // of schema order is wrong on the first event and right on every one
        // after. Reads the hint table directly, because the whole effect is
        // invisible from the returned values -- they are correct either way.
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add("Alpha", TdhInType::UInt32, TdhOutType::Null)
            .add("Beta", TdhInType::UInt32, TdhOutType::Null)
            .add("Gamma", TdhInType::UInt32, TdhOutType::Null)
            .add("Delta", TdhInType::UInt32, TdhOutType::Null)
            .build_with_cache();

        let mut data = Vec::new();
        for value in [10u32, 20, 30, 40] {
            data.extend_from_slice(&value.to_le_bytes());
        }

        // Seeded with the identity mapping, so before any event the table simply
        // guesses that position N wants index N.
        assert_eq!(cache.learned_hints, vec![0, 1, 2, 3]);

        // Reads the same two names, in the same order, as one event would. Kept in
        // a function so the parser's borrow of the cache ends before the table is
        // inspected.
        fn read_delta_then_beta(data: &[u8], schema: &EventSchema, cache: &mut ParserCache) {
            let mut parser = EventParser::from_raw_parts(data, schema, cache);
            assert_eq!(parser.get::<u32>("Delta").unwrap(), 40);
            assert_eq!(parser.get::<u32>("Beta").unwrap(), 20);
        }

        // First event: position 0 asks for "Delta" (index 3) and misses the seed's
        // guess of 0; position 1 asks for "Beta" (index 1) and happens to hit.
        read_delta_then_beta(&data, &schema, &mut cache);
        assert_eq!(
            cache.learned_hints[0], 3,
            "position 0 resolved to index 3 and should have recorded it"
        );
        assert_eq!(cache.learned_hints[1], 1, "position 1 was already correct");
        assert_eq!(
            &cache.learned_hints[2..],
            &[2, 3],
            "positions never used must keep their seed"
        );

        // Second event, same order: both positions now hit what they learned. The
        // values must be unchanged, and the table must be stable.
        read_delta_then_beta(&data, &schema, &mut cache);
        assert_eq!(cache.learned_hints[0], 3);
        assert_eq!(cache.learned_hints[1], 1);
    }

    #[test]
    fn learned_hints_do_not_change_results_for_out_of_order_access() {
        // The hint table is a cost optimisation, not a protocol: `get` must return
        // the same value for a name no matter what was read before it. Reading
        // strictly backwards defeats the identity seed at every position, so every
        // value here comes from the hash fallback.
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add("Alpha", TdhInType::UInt32, TdhOutType::Null)
            .add("Beta", TdhInType::UInt32, TdhOutType::Null)
            .add("Gamma", TdhInType::UInt32, TdhOutType::Null)
            .add("Delta", TdhInType::UInt32, TdhOutType::Null)
            .build_with_cache();

        let mut data = Vec::new();
        for v in [10u32, 20, 30, 40] {
            data.extend_from_slice(&v.to_le_bytes());
        }

        let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
        assert_eq!(parser.get::<u32>("Delta").unwrap(), 40);
        assert_eq!(parser.get::<u32>("Gamma").unwrap(), 30);
        assert_eq!(parser.get::<u32>("Beta").unwrap(), 20);
        assert_eq!(parser.get::<u32>("Alpha").unwrap(), 10);
    }

    #[test]
    fn learned_hints_allow_repeated_reads_of_one_property() {
        // Re-reading a name advances the call position, so the second read of
        // "Beta" consults a different hint slot and misses. It must still resolve,
        // and to the same value.
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add("Alpha", TdhInType::UInt32, TdhOutType::Null)
            .add("Beta", TdhInType::UInt32, TdhOutType::Null)
            .build_with_cache();

        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&2u32.to_le_bytes());

        let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
        assert_eq!(parser.get::<u32>("Beta").unwrap(), 2);
        assert_eq!(parser.get::<u32>("Beta").unwrap(), 2);
        assert_eq!(parser.get::<u32>("Alpha").unwrap(), 1);
    }

    #[test]
    fn call_position_past_the_hint_table_falls_back_to_name_lookup() {
        // The table has one slot per property, so a caller reading more properties
        // than the schema has runs off the end of it. Those positions must fall
        // through to the hash lookup rather than erroring.
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add("Alpha", TdhInType::UInt32, TdhOutType::Null)
            .add("Beta", TdhInType::UInt32, TdhOutType::Null)
            .build_with_cache();

        let mut data = Vec::new();
        data.extend_from_slice(&7u32.to_le_bytes());
        data.extend_from_slice(&8u32.to_le_bytes());

        let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
        assert_eq!(parser.get::<u32>("Beta").unwrap(), 8);
        // Cursor is now 2, one past the last index.
        assert_eq!(parser.get::<u32>("Alpha").unwrap(), 7);
    }

    #[test]
    fn learned_hints_do_not_mask_a_missing_property() {
        // A name that is in no schema must still be PropertyNotFound, whatever
        // the hint for that call position happens to be.
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add("Alpha", TdhInType::UInt32, TdhOutType::Null)
            .add("Beta", TdhInType::UInt32, TdhOutType::Null)
            .build_with_cache();

        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&2u32.to_le_bytes());

        let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
        assert_eq!(parser.get::<u32>("Alpha").unwrap(), 1);
        let err = parser.get::<u32>("Nope").unwrap_err();
        assert!(
            matches!(err, Error::PropertyNotFound { ref name, .. } if name == "Nope"),
            "expected PropertyNotFound for an absent name, got {err:?}"
        );
    }

    #[test]
    fn bad_hint_wrong_index_falls_back_to_name_lookup() {
        // A wrong hint should silently fall back to name lookup and return the correct value.
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add("Alpha", TdhInType::UInt32, TdhOutType::Null)
            .add("Beta", TdhInType::UInt32, TdhOutType::Null)
            .build_with_cache();

        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes()); // Alpha
        data.extend_from_slice(&2u32.to_le_bytes()); // Beta

        let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
        // Hint says index 0, but we ask for "Beta" which is at index 1.
        let val: u32 = parser.get_hinted("Beta", 0).unwrap();
        assert_eq!(val, 2);
    }

    #[test]
    fn bad_hint_out_of_range_falls_back_to_name_lookup() {
        // A hint beyond the property count should silently fall back to name lookup.
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add("Alpha", TdhInType::UInt32, TdhOutType::Null)
            .build_with_cache();

        let data = 42u32.to_le_bytes();
        let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
        // Hint 99 is way out of range, but "Alpha" exists at index 0.
        let val: u32 = parser.get_hinted("Alpha", 99).unwrap();
        assert_eq!(val, 42);
    }

    // =========================================================================
    // Static array count > 1 (regression tests for bugs #1–#5)
    // =========================================================================

    #[test]
    fn static_array_u32_fixed_path() {
        // Schema: [Values: u32 x3, Sentinel: u32]
        // Bug #2: prepopulate_fixed stored per-element size, not total.
        // Pre-fix: Sentinel at offset 4; post-fix: offset 12.
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add_static_array("Values", TdhInType::UInt32, TdhOutType::Null, 3)
            .add("Sentinel", TdhInType::UInt32, TdhOutType::Null)
            .build_with_cache();

        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes()); // Values[0]
        data.extend_from_slice(&2u32.to_le_bytes()); // Values[1]
        data.extend_from_slice(&3u32.to_le_bytes()); // Values[2]
        data.extend_from_slice(&0xCAFEu32.to_le_bytes()); // Sentinel

        let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
        let sentinel: u32 = parser.get("Sentinel").unwrap();
        assert_eq!(sentinel, 0xCAFE);
    }

    #[test]
    fn static_array_struct_member_count_fixed_path() {
        // Schema: [S{FieldA: u32 x2, FieldB: u16}, Sentinel: u32]
        // Bug #1: prepopulate_fixed inner loop missing `* member.count().max(1)`.
        // Struct size = 4*2 + 2 = 10. Pre-fix: 4 + 2 = 6.
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add_struct_with_count(
                "MyStruct",
                &[
                    ("FieldA", TdhInType::UInt32, TdhOutType::Null, 0, 2),
                    ("FieldB", TdhInType::UInt16, TdhOutType::Null, 0, 0),
                ],
                0,
            )
            .add("Sentinel", TdhInType::UInt32, TdhOutType::Null)
            .build_with_cache();

        let mut data = Vec::new();
        data.extend_from_slice(&10u32.to_le_bytes()); // FieldA[0]
        data.extend_from_slice(&20u32.to_le_bytes()); // FieldA[1]
        data.extend_from_slice(&99u16.to_le_bytes()); // FieldB
        data.extend_from_slice(&0xBEEFu32.to_le_bytes()); // Sentinel

        let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
        let sentinel: u32 = parser.get("Sentinel").unwrap();
        assert_eq!(sentinel, 0xBEEF);
    }

    #[test]
    fn static_array_struct_member_count_variable_path() {
        // Schema: [Str: UnicodeString, S{FieldA: u32 x2, FieldB: u16}, Sentinel: u32]
        // Bug #3: compute_struct_size member loop missing `* member.count().max(1)`.
        // The string forces the variable (non-prepopulated) code path.
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add("Prefix", TdhInType::UnicodeString, TdhOutType::Null)
            .add_struct_with_count(
                "MyStruct",
                &[
                    ("FieldA", TdhInType::UInt32, TdhOutType::Null, 0, 2),
                    ("FieldB", TdhInType::UInt16, TdhOutType::Null, 0, 0),
                ],
                0,
            )
            .add("Sentinel", TdhInType::UInt32, TdhOutType::Null)
            .build_with_cache();

        let mut data = Vec::new();
        data.extend(wide_str_bytes("hi")); // Prefix
        data.extend_from_slice(&10u32.to_le_bytes()); // FieldA[0]
        data.extend_from_slice(&20u32.to_le_bytes()); // FieldA[1]
        data.extend_from_slice(&99u16.to_le_bytes()); // FieldB
        data.extend_from_slice(&0xFACEu32.to_le_bytes()); // Sentinel

        let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
        let sentinel: u32 = parser.get("Sentinel").unwrap();
        assert_eq!(sentinel, 0xFACE);
    }

    #[test]
    fn static_array_struct_members_with_count() {
        // Schema: [S{FieldA: u32 x2, FieldB: u16}]
        // Bug #4: struct_members() used per-element size for member_data and offset.
        // FieldA should yield 8 bytes (two u32s), FieldB at offset 8.
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add_struct_with_count(
                "MyStruct",
                &[
                    ("FieldA", TdhInType::UInt32, TdhOutType::Null, 0, 2),
                    ("FieldB", TdhInType::UInt16, TdhOutType::Null, 0, 0),
                ],
                0,
            )
            .build_with_cache();

        let mut data = Vec::new();
        data.extend_from_slice(&10u32.to_le_bytes()); // FieldA[0]
        data.extend_from_slice(&20u32.to_le_bytes()); // FieldA[1]
        data.extend_from_slice(&42u16.to_le_bytes()); // FieldB

        let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
        let members = parser.struct_members("MyStruct").unwrap();
        assert_eq!(members.len(), 2);
        // FieldA: 8 bytes covering both array elements
        assert_eq!(members[0].data.len(), 8);
        // FieldB: 2 bytes at the correct offset
        assert_eq!(members[1].data.len(), 2);
        let field_b_val = u16::from_le_bytes(members[1].data.try_into().unwrap());
        assert_eq!(field_b_val, 42);
    }

    #[test]
    fn static_array_struct_with_count_variable_path() {
        // Schema: [Str: UnicodeString, S{FieldA: u32, FieldB: u16} x2, Sentinel: u32]
        // Bug #5: compute_property_size struct early-return didn't multiply by count.
        // Per-instance = 4 + 2 = 6; total = 12. Pre-fix: 6.
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add("Prefix", TdhInType::UnicodeString, TdhOutType::Null)
            .add_struct_with_count(
                "MyStruct",
                &[
                    ("FieldA", TdhInType::UInt32, TdhOutType::Null, 0, 0),
                    ("FieldB", TdhInType::UInt16, TdhOutType::Null, 0, 0),
                ],
                2,
            )
            .add("Sentinel", TdhInType::UInt32, TdhOutType::Null)
            .build_with_cache();

        let mut data = Vec::new();
        data.extend(wide_str_bytes("hi")); // Prefix
        // Struct instance 0
        data.extend_from_slice(&1u32.to_le_bytes()); // FieldA
        data.extend_from_slice(&2u16.to_le_bytes()); // FieldB
        // Struct instance 1
        data.extend_from_slice(&3u32.to_le_bytes()); // FieldA
        data.extend_from_slice(&4u16.to_le_bytes()); // FieldB
        data.extend_from_slice(&0xDEADu32.to_le_bytes()); // Sentinel

        let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
        let sentinel: u32 = parser.get("Sentinel").unwrap();
        assert_eq!(sentinel, 0xDEAD);
    }

    #[test]
    fn static_array_struct_with_count_fixed_path() {
        // Schema: [S{FieldA: u32, FieldB: u16} x2, Sentinel: u32]
        // Bug #2 (structs): prepopulate_fixed stored per-element struct size.
        // Per-instance = 4 + 2 = 6; total = 12. Pre-fix: Sentinel at offset 6.
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add_struct_with_count(
                "MyStruct",
                &[
                    ("FieldA", TdhInType::UInt32, TdhOutType::Null, 0, 0),
                    ("FieldB", TdhInType::UInt16, TdhOutType::Null, 0, 0),
                ],
                2,
            )
            .add("Sentinel", TdhInType::UInt32, TdhOutType::Null)
            .build_with_cache();

        let mut data = Vec::new();
        // Struct instance 0
        data.extend_from_slice(&1u32.to_le_bytes()); // FieldA
        data.extend_from_slice(&2u16.to_le_bytes()); // FieldB
        // Struct instance 1
        data.extend_from_slice(&3u32.to_le_bytes()); // FieldA
        data.extend_from_slice(&4u16.to_le_bytes()); // FieldB
        data.extend_from_slice(&0xCAFEu32.to_le_bytes()); // Sentinel

        let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
        let sentinel: u32 = parser.get("Sentinel").unwrap();
        assert_eq!(sentinel, 0xCAFE);
    }

    // =========================================================================
    // Property struct accessors (data, in_type, out_type, is_struct)
    // =========================================================================

    #[test]
    fn property_accessors_data_in_type_out_type() {
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add("Val", TdhInType::UInt32, TdhOutType::HexInt32)
            .build_with_cache();
        let data = 0x1234_5678u32.to_le_bytes();
        let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
        let mut iter = parser.properties().expect("properties ok");
        let prop = iter.next().expect("has property");
        assert_eq!(prop.data(), &data);
        assert_eq!(prop.in_type(), TdhInType::UInt32);
        assert_eq!(prop.out_type(), TdhOutType::HexInt32);
        assert!(!prop.is_struct());
    }

    #[test]
    fn property_is_struct_returns_true_for_struct_placeholder() {
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add_struct("Inner", &[("X", TdhInType::UInt32, TdhOutType::Null, 0)])
            .build_with_cache();
        // The struct uses 4 bytes in the data
        let data = 0u32.to_le_bytes();
        let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
        let mut iter = parser.properties().expect("properties ok");
        let prop = iter.next().expect("has property");
        assert!(prop.is_struct());
        // in_type for a struct is TdhInType::Struct
        assert_eq!(prop.in_type(), TdhInType::Struct);
    }

    #[test]
    fn property_iter_empty_data_returns_empty_slice() {
        // With empty data, the first property at offset 0 satisfies 0 >= 0, returning &[].
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add("Val", TdhInType::UInt32, TdhOutType::Null)
            .build_with_cache();
        let data: &[u8] = &[];
        let mut parser = EventParser::from_raw_parts(data, &schema, &mut cache);
        let mut iter = parser.properties().expect("properties ok");
        let prop = iter.next().expect("has property");
        assert_eq!(prop.data(), &[] as &[u8]);
    }

    // =========================================================================
    // Property::fmt Display — out_type based arms
    // =========================================================================

    fn display_prop(in_type: TdhInType, out_type: TdhOutType, bytes: &[u8]) -> String {
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add("F", in_type, out_type)
            .build_with_cache();
        let mut parser = EventParser::from_raw_parts(bytes, &schema, &mut cache);
        let mut iter = parser.properties().expect("properties ok");
        format!("{}", iter.next().expect("has property"))
    }

    fn display_prop_fixed(
        in_type: TdhInType,
        out_type: TdhOutType,
        length: u16,
        bytes: &[u8],
    ) -> String {
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add_fixed_typed("F", in_type, out_type, length)
            .build_with_cache();
        let mut parser = EventParser::from_raw_parts(bytes, &schema, &mut cache);
        let mut iter = parser.properties().expect("properties ok");
        format!("{}", iter.next().expect("has property"))
    }

    #[test]
    fn property_display_hex_int8() {
        let s = display_prop(TdhInType::UInt8, TdhOutType::HexInt8, &[0xABu8]);
        assert_eq!(s, "0xAB");
    }

    #[test]
    fn property_display_hex_int16() {
        let s = display_prop(
            TdhInType::UInt16,
            TdhOutType::HexInt16,
            &0x1234u16.to_le_bytes(),
        );
        assert_eq!(s, "0x1234");
    }

    #[test]
    fn property_display_hex_int32() {
        let s = display_prop(
            TdhInType::UInt32,
            TdhOutType::HexInt32,
            &0xDEAD_BEEFu32.to_le_bytes(),
        );
        assert_eq!(s, "0xDEADBEEF");
    }

    #[test]
    fn property_display_hex_int64() {
        let s = display_prop(
            TdhInType::UInt64,
            TdhOutType::HexInt64,
            &0xCAFE_F00Du64.to_le_bytes(),
        );
        assert_eq!(s, "0x00000000CAFEF00D");
    }

    #[test]
    fn property_display_pid() {
        let s = display_prop(TdhInType::UInt32, TdhOutType::Pid, &1234u32.to_le_bytes());
        assert_eq!(s, "1234");
    }

    #[test]
    fn property_display_port() {
        // Port is network byte order (big-endian) u16: bytes [0x00, 0x50] = 80
        let s = display_prop(TdhInType::UInt16, TdhOutType::Port, &[0x00u8, 0x50]);
        assert_eq!(s, "80");
    }

    #[test]
    fn property_display_ipv4() {
        // 192.168.1.1
        let s = display_prop(TdhInType::UInt32, TdhOutType::Ipv4, &[192u8, 168, 1, 1]);
        assert_eq!(s, "192.168.1.1");
    }

    #[test]
    fn property_display_ipv6() {
        let bytes = [0u8; 16]; // All-zero IPv6 (::)
        let s = display_prop_fixed(TdhInType::Binary, TdhOutType::Ipv6, 16, &bytes);
        assert_eq!(s, "::");
    }

    /// With neither a length nor a `PropertyParamLength` there is nothing to
    /// size a Binary property by, so it is rejected rather than guessed.
    #[test]
    fn unsized_binary_is_rejected() {
        let err = EventParser::compute_variable_element_size(&[0u8; 16], TdhInType::Binary, 8)
            .expect_err("unsized Binary must not be sized");
        assert!(
            err.to_string().contains(
                "Binary property has no declared length and no PropertyParamLength; \
                 cannot determine its size"
            ),
            "got: {err}"
        );
    }

    #[test]
    fn property_display_boolean_out_type() {
        // TdhOutType::Boolean with non-zero byte = true
        let s = display_prop(TdhInType::UInt32, TdhOutType::Boolean, &[0x01u8, 0, 0, 0]);
        assert_eq!(s, "true");
        let s2 = display_prop(TdhInType::UInt32, TdhOutType::Boolean, &[0u8, 0, 0, 0]);
        assert_eq!(s2, "false");
    }

    #[test]
    fn property_display_no_print_out_type() {
        let s = display_prop(TdhInType::UInt32, TdhOutType::NoPrint, &0u32.to_le_bytes());
        assert_eq!(s, "");
    }

    #[test]
    fn property_display_in_type_int8() {
        let s = display_prop(TdhInType::Int8, TdhOutType::Null, &[0xFFu8]);
        assert_eq!(s, "-1");
    }

    #[test]
    fn property_display_in_type_uint8() {
        let s = display_prop(TdhInType::UInt8, TdhOutType::Null, &[42u8]);
        assert_eq!(s, "42");
    }

    #[test]
    fn property_display_in_type_int16() {
        let s = display_prop(TdhInType::Int16, TdhOutType::Null, &(-100i16).to_le_bytes());
        assert_eq!(s, "-100");
    }

    // =========================================================================
    // Property::fmt Display — remaining out_type arms
    // =========================================================================

    #[test]
    fn property_display_code_pointer() {
        let val: usize = 0xDEAD_BEEF_1234_5678;
        let s = display_prop(
            TdhInType::Pointer,
            TdhOutType::CodePointer,
            &val.to_le_bytes(),
        );
        assert_eq!(s, "0xDEADBEEF12345678");
    }

    #[test]
    fn property_display_guid_out_type() {
        let s = display_prop(TdhInType::Guid, TdhOutType::Guid, &[0u8; 16]);
        assert_eq!(s, "00000000-0000-0000-0000-000000000000");
    }

    #[test]
    fn property_display_datetime_out_type() {
        // FileTime = 0 → 1601-01-01T00:00:00.0000000Z
        let s = display_prop(TdhInType::FileTime, TdhOutType::DateTime, &[0u8; 8]);
        assert!(s.contains("1601-01-01"), "expected 1601 date, got: {s}");
    }

    #[test]
    fn property_display_datetime_utc_out_type() {
        let s = display_prop(TdhInType::FileTime, TdhOutType::DateTimeUtc, &[0u8; 8]);
        assert!(s.contains("1601-01-01"), "expected 1601 date, got: {s}");
    }

    /// `win:SYSTEMTIME` + `xs:dateTime` is a legal manifest pairing; the
    /// out-type must not force the FileTime-only `Timestamp` parse.
    #[test]
    fn property_display_systemtime_with_datetime_out_type() {
        let bytes: [u8; 16] = [
            0xE8, 0x07, 0x01, 0x00, 0x00, 0x00, 0x0F, 0x00, // 2024-01-(dow)-15
            0x0A, 0x00, 0x1E, 0x00, 0x2D, 0x00, 0x7B, 0x00, // 10:30:45.123
        ];
        for out_type in [
            TdhOutType::DateTime,
            TdhOutType::DateTimeUtc,
            TdhOutType::CultureInsensitiveDateTime,
        ] {
            let s = display_prop_fixed(TdhInType::SystemTime, out_type, 16, &bytes);
            assert_eq!(s, "2024-01-15T10:30:45.1230000", "out_type {out_type:?}");
        }
    }

    // =========================================================================
    // Property::fmt Display — remaining in_type arms
    // =========================================================================

    #[test]
    fn property_display_in_type_unicode_string() {
        // "Hi\0" in UTF-16LE: 0x48,0x00, 0x69,0x00, null terminator 0x00,0x00
        let bytes = [0x48u8, 0x00, 0x69, 0x00, 0x00, 0x00];
        let s = display_prop(TdhInType::UnicodeString, TdhOutType::Null, &bytes);
        assert_eq!(s, "Hi");
    }

    #[test]
    fn property_display_in_type_ansi_string() {
        let bytes = b"Hello\x00";
        let s = display_prop(TdhInType::AnsiString, TdhOutType::Null, bytes);
        assert_eq!(s, "Hello");
    }

    #[test]
    fn property_display_in_type_uint16() {
        let s = display_prop(TdhInType::UInt16, TdhOutType::Null, &1000u16.to_le_bytes());
        assert_eq!(s, "1000");
    }

    /// A WCHAR is text, not a number: 'A' prints as `A`, not `65`.
    #[test]
    fn property_display_in_type_unicode_char() {
        let s = display_prop_fixed(TdhInType::UnicodeChar, TdhOutType::Null, 2, &[0x41, 0x00]);
        assert_eq!(s, "A");
    }

    /// A fixed-length WCHAR array arrives as one property spanning every code
    /// unit, so all of them must be decoded — not just the first.
    #[test]
    fn property_display_in_type_unicode_char_array() {
        let bytes = [0x48u8, 0x00, 0x69, 0x00, 0xAC, 0x20]; // "Hi€"
        let s = display_prop_fixed(TdhInType::UnicodeChar, TdhOutType::Null, 6, &bytes);
        assert_eq!(s, "Hi\u{20AC}");
    }

    #[test]
    fn property_display_in_type_int32() {
        let s = display_prop(TdhInType::Int32, TdhOutType::Null, &(-1i32).to_le_bytes());
        assert_eq!(s, "-1");
    }

    #[test]
    fn property_display_in_type_uint32() {
        let s = display_prop(TdhInType::UInt32, TdhOutType::Null, &99u32.to_le_bytes());
        assert_eq!(s, "99");
    }

    #[test]
    fn property_display_in_type_int64() {
        let s = display_prop(TdhInType::Int64, TdhOutType::Null, &(-1i64).to_le_bytes());
        assert_eq!(s, "-1");
    }

    #[test]
    fn property_display_in_type_uint64() {
        let s = display_prop(TdhInType::UInt64, TdhOutType::Null, &1234u64.to_le_bytes());
        assert_eq!(s, "1234");
    }

    #[test]
    fn property_display_in_type_filetime() {
        // FileTime = 0 → 1601-01-01T00:00:00.0000000Z
        let s = display_prop(TdhInType::FileTime, TdhOutType::Null, &[0u8; 8]);
        assert!(s.contains("1601-01-01"), "expected 1601 date, got: {s}");
    }

    #[test]
    fn property_display_in_type_systemtime() {
        // SYSTEMTIME bytes for 2024-01-15T10:30:45.123
        // wYear(2024), wMonth(1), wDayOfWeek(0), wDay(15),
        // wHour(10), wMinute(30), wSecond(45), wMilliseconds(123)
        let bytes: [u8; 16] = [
            0xE8, 0x07, // year = 2024
            0x01, 0x00, // month = 1
            0x00, 0x00, // day-of-week (ignored)
            0x0F, 0x00, // day = 15
            0x0A, 0x00, // hour = 10
            0x1E, 0x00, // minute = 30
            0x2D, 0x00, // second = 45
            0x7B, 0x00, // ms = 123
        ];
        let s = display_prop_fixed(TdhInType::SystemTime, TdhOutType::Null, 16, &bytes);
        assert_eq!(s, "2024-01-15T10:30:45.1230000");
    }

    #[test]
    fn property_display_in_type_hexint32() {
        let s = display_prop(
            TdhInType::HexInt32,
            TdhOutType::Null,
            &0xDEAD_C0DEu32.to_le_bytes(),
        );
        assert_eq!(s, "0xDEADC0DE");
    }

    #[test]
    fn property_display_in_type_hexint64() {
        let s = display_prop(
            TdhInType::HexInt64,
            TdhOutType::Null,
            &0xCAFE_BABE_DEAD_C0DEu64.to_le_bytes(),
        );
        assert_eq!(s, "0xCAFEBABEDEADC0DE");
    }

    #[test]
    fn property_display_in_type_pointer() {
        let s = display_prop(TdhInType::Pointer, TdhOutType::Null, &0usize.to_le_bytes());
        assert_eq!(s, "0x0");
    }

    #[test]
    fn property_display_in_type_float() {
        let s = display_prop(TdhInType::Float, TdhOutType::Null, &1.5f32.to_le_bytes());
        assert_eq!(s, "1.5");
    }

    #[test]
    fn property_display_in_type_double() {
        let s = display_prop(TdhInType::Double, TdhOutType::Null, &2.5f64.to_le_bytes());
        assert_eq!(s, "2.5");
    }

    #[test]
    fn property_display_in_type_boolean_true() {
        // Windows BOOL: non-zero = true (4 bytes)
        let s = display_prop(TdhInType::Boolean, TdhOutType::Null, &1u32.to_le_bytes());
        assert_eq!(s, "true");
    }

    #[test]
    fn property_display_in_type_boolean_false() {
        let s = display_prop(TdhInType::Boolean, TdhOutType::Null, &0u32.to_le_bytes());
        assert_eq!(s, "false");
    }

    #[test]
    fn property_display_in_type_guid() {
        let s = display_prop(TdhInType::Guid, TdhOutType::Null, &[0u8; 16]);
        assert_eq!(s, "00000000-0000-0000-0000-000000000000");
    }

    #[test]
    fn property_display_in_type_sid() {
        // S-1-5-18 (LocalSystem): revision=1, subauth_count=1, authority=5, subauth[0]=18
        let sid = [
            0x01u8, 0x01, // revision=1, subauth_count=1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // IdentifierAuthority = 5
            0x12, 0x00, 0x00, 0x00, // SubAuthority[0] = 18
        ];
        let s = display_prop(TdhInType::Sid, TdhOutType::Null, &sid);
        assert!(s.contains("S-1-"), "expected SID format, got: {s}");
    }

    #[test]
    fn property_display_in_type_wbem_sid() {
        // TOKEN_USER header (16 bytes on 64-bit) + S-1-5-18 SID (12 bytes)
        let mut bytes = [0u8; 28];
        bytes[16..].copy_from_slice(&[
            0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00,
        ]);
        let s = display_prop(TdhInType::WbemSid, TdhOutType::Null, &bytes);
        assert!(s.contains("S-1-"), "expected SID format, got: {s}");
    }

    #[test]
    fn property_display_in_type_catchall_hex_dump() {
        // Binary with fixed length → falls through to the catch-all hex dump arm
        let s = display_prop_fixed(
            TdhInType::Binary,
            TdhOutType::Null,
            3,
            &[0xABu8, 0xCD, 0xEF],
        );
        assert_eq!(s, "[AB CD EF]");
    }

    // =========================================================================
    // EventParser convenience methods: named_properties, format_event,
    // as_ref_hinted, get_hinted, Debug impls
    // =========================================================================

    #[test]
    fn parser_cache_debug_format() {
        let (_schema, cache) = MockSchemaBuilder::new()
            .add("A", TdhInType::UInt32, TdhOutType::Null)
            .build_with_cache();
        let s = format!("{cache:?}");
        assert!(s.contains("ParserCache"), "got: {s}");
        assert!(s.contains("parsed_count"), "got: {s}");
        assert!(s.contains("fixed_prefix_size"), "got: {s}");
    }

    #[test]
    fn event_parser_debug_format() {
        let data = 1u32.to_le_bytes();
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add("A", TdhInType::UInt32, TdhOutType::Null)
            .build_with_cache();
        let parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
        let s = format!("{parser:?}");
        assert!(s.contains("EventParser"), "got: {s}");
        assert!(s.contains("data_len: 4"), "got: {s}");
    }

    #[test]
    fn parser_named_properties_returns_pairs() {
        let mut data = Vec::<u8>::new();
        data.extend_from_slice(&42u32.to_le_bytes());
        data.extend_from_slice(&100u16.to_le_bytes());
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add("Pid", TdhInType::UInt32, TdhOutType::Null)
            .add("Port", TdhInType::UInt16, TdhOutType::Null)
            .build_with_cache();
        let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
        let pairs = parser.named_properties().expect("named_properties ok");
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].0, "Pid");
        assert_eq!(pairs[1].0, "Port");
    }

    #[test]
    fn parser_format_event_falls_back_to_unknown() {
        // MockSchemaBuilder doesn't set event/task/opcode names → "Unknown"
        let data = 7u32.to_le_bytes();
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add("Val", TdhInType::UInt32, TdhOutType::Null)
            .build_with_cache();
        let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
        let s = parser.format_event().expect("format_event ok");
        assert!(s.starts_with("Unknown {"), "got: {s}");
        assert!(s.contains("Val: 7"), "got: {s}");
        assert!(s.ends_with('}'), "got: {s}");
    }

    #[test]
    fn parser_get_hinted_correct_index() {
        let mut data = Vec::<u8>::new();
        data.extend_from_slice(&100u32.to_le_bytes());
        data.extend_from_slice(&200u32.to_le_bytes());
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add("First", TdhInType::UInt32, TdhOutType::Null)
            .add("Second", TdhInType::UInt32, TdhOutType::Null)
            .build_with_cache();
        let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
        // Correct hint
        assert_eq!(parser.get_hinted::<u32>("Second", 1).unwrap(), 200);
    }

    #[test]
    fn parser_get_hinted_wrong_index_falls_back_to_name() {
        let mut data = Vec::<u8>::new();
        data.extend_from_slice(&100u32.to_le_bytes());
        data.extend_from_slice(&200u32.to_le_bytes());
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add("First", TdhInType::UInt32, TdhOutType::Null)
            .add("Second", TdhInType::UInt32, TdhOutType::Null)
            .build_with_cache();
        let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
        // Hint index 0 has "First", not "Second" — falls back to name lookup
        assert_eq!(parser.get_hinted::<u32>("Second", 0).unwrap(), 200);
    }

    #[test]
    fn parser_as_ref_hinted_correct_index() {
        let bytes = [0x48u8, 0x00, 0x69, 0x00, 0x00, 0x00];
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add("Name", TdhInType::UnicodeString, TdhOutType::Null)
            .build_with_cache();
        let mut parser = EventParser::from_raw_parts(&bytes, &schema, &mut cache);
        let s: crate::types::WideStrRef<'_> = parser.as_ref_hinted("Name", 0).unwrap();
        assert_eq!(s.to_string_lossy(), "Hi");
    }

    // =========================================================================
    // FromPropertyRef branches: CountedString, ManifestCountedString, etc.
    // =========================================================================

    #[test]
    fn wide_str_ref_from_counted_string() {
        // 2-byte LE byte count = 4, followed by "Hi" UTF-16 (2 chars = 4 bytes)
        let bytes = [0x04u8, 0x00, 0x48, 0x00, 0x69, 0x00];
        let s = <crate::types::WideStrRef<'_> as FromPropertyRef<'_>>::from_property_ref(
            &bytes,
            TdhInType::CountedString,
        )
        .unwrap();
        assert_eq!(s.to_string_lossy(), "Hi");
    }

    #[test]
    fn wide_str_ref_from_reversed_counted_string() {
        // 2-byte BE byte count = 4, followed by "Hi" UTF-16 (2 chars = 4 bytes)
        let bytes = [0x00u8, 0x04, 0x48, 0x00, 0x69, 0x00];
        let s = <crate::types::WideStrRef<'_> as FromPropertyRef<'_>>::from_property_ref(
            &bytes,
            TdhInType::ReversedCountedString,
        )
        .unwrap();
        assert_eq!(s.to_string_lossy(), "Hi");
    }

    #[test]
    fn wide_str_ref_from_counted_string_short_returns_empty() {
        let bytes = [0x01u8]; // < 2 bytes
        let s = <crate::types::WideStrRef<'_> as FromPropertyRef<'_>>::from_property_ref(
            &bytes,
            TdhInType::CountedString,
        )
        .unwrap();
        assert!(s.is_empty());
    }

    #[test]
    fn wide_str_ref_from_manifest_counted_string() {
        // 2-byte LE byte count = 4, followed by "Hi" UTF-16 (4 bytes)
        let bytes = [0x04u8, 0x00, 0x48, 0x00, 0x69, 0x00];
        let s = <crate::types::WideStrRef<'_> as FromPropertyRef<'_>>::from_property_ref(
            &bytes,
            TdhInType::ManifestCountedString,
        )
        .unwrap();
        assert_eq!(s.to_string_lossy(), "Hi");
    }

    #[test]
    fn wide_str_ref_manifest_counted_odd_byte_count_errors() {
        // 2-byte LE byte count = 3 (odd → invalid for UTF-16)
        let bytes = [0x03u8, 0x00, 0x48, 0x00, 0x69];
        let r = <crate::types::WideStrRef<'_> as FromPropertyRef<'_>>::from_property_ref(
            &bytes,
            TdhInType::ManifestCountedString,
        );
        assert!(r.is_err());
    }

    #[test]
    fn wide_str_ref_manifest_counted_short_returns_empty() {
        let bytes = [0x01u8];
        let s = <crate::types::WideStrRef<'_> as FromPropertyRef<'_>>::from_property_ref(
            &bytes,
            TdhInType::ManifestCountedString,
        )
        .unwrap();
        assert!(s.is_empty());
    }

    #[test]
    fn wide_str_ref_from_unsupported_type_errors() {
        let r = <crate::types::WideStrRef<'_> as FromPropertyRef<'_>>::from_property_ref(
            &[0u8; 4],
            TdhInType::UInt32,
        );
        assert!(r.is_err());
    }

    #[test]
    fn ansi_str_ref_from_counted_ansi_string() {
        // 2-byte LE byte count = 2, followed by "Hi"
        let bytes = [0x02u8, 0x00, 0x48, 0x69];
        let s = <crate::types::AnsiStrRef<'_> as FromPropertyRef<'_>>::from_property_ref(
            &bytes,
            TdhInType::CountedAnsiString,
        )
        .unwrap();
        assert_eq!(s.to_string_lossy(), "Hi");
    }

    #[test]
    fn ansi_str_ref_from_reversed_counted_ansi_string() {
        let bytes = [0x00u8, 0x02, 0x48, 0x69];
        let s = <crate::types::AnsiStrRef<'_> as FromPropertyRef<'_>>::from_property_ref(
            &bytes,
            TdhInType::ReversedCountedAnsiString,
        )
        .unwrap();
        assert_eq!(s.to_string_lossy(), "Hi");
    }

    #[test]
    fn ansi_str_ref_from_counted_ansi_short_returns_empty() {
        let bytes = [0x01u8];
        let s = <crate::types::AnsiStrRef<'_> as FromPropertyRef<'_>>::from_property_ref(
            &bytes,
            TdhInType::CountedAnsiString,
        )
        .unwrap();
        assert!(s.is_empty());
    }

    #[test]
    fn ansi_str_ref_from_manifest_counted_ansi() {
        let bytes = [0x02u8, 0x00, 0x48, 0x69];
        let s = <crate::types::AnsiStrRef<'_> as FromPropertyRef<'_>>::from_property_ref(
            &bytes,
            TdhInType::ManifestCountedAnsiString,
        )
        .unwrap();
        assert_eq!(s.to_string_lossy(), "Hi");
    }

    #[test]
    fn ansi_str_ref_manifest_counted_short_returns_empty() {
        let bytes = [0x01u8];
        let s = <crate::types::AnsiStrRef<'_> as FromPropertyRef<'_>>::from_property_ref(
            &bytes,
            TdhInType::ManifestCountedAnsiString,
        )
        .unwrap();
        assert!(s.is_empty());
    }

    #[test]
    fn ansi_str_ref_from_unsupported_type_errors() {
        let r = <crate::types::AnsiStrRef<'_> as FromPropertyRef<'_>>::from_property_ref(
            &[0u8; 4],
            TdhInType::UInt32,
        );
        assert!(r.is_err());
    }

    #[test]
    fn binary_slice_from_manifest_counted_binary() {
        // 2-byte LE byte count = 3, followed by 3 payload bytes
        let bytes = [0x03u8, 0x00, 0xAA, 0xBB, 0xCC];
        let s: &[u8] = <&[u8] as FromPropertyRef<'_>>::from_property_ref(
            &bytes,
            TdhInType::ManifestCountedBinary,
        )
        .unwrap();
        assert_eq!(s, &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn binary_slice_manifest_counted_binary_short_returns_empty() {
        let bytes = [0x01u8];
        let s: &[u8] = <&[u8] as FromPropertyRef<'_>>::from_property_ref(
            &bytes,
            TdhInType::ManifestCountedBinary,
        )
        .unwrap();
        assert!(s.is_empty());
    }

    #[test]
    fn binary_slice_from_unsupported_type_errors() {
        let r = <&[u8] as FromPropertyRef<'_>>::from_property_ref(&[0u8; 4], TdhInType::UInt32);
        assert!(r.is_err());
    }

    // =========================================================================
    // parse_sockaddr — unknown family error
    // =========================================================================

    #[test]
    fn parse_sockaddr_unknown_family_errors() {
        // Family 99 — not AF_INET (2) or AF_INET6 (23)
        let bytes = [0x63u8, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(parse_sockaddr(&bytes).is_err());
    }

    #[test]
    fn parse_sockaddr_too_short_errors() {
        let bytes = [0x02u8]; // < 2 bytes
        assert!(parse_sockaddr(&bytes).is_err());
    }

    // =========================================================================
    // EventParser::array_elements — error and edge paths
    // =========================================================================

    #[test]
    fn array_elements_on_non_array_property_errors() {
        // count == 0 (scalar) → "not an array"
        let data = 42u32.to_le_bytes();
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add("Pid", TdhInType::UInt32, TdhOutType::Null)
            .build_with_cache();
        let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
        assert!(parser.array_elements("Pid").is_err());
    }

    #[test]
    fn array_elements_property_not_found() {
        let data = 42u32.to_le_bytes();
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add("Pid", TdhInType::UInt32, TdhOutType::Null)
            .build_with_cache();
        let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
        assert!(parser.array_elements("DoesNotExist").is_err());
    }

    #[test]
    fn array_elements_static_fixed_size_array() {
        // 4 × u32, [10, 20, 30, 40]
        let mut data = Vec::new();
        for v in &[10u32, 20, 30, 40] {
            data.extend_from_slice(&v.to_le_bytes());
        }
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add_static_array("Vals", TdhInType::UInt32, TdhOutType::Null, 4)
            .build_with_cache();
        let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
        let elems = parser.array_elements("Vals").unwrap();
        assert_eq!(elems.len(), 4);
        let collected: Vec<u32> = elems.iter().map(|p| p.get::<u32>().unwrap()).collect();
        assert_eq!(collected, vec![10, 20, 30, 40]);
    }

    // =========================================================================
    // EventParser::get and get_hinted — name-not-found error wrapping
    // =========================================================================

    #[test]
    fn get_property_not_found_errors() {
        let data = 42u32.to_le_bytes();
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add("Pid", TdhInType::UInt32, TdhOutType::Null)
            .build_with_cache();
        let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
        let r = parser.get::<u32>("Missing");
        assert!(r.is_err());
    }

    #[test]
    fn as_ref_property_not_found_errors() {
        let data = [0u8; 4];
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add("F", TdhInType::Binary, TdhOutType::Null)
            .build_with_cache();
        let mut parser = EventParser::from_raw_parts(&data, &schema, &mut cache);
        let r = parser.as_ref::<&[u8]>("Missing");
        assert!(r.is_err());
    }

    // =========================================================================
    // EventParser::properties — empty schema short-circuit
    // =========================================================================

    #[test]
    fn properties_iterator_empty_schema() {
        let (schema, mut cache) = MockSchemaBuilder::new().build_with_cache();
        let data: &[u8] = &[];
        let mut parser = EventParser::from_raw_parts(data, &schema, &mut cache);
        let props: Vec<_> = parser.properties().unwrap().collect();
        assert!(props.is_empty());
    }

    // =========================================================================
    // Property::as_ref — direct accessor
    // =========================================================================

    #[test]
    fn property_as_ref_returns_borrowed_data() {
        let bytes = [0xAAu8, 0xBB, 0xCC, 0xDD];
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add_fixed_typed("Bin", TdhInType::Binary, TdhOutType::Null, 4)
            .build_with_cache();
        let mut parser = EventParser::from_raw_parts(&bytes, &schema, &mut cache);
        let mut iter = parser.properties().unwrap();
        let prop = iter.next().unwrap();
        let s: &[u8] = prop.as_ref().unwrap();
        assert_eq!(s, &bytes);
    }
}
