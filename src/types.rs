//! Core type definitions for ETW event parsing.
//!
//! This module contains the fundamental types used throughout the crate:
//! TDH type enumerations, string wrappers (both borrowed and owned),
//! GUID, SID, and SYSTEMTIME wrappers.

use crate::{Error, Result};
use windows_sys::Win32::System::Diagnostics::Etw as etw;

/// TDH output type constants.
///
/// Specifies the intended display format for a property value. When `Null`,
/// the decoder should use the default output type for the property's
/// [`TdhInType`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TdhOutType {
    /// Default output type (use the in-type's default format).
    Null,
    /// Display as a string.
    String,
    /// Display as a date/time.
    DateTime,
    /// Display as a signed byte.
    Byte,
    /// Display as an unsigned byte.
    UnsignedByte,
    /// Display as a signed 16-bit integer.
    Short,
    /// Display as an unsigned 16-bit integer.
    UnsignedShort,
    /// Display as a signed 32-bit integer.
    Int,
    /// Display as an unsigned 32-bit integer.
    UnsignedInt,
    /// Display as a signed 64-bit integer.
    Long,
    /// Display as an unsigned 64-bit integer.
    UnsignedLong,
    /// Display as a 32-bit float.
    Float,
    /// Display as a 64-bit float.
    Double,
    /// Display as a boolean.
    Boolean,
    /// Display as a GUID.
    Guid,
    /// Display as hexadecimal binary data.
    HexBinary,
    /// Display as a hexadecimal 8-bit integer.
    HexInt8,
    /// Display as a hexadecimal 16-bit integer.
    HexInt16,
    /// Display as a hexadecimal 32-bit integer.
    HexInt32,
    /// Display as a hexadecimal 64-bit integer.
    HexInt64,
    /// Display as a process ID.
    Pid,
    /// Display as a thread ID.
    Tid,
    /// Display as a network port number.
    Port,
    /// Display as an IPv4 address.
    Ipv4,
    /// Display as an IPv6 address.
    Ipv6,
    /// Display as a socket address.
    SocketAddress,
    /// Display as a CIM date/time.
    CimDateTime,
    /// Display as an ETW relative time.
    EtwTime,
    /// Display as XML.
    Xml,
    /// Display as a generic error code.
    ErrorCode,
    /// Display as a Win32 error code.
    Win32Error,
    /// Display as an NTSTATUS code.
    NtStatus,
    /// Display as an HRESULT code.
    HResult,
    /// Display as a culture-insensitive date/time.
    CultureInsensitiveDateTime,
    /// Display as JSON.
    Json,
    /// Display as a UTF-8 string.
    Utf8,
    /// PKCS7 data with type information.
    Pkcs7WithTypeInfo,
    /// Display as a code pointer address.
    CodePointer,
    /// Display as a UTC date/time.
    DateTimeUtc,
    /// WBEM reduced string (wire value 300).
    ReducedString,
    /// WBEM no-print (wire value 301).
    NoPrint,
    /// Unknown output type not recognised by this version of etw-rs.
    Unknown(u16),
}

impl TdhOutType {
    /// Creates a `TdhOutType` from a raw u16 value.
    pub const fn from_raw(value: u16) -> Self {
        match value as i32 {
            etw::TDH_OUTTYPE_NULL => Self::Null,
            etw::TDH_OUTTYPE_STRING => Self::String,
            etw::TDH_OUTTYPE_DATETIME => Self::DateTime,
            etw::TDH_OUTTYPE_BYTE => Self::Byte,
            etw::TDH_OUTTYPE_UNSIGNEDBYTE => Self::UnsignedByte,
            etw::TDH_OUTTYPE_SHORT => Self::Short,
            etw::TDH_OUTTYPE_UNSIGNEDSHORT => Self::UnsignedShort,
            etw::TDH_OUTTYPE_INT => Self::Int,
            etw::TDH_OUTTYPE_UNSIGNEDINT => Self::UnsignedInt,
            etw::TDH_OUTTYPE_LONG => Self::Long,
            etw::TDH_OUTTYPE_UNSIGNEDLONG => Self::UnsignedLong,
            etw::TDH_OUTTYPE_FLOAT => Self::Float,
            etw::TDH_OUTTYPE_DOUBLE => Self::Double,
            etw::TDH_OUTTYPE_BOOLEAN => Self::Boolean,
            etw::TDH_OUTTYPE_GUID => Self::Guid,
            etw::TDH_OUTTYPE_HEXBINARY => Self::HexBinary,
            etw::TDH_OUTTYPE_HEXINT8 => Self::HexInt8,
            etw::TDH_OUTTYPE_HEXINT16 => Self::HexInt16,
            etw::TDH_OUTTYPE_HEXINT32 => Self::HexInt32,
            etw::TDH_OUTTYPE_HEXINT64 => Self::HexInt64,
            etw::TDH_OUTTYPE_PID => Self::Pid,
            etw::TDH_OUTTYPE_TID => Self::Tid,
            etw::TDH_OUTTYPE_PORT => Self::Port,
            etw::TDH_OUTTYPE_IPV4 => Self::Ipv4,
            etw::TDH_OUTTYPE_IPV6 => Self::Ipv6,
            etw::TDH_OUTTYPE_SOCKETADDRESS => Self::SocketAddress,
            etw::TDH_OUTTYPE_CIMDATETIME => Self::CimDateTime,
            etw::TDH_OUTTYPE_ETWTIME => Self::EtwTime,
            etw::TDH_OUTTYPE_XML => Self::Xml,
            etw::TDH_OUTTYPE_ERRORCODE => Self::ErrorCode,
            etw::TDH_OUTTYPE_WIN32ERROR => Self::Win32Error,
            etw::TDH_OUTTYPE_NTSTATUS => Self::NtStatus,
            etw::TDH_OUTTYPE_HRESULT => Self::HResult,
            etw::TDH_OUTTYPE_CULTURE_INSENSITIVE_DATETIME => Self::CultureInsensitiveDateTime,
            etw::TDH_OUTTYPE_JSON => Self::Json,
            etw::TDH_OUTTYPE_UTF8 => Self::Utf8,
            etw::TDH_OUTTYPE_PKCS7_WITH_TYPE_INFO => Self::Pkcs7WithTypeInfo,
            etw::TDH_OUTTYPE_CODE_POINTER => Self::CodePointer,
            etw::TDH_OUTTYPE_DATETIME_UTC => Self::DateTimeUtc,
            etw::TDH_OUTTYPE_REDUCEDSTRING => Self::ReducedString,
            etw::TDH_OUTTYPE_NOPRINT => Self::NoPrint,
            _ => Self::Unknown(value),
        }
    }

    /// Returns the raw `u16` wire value for this output type.
    #[must_use]
    pub const fn raw_value(self) -> u16 {
        let v = match self {
            Self::Null => etw::TDH_OUTTYPE_NULL,
            Self::String => etw::TDH_OUTTYPE_STRING,
            Self::DateTime => etw::TDH_OUTTYPE_DATETIME,
            Self::Byte => etw::TDH_OUTTYPE_BYTE,
            Self::UnsignedByte => etw::TDH_OUTTYPE_UNSIGNEDBYTE,
            Self::Short => etw::TDH_OUTTYPE_SHORT,
            Self::UnsignedShort => etw::TDH_OUTTYPE_UNSIGNEDSHORT,
            Self::Int => etw::TDH_OUTTYPE_INT,
            Self::UnsignedInt => etw::TDH_OUTTYPE_UNSIGNEDINT,
            Self::Long => etw::TDH_OUTTYPE_LONG,
            Self::UnsignedLong => etw::TDH_OUTTYPE_UNSIGNEDLONG,
            Self::Float => etw::TDH_OUTTYPE_FLOAT,
            Self::Double => etw::TDH_OUTTYPE_DOUBLE,
            Self::Boolean => etw::TDH_OUTTYPE_BOOLEAN,
            Self::Guid => etw::TDH_OUTTYPE_GUID,
            Self::HexBinary => etw::TDH_OUTTYPE_HEXBINARY,
            Self::HexInt8 => etw::TDH_OUTTYPE_HEXINT8,
            Self::HexInt16 => etw::TDH_OUTTYPE_HEXINT16,
            Self::HexInt32 => etw::TDH_OUTTYPE_HEXINT32,
            Self::HexInt64 => etw::TDH_OUTTYPE_HEXINT64,
            Self::Pid => etw::TDH_OUTTYPE_PID,
            Self::Tid => etw::TDH_OUTTYPE_TID,
            Self::Port => etw::TDH_OUTTYPE_PORT,
            Self::Ipv4 => etw::TDH_OUTTYPE_IPV4,
            Self::Ipv6 => etw::TDH_OUTTYPE_IPV6,
            Self::SocketAddress => etw::TDH_OUTTYPE_SOCKETADDRESS,
            Self::CimDateTime => etw::TDH_OUTTYPE_CIMDATETIME,
            Self::EtwTime => etw::TDH_OUTTYPE_ETWTIME,
            Self::Xml => etw::TDH_OUTTYPE_XML,
            Self::ErrorCode => etw::TDH_OUTTYPE_ERRORCODE,
            Self::Win32Error => etw::TDH_OUTTYPE_WIN32ERROR,
            Self::NtStatus => etw::TDH_OUTTYPE_NTSTATUS,
            Self::HResult => etw::TDH_OUTTYPE_HRESULT,
            Self::CultureInsensitiveDateTime => etw::TDH_OUTTYPE_CULTURE_INSENSITIVE_DATETIME,
            Self::Json => etw::TDH_OUTTYPE_JSON,
            Self::Utf8 => etw::TDH_OUTTYPE_UTF8,
            Self::Pkcs7WithTypeInfo => etw::TDH_OUTTYPE_PKCS7_WITH_TYPE_INFO,
            Self::CodePointer => etw::TDH_OUTTYPE_CODE_POINTER,
            Self::DateTimeUtc => etw::TDH_OUTTYPE_DATETIME_UTC,
            Self::ReducedString => etw::TDH_OUTTYPE_REDUCEDSTRING,
            Self::NoPrint => etw::TDH_OUTTYPE_NOPRINT,
            Self::Unknown(v) => return v,
        };
        v as u16
    }

    /// The code page an ANSI string property with this out-type is encoded in.
    ///
    /// `Utf8`, `Json` and `Xml` mean UTF-8 (`<tdh.h>`; an XML document may override
    /// that with its own `encoding` attribute, which is not consulted here). Every
    /// other out-type means the provider's ANSI code page. The event does not record
    /// which code page that was, so this assumes the local
    /// [`CP_ACP`](windows_sys::Win32::Globalization::CP_ACP) — right for events
    /// produced on this machine.
    #[must_use]
    pub const fn ansi_code_page(self) -> u32 {
        use windows_sys::Win32::Globalization::{CP_ACP, CP_UTF8};
        match self {
            Self::Utf8 | Self::Json | Self::Xml => CP_UTF8,
            _ => CP_ACP,
        }
    }
}

/// TDH input type constants.
///
/// Specifies the encoding format of a property's raw bytes. The decoder uses this together with
/// [`TdhOutType`] to interpret and display the value.
///
/// # Determining a field's size
///
/// An InType's primary job is to tell a decoder how long the field is. There are three distinct
/// mechanisms, and which one applies is a property of the InType:
///
/// 1. **Fixed** — the size is implied by the type alone ([`Self::UInt16`] is always 2 bytes). The
///    `length` field of the property's `EVENT_PROPERTY_INFO` can be ignored.
/// 2. **Self-describing** — the size is read out of the field's own data ([`Self::Sid`],
///    [`Self::CountedString`]). The `length` field must be *ignored*, not consulted.
/// 3. **Descriptor-driven** — the size comes from the `Flags` and `length` fields of the property's
///    `EVENT_PROPERTY_INFO` ([`Self::UnicodeString`], [`Self::Binary`]). The per-variant docs below
///    give the precedence order.
///
/// Note that the unit of `EVENT_PROPERTY_INFO::length` is type-dependent: WCHARs for
/// [`Self::UnicodeString`], bytes for [`Self::AnsiString`] and [`Self::Binary`].
///
/// # Output types
///
/// For the manifest InTypes (values 1–25) the default [`TdhOutType`] and the set of applicable
/// out-types are defined by `winmeta.xml`, not by this enum. For the legacy WBEM InTypes (values
/// 300+) they are specified per-variant below.
///
/// Sizing and deprecation notes are drawn from the `_TDH_IN_TYPE` definition in the Windows SDK
/// `<tdh.h>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TdhInType {
    /// `TDH_INTYPE_NULL` (0) — invalid InType value.
    Null,
    /// `TDH_INTYPE_UNICODESTRING` (1) — UTF-16LE string.
    ///
    /// Size is descriptor-driven, in precedence order: `PropertyParamLength` set → the property at
    /// `lengthPropertyIndex` holds the number of **WCHARs**; else `length != 0` → that many
    /// **WCHARs**; else NUL-terminated by a `(WCHAR)0`.
    ///
    /// Some providers omit the terminator on an event's final string field. This is technically
    /// invalid, but decoders generally tolerate it rather than rejecting the event.
    UnicodeString,
    /// `TDH_INTYPE_ANSISTRING` (2) — 8-bit string.
    ///
    /// Size is descriptor-driven, in precedence order: `PropertyParamLength` set → the property at
    /// `lengthPropertyIndex` holds the number of **bytes**; else `length != 0` → that many
    /// **bytes**; else NUL-terminated by a `(CHAR)0`.
    ///
    /// The same missing-terminator tolerance as [`Self::UnicodeString`] applies.
    AnsiString,
    /// `TDH_INTYPE_INT8` (3) — signed 8-bit integer. Always 1 byte.
    Int8,
    /// `TDH_INTYPE_UINT8` (4) — unsigned 8-bit integer. Always 1 byte.
    UInt8,
    /// `TDH_INTYPE_INT16` (5) — signed 16-bit integer. Always 2 bytes.
    Int16,
    /// `TDH_INTYPE_UINT16` (6) — unsigned 16-bit integer. Always 2 bytes.
    UInt16,
    /// `TDH_INTYPE_INT32` (7) — signed 32-bit integer. Always 4 bytes.
    Int32,
    /// `TDH_INTYPE_UINT32` (8) — unsigned 32-bit integer. Always 4 bytes.
    UInt32,
    /// `TDH_INTYPE_INT64` (9) — signed 64-bit integer. Always 8 bytes.
    Int64,
    /// `TDH_INTYPE_UINT64` (10) — unsigned 64-bit integer. Always 8 bytes.
    UInt64,
    /// `TDH_INTYPE_FLOAT` (11) — 32-bit floating point. Always 4 bytes.
    Float,
    /// `TDH_INTYPE_DOUBLE` (12) — 64-bit floating point. Always 8 bytes.
    Double,
    /// `TDH_INTYPE_BOOLEAN` (13) — boolean. Always **4** bytes, not 1.
    Boolean,
    /// `TDH_INTYPE_BINARY` (14) — binary data.
    ///
    /// Size is descriptor-driven, in precedence order: `PropertyParamLength` set → the property at
    /// `lengthPropertyIndex` holds the number of bytes; else `length != 0` → that many bytes; else
    /// `out_type == TDH_OUTTYPE_IPV6` → 16 bytes; else the field is incorrectly encoded.
    ///
    /// The IPv6 rule is the only case where an InType's size depends on its [`TdhOutType`].
    Binary,
    /// `TDH_INTYPE_GUID` (15) — GUID. Always 16 bytes.
    Guid,
    /// `TDH_INTYPE_POINTER` (16) — pointer-sized integer.
    ///
    /// Size comes from the *event*, not the property: 4 bytes when the event header has
    /// `EVENT_HEADER_FLAG_32_BIT_HEADER`, 8 bytes when it has `EVENT_HEADER_FLAG_64_BIT_HEADER`.
    /// A 32-bit provider on a 64-bit host emits 4-byte pointers.
    ///
    /// Default out-type is `HexInt64`; `CodePointer`, `Long`, and `UnsignedLong` are also usable.
    Pointer,
    /// `TDH_INTYPE_FILETIME` (17) — `FILETIME`. Always 8 bytes.
    FileTime,
    /// `TDH_INTYPE_SYSTEMTIME` (18) — `SYSTEMTIME`. Always 16 bytes.
    SystemTime,
    /// `TDH_INTYPE_SID` (19) — security identifier.
    ///
    /// Self-describing: the sub-authority count is read from the second byte of the field, giving
    /// `8 + sub_authority_count * 4` bytes.
    Sid,
    /// `TDH_INTYPE_HEXINT32` (20) — 32-bit integer displayed as hexadecimal. Always 4 bytes.
    HexInt32,
    /// `TDH_INTYPE_HEXINT64` (21) — 64-bit integer displayed as hexadecimal. Always 8 bytes.
    HexInt64,
    /// `TDH_INTYPE_MANIFEST_COUNTEDSTRING` (22) — counted UTF-16LE string, usable in manifests.
    ///
    /// Self-describing: a little-endian `u16` **byte** count (not a character count) followed by
    /// that many bytes of UTF-16LE. Requires Windows 10 1809 (the 2018 Fall Update) or later.
    ManifestCountedString,
    /// `TDH_INTYPE_MANIFEST_COUNTEDANSISTRING` (23) — counted 8-bit string, usable in manifests.
    ///
    /// Self-describing: a little-endian `u16` byte count followed by that many bytes. Requires
    /// Windows 10 1809 (the 2018 Fall Update) or later.
    ManifestCountedAnsiString,
    /// `TDH_INTYPE_MANIFEST_COUNTEDBINARY` (25) — counted binary data, usable in manifests.
    ///
    /// Self-describing: a little-endian `u16` byte count followed by that many bytes. Requires
    /// Windows 10 1809 (the 2018 Fall Update) or later.
    ///
    /// Value 24 is `TDH_INTYPE_RESERVED24` and is not used.
    ManifestCountedBinary,
    // Legacy WBEM intypes (300+). These cannot be used in manifests.
    /// `TDH_INTYPE_COUNTEDSTRING` (300) — counted UTF-16LE string.
    ///
    /// Self-describing: a little-endian `u16` **byte** count followed by that many bytes of
    /// UTF-16LE. The prefix counts bytes, not characters — reading it as a character count
    /// over-reads the field and drifts every subsequent property in the event.
    ///
    /// Default out-type is `String`; `Xml` and `Json` are also usable.
    CountedString,
    /// `TDH_INTYPE_COUNTEDANSISTRING` (301) — counted 8-bit string.
    ///
    /// Self-describing: a little-endian `u16` byte count followed by that many bytes.
    ///
    /// Default out-type is `String`; `Xml`, `Json`, and `Utf8` are also usable.
    CountedAnsiString,
    /// `TDH_INTYPE_REVERSEDCOUNTEDSTRING` (302) — counted UTF-16LE string with a big-endian count.
    ///
    /// Self-describing: a **big-endian** `u16` byte count followed by that many bytes of
    /// little-endian UTF-16LE. Only the count is byte-swapped; the payload is not.
    ///
    /// Deprecated by the SDK in favour of [`Self::CountedString`].
    ReversedCountedString,
    /// `TDH_INTYPE_REVERSEDCOUNTEDANSISTRING` (303) — counted 8-bit string with a big-endian count.
    ///
    /// Self-describing: a **big-endian** `u16` byte count followed by that many bytes.
    ///
    /// Deprecated by the SDK in favour of [`Self::CountedAnsiString`].
    ReversedCountedAnsiString,
    /// `TDH_INTYPE_NONNULLTERMINATEDSTRING` (304) — unterminated UTF-16LE string.
    ///
    /// Size is all remaining bytes of the event's data. Consequently this type can only appear as
    /// an event's final property.
    ///
    /// Deprecated by the SDK in favour of [`Self::CountedString`].
    NonNullTerminatedString,
    /// `TDH_INTYPE_NONNULLTERMINATEDANSISTRING` (305) — unterminated 8-bit string.
    ///
    /// Size is all remaining bytes of the event's data, with the same final-property consequence
    /// as [`Self::NonNullTerminatedString`].
    ///
    /// Deprecated by the SDK in favour of [`Self::CountedAnsiString`].
    NonNullTerminatedAnsiString,
    /// `TDH_INTYPE_UNICODECHAR` (306) — a UTF-16 code unit: 2 bytes, or a fixed WCHAR array when
    /// the property declares a length.
    ///
    /// Deprecated by the SDK in favour of [`Self::UInt16`] with a `String` out-type.
    UnicodeChar,
    /// `TDH_INTYPE_ANSICHAR` (307) — a single 8-bit character. Always 1 byte.
    ///
    /// Deprecated by the SDK in favour of [`Self::UInt8`] with a `String` out-type.
    AnsiChar,
    /// `TDH_INTYPE_SIZET` (308) — `SIZE_T`.
    ///
    /// Pointer-sized, resolved from the event header flags exactly as [`Self::Pointer`] is.
    ///
    /// Deprecated by the SDK in favour of [`Self::Pointer`] with an `UnsignedLong` out-type.
    SizeT,
    /// `TDH_INTYPE_HEXDUMP` (309) — binary data with a 32-bit length prefix.
    ///
    /// Self-describing: a little-endian **`u32`** byte count followed by that many bytes. Note the
    /// 4-byte prefix — every other counted type in this enum uses a 2-byte prefix.
    ///
    /// Deprecated by the SDK in favour of [`Self::Binary`].
    HexDump,
    /// `TDH_INTYPE_WBEMSID` (310) — an `SE_TOKEN_USER` followed by SID data.
    ///
    /// Self-describing, but pointer-size dependent: `SE_TOKEN_USER` opens with a
    /// `SID_AND_ATTRIBUTES { Sid: *SID, Attributes: DWORD }`, which is 16 bytes on 64-bit (8-byte
    /// pointer plus a padded `DWORD`) and 8 bytes on 32-bit. The SID therefore does not start at a
    /// fixed offset — the prefix must be sized from the event header flags before the
    /// sub-authority count can be read.
    ///
    /// Deprecated by the SDK in favour of [`Self::Sid`].
    WbemSid,
    /// Synthetic marker for struct properties.
    ///
    /// TDH does not define an InType for structs — struct properties use the
    /// `PropertyStruct` flag and their InType field is zero (Null). This variant
    /// exists so callers can distinguish struct properties from genuinely null
    /// types without inspecting flags directly. It has no wire representation
    /// and is never returned by [`TdhInType::from_raw`].
    Struct,
    /// Unknown input type not recognised by this version of etw-rs.
    Unknown(u16),
}

impl TdhInType {
    /// Creates a `TdhInType` from a raw u16 value.
    ///
    /// `TDH_INTYPE_RESERVED24` has no variant and falls through to [`Self::Unknown`].
    pub const fn from_raw(value: u16) -> Self {
        match value as i32 {
            etw::TDH_INTYPE_NULL => Self::Null,
            etw::TDH_INTYPE_UNICODESTRING => Self::UnicodeString,
            etw::TDH_INTYPE_ANSISTRING => Self::AnsiString,
            etw::TDH_INTYPE_INT8 => Self::Int8,
            etw::TDH_INTYPE_UINT8 => Self::UInt8,
            etw::TDH_INTYPE_INT16 => Self::Int16,
            etw::TDH_INTYPE_UINT16 => Self::UInt16,
            etw::TDH_INTYPE_INT32 => Self::Int32,
            etw::TDH_INTYPE_UINT32 => Self::UInt32,
            etw::TDH_INTYPE_INT64 => Self::Int64,
            etw::TDH_INTYPE_UINT64 => Self::UInt64,
            etw::TDH_INTYPE_FLOAT => Self::Float,
            etw::TDH_INTYPE_DOUBLE => Self::Double,
            etw::TDH_INTYPE_BOOLEAN => Self::Boolean,
            etw::TDH_INTYPE_BINARY => Self::Binary,
            etw::TDH_INTYPE_GUID => Self::Guid,
            etw::TDH_INTYPE_POINTER => Self::Pointer,
            etw::TDH_INTYPE_FILETIME => Self::FileTime,
            etw::TDH_INTYPE_SYSTEMTIME => Self::SystemTime,
            etw::TDH_INTYPE_SID => Self::Sid,
            etw::TDH_INTYPE_HEXINT32 => Self::HexInt32,
            etw::TDH_INTYPE_HEXINT64 => Self::HexInt64,
            etw::TDH_INTYPE_MANIFEST_COUNTEDSTRING => Self::ManifestCountedString,
            etw::TDH_INTYPE_MANIFEST_COUNTEDANSISTRING => Self::ManifestCountedAnsiString,
            etw::TDH_INTYPE_MANIFEST_COUNTEDBINARY => Self::ManifestCountedBinary,
            etw::TDH_INTYPE_COUNTEDSTRING => Self::CountedString,
            etw::TDH_INTYPE_COUNTEDANSISTRING => Self::CountedAnsiString,
            etw::TDH_INTYPE_REVERSEDCOUNTEDSTRING => Self::ReversedCountedString,
            etw::TDH_INTYPE_REVERSEDCOUNTEDANSISTRING => Self::ReversedCountedAnsiString,
            etw::TDH_INTYPE_NONNULLTERMINATEDSTRING => Self::NonNullTerminatedString,
            etw::TDH_INTYPE_NONNULLTERMINATEDANSISTRING => Self::NonNullTerminatedAnsiString,
            etw::TDH_INTYPE_UNICODECHAR => Self::UnicodeChar,
            etw::TDH_INTYPE_ANSICHAR => Self::AnsiChar,
            etw::TDH_INTYPE_SIZET => Self::SizeT,
            etw::TDH_INTYPE_HEXDUMP => Self::HexDump,
            etw::TDH_INTYPE_WBEMSID => Self::WbemSid,
            _ => Self::Unknown(value),
        }
    }

    /// Returns the raw `u16` wire value for this input type.
    #[must_use]
    pub const fn raw_value(self) -> u16 {
        let v = match self {
            Self::Null => etw::TDH_INTYPE_NULL,
            Self::UnicodeString => etw::TDH_INTYPE_UNICODESTRING,
            Self::AnsiString => etw::TDH_INTYPE_ANSISTRING,
            Self::Int8 => etw::TDH_INTYPE_INT8,
            Self::UInt8 => etw::TDH_INTYPE_UINT8,
            Self::Int16 => etw::TDH_INTYPE_INT16,
            Self::UInt16 => etw::TDH_INTYPE_UINT16,
            Self::Int32 => etw::TDH_INTYPE_INT32,
            Self::UInt32 => etw::TDH_INTYPE_UINT32,
            Self::Int64 => etw::TDH_INTYPE_INT64,
            Self::UInt64 => etw::TDH_INTYPE_UINT64,
            Self::Float => etw::TDH_INTYPE_FLOAT,
            Self::Double => etw::TDH_INTYPE_DOUBLE,
            Self::Boolean => etw::TDH_INTYPE_BOOLEAN,
            Self::Binary => etw::TDH_INTYPE_BINARY,
            Self::Guid => etw::TDH_INTYPE_GUID,
            Self::Pointer => etw::TDH_INTYPE_POINTER,
            Self::FileTime => etw::TDH_INTYPE_FILETIME,
            Self::SystemTime => etw::TDH_INTYPE_SYSTEMTIME,
            Self::Sid => etw::TDH_INTYPE_SID,
            Self::HexInt32 => etw::TDH_INTYPE_HEXINT32,
            Self::HexInt64 => etw::TDH_INTYPE_HEXINT64,
            Self::ManifestCountedString => etw::TDH_INTYPE_MANIFEST_COUNTEDSTRING,
            Self::ManifestCountedAnsiString => etw::TDH_INTYPE_MANIFEST_COUNTEDANSISTRING,
            Self::ManifestCountedBinary => etw::TDH_INTYPE_MANIFEST_COUNTEDBINARY,
            Self::CountedString => etw::TDH_INTYPE_COUNTEDSTRING,
            Self::CountedAnsiString => etw::TDH_INTYPE_COUNTEDANSISTRING,
            Self::ReversedCountedString => etw::TDH_INTYPE_REVERSEDCOUNTEDSTRING,
            Self::ReversedCountedAnsiString => etw::TDH_INTYPE_REVERSEDCOUNTEDANSISTRING,
            Self::NonNullTerminatedString => etw::TDH_INTYPE_NONNULLTERMINATEDSTRING,
            Self::NonNullTerminatedAnsiString => etw::TDH_INTYPE_NONNULLTERMINATEDANSISTRING,
            Self::UnicodeChar => etw::TDH_INTYPE_UNICODECHAR,
            Self::AnsiChar => etw::TDH_INTYPE_ANSICHAR,
            Self::SizeT => etw::TDH_INTYPE_SIZET,
            Self::HexDump => etw::TDH_INTYPE_HEXDUMP,
            Self::WbemSid => etw::TDH_INTYPE_WBEMSID,
            Self::Struct => return u16::MAX,
            Self::Unknown(v) => return v,
        };
        v as u16
    }

    /// Returns the fixed size in bytes for this type, or `None` if variable-length.
    ///
    /// `pointer_size` must be 4 (32-bit) or 8 (64-bit) and controls the size
    /// of `Pointer` and `SizeT` types.
    pub const fn fixed_size(&self, pointer_size: usize) -> Option<usize> {
        match self {
            Self::Int8 | Self::UInt8 | Self::AnsiChar => Some(1),
            Self::Int16 | Self::UInt16 | Self::UnicodeChar => Some(2),
            Self::Int32 | Self::UInt32 | Self::HexInt32 | Self::Boolean | Self::Float => Some(4),
            Self::Int64 | Self::UInt64 | Self::HexInt64 | Self::FileTime | Self::Double => Some(8),
            Self::Pointer | Self::SizeT => Some(pointer_size),
            Self::Guid | Self::SystemTime => Some(16),
            // Variable-length types
            Self::UnicodeString
            | Self::AnsiString
            | Self::Binary
            | Self::Sid
            | Self::WbemSid
            | Self::CountedString
            | Self::CountedAnsiString
            | Self::ReversedCountedString
            | Self::ReversedCountedAnsiString
            | Self::NonNullTerminatedString
            | Self::NonNullTerminatedAnsiString
            | Self::HexDump
            | Self::ManifestCountedString
            | Self::ManifestCountedAnsiString
            | Self::ManifestCountedBinary
            | Self::Struct
            | Self::Null
            | Self::Unknown(_) => None,
        }
    }
}

// =============================================================================
// Windows-1252 (CP1252) Codec
// =============================================================================

/// Windows-1252 code page mapping for bytes 0x80-0x9F.
///
/// These are the only bytes that differ from ISO-8859-1.
/// Bytes 0x00-0x7F map to themselves (ASCII).
/// Bytes 0xA0-0xFF map to themselves (Latin-1 supplement).
/// Values of 0xFFFD indicate undefined characters (we use replacement char).
const CP1252_HIGH: [char; 32] = [
    '\u{20AC}', // 0x80 € Euro sign
    '\u{FFFD}', // 0x81   Undefined
    '\u{201A}', // 0x82 ‚ Single low-9 quotation mark
    '\u{0192}', // 0x83 ƒ Latin small letter f with hook
    '\u{201E}', // 0x84 „ Double low-9 quotation mark
    '\u{2026}', // 0x85 … Horizontal ellipsis
    '\u{2020}', // 0x86 † Dagger
    '\u{2021}', // 0x87 ‡ Double dagger
    '\u{02C6}', // 0x88 ˆ Modifier letter circumflex accent
    '\u{2030}', // 0x89 ‰ Per mille sign
    '\u{0160}', // 0x8A Š Latin capital letter S with caron
    '\u{2039}', // 0x8B ‹ Single left-pointing angle quotation mark
    '\u{0152}', // 0x8C Œ Latin capital ligature OE
    '\u{FFFD}', // 0x8D   Undefined
    '\u{017D}', // 0x8E Ž Latin capital letter Z with caron
    '\u{FFFD}', // 0x8F   Undefined
    '\u{FFFD}', // 0x90   Undefined
    '\u{2018}', // 0x91 ' Left single quotation mark
    '\u{2019}', // 0x92 ' Right single quotation mark
    '\u{201C}', // 0x93 " Left double quotation mark
    '\u{201D}', // 0x94 " Right double quotation mark
    '\u{2022}', // 0x95 • Bullet
    '\u{2013}', // 0x96 – En dash
    '\u{2014}', // 0x97 — Em dash
    '\u{02DC}', // 0x98 ˜ Small tilde
    '\u{2122}', // 0x99 ™ Trade mark sign
    '\u{0161}', // 0x9A š Latin small letter s with caron
    '\u{203A}', // 0x9B › Single right-pointing angle quotation mark
    '\u{0153}', // 0x9C œ Latin small ligature oe
    '\u{FFFD}', // 0x9D   Undefined
    '\u{017E}', // 0x9E ž Latin small letter z with caron
    '\u{0178}', // 0x9F Ÿ Latin capital letter Y with diaeresis
];

/// Decode a single Windows-1252 byte to a Unicode char.
#[inline]
pub(crate) const fn cp1252_to_char(byte: u8) -> char {
    match byte {
        0x80..=0x9F => CP1252_HIGH[(byte - 0x80) as usize], // Special range
        _ => byte as char,                                  /* ASCII (0x00-0x7F) and Latin-1
                                                              * supplement (0xA0-0xFF) map
                                                              * directly */
    }
}

/// Decode Windows-1252 bytes to a String.
pub(crate) fn decode_cp1252(data: &[u8]) -> String {
    data.iter().map(|&b| cp1252_to_char(b)).collect()
}

/// Check if Windows-1252 bytes are valid ASCII (for fast path).
#[inline]
pub(crate) fn is_ascii_only(data: &[u8]) -> bool {
    data.iter().all(|&b| b < 0x80)
}

// =============================================================================
// WideStrRef - Zero-Copy UTF-16LE String
// =============================================================================

/// A borrowed UTF-16LE string from an ETW event buffer.
///
/// This is a zero-copy wrapper that references the original event data.
/// Use this when you want to avoid allocation, especially for filtering
/// or when passing data to Windows APIs that expect UTF-16.
///
/// # Example
///
/// ```no_run
/// # fn example(parser: &mut etw::EventParser) -> etw::Result<()> {
/// use etw::types::WideStrRef;
/// // Zero-copy access
/// let name: WideStrRef = parser.as_ref("QueryName")?;
///
/// // Compare without allocating
/// if name.eq_ascii_ignore_case("example.com") {
///     // ...
/// }
///
/// // Convert to String only when needed
/// let s: String = name.decode_utf16()?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy)]
pub struct WideStrRef<'a> {
    /// Raw UTF-16LE bytes (not including null terminator)
    data: &'a [u8],
}

impl<'a> WideStrRef<'a> {
    /// Create a new `WideStrRef` from raw UTF-16LE bytes.
    ///
    /// The data should NOT include a null terminator.
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Create from raw bytes, stripping null terminator if present.
    #[must_use]
    pub fn from_raw_with_null(data: &'a [u8]) -> Self {
        let byte_len = data.len();
        debug_assert!(
            byte_len.is_multiple_of(2),
            "WideStr data must be even-length"
        );
        // Fast path: ETW property buffers are sized to include exactly one trailing
        // null terminator (no embedded nulls in practice). Checking the final two
        // bytes avoids an O(n) scan. The slow path handles the rare case where the
        // last u16 is not null (e.g., truncated buffers) by scanning for the first null.
        Self::new(&data[..Self::null_terminated_len(data)])
    }

    /// Length in bytes of `data` up to, but excluding, its null terminator.
    ///
    /// Drops exactly one trailing null code unit when present, otherwise
    /// truncates at the first embedded null, otherwise returns the full length —
    /// the same rule [`WideString::from_bytes`] applies to owned data. Factored
    /// out so the borrowing decoders can share it without also inheriting
    /// [`Self::from_raw_with_null`]'s even-length debug assertion.
    pub(crate) fn null_terminated_len(data: &[u8]) -> usize {
        let byte_len = data.len();
        if byte_len >= 2 && data[byte_len - 2] == 0 && data[byte_len - 1] == 0 {
            byte_len - 2
        } else {
            Self::find_null_terminator(data).unwrap_or(byte_len)
        }
    }

    /// Find the position of the null terminator (in bytes).
    pub(crate) fn find_null_terminator(data: &[u8]) -> Option<usize> {
        // Fast path: if the data is u16-aligned, use native u16 scanning.
        if (data.as_ptr() as usize) & 1 == 0 {
            let len = data.len() / 2;
            // SAFETY: We verified 2-byte alignment above, and `len` does not exceed half
            // the byte length, so the resulting slice is within bounds.
            let wide = unsafe { std::slice::from_raw_parts(data.as_ptr().cast::<u16>(), len) };
            if let Some(pos) = wide.iter().position(|&u| u == 0) {
                return Some(pos * 2);
            }
            return None;
        }
        // Slow path: unaligned — scan byte pairs manually.
        let mut i = 0;
        while i + 1 < data.len() {
            if data[i] == 0 && data[i + 1] == 0 {
                return Some(i);
            }
            i += 2;
        }
        None
    }

    /// Returns the raw UTF-16LE bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.data
    }

    /// Returns the string as a slice of u16 code units.
    ///
    /// Returns `None` if the byte length is not even.
    #[must_use]
    pub fn as_wide_slice(&self) -> Option<&'a [u16]> {
        if !self.data.len().is_multiple_of(2) {
            return None;
        }
        if (self.data.as_ptr() as usize) & 1 != 0 {
            return None; // Not aligned
        }
        // SAFETY: We've verified the length is even and the pointer is u16-aligned.
        Some(unsafe {
            std::slice::from_raw_parts(self.data.as_ptr().cast::<u16>(), self.data.len() / 2)
        })
    }

    /// Returns the number of UTF-16 code units.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len() / 2
    }

    /// Returns true if the string is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Decode the UTF-16LE data into an owned `String`.
    ///
    /// This allocates and performs UTF-16 to UTF-8 conversion. When the
    /// underlying data is u16-aligned (the common case for ETW buffers),
    /// the intermediate `Vec<u16>` allocation is skipped entirely.
    pub fn decode_utf16(&self) -> Result<String> {
        if self.data.is_empty() {
            return Ok(String::new());
        }
        // Fast path: data is u16-aligned — pass &[u16] directly to from_utf16,
        // avoiding the intermediate Vec<u16> allocation.
        if let Some(wide) = self.as_wide_slice() {
            return String::from_utf16(wide)
                .map_err(|e| Error::parse(format!("Invalid UTF-16: {e}")));
        }
        // Fallback: unaligned data — reconstruct u16 values from bytes.
        let chars: Vec<u16> = self
            .data
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16(&chars).map_err(|e| Error::parse(format!("Invalid UTF-16: {e}")))
    }

    /// Convert to an owned `String`, replacing invalid sequences with U+FFFD.
    ///
    /// When the underlying data is u16-aligned (the common case for ETW
    /// buffers), the intermediate `Vec<u16>` allocation is skipped entirely.
    #[must_use]
    pub fn to_string_lossy(&self) -> String {
        if self.data.is_empty() {
            return String::new();
        }
        // Pre-allocate to match the number of code units. Most ETW strings are ASCII
        // (1 UTF-8 byte per char), so this is a tight estimate and avoids the repeated
        // heap reallocations caused by `String::from_utf16_lossy`'s `size_hint` of 0.
        let code_units = self.data.len() / 2;
        let mut s = String::with_capacity(code_units);
        // Fast path: data is u16-aligned — iterate &[u16] directly.
        if let Some(wide) = self.as_wide_slice() {
            for c in char::decode_utf16(wide.iter().copied()) {
                s.push(c.unwrap_or(char::REPLACEMENT_CHARACTER));
            }
        } else {
            // Fallback: unaligned data — reconstruct u16 values from byte pairs.
            // Also avoids the intermediate Vec<u16> that the old `from_utf16_lossy` path
            // required.
            for c in char::decode_utf16(
                self.data
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_le_bytes([c[0], c[1]])),
            ) {
                s.push(c.unwrap_or(char::REPLACEMENT_CHARACTER));
            }
        }
        s
    }

    /// Convert to an owned [`OsString`](std::ffi::OsString) without loss.
    ///
    /// Unlike [`decode_utf16()`](Self::decode_utf16) this cannot fail, and unlike
    /// [`to_string_lossy()`](Self::to_string_lossy) it preserves unpaired surrogates,
    /// which Windows permits in file names, registry keys and other identifiers.
    #[must_use]
    pub fn to_os_string(&self) -> std::ffi::OsString {
        use std::os::windows::ffi::OsStringExt;
        if let Some(wide) = self.as_wide_slice() {
            return std::ffi::OsString::from_wide(wide);
        }
        let wide: Vec<u16> = self
            .data
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        std::ffi::OsString::from_wide(&wide)
    }

    /// Compare against an ASCII string without allocation.
    ///
    /// Returns `false` if `other` contains non-ASCII characters.
    #[must_use]
    pub fn eq_ascii(&self, other: &str) -> bool {
        if !other.is_ascii() {
            return false;
        }
        if self.len() != other.len() {
            return false;
        }
        self.data
            .as_chunks::<2>()
            .0
            .iter()
            .zip(other.bytes())
            .all(|(wide, ascii)| wide[0] == ascii && wide[1] == 0)
    }

    /// Compare against an ASCII string case-insensitively without allocation.
    ///
    /// Returns `false` if `other` contains non-ASCII characters.
    #[must_use]
    pub fn eq_ascii_ignore_case(&self, other: &str) -> bool {
        if !other.is_ascii() {
            return false;
        }
        if self.len() != other.len() {
            return false;
        }
        self.data
            .as_chunks::<2>()
            .0
            .iter()
            .zip(other.bytes())
            .all(|(wide, ascii)| wide[1] == 0 && wide[0].eq_ignore_ascii_case(&ascii))
    }

    /// Check if the string starts with an ASCII prefix.
    #[must_use]
    pub fn starts_with_ascii(&self, prefix: &str) -> bool {
        if !prefix.is_ascii() || self.len() < prefix.len() {
            return false;
        }
        self.data[..prefix.len() * 2]
            .as_chunks::<2>()
            .0
            .iter()
            .zip(prefix.bytes())
            .all(|(wide, ascii)| wide[0] == ascii && wide[1] == 0)
    }

    /// Check if the string ends with an ASCII suffix.
    #[must_use]
    pub fn ends_with_ascii(&self, suffix: &str) -> bool {
        if !suffix.is_ascii() || self.len() < suffix.len() {
            return false;
        }
        let start = self.data.len() - suffix.len() * 2;
        self.data[start..]
            .as_chunks::<2>()
            .0
            .iter()
            .zip(suffix.bytes())
            .all(|(wide, ascii)| wide[0] == ascii && wide[1] == 0)
    }

    /// Check if the string contains an ASCII substring.
    #[must_use]
    pub fn contains_ascii(&self, needle: &str) -> bool {
        if !needle.is_ascii() || self.len() < needle.len() {
            return false;
        }
        if needle.is_empty() {
            return true;
        }
        // Simple O(n*m) search — could be optimised
        let needle_bytes = needle.as_bytes();
        'outer: for i in 0..=(self.len() - needle.len()) {
            for (j, &ascii) in needle_bytes.iter().enumerate() {
                let idx = (i + j) * 2;
                if self.data[idx] != ascii || self.data[idx + 1] != 0 {
                    continue 'outer;
                }
            }
            return true;
        }
        false
    }
}

impl std::fmt::Debug for WideStrRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WideStrRef({:?})", self.to_string_lossy())
    }
}

impl std::fmt::Display for WideStrRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string_lossy())
    }
}

impl PartialEq for WideStrRef<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl Eq for WideStrRef<'_> {}

/// Note: comparing against non-ASCII `str` values requires a temporary UTF-8
/// allocation via [`decode_utf16()`](WideStrRef::decode_utf16). For hot paths
/// with non-ASCII strings, prefer calling `decode_utf16()` explicitly and
/// caching the result.
impl PartialEq<str> for WideStrRef<'_> {
    fn eq(&self, other: &str) -> bool {
        if other.is_ascii() {
            self.eq_ascii(other)
        } else {
            self.decode_utf16().is_ok_and(|s| s == other)
        }
    }
}

impl PartialEq<&str> for WideStrRef<'_> {
    fn eq(&self, other: &&str) -> bool {
        self == *other
    }
}

// =============================================================================
// AnsiStrRef - Zero-Copy Windows ANSI String
// =============================================================================

/// A borrowed Windows ANSI (code page 1252) string from an ETW event buffer.
///
/// This is a zero-copy wrapper that references the original event data.
/// Windows ANSI strings use the system's default code page, which is typically
/// Windows-1252 on Western systems.
///
/// # Example
///
/// ```no_run
/// # fn example(parser: &mut etw::EventParser) -> etw::Result<()> {
/// use etw::types::AnsiStrRef;
/// // Zero-copy access
/// let name: AnsiStrRef = parser.as_ref("ProcessName")?;
///
/// // Check if ASCII-only (fast path)
/// if name.is_ascii() {
///     let s = name.to_string_ascii().unwrap();
/// } else {
///     let s = name.to_string_cp1252();
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy)]
pub struct AnsiStrRef<'a> {
    /// Raw ANSI bytes (not including null terminator)
    data: &'a [u8],
}

impl<'a> AnsiStrRef<'a> {
    /// Create a new `AnsiStrRef` from raw bytes.
    ///
    /// The data should NOT include a null terminator.
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Create from raw bytes, stripping null terminator if present.
    #[must_use]
    pub fn from_raw_with_null(data: &'a [u8]) -> Self {
        let len = data.iter().position(|&b| b == 0).unwrap_or(data.len());
        Self { data: &data[..len] }
    }

    /// Returns the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.data
    }

    /// Returns the length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if the string is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns true if all bytes are ASCII (< 128).
    #[must_use]
    pub fn is_ascii(&self) -> bool {
        is_ascii_only(self.data)
    }

    /// Convert to String assuming ASCII-only content.
    ///
    /// Returns `None` if any byte is >= 128.
    #[must_use]
    pub fn to_string_ascii(&self) -> Option<String> {
        // SAFETY: is_ascii() verifies all bytes are ASCII, which is valid UTF-8.
        self.is_ascii()
            .then(|| unsafe { String::from_utf8_unchecked(self.data.to_vec()) })
    }

    /// Convert to String using Windows-1252 decoding.
    ///
    /// This is the correct way to decode Windows ANSI strings.
    /// It never fails - undefined bytes map to U+FFFD.
    #[must_use]
    pub fn to_string_cp1252(&self) -> String {
        decode_cp1252(self.data)
    }

    /// Convert to String, trying UTF-8 first, falling back to Windows-1252.
    ///
    /// This handles the common case where ANSI strings are actually ASCII/UTF-8,
    /// but correctly decodes true Windows-1252 content.
    #[must_use]
    pub fn to_string_lossy(&self) -> String {
        // Fast path: if all ASCII, it's valid UTF-8
        if self.is_ascii() {
            // SAFETY: ASCII is valid UTF-8
            return unsafe { String::from_utf8_unchecked(self.data.to_vec()) };
        }
        // Try UTF-8 first (some ANSI strings are actually UTF-8)
        if let Ok(s) = std::str::from_utf8(self.data) {
            return s.to_owned();
        }
        // Fall back to Windows-1252
        decode_cp1252(self.data)
    }

    /// Decode the bytes to a `String` using a specific Windows code page.
    ///
    /// Unlike [`to_string_lossy()`](Self::to_string_lossy), this method returns
    /// `Err` if any byte is invalid for `codepage` — no substitution occurs.
    ///
    /// Common values for `codepage`: `1252` (Windows-1252), `932` (Shift-JIS),
    /// `65001` (UTF-8), [`CP_ACP`](windows_sys::Win32::Globalization::CP_ACP) (system code page).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Win32Error`] if the bytes are not valid for `codepage`
    /// (e.g. `ERROR_NO_UNICODE_TRANSLATION` when an invalid byte sequence is
    /// encountered).
    ///
    /// # Example
    ///
    /// ```no_run
    /// use etw::AnsiStrRef;
    ///
    /// let bytes = b"caf\xe9"; // "café" in Latin-1 / CP1252
    /// let s = AnsiStrRef::new(bytes);
    /// let decoded = s.decode(1252)?;
    /// assert_eq!(decoded, "café");
    /// # Ok::<(), etw::Error>(())
    /// ```
    pub fn decode(&self, codepage: u32) -> Result<String> {
        use windows_sys::Win32::{
            Foundation::GetLastError,
            Globalization::{MB_ERR_INVALID_CHARS, MultiByteToWideChar},
        };

        if self.data.is_empty() {
            return Ok(String::new());
        }

        // Fast path: ASCII is valid in every code page and always valid UTF-8.
        if self.is_ascii() {
            // SAFETY: All bytes are < 128, so the slice is valid UTF-8.
            return Ok(unsafe { String::from_utf8_unchecked(self.data.to_vec()) });
        }

        // SAFETY: MultiByteToWideChar is a Win32 FFI call. Passing None for
        // the output buffer is the documented pattern for querying the required
        // UTF-16 buffer size without writing any data.
        let needed = unsafe {
            MultiByteToWideChar(
                codepage,
                MB_ERR_INVALID_CHARS,
                self.data.as_ptr(),
                self.data.len() as i32,
                std::ptr::null_mut(),
                0,
            )
        };

        if needed == 0 {
            // SAFETY: GetLastError is called immediately after the failed API
            // call, on the same thread, with no intervening Win32 calls.
            return Err(Error::from_win32(unsafe { GetLastError() }));
        }

        let mut buf = vec![0u16; needed as usize];

        // SAFETY: buf has `needed` elements, matching the size returned above.
        let written = unsafe {
            MultiByteToWideChar(
                codepage,
                MB_ERR_INVALID_CHARS,
                self.data.as_ptr(),
                self.data.len() as i32,
                buf.as_mut_ptr(),
                buf.len() as i32,
            )
        };

        if written == 0 {
            // SAFETY: GetLastError is called immediately after the failed API
            // call, on the same thread, with no intervening Win32 calls.
            return Err(Error::from_win32(unsafe { GetLastError() }));
        }

        String::from_utf16(&buf[..written as usize])
            .map_err(|e| Error::parse(format!("UTF-16 decode error: {e}")))
    }

    /// Compare against a string without allocation (ASCII only).
    #[must_use]
    pub fn eq_ascii(&self, other: &str) -> bool {
        if !other.is_ascii() {
            return false;
        }
        self.data == other.as_bytes()
    }

    /// Compare against a string case-insensitively (ASCII only).
    #[must_use]
    pub fn eq_ascii_ignore_case(&self, other: &str) -> bool {
        if !other.is_ascii() || self.len() != other.len() {
            return false;
        }
        self.data
            .iter()
            .zip(other.bytes())
            .all(|(&a, b)| a.eq_ignore_ascii_case(&b))
    }
}

impl std::fmt::Debug for AnsiStrRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AnsiStrRef({:?})", self.to_string_lossy())
    }
}

impl std::fmt::Display for AnsiStrRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string_lossy())
    }
}

impl PartialEq for AnsiStrRef<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl Eq for AnsiStrRef<'_> {}

/// Compares the bytes, so this holds exactly when the data *is* `other`'s UTF-8
/// encoding.
///
/// It deliberately does not decode through
/// [`to_string_lossy()`](AnsiStrRef::to_string_lossy), which would make it
/// inconsistent with [`PartialEq`] against another `AnsiStrRef`: that compares
/// bytes, while `to_string_lossy` tries UTF-8 and falls back to CP1252, so two
/// different byte strings can decode to the same text. `é` is `C3 A9` in UTF-8
/// and `E9` in CP1252 — decoding made both equal to `"é"` while they stayed
/// unequal to each other, which is not an equivalence relation, and `Eq` is
/// implemented for this type.
///
/// The cost is that genuinely CP1252-encoded data no longer equals its decoded
/// form. Decode it explicitly with [`decode()`](AnsiStrRef::decode) and compare
/// the `String` when that is what you mean, which also makes the code page a
/// choice rather than a guess.
impl PartialEq<str> for AnsiStrRef<'_> {
    fn eq(&self, other: &str) -> bool {
        self.data == other.as_bytes()
    }
}

impl PartialEq<&str> for AnsiStrRef<'_> {
    fn eq(&self, other: &&str) -> bool {
        self == *other
    }
}

// =============================================================================
// WideString - Owned UTF-16 String
// =============================================================================

/// An owned UTF-16 string for ETW Unicode data.
///
/// This is the owned equivalent of [`WideStrRef`], storing UTF-16 code units
/// in native Windows encoding. Useful when you need to own the string or pass
/// it to Windows APIs without UTF-16 to UTF-8 conversion.
///
/// # Example
///
/// ```no_run
/// # fn example(parser: &mut etw::EventParser) -> etw::Result<()> {
/// use etw::types::WideString;
///
/// // Get as owned UTF-16 (no UTF-8 conversion)
/// let name: WideString = parser.get("ProcessName")?;
///
/// // Convert to UTF-8 only when needed
/// println!("{}", name.to_string_lossy());
///
/// // Or use for Windows API calls directly
/// let wide_slice: &[u16] = name.as_slice();
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Default)]
pub struct WideString {
    data: Vec<u16>,
}

impl WideString {
    /// Create a new empty `WideString`.
    #[must_use]
    pub const fn new() -> Self {
        Self { data: Vec::new() }
    }

    /// Create a `WideString` from a `Vec<u16>`.
    #[must_use]
    pub const fn from_vec(data: Vec<u16>) -> Self {
        Self { data }
    }

    /// Create a `WideString` from raw UTF-16LE bytes.
    ///
    /// Strips null terminator if present.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return Self::new();
        }

        let byte_len = bytes.len();

        // Fast path: check if last code unit is null terminator.
        // When the exact size is known (e.g., from ETW property parsing),
        // the slice ends exactly at the null terminator — no scanning needed.
        // Requires even byte_len so copy_len is also even (matching u16 alignment).
        if byte_len >= 2 && byte_len.is_multiple_of(2) {
            let last_unit = u16::from_le_bytes([bytes[byte_len - 2], bytes[byte_len - 1]]);
            if last_unit == 0 {
                // Direct memory copy excluding null terminator.
                let copy_len = byte_len - 2;
                let char_count = copy_len / 2;
                let mut data = vec![0u16; char_count];
                #[expect(
                    clippy::semicolon_outside_block,
                    reason = "unsafe block is a statement, not an expression"
                )]
                // SAFETY: `copy_len` is even (byte_len is even, minus 2), so
                // `char_count * 2 == copy_len` — the destination has exactly enough
                // room. u16 is little-endian on x86_64 and aarch64, matching UTF-16LE
                // byte order.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        bytes.as_ptr(),
                        data.as_mut_ptr().cast::<u8>(),
                        copy_len,
                    );
                }
                return Self { data };
            }
        }

        // Slow path: scan for null terminator (handles unterminated strings
        // or odd-length input). Stops at the first null code unit.
        let mut data = Vec::with_capacity(byte_len / 2);
        let mut i = 0;
        while i + 1 < byte_len {
            let code_unit = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
            if code_unit == 0 {
                break;
            }
            data.push(code_unit);
            i += 2;
        }
        Self { data }
    }

    /// Create a `WideString` from a UTF-8 string.
    #[must_use]
    #[expect(
        clippy::should_implement_trait,
        reason = "infallible — FromStr would require Err = Infallible"
    )]
    pub fn from_str(s: &str) -> Self {
        Self {
            data: s.encode_utf16().collect(),
        }
    }

    /// Returns the UTF-16 code units as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[u16] {
        &self.data
    }

    /// Returns the number of UTF-16 code units.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if the string is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Decode the UTF-16 data into an owned `String`.
    ///
    /// Returns an error if the string contains invalid UTF-16.
    pub fn decode_utf16(&self) -> Result<String> {
        String::from_utf16(&self.data).map_err(|e| Error::parse(format!("Invalid UTF-16: {e}")))
    }

    /// Convert to a `String`, replacing invalid sequences with U+FFFD.
    #[must_use]
    pub fn to_string_lossy(&self) -> String {
        String::from_utf16_lossy(&self.data)
    }

    /// Convert to an owned [`OsString`](std::ffi::OsString) without loss.
    ///
    /// See [`WideStrRef::to_os_string`].
    #[must_use]
    pub fn to_os_string(&self) -> std::ffi::OsString {
        use std::os::windows::ffi::OsStringExt;
        std::ffi::OsString::from_wide(&self.data)
    }

    /// Borrow as a `WideStrRef`.
    #[must_use]
    pub const fn as_wide_str(&self) -> WideStrRef<'_> {
        // SAFETY: Vec<u16> is properly aligned and we're creating a byte view
        let bytes = unsafe {
            std::slice::from_raw_parts(self.data.as_ptr().cast::<u8>(), self.data.len() * 2)
        };
        WideStrRef::new(bytes)
    }

    /// Convert to a null-terminated vector for Windows API calls.
    #[must_use]
    pub fn to_null_terminated(&self) -> Vec<u16> {
        let mut result = self.data.clone();
        result.push(0);
        result
    }
}

impl std::fmt::Debug for WideString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WideString({:?})", self.to_string_lossy())
    }
}

impl std::fmt::Display for WideString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string_lossy())
    }
}

impl PartialEq for WideString {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl Eq for WideString {}

/// Decodes strictly, matching [`WideStrRef`]'s implementation.
///
/// Invalid UTF-16 compares unequal to everything rather than decoding lossily:
/// `to_string_lossy` maps every malformed sequence to the replacement character,
/// so two different payloads would both equal a string containing it while
/// comparing unequal to each other. Valid UTF-16 has exactly one decoding, so
/// this stays consistent with [`PartialEq`] against another `WideString`, which
/// compares code units.
impl PartialEq<str> for WideString {
    fn eq(&self, other: &str) -> bool {
        if other.is_ascii() {
            self.as_wide_str().eq_ascii(other)
        } else {
            self.decode_utf16().is_ok_and(|decoded| decoded == other)
        }
    }
}

impl From<WideStrRef<'_>> for WideString {
    fn from(s: WideStrRef<'_>) -> Self {
        Self::from_bytes(s.as_bytes())
    }
}

impl From<&str> for WideString {
    fn from(s: &str) -> Self {
        Self::from_str(s)
    }
}

impl From<String> for WideString {
    fn from(s: String) -> Self {
        Self::from_str(&s)
    }
}

// =============================================================================
// AnsiString - Owned ANSI String
// =============================================================================

/// An owned Windows ANSI string for ETW ANSI data.
///
/// This is the owned equivalent of [`AnsiStrRef`], storing raw bytes
/// typically encoded in Windows-1252.
///
/// Unlike `CString`, this type:
/// - Does NOT require null termination
/// - Allows interior null bytes
/// - Is designed for ETW's variable-length ANSI strings
///
/// # Example
///
/// ```no_run
/// # fn example(parser: &mut etw::EventParser) -> etw::Result<()> {
/// use etw::types::AnsiString;
///
/// // Get as owned ANSI bytes (no conversion)
/// let name: AnsiString = parser.get("Name")?;
///
/// // Convert to UTF-8 only when needed
/// println!("{}", name.to_string_lossy());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Default)]
pub struct AnsiString {
    data: Vec<u8>,
}

impl AnsiString {
    /// Create a new empty `AnsiString`.
    #[must_use]
    pub const fn new() -> Self {
        Self { data: Vec::new() }
    }

    /// Create an `AnsiString` from a `Vec<u8>`.
    #[must_use]
    pub const fn from_vec(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Create an `AnsiString` from raw bytes.
    ///
    /// Stops at the first null byte (C-string semantics). Use
    /// [`from_bytes_with_interior_nulls`](Self::from_bytes_with_interior_nulls)
    /// if the data may contain embedded nulls.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        Self {
            data: bytes[..end].to_vec(),
        }
    }

    /// Create an `AnsiString` from raw bytes, keeping interior nulls.
    ///
    /// Only strips trailing null terminator.
    #[must_use]
    pub fn from_bytes_with_interior_nulls(bytes: &[u8]) -> Self {
        let end = bytes.len();
        // Only strip trailing null
        let end = if end > 0 && bytes[end - 1] == 0 {
            end - 1
        } else {
            end
        };
        Self {
            data: bytes[..end].to_vec(),
        }
    }

    /// Returns the raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Returns the length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if the string is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns true if all bytes are ASCII (< 128).
    #[must_use]
    pub fn is_ascii(&self) -> bool {
        is_ascii_only(&self.data)
    }

    /// Returns true if there are no interior null bytes.
    #[must_use]
    pub fn has_no_interior_nulls(&self) -> bool {
        !self.data.contains(&0)
    }

    /// Convert to `String` assuming ASCII-only content.
    ///
    /// Returns `None` if any byte is >= 128.
    #[must_use]
    pub fn to_string_ascii(&self) -> Option<String> {
        // SAFETY: is_ascii() verifies all bytes are ASCII, which is valid UTF-8.
        self.is_ascii()
            .then(|| unsafe { String::from_utf8_unchecked(self.data.clone()) })
    }

    /// Convert to `String` using Windows-1252 decoding.
    #[must_use]
    pub fn to_string_cp1252(&self) -> String {
        decode_cp1252(&self.data)
    }

    /// Decode the bytes to a `String` using a specific Windows code page.
    ///
    /// Unlike [`to_string_lossy()`](Self::to_string_lossy), this method returns
    /// `Err` if any byte is invalid for `codepage` — no substitution occurs.
    ///
    /// Common values for `codepage`: `1252` (Windows-1252), `932` (Shift-JIS),
    /// `65001` (UTF-8), [`CP_ACP`](windows_sys::Win32::Globalization::CP_ACP) (system code page).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Win32Error`] if the bytes are not valid for `codepage`
    /// (e.g. `ERROR_NO_UNICODE_TRANSLATION` when an invalid byte sequence is
    /// encountered).
    pub fn decode(&self, codepage: u32) -> Result<String> {
        self.as_ansi_str().decode(codepage)
    }

    /// Convert to `String`, trying UTF-8 first, falling back to Windows-1252.
    #[must_use]
    pub fn to_string_lossy(&self) -> String {
        // Fast path: if all ASCII, it's valid UTF-8
        if self.is_ascii() {
            // SAFETY: ASCII is valid UTF-8
            return unsafe { String::from_utf8_unchecked(self.data.clone()) };
        }
        // Try UTF-8 first (some ANSI strings are actually UTF-8)
        if let Ok(s) = std::str::from_utf8(&self.data) {
            return s.to_owned();
        }
        // Fall back to Windows-1252
        decode_cp1252(&self.data)
    }

    /// Borrow as an `AnsiStrRef`.
    #[must_use]
    pub fn as_ansi_str(&self) -> AnsiStrRef<'_> {
        AnsiStrRef::new(&self.data)
    }

    /// Try to convert to a `CString`.
    ///
    /// Returns `None` if the string contains interior null bytes.
    #[must_use]
    pub fn to_cstring(&self) -> Option<std::ffi::CString> {
        std::ffi::CString::new(self.data.clone()).ok()
    }
}

impl std::fmt::Debug for AnsiString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AnsiString({:?})", self.to_string_lossy())
    }
}

impl std::fmt::Display for AnsiString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string_lossy())
    }
}

impl PartialEq for AnsiString {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl Eq for AnsiString {}

/// Compares the bytes, for the reasons given on [`AnsiStrRef`]'s implementation.
impl PartialEq<str> for AnsiString {
    fn eq(&self, other: &str) -> bool {
        self.data == other.as_bytes()
    }
}

impl From<AnsiStrRef<'_>> for AnsiString {
    fn from(s: AnsiStrRef<'_>) -> Self {
        Self {
            data: s.as_bytes().to_vec(),
        }
    }
}

impl From<&[u8]> for AnsiString {
    fn from(bytes: &[u8]) -> Self {
        Self::from_bytes(bytes)
    }
}

/// Windows SYSTEMTIME structure (16 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemTime {
    /// Year (1601-30827).
    pub year: u16,
    /// Month (1-12).
    pub month: u16,
    /// Day of the week (0 = Sunday, 6 = Saturday).
    pub day_of_week: u16,
    /// Day of the month (1-31).
    pub day: u16,
    /// Hour (0-23).
    pub hour: u16,
    /// Minute (0-59).
    pub minute: u16,
    /// Second (0-59).
    pub second: u16,
    /// Milliseconds (0-999).
    pub milliseconds: u16,
}

impl SystemTime {
    /// Parses a 16-byte SYSTEMTIME from a little-endian byte slice.
    ///
    /// The layout is 8 consecutive `u16` fields in little-endian order:
    /// year, month, day_of_week, day, hour, minute, second, milliseconds.
    ///
    /// Returns `None` if `data` is shorter than 16 bytes.
    #[must_use]
    #[expect(
        clippy::same_name_method,
        reason = "different signature from the FromBytes trait"
    )]
    pub const fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }
        Some(Self {
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
}

impl std::fmt::Display for SystemTime {
    /// Formats as ISO 8601: `YYYY-MM-DDThh:mm:ss.mmm`
    ///
    /// No timezone suffix is appended — `SYSTEMTIME` has no inherent timezone.
    /// Callers should verify with the specific ETW provider whether values are
    /// UTC or local time.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}",
            self.year, self.month, self.day, self.hour, self.minute, self.second, self.milliseconds,
        )
    }
}

/// A provider, class, or activity GUID.
///
/// `Display` formats the GUID in the standard lowercase format (e.g.,
/// "12345678-1234-5678-abcd-ef1234567890"). Construct from a `u128` literal
/// with [`Guid::from_u128`]; convert to other GUID types via [`Guid::to_u128`].
///
/// # Example
///
/// ```
/// use etw::Guid;
///
/// let guid = Guid::from_u128(0xb675ec37_bdb6_4648_bc92_f3fdc74d3ca2);
/// assert_eq!(format!("{}", guid), "b675ec37-bdb6-4648-bc92-f3fdc74d3ca2");
/// ```
// Self-contained on purpose: no `windows-sys` type appears in the definition,
// so a `windows-sys` major bump is not a breaking change for this crate, and
// PartialEq/Eq derive structurally — which is what lets constants of this type
// be used in `match` patterns. Interop with `windows`(-sys) GUIDs goes through
// `u128` publicly and `from_sys`/`to_sys`/`as_sys` inside the crate.
// repr(C) with these fields is layout-identical to the Win32 GUID for
// in-place buffer reads. The u128 mapping is the canonical one: data1 in bits
// 127-96, data2 in 95-80, data3 in 79-64, and data4 as big-endian bytes in
// 63-0.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

impl Guid {
    /// Creates a new Guid from a u128 value.
    pub const fn from_u128(value: u128) -> Self {
        Self::from_values(
            (value >> 96) as u32,
            (value >> 80) as u16,
            (value >> 64) as u16,
            (value as u64).to_be_bytes(),
        )
    }

    /// Creates a new Guid from components.
    pub const fn from_values(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Self {
        Self {
            data1,
            data2,
            data3,
            data4,
        }
    }

    /// Returns the GUID as a `u128` value.
    ///
    /// This is the lossless interop escape hatch: convert to any GUID type
    /// (e.g. `windows::core::GUID::from_u128`) without version coupling.
    #[must_use]
    pub const fn to_u128(self) -> u128 {
        ((self.data1 as u128) << 96)
            | ((self.data2 as u128) << 80)
            | ((self.data3 as u128) << 64)
            | (u64::from_be_bytes(self.data4) as u128)
    }

    /// Crate-internal seam from the windows-sys FFI type.
    pub(crate) const fn from_sys(g: windows_sys::core::GUID) -> Self {
        Self::from_values(g.data1, g.data2, g.data3, g.data4)
    }

    /// Crate-internal seam to the windows-sys FFI type, by value.
    pub(crate) const fn to_sys(self) -> windows_sys::core::GUID {
        windows_sys::core::GUID {
            data1: self.data1,
            data2: self.data2,
            data3: self.data3,
            data4: self.data4,
        }
    }

    /// Crate-internal seam to the windows-sys FFI type, by reference — for
    /// FFI parameters that want a `*const GUID` without a copy.
    pub(crate) const fn as_sys(&self) -> &windows_sys::core::GUID {
        // SAFETY: `Guid` and `GUID` are field-for-field identical repr(C)
        // layouts, so the reference cast is sound.
        unsafe { &*std::ptr::from_ref(self).cast::<windows_sys::core::GUID>() }
    }
}

impl std::fmt::Debug for Guid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Guid({self})")
    }
}

impl std::fmt::Display for Guid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let g = self;
        write!(
            f,
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            g.data1,
            g.data2,
            g.data3,
            g.data4[0],
            g.data4[1],
            g.data4[2],
            g.data4[3],
            g.data4[4],
            g.data4[5],
            g.data4[6],
            g.data4[7]
        )
    }
}

/// A borrowed reference to a Security Identifier (SID).
///
/// This is a zero-copy wrapper around raw SID bytes that provides
/// access to both the raw bytes and string conversion.
///
/// # Example
///
/// ```no_run
/// # use etw::{RawEvent, SidRef};
/// # fn example(event: &RawEvent) {
/// if let Ok(sid) = event.sid() {
///     println!("SID: {sid}");
///     println!("Raw bytes: {:?}", sid.as_bytes());
/// }
/// # }
/// ```
#[derive(Clone, Copy)]
pub struct SidRef<'a>(&'a [u8]);

impl<'a> SidRef<'a> {
    /// Wrap raw SID bytes.
    ///
    /// Returns `None` if the bytes are too short to contain a valid SID header
    /// or the revision is not 1 (the only valid SID revision defined by Windows).
    #[must_use]
    pub fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        // SID_REVISION (1) is the only valid revision per the Windows SDK.
        if data[0] != 1 {
            return None;
        }
        let sub_auth_count = data[1] as usize;
        // SID_MAX_SUB_AUTHORITIES = 15 per the Windows SDK.
        if sub_auth_count > 15 {
            return None;
        }
        let expected_len = 8 + sub_auth_count * 4;
        if data.len() < expected_len {
            return None;
        }
        Some(Self(&data[..expected_len]))
    }

    /// Returns the raw SID bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.0
    }

    /// Returns the SID revision number.
    #[must_use]
    pub const fn revision(&self) -> u8 {
        self.0[0]
    }

    /// Returns the number of sub-authorities.
    #[must_use]
    pub const fn sub_authority_count(&self) -> u8 {
        self.0[1]
    }

    /// Returns the identifier authority (6 bytes).
    #[must_use]
    pub fn authority(&self) -> &[u8; 6] {
        #[expect(clippy::expect_used, reason = "infallible: SidRef guarantees ≥8 bytes")]
        self.0[2..8]
            .try_into()
            .expect("SidRef guarantees at least 8 bytes")
    }

    /// Returns the sub-authority at the given index.
    #[must_use]
    pub const fn sub_authority(&self, index: usize) -> Option<u32> {
        if index >= self.sub_authority_count() as usize {
            return None;
        }
        let offset = 8 + index * 4;
        Some(u32::from_le_bytes([
            self.0[offset],
            self.0[offset + 1],
            self.0[offset + 2],
            self.0[offset + 3],
        ]))
    }

    /// Converts to an owned [`Sid`].
    #[must_use]
    pub fn to_owned(&self) -> Sid {
        let mut sub_authorities = Vec::with_capacity(self.sub_authority_count() as usize);
        for i in 0..self.sub_authority_count() as usize {
            #[expect(
                clippy::expect_used,
                reason = "infallible: i < sub_authority_count() by construction"
            )]
            sub_authorities.push(
                self.sub_authority(i)
                    .expect("sub_authority index within sub_authority_count"),
            );
        }
        Sid {
            revision: self.revision(),
            authority: *self.authority(),
            sub_authorities,
        }
    }
}

/// Longest text a SID accepted by [`SidRef::new`] can render to.
///
/// `"S-"`, a revision of up to 3 digits, `"-"`, the 15 digits of a 48-bit authority,
/// and the SID maximum of 15 sub-authorities, each a `"-"` and up to 10 digits.
/// Rendering anything longer falls back to the formatter, so this is a fast-path
/// budget rather than a correctness limit.
const SID_TEXT_CAPACITY: usize = 2 + 3 + 1 + 15 + 15 * 11;

/// A stack buffer that renders a SID without touching the formatting machinery.
///
/// `write!("-{sub}")` per sub-authority costs a `core::fmt::Arguments` build, a
/// `Formatter::write_fmt` dispatch and a trip through the generic integer `Display`
/// path — seven times over for a typical `S-1-5-21-a-b-c-d`. Encoding the digits
/// directly and emitting one `write_str` avoids all of it.
struct SidText {
    buf: [u8; SID_TEXT_CAPACITY],
    len: usize,
}

impl SidText {
    const fn new() -> Self {
        Self {
            buf: [0; SID_TEXT_CAPACITY],
            len: 0,
        }
    }

    /// Append one ASCII byte, or return `None` if the buffer is full.
    fn push(&mut self, byte: u8) -> Option<()> {
        *self.buf.get_mut(self.len)? = byte;
        self.len += 1;
        Some(())
    }

    /// Append `value` in decimal, or return `None` if it does not fit.
    fn push_decimal(&mut self, value: u64) -> Option<()> {
        // 20 digits is the widest a u64 can be, so the reversal buffer never overflows.
        let mut digits = [0u8; 20];
        let mut count = 0;
        let mut rest = value;
        loop {
            // `rest % 10` is 0..=9, so its least significant byte is the digit itself.
            let digit = (rest % 10).to_le_bytes()[0];
            digits[count] = b'0' + digit;
            count += 1;
            rest /= 10;
            if rest == 0 {
                break;
            }
        }
        for i in (0..count).rev() {
            self.push(digits[i])?;
        }
        Some(())
    }

    /// Render a whole SID, or return `None` if it does not fit.
    fn push_sid(
        &mut self,
        revision: u8,
        authority: u64,
        subs: impl Iterator<Item = u32>,
    ) -> Option<()> {
        self.push(b'S')?;
        self.push(b'-')?;
        self.push_decimal(u64::from(revision))?;
        self.push(b'-')?;
        self.push_decimal(authority)?;
        for sub in subs {
            self.push(b'-')?;
            self.push_decimal(u64::from(sub))?;
        }
        Some(())
    }

    /// Borrow the rendered text.
    fn as_str(&self) -> Option<&str> {
        str::from_utf8(self.buf.get(..self.len)?).ok()
    }
}

impl std::fmt::Display for SidRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let auth = self.authority();
        let authority_value =
            u64::from_be_bytes([0, 0, auth[0], auth[1], auth[2], auth[3], auth[4], auth[5]]);

        let count = self.sub_authority_count() as usize;
        let mut text = SidText::new();
        if text
            .push_sid(
                self.revision(),
                authority_value,
                (0..count).filter_map(|i| self.sub_authority(i)),
            )
            .is_some()
            && let Some(rendered) = text.as_str()
        {
            return f.write_str(rendered);
        }

        // `SidRef::new` bounds both the revision and the sub-authority count, so the
        // buffer always suffices in practice; this keeps output correct regardless.
        write!(f, "S-{}-{}", self.revision(), authority_value)?;
        for i in 0..count {
            if let Some(sub) = self.sub_authority(i) {
                write!(f, "-{sub}")?;
            }
        }
        Ok(())
    }
}

impl std::fmt::Debug for SidRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SidRef(\"{self}\")")
    }
}

/// An owned Security Identifier (SID).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sid {
    /// SID revision level (always 1).
    pub revision: u8,
    /// 48-bit identifier authority value.
    pub authority: [u8; 6],
    /// Sub-authority values.
    pub sub_authorities: Vec<u32>,
}

impl Sid {
    /// Parse a SID from raw bytes.
    ///
    /// Returns `None` if the bytes are too short or malformed.
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        SidRef::new(data).map(|r| r.to_owned())
    }
}

impl std::fmt::Display for Sid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let authority_value = u64::from_be_bytes([
            0,
            0,
            self.authority[0],
            self.authority[1],
            self.authority[2],
            self.authority[3],
            self.authority[4],
            self.authority[5],
        ]);
        let mut text = SidText::new();
        if text
            .push_sid(
                self.revision,
                authority_value,
                self.sub_authorities.iter().copied(),
            )
            .is_some()
            && let Some(rendered) = text.as_str()
        {
            return f.write_str(rendered);
        }

        // The fields are public, so a `Sid` may hold more sub-authorities or a wider
        // revision than the SID specification allows. Those still format correctly,
        // just without the fast path.
        write!(f, "S-{}-{}", self.revision, authority_value)?;
        for sub in &self.sub_authorities {
            write!(f, "-{sub}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test-only assertions"
)]
mod tests {
    use super::*;

    #[test]
    fn wide_string_from_bytes_empty() {
        let s = WideString::from_bytes(&[]);
        assert!(s.is_empty());
    }

    #[test]
    fn wide_string_from_bytes_null_terminated() {
        // "AB\0" in UTF-16LE = [0x41, 0x00, 0x42, 0x00, 0x00, 0x00]
        let bytes = [0x41u8, 0x00, 0x42, 0x00, 0x00, 0x00];
        let s = WideString::from_bytes(&bytes);
        assert_eq!(s.as_slice(), &[0x0041, 0x0042]);
    }

    #[test]
    fn wide_string_from_bytes_no_terminator() {
        // "AB" without null terminator
        let bytes = [0x41u8, 0x00, 0x42, 0x00];
        let s = WideString::from_bytes(&bytes);
        assert_eq!(s.as_slice(), &[0x0041, 0x0042]);
    }

    #[test]
    fn wide_string_from_bytes_odd_length_no_overflow() {
        // Odd-length input must not cause heap overflow.
        // 5 bytes: "A\0" + trailing 0x00 byte (odd).
        let bytes = [0x41u8, 0x00, 0x00, 0x00, 0x00];
        let s = WideString::from_bytes(&bytes);
        // Slow path: reads [0x41, 0x00] = 'A', then [0x00, 0x00] = null → stops.
        assert_eq!(s.as_slice(), &[0x0041]);
    }

    #[test]
    fn wide_string_from_bytes_odd_length_three_bytes() {
        // 3 bytes: [0x00, 0x00, 0x00] — odd length, last two bytes are null.
        // Must fall through to slow path, not overflow.
        let bytes = [0x00u8, 0x00, 0x00];
        let s = WideString::from_bytes(&bytes);
        // Slow path: reads [0x00, 0x00] = null → stops immediately.
        assert!(s.is_empty());
    }

    #[test]
    fn wide_string_from_bytes_single_byte() {
        // 1 byte: too short for any code unit.
        let bytes = [0x41u8];
        let s = WideString::from_bytes(&bytes);
        assert!(s.is_empty());
    }

    // =========================================================================
    // WideStrRef comparison methods
    // =========================================================================

    fn make_wide_str(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn wide_str_ref_eq_ascii_match() {
        let bytes = make_wide_str("hello");
        let w = WideStrRef::new(&bytes);
        assert!(w.eq_ascii("hello"));
    }

    #[test]
    fn wide_str_ref_eq_ascii_mismatch() {
        let bytes = make_wide_str("hello");
        let w = WideStrRef::new(&bytes);
        assert!(!w.eq_ascii("world"));
    }

    #[test]
    fn wide_str_ref_eq_ascii_length_mismatch() {
        let bytes = make_wide_str("hi");
        let w = WideStrRef::new(&bytes);
        assert!(!w.eq_ascii("hello"));
    }

    #[test]
    fn wide_str_ref_eq_ascii_empty() {
        let w = WideStrRef::new(&[]);
        assert!(w.eq_ascii(""));
        assert!(!w.eq_ascii("x"));
    }

    #[test]
    fn wide_str_ref_eq_ascii_ignore_case() {
        let bytes = make_wide_str("Hello");
        let w = WideStrRef::new(&bytes);
        assert!(w.eq_ascii_ignore_case("HELLO"));
        assert!(w.eq_ascii_ignore_case("hello"));
        assert!(!w.eq_ascii_ignore_case("world"));
    }

    #[test]
    fn wide_str_ref_starts_with_ascii() {
        let bytes = make_wide_str("hello world");
        let w = WideStrRef::new(&bytes);
        assert!(w.starts_with_ascii("hello"));
        assert!(w.starts_with_ascii(""));
        assert!(!w.starts_with_ascii("world"));
        assert!(!w.starts_with_ascii("hello world and more"));
    }

    #[test]
    fn wide_str_ref_ends_with_ascii() {
        let bytes = make_wide_str("hello world");
        let w = WideStrRef::new(&bytes);
        assert!(w.ends_with_ascii("world"));
        assert!(w.ends_with_ascii(""));
        assert!(!w.ends_with_ascii("hello"));
        assert!(!w.ends_with_ascii("this is longer than the string"));
    }

    #[test]
    fn wide_str_ref_contains_ascii() {
        let bytes = make_wide_str("hello world");
        let w = WideStrRef::new(&bytes);
        assert!(w.contains_ascii("lo wo"));
        assert!(w.contains_ascii("hello"));
        assert!(w.contains_ascii("world"));
        assert!(w.contains_ascii(""));
        assert!(!w.contains_ascii("xyz"));
    }

    #[test]
    fn wide_str_ref_ascii_methods_reject_non_ascii_other() {
        let bytes = make_wide_str("hello");
        let w = WideStrRef::new(&bytes);
        // Non-ASCII `other` always returns false (no allocation, no decode).
        assert!(!w.eq_ascii("héllo"));
        assert!(!w.eq_ascii_ignore_case("héllo"));
        assert!(!w.contains_ascii("héllo"));
        assert!(!w.starts_with_ascii("héllo"));
        assert!(!w.ends_with_ascii("héllo"));
    }

    #[test]
    fn wide_str_ref_contains_ascii_needle_longer_than_haystack() {
        let bytes = make_wide_str("hi");
        let w = WideStrRef::new(&bytes);
        assert!(!w.contains_ascii("hello world"));
    }

    // =========================================================================
    // AnsiStrRef / AnsiString decode paths
    // =========================================================================

    #[test]
    fn ansi_str_ref_ascii_fast_path() {
        let data = b"hello world";
        let s = AnsiStrRef::new(data);
        assert!(s.is_ascii());
        assert_eq!(s.to_string_lossy(), "hello world");
    }

    #[test]
    fn ansi_str_ref_valid_utf8_non_ascii() {
        // UTF-8 encoded "café" — the 'é' is 0xC3 0xA9
        let data = "café".as_bytes();
        let s = AnsiStrRef::new(data);
        assert!(!s.is_ascii());
        assert_eq!(s.to_string_lossy(), "café");
    }

    #[test]
    fn ansi_str_ref_cp1252_fallback() {
        // 0x80 = Euro sign in CP1252, which is not valid UTF-8 (bare continuation byte)
        let data = &[0x48, 0x80]; // "H" + Euro sign
        let s = AnsiStrRef::new(data);
        assert!(!s.is_ascii());
        assert_eq!(s.to_string_lossy(), "H\u{20AC}");
    }

    #[test]
    fn ansi_str_ref_cp1252_undefined_byte() {
        // 0x81 is undefined in CP1252, should map to U+FFFD replacement character.
        let data = &[0x81];
        let s = AnsiStrRef::new(data);
        assert_eq!(s.to_string_lossy(), "\u{FFFD}");
    }

    #[test]
    fn ansi_str_ref_to_string_ascii() {
        let data = b"ASCII";
        let s = AnsiStrRef::new(data);
        assert_eq!(s.to_string_ascii(), Some("ASCII".to_owned()));

        let non_ascii = &[0x80];
        let s2 = AnsiStrRef::new(non_ascii);
        assert_eq!(s2.to_string_ascii(), None);
    }

    #[test]
    fn ansi_str_ref_to_string_cp1252() {
        // 0xA9 = © in both Latin-1 and CP1252
        let data = &[0xA9];
        let s = AnsiStrRef::new(data);
        assert_eq!(s.to_string_cp1252(), "\u{00A9}");
    }

    #[test]
    fn ansi_string_to_string_lossy_delegates() {
        let owned = AnsiString::from_bytes(&[0x48, 0x65, 0x6C, 0x6C, 0x6F]); // "Hello"
        assert_eq!(owned.to_string_lossy(), "Hello");

        let owned_cp = AnsiString::from_bytes(&[0x93]); // Left double quotation mark in CP1252
        assert_eq!(owned_cp.to_string_lossy(), "\u{201C}");
    }

    #[test]
    fn ansi_str_ref_eq_ascii_methods() {
        let s = AnsiStrRef::new(b"hello");
        assert!(s.eq_ascii("hello"));
        assert!(!s.eq_ascii("world"));
        assert!(s.eq_ascii_ignore_case("HELLO"));
        assert!(!s.eq_ascii_ignore_case("WORLD"));

        // Length mismatch in eq_ascii_ignore_case
        assert!(!s.eq_ascii_ignore_case("hi"));

        // Non-ASCII `other` short-circuits to false on both methods.
        assert!(!s.eq_ascii("héllo"));
        assert!(!s.eq_ascii_ignore_case("héllo"));
    }

    #[test]
    fn ansi_string_to_string_lossy_utf8_fast_path() {
        // UTF-8 "café" — bytes are valid UTF-8 but not pure ASCII.
        // The fast path returns the UTF-8 directly without CP1252 fallback.
        let s = AnsiString::from_bytes("café".as_bytes());
        assert_eq!(s.to_string_lossy(), "café");
    }

    #[test]
    fn ansi_str_ref_decode_ascii_fast_path() {
        // ASCII is valid in every code page; no Win32 call needed.
        let s = AnsiStrRef::new(b"hello");
        assert_eq!(s.decode(1252).unwrap(), "hello");
        assert_eq!(s.decode(65001).unwrap(), "hello");
        assert_eq!(s.decode(0).unwrap(), "hello");
    }

    #[test]
    fn ansi_str_ref_decode_empty() {
        let s = AnsiStrRef::new(&[]);
        assert_eq!(s.decode(1252).unwrap(), "");
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls MultiByteToWideChar (Win32)")]
    fn ansi_str_ref_decode_cp1252() {
        // 0xA9 = © in CP1252
        let s = AnsiStrRef::new(&[0xA9]);
        assert_eq!(s.decode(1252).unwrap(), "\u{00A9}");
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls MultiByteToWideChar (Win32)")]
    fn ansi_str_ref_decode_invalid_utf8_as_utf8_fails() {
        // 0xA9 is not valid UTF-8 (bare continuation byte), so CP65001 must fail.
        let s = AnsiStrRef::new(&[0xA9]);
        assert!(s.decode(65001).is_err());
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls MultiByteToWideChar (Win32)")]
    fn ansi_string_decode_delegates() {
        let owned = AnsiString::from_bytes(&[0xA9]);
        assert_eq!(owned.decode(1252).unwrap(), "\u{00A9}");
    }

    #[test]
    fn ansi_str_ref_empty() {
        let s = AnsiStrRef::new(&[]);
        assert!(s.is_empty());
        assert!(s.is_ascii());
        assert_eq!(s.to_string_lossy(), "");
    }

    // =========================================================================
    // TdhInType::fixed_size
    // =========================================================================

    #[test]
    fn tdh_in_type_fixed_sizes() {
        // 1-byte types
        assert_eq!(TdhInType::Int8.fixed_size(8), Some(1));
        assert_eq!(TdhInType::UInt8.fixed_size(8), Some(1));
        assert_eq!(TdhInType::AnsiChar.fixed_size(8), Some(1));

        // 2-byte types
        assert_eq!(TdhInType::Int16.fixed_size(8), Some(2));
        assert_eq!(TdhInType::UInt16.fixed_size(8), Some(2));
        assert_eq!(TdhInType::UnicodeChar.fixed_size(8), Some(2));

        // 4-byte types
        assert_eq!(TdhInType::Int32.fixed_size(8), Some(4));
        assert_eq!(TdhInType::UInt32.fixed_size(8), Some(4));
        assert_eq!(TdhInType::HexInt32.fixed_size(8), Some(4));
        assert_eq!(TdhInType::Boolean.fixed_size(8), Some(4));
        assert_eq!(TdhInType::Float.fixed_size(8), Some(4));

        // 8-byte types
        assert_eq!(TdhInType::Int64.fixed_size(8), Some(8));
        assert_eq!(TdhInType::UInt64.fixed_size(8), Some(8));
        assert_eq!(TdhInType::HexInt64.fixed_size(8), Some(8));
        assert_eq!(TdhInType::FileTime.fixed_size(8), Some(8));
        assert_eq!(TdhInType::Double.fixed_size(8), Some(8));

        // 16-byte types
        assert_eq!(TdhInType::Guid.fixed_size(8), Some(16));
        assert_eq!(TdhInType::SystemTime.fixed_size(8), Some(16));

        // Pointer-sized types
        assert_eq!(TdhInType::Pointer.fixed_size(8), Some(8));
        assert_eq!(TdhInType::Pointer.fixed_size(4), Some(4));
        assert_eq!(TdhInType::SizeT.fixed_size(8), Some(8));
        assert_eq!(TdhInType::SizeT.fixed_size(4), Some(4));

        // Variable-length types
        assert_eq!(TdhInType::UnicodeString.fixed_size(8), None);
        assert_eq!(TdhInType::AnsiString.fixed_size(8), None);
        assert_eq!(TdhInType::Binary.fixed_size(8), None);
        assert_eq!(TdhInType::Sid.fixed_size(8), None);
        assert_eq!(TdhInType::HexDump.fixed_size(8), None);
        assert_eq!(TdhInType::Null.fixed_size(8), None);
        assert_eq!(TdhInType::Unknown(999).fixed_size(8), None);
    }

    // =========================================================================
    // Guid Display
    // =========================================================================

    #[test]
    fn guid_display_format() {
        let guid = Guid::from_sys(windows_sys::core::GUID {
            data1: 0x6B20C94B,
            data2: 0xD39C,
            data3: 0x4FAE,
            data4: [0xAE, 0x15, 0x29, 0xC6, 0x21, 0x89, 0x9F, 0x1C],
        });
        assert_eq!(format!("{guid}"), "6b20c94b-d39c-4fae-ae15-29c621899f1c");
    }

    #[test]
    fn guid_display_zeroes() {
        let guid = Guid::from_sys(windows_sys::core::GUID {
            data1: 0,
            data2: 0,
            data3: 0,
            data4: [0; 8],
        });
        assert_eq!(format!("{guid}"), "00000000-0000-0000-0000-000000000000");
    }

    // =========================================================================
    // SystemTime::from_bytes and Display
    // =========================================================================

    #[test]
    fn system_time_from_bytes_valid() {
        // 2025-03-15T14:30:45.123 (Saturday = day_of_week 6)
        #[rustfmt::skip]
        let bytes: [u8; 16] = [
            0xE9, 0x07, // year: 2025
            0x03, 0x00, // month: 3
            0x06, 0x00, // day_of_week: 6
            0x0F, 0x00, // day: 15
            0x0E, 0x00, // hour: 14
            0x1E, 0x00, // minute: 30
            0x2D, 0x00, // second: 45
            0x7B, 0x00, // milliseconds: 123
        ];
        let st = SystemTime::from_bytes(&bytes).expect("valid 16 bytes");
        assert_eq!(st.year, 2025);
        assert_eq!(st.month, 3);
        assert_eq!(st.day_of_week, 6);
        assert_eq!(st.day, 15);
        assert_eq!(st.hour, 14);
        assert_eq!(st.minute, 30);
        assert_eq!(st.second, 45);
        assert_eq!(st.milliseconds, 123);
    }

    #[test]
    fn system_time_display() {
        let st = SystemTime {
            year: 2025,
            month: 3,
            day_of_week: 6,
            day: 15,
            hour: 14,
            minute: 30,
            second: 45,
            milliseconds: 123,
        };
        assert_eq!(format!("{st}"), "2025-03-15T14:30:45.123");
    }

    #[test]
    fn system_time_display_zero_padded() {
        let st = SystemTime {
            year: 1,
            month: 1,
            day_of_week: 0,
            day: 1,
            hour: 0,
            minute: 0,
            second: 0,
            milliseconds: 0,
        };
        assert_eq!(format!("{st}"), "0001-01-01T00:00:00.000");
    }

    #[test]
    fn system_time_from_bytes_too_short() {
        assert!(SystemTime::from_bytes(&[0u8; 15]).is_none());
        assert!(SystemTime::from_bytes(&[]).is_none());
    }

    // =========================================================================
    // SidRef / Sid parsing and Display
    // =========================================================================

    #[test]
    fn sid_ref_well_known_local_system() {
        // S-1-5-18 (Local System)
        // Revision=1, SubAuthCount=1, Authority=0x000000000005, SubAuth[0]=18
        #[rustfmt::skip]
        let bytes: [u8; 12] = [
            0x01,                   // revision
            0x01,                   // sub-authority count
            0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // authority (NT Authority = 5)
            0x12, 0x00, 0x00, 0x00, // sub-authority 0 = 18
        ];
        let sid = SidRef::new(&bytes).expect("valid SID");
        assert_eq!(sid.revision(), 1);
        assert_eq!(sid.sub_authority_count(), 1);
        assert_eq!(sid.sub_authority(0), Some(18));
        assert_eq!(sid.sub_authority(1), None);
        assert_eq!(format!("{sid}"), "S-1-5-18");
    }

    #[test]
    fn sid_ref_multiple_sub_authorities() {
        // S-1-5-21-100-200-300-1000 (typical user SID structure)
        #[rustfmt::skip]
        let bytes: [u8; 24] = [
            0x01,                   // revision
            0x04,                   // sub-authority count = 4
            0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // authority = 5
            0x15, 0x00, 0x00, 0x00, // sub-auth 0 = 21
            0x64, 0x00, 0x00, 0x00, // sub-auth 1 = 100
            0xC8, 0x00, 0x00, 0x00, // sub-auth 2 = 200
            0x2C, 0x01, 0x00, 0x00, // sub-auth 3 = 300
        ];
        let sid = SidRef::new(&bytes).expect("valid SID");
        assert_eq!(format!("{sid}"), "S-1-5-21-100-200-300");
    }

    #[test]
    fn sid_ref_too_short_header() {
        assert!(SidRef::new(&[0x01, 0x01, 0x00]).is_none());
        assert!(SidRef::new(&[]).is_none());
    }

    #[test]
    fn sid_ref_truncated_sub_authorities() {
        // Claims 2 sub-authorities but only provides space for 1
        #[rustfmt::skip]
        let bytes: [u8; 12] = [
            0x01, 0x02, // revision=1, sub-auth count=2
            0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
            0x12, 0x00, 0x00, 0x00, // only 1 sub-authority
        ];
        assert!(SidRef::new(&bytes).is_none());
    }

    #[test]
    fn sid_ref_rejects_excessive_sub_auth_count() {
        // Sub-authority count > 15 (SID_MAX_SUB_AUTHORITIES) should be rejected.
        let mut bytes = [0u8; 8 + 16 * 4]; // enough space for 16 sub-auths
        bytes[0] = 0x01; // revision
        bytes[1] = 16; // sub_auth_count = 16 (exceeds max of 15)
        assert!(SidRef::new(&bytes).is_none());
    }

    #[test]
    fn sid_owned_from_bytes_and_display() {
        #[rustfmt::skip]
        let bytes: [u8; 12] = [
            0x01, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
            0x12, 0x00, 0x00, 0x00,
        ];
        let sid = Sid::from_bytes(&bytes).expect("valid SID");
        assert_eq!(sid.revision, 1);
        assert_eq!(sid.sub_authorities, vec![18]);
        assert_eq!(format!("{sid}"), "S-1-5-18");
    }

    #[test]
    fn sid_owned_display_widest_in_spec() {
        // The fast-path buffer is sized for exactly this: the 15 sub-authority maximum,
        // each at the widest a u32 renders, on top of a full 48-bit authority.
        let sid = Sid {
            revision: 1,
            authority: [0xFF; 6],
            sub_authorities: vec![u32::MAX; 15],
        };
        let expected = format!("S-1-281474976710655{}", "-4294967295".repeat(15));
        assert_eq!(format!("{sid}"), expected);
        assert_eq!(expected.len(), SID_TEXT_CAPACITY - 2);
    }

    #[test]
    fn sid_owned_display_falls_back_past_buffer() {
        // `Sid` has public fields, so it can hold more sub-authorities than the SID
        // specification allows and overflow the fast path. Output must stay correct.
        let sid = Sid {
            revision: 1,
            authority: [0, 0, 0, 0, 0, 5],
            sub_authorities: vec![7; 64],
        };
        let expected = format!("S-1-5{}", "-7".repeat(64));
        assert_eq!(format!("{sid}"), expected);
    }

    #[test]
    fn sid_ref_extra_trailing_data() {
        // Valid SID followed by extra bytes — SidRef should slice to exact length.
        #[rustfmt::skip]
        let bytes: [u8; 16] = [
            0x01, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
            0x12, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, // trailing garbage
        ];
        let sid = SidRef::new(&bytes).expect("valid SID with trailing data");
        assert_eq!(sid.as_bytes().len(), 12); // exact SID length, no trailing data
        assert_eq!(format!("{sid}"), "S-1-5-18");
    }

    #[test]
    fn sid_ref_debug_format() {
        #[rustfmt::skip]
        let bytes: [u8; 12] = [
            0x01, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
            0x12, 0x00, 0x00, 0x00,
        ];
        let sid = SidRef::new(&bytes).expect("valid SID");
        assert_eq!(format!("{sid:?}"), "SidRef(\"S-1-5-18\")");
    }

    // =========================================================================
    // WideStrRef — decode, format, equality
    // =========================================================================

    #[test]
    fn wide_str_ref_as_bytes_round_trip() {
        let bytes = make_wide_str("hi");
        let w = WideStrRef::new(&bytes);
        assert_eq!(w.as_bytes(), bytes.as_slice());
    }

    #[test]
    fn wide_str_ref_len_and_is_empty() {
        let bytes = make_wide_str("abc");
        let w = WideStrRef::new(&bytes);
        assert_eq!(w.len(), 3);
        assert!(!w.is_empty());
        let empty = WideStrRef::new(&[]);
        assert_eq!(empty.len(), 0);
        assert!(empty.is_empty());
    }

    #[test]
    fn wide_str_ref_decode_utf16_ascii() {
        let bytes = make_wide_str("hello");
        let w = WideStrRef::new(&bytes);
        assert_eq!(w.decode_utf16().unwrap(), "hello");
    }

    #[test]
    fn wide_str_ref_decode_utf16_unicode() {
        // "héllo" — é is U+00E9
        let bytes = make_wide_str("héllo");
        let w = WideStrRef::new(&bytes);
        assert_eq!(w.decode_utf16().unwrap(), "héllo");
    }

    #[test]
    fn wide_str_ref_decode_utf16_empty() {
        let w = WideStrRef::new(&[]);
        assert_eq!(w.decode_utf16().unwrap(), "");
    }

    #[test]
    fn wide_str_ref_to_string_lossy_ascii() {
        let bytes = make_wide_str("world");
        let w = WideStrRef::new(&bytes);
        assert_eq!(w.to_string_lossy(), "world");
    }

    #[test]
    fn wide_str_ref_to_string_lossy_replacement_for_surrogate() {
        // An unpaired high surrogate (U+D800) should produce the replacement character.
        // UTF-16LE bytes for code unit 0xD800: low byte 0x00, high byte 0xD8.
        let bytes: Vec<u8> = vec![0x00u8, 0xD8];
        let w = WideStrRef::new(&bytes);
        assert_eq!(w.to_string_lossy(), "\u{FFFD}");
    }

    #[test]
    fn wide_str_ref_from_raw_with_null_strips_null() {
        // "AB\0" in UTF-16LE
        let bytes: Vec<u8> = [0x0041u16, 0x0042, 0x0000]
            .iter()
            .flat_map(|&u| u16::to_le_bytes(u))
            .collect();
        let w = WideStrRef::from_raw_with_null(&bytes);
        assert_eq!(w.len(), 2);
        assert_eq!(w.to_string_lossy(), "AB");
    }

    #[test]
    fn wide_str_ref_from_raw_with_null_no_null() {
        // "AB" with no null terminator — data is used as-is
        let bytes: Vec<u8> = [0x0041u16, 0x0042]
            .iter()
            .flat_map(|&u| u16::to_le_bytes(u))
            .collect();
        let w = WideStrRef::from_raw_with_null(&bytes);
        assert_eq!(w.len(), 2);
    }

    #[test]
    fn wide_str_ref_from_raw_with_null_empty() {
        let w = WideStrRef::from_raw_with_null(&[]);
        assert!(w.is_empty());
    }

    #[test]
    fn wide_str_ref_debug_and_display() {
        let bytes = make_wide_str("test");
        let w = WideStrRef::new(&bytes);
        assert_eq!(format!("{w}"), "test");
        assert_eq!(format!("{w:?}"), "WideStrRef(\"test\")");
    }

    #[test]
    fn wide_str_ref_partial_eq_self() {
        let bytes = make_wide_str("abc");
        let a = WideStrRef::new(&bytes);
        let b = WideStrRef::new(&bytes);
        assert_eq!(a, b);
        let other = make_wide_str("xyz");
        let c = WideStrRef::new(&other);
        assert_ne!(a, c);
    }

    #[test]
    fn wide_str_ref_partial_eq_str_non_ascii() {
        // Non-ASCII comparison path — goes through decode_utf16
        let bytes = make_wide_str("café");
        let w = WideStrRef::new(&bytes);
        assert_eq!(w, "café");
        assert!(w != "cafe");
    }

    // =========================================================================
    // AnsiStrRef — Debug, Display, PartialEq
    // =========================================================================

    #[test]
    fn ansi_str_ref_debug_and_display() {
        let s = AnsiStrRef::new(b"hello");
        assert_eq!(format!("{s}"), "hello");
        assert_eq!(format!("{s:?}"), "AnsiStrRef(\"hello\")");
    }

    #[test]
    fn ansi_str_ref_partial_eq_self() {
        let a = AnsiStrRef::new(b"hello");
        let b = AnsiStrRef::new(b"hello");
        assert_eq!(a, b);
        let c = AnsiStrRef::new(b"world");
        assert_ne!(a, c);
    }

    #[test]
    fn ansi_str_ref_partial_eq_str_compares_bytes_not_decoded_text() {
        // Byte 0x80 is the Euro sign in CP1252, and `to_string_lossy` decodes it
        // to "€" — but comparing that way contradicts comparing two `AnsiStrRef`s,
        // which compares bytes. "€" is `E2 82 AC` in UTF-8, so the two encodings
        // are different data and must not both equal the same `str`, or equality
        // stops being an equivalence relation while `Eq` claims it is one.
        let cp1252 = AnsiStrRef::new(&[0x80]);
        let utf8 = AnsiStrRef::new("\u{20AC}".as_bytes());

        assert_ne!(cp1252, utf8, "different bytes must not compare equal");
        assert_eq!(
            utf8, "\u{20AC}",
            "data that is the UTF-8 encoding compares equal"
        );
        assert!(
            cp1252 != "\u{20AC}",
            "CP1252 bytes must not equal the decoded text"
        );

        // Comparing across encodings is still possible, by naming the code page.
        #[cfg(not(miri))] // Non-ASCII decode calls MultiByteToWideChar (Win32).
        assert_eq!(cp1252.decode(1252).unwrap(), "\u{20AC}");
    }

    #[test]
    fn ansi_str_ref_partial_eq_str_ascii() {
        let s = AnsiStrRef::new(b"abc");
        assert_eq!(s, "abc");
        assert!(s != "xyz");
    }

    // =========================================================================
    // WideString — constructors, methods, traits
    // =========================================================================

    #[test]
    fn wide_string_from_vec() {
        let s = WideString::from_vec(vec![0x0041, 0x0042]); // "AB"
        assert_eq!(s.as_slice(), &[0x0041u16, 0x0042]);
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn wide_string_from_str() {
        let s = WideString::from_str("hello");
        assert_eq!(s.to_string_lossy(), "hello");
        assert_eq!(s.len(), 5);
        assert!(!s.is_empty());
    }

    #[test]
    fn wide_string_len_and_is_empty() {
        let empty = WideString::new();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
    }

    #[test]
    fn wide_string_decode_utf16() {
        let s = WideString::from_str("hello");
        assert_eq!(s.decode_utf16().unwrap(), "hello");
    }

    #[test]
    fn wide_string_as_wide_str() {
        let s = WideString::from_str("hi");
        let r = s.as_wide_str();
        assert_eq!(r.to_string_lossy(), "hi");
    }

    #[test]
    fn wide_string_to_null_terminated() {
        let s = WideString::from_str("AB");
        let nt = s.to_null_terminated();
        assert_eq!(nt, vec![0x0041, 0x0042, 0x0000]);
    }

    #[test]
    fn wide_string_debug_and_display() {
        let s = WideString::from_str("test");
        assert_eq!(format!("{s}"), "test");
        assert_eq!(format!("{s:?}"), "WideString(\"test\")");
    }

    #[test]
    fn wide_string_partial_eq_self() {
        let a = WideString::from_str("abc");
        let b = WideString::from_str("abc");
        assert_eq!(a, b);
        let c = WideString::from_str("xyz");
        assert_ne!(a, c);
    }

    #[test]
    fn wide_string_partial_eq_str() {
        let s = WideString::from_str("hello");
        assert_eq!(s, *"hello");
        assert!(s != *"world");
    }

    #[test]
    fn wide_string_partial_eq_str_non_ascii() {
        let s = WideString::from_str("héllo");
        assert_eq!(s, *"héllo");
        assert!(s != *"hello");
    }

    #[test]
    fn wide_string_from_wide_str_ref() {
        let bytes = make_wide_str("from_ref");
        let r = WideStrRef::new(&bytes);
        let owned = WideString::from(r);
        assert_eq!(owned.to_string_lossy(), "from_ref");
    }

    #[test]
    fn wide_string_from_str_ref() {
        let s = WideString::from("from &str");
        assert_eq!(s.to_string_lossy(), "from &str");
    }

    #[test]
    fn wide_string_from_string() {
        let s = WideString::from(String::from("from String"));
        assert_eq!(s.to_string_lossy(), "from String");
    }

    // =========================================================================
    // AnsiString — constructors, methods, traits
    // =========================================================================

    #[test]
    fn ansi_string_new_is_empty() {
        let s = AnsiString::new();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert!(s.has_no_interior_nulls());
    }

    #[test]
    fn ansi_string_from_bytes_with_interior_nulls() {
        // Interior null preserved, trailing null stripped
        let s = AnsiString::from_bytes_with_interior_nulls(&[0x48, 0x00, 0x69, 0x00]); // "H\0i\0"
        assert_eq!(s.as_bytes(), &[0x48, 0x00, 0x69]); // trailing null stripped
        assert!(!s.has_no_interior_nulls()); // interior null present
    }

    #[test]
    fn ansi_string_from_bytes_with_interior_nulls_no_trailing() {
        let s = AnsiString::from_bytes_with_interior_nulls(b"abc");
        assert_eq!(s.as_bytes(), b"abc");
    }

    #[test]
    fn ansi_string_as_bytes() {
        let s = AnsiString::from_bytes(b"hello");
        assert_eq!(s.as_bytes(), b"hello");
    }

    #[test]
    fn ansi_string_len() {
        let s = AnsiString::from_bytes(b"hi");
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn ansi_string_is_empty() {
        let s = AnsiString::new();
        assert!(s.is_empty());
        let s2 = AnsiString::from_bytes(b"x");
        assert!(!s2.is_empty());
    }

    #[test]
    fn ansi_string_to_string_ascii() {
        let s = AnsiString::from_bytes(b"ASCII");
        assert_eq!(s.to_string_ascii(), Some("ASCII".to_owned()));
        let non = AnsiString::from_bytes(&[0x80]);
        assert_eq!(non.to_string_ascii(), None);
    }

    #[test]
    fn ansi_string_to_string_cp1252() {
        let s = AnsiString::from_bytes(&[0xA9]); // © in Latin-1 / CP1252
        assert_eq!(s.to_string_cp1252(), "\u{00A9}");
    }

    #[test]
    fn ansi_string_to_cstring_no_nulls() {
        let s = AnsiString::from_bytes(b"hello");
        let cs = s.to_cstring().expect("no interior nulls");
        assert_eq!(cs.to_bytes(), b"hello");
    }

    #[test]
    fn ansi_string_to_cstring_with_interior_null() {
        let s = AnsiString::from_bytes_with_interior_nulls(&[0x48, 0x00, 0x69]);
        assert!(s.to_cstring().is_none());
    }

    #[test]
    fn ansi_string_debug_and_display() {
        let s = AnsiString::from_bytes(b"test");
        assert_eq!(format!("{s}"), "test");
        assert_eq!(format!("{s:?}"), "AnsiString(\"test\")");
    }

    #[test]
    fn ansi_string_partial_eq_self() {
        let a = AnsiString::from_bytes(b"hello");
        let b = AnsiString::from_bytes(b"hello");
        assert_eq!(a, b);
        let c = AnsiString::from_bytes(b"world");
        assert_ne!(a, c);
    }

    #[test]
    fn ansi_string_partial_eq_str() {
        let s = AnsiString::from_bytes(b"hello");
        assert_eq!(s, *"hello");
        assert!(s != *"world");
    }

    #[test]
    fn ansi_string_partial_eq_str_compares_bytes_not_decoded_text() {
        // Same invariant as `AnsiStrRef`; see that test for why.
        let cp1252 = AnsiString::from_bytes(&[0x80]);
        let utf8 = AnsiString::from_bytes("\u{20AC}".as_bytes());

        assert_ne!(cp1252, utf8);
        assert_eq!(utf8, *"\u{20AC}");
        assert!(cp1252 != *"\u{20AC}");
    }

    #[test]
    fn wide_string_partial_eq_str_rejects_invalid_utf16() {
        // A lone high surrogate. `to_string_lossy` renders it as the replacement
        // character, so under the old comparison it — and every other malformed
        // payload — equalled a string of just that character, while all of them
        // compared unequal to each other.
        let lone_surrogate = WideString::from_bytes(&[0x00, 0xD8]);
        assert!(
            lone_surrogate != *"\u{FFFD}",
            "invalid UTF-16 must not equal U+FFFD"
        );

        // Valid UTF-16 still compares by its decoded text.
        assert_eq!(WideString::from_bytes(&[0xAC, 0x20]), *"\u{20AC}");
    }

    #[test]
    fn ansi_string_from_ansi_str_ref() {
        let r = AnsiStrRef::new(b"from_ref");
        let owned = AnsiString::from(r);
        assert_eq!(owned.as_bytes(), b"from_ref");
    }

    #[test]
    fn ansi_string_from_bytes_slice() {
        let s = AnsiString::from(&b"hello\0"[..]);
        // From<&[u8]> uses from_bytes which stops at null
        assert_eq!(s.as_bytes(), b"hello");
    }

    // =========================================================================
    // Guid — constructors and into_inner
    // =========================================================================

    #[test]
    fn guid_from_u128() {
        let g = Guid::from_u128(0xb675ec37_bdb6_4648_bc92_f3fdc74d3ca2);
        assert_eq!(format!("{g}"), "b675ec37-bdb6-4648-bc92-f3fdc74d3ca2");
    }

    #[test]
    fn guid_from_values() {
        let g = Guid::from_values(
            0xb675ec37,
            0xbdb6,
            0x4648,
            [0xbc, 0x92, 0xf3, 0xfd, 0xc7, 0x4d, 0x3c, 0xa2],
        );
        assert_eq!(format!("{g}"), "b675ec37-bdb6-4648-bc92-f3fdc74d3ca2");
    }

    #[test]
    fn guid_u128_round_trip() {
        let g = Guid::from_u128(0x1234_5678_9abc_def0_1122_3344_5566_7788);
        assert_eq!(g.to_u128(), 0x1234_5678_9abc_def0_1122_3344_5566_7788);
        assert_eq!(Guid::from_u128(g.to_u128()), g);
    }

    /// `to_u128` is the documented interop seam, so its bit mapping must agree
    /// with the `windows` crate's — every consumer-side
    /// `windows::core::GUID::from_u128(guid.to_u128())` depends on it.
    #[test]
    fn guid_u128_mapping_matches_windows_crate() {
        let value = 0x1234_5678_9abc_def0_1122_3344_5566_7788_u128;
        let ours = Guid::from_u128(value);
        let theirs = windows::core::GUID::from_u128(ours.to_u128());

        assert_eq!(theirs.data1, 0x1234_5678);
        assert_eq!(theirs.data2, 0x9abc);
        assert_eq!(theirs.data3, 0xdef0);
        assert_eq!(
            theirs.data4,
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
        );
        assert_eq!(Guid::from_u128(theirs.to_u128()), ours);
    }

    // =========================================================================
    // TdhOutType / TdhInType round-trip coverage
    // =========================================================================

    #[test]
    fn ansi_code_page_follows_out_type() {
        use windows_sys::Win32::Globalization::{CP_ACP, CP_UTF8};
        for utf8 in [TdhOutType::Utf8, TdhOutType::Json, TdhOutType::Xml] {
            assert_eq!(utf8.ansi_code_page(), CP_UTF8, "{utf8:?}");
        }
        for acp in [
            TdhOutType::Null,
            TdhOutType::String,
            TdhOutType::Unknown(999),
        ] {
            assert_eq!(acp.ansi_code_page(), CP_ACP, "{acp:?}");
        }
    }

    #[test]
    fn tdh_out_type_round_trip_all_variants() {
        // Every (raw_value, variant) pair from from_raw / raw_value.
        let cases: &[(u16, TdhOutType)] = &[
            (0, TdhOutType::Null),
            (1, TdhOutType::String),
            (2, TdhOutType::DateTime),
            (3, TdhOutType::Byte),
            (4, TdhOutType::UnsignedByte),
            (5, TdhOutType::Short),
            (6, TdhOutType::UnsignedShort),
            (7, TdhOutType::Int),
            (8, TdhOutType::UnsignedInt),
            (9, TdhOutType::Long),
            (10, TdhOutType::UnsignedLong),
            (11, TdhOutType::Float),
            (12, TdhOutType::Double),
            (13, TdhOutType::Boolean),
            (14, TdhOutType::Guid),
            (15, TdhOutType::HexBinary),
            (16, TdhOutType::HexInt8),
            (17, TdhOutType::HexInt16),
            (18, TdhOutType::HexInt32),
            (19, TdhOutType::HexInt64),
            (20, TdhOutType::Pid),
            (21, TdhOutType::Tid),
            (22, TdhOutType::Port),
            (23, TdhOutType::Ipv4),
            (24, TdhOutType::Ipv6),
            (25, TdhOutType::SocketAddress),
            (26, TdhOutType::CimDateTime),
            (27, TdhOutType::EtwTime),
            (28, TdhOutType::Xml),
            (29, TdhOutType::ErrorCode),
            (30, TdhOutType::Win32Error),
            (31, TdhOutType::NtStatus),
            (32, TdhOutType::HResult),
            (33, TdhOutType::CultureInsensitiveDateTime),
            (34, TdhOutType::Json),
            (35, TdhOutType::Utf8),
            (36, TdhOutType::Pkcs7WithTypeInfo),
            (37, TdhOutType::CodePointer),
            (38, TdhOutType::DateTimeUtc),
            (300, TdhOutType::ReducedString),
            (301, TdhOutType::NoPrint),
        ];
        for &(raw, variant) in cases {
            assert_eq!(TdhOutType::from_raw(raw), variant, "from_raw({raw})");
            assert_eq!(variant.raw_value(), raw, "raw_value({variant:?})");
        }
        // Unknown round-trip preserves the value.
        let u = TdhOutType::from_raw(9999);
        assert_eq!(u, TdhOutType::Unknown(9999));
        assert_eq!(u.raw_value(), 9999);
    }

    #[test]
    fn tdh_in_type_round_trip_all_variants() {
        let cases: &[(u16, TdhInType)] = &[
            (0, TdhInType::Null),
            (1, TdhInType::UnicodeString),
            (2, TdhInType::AnsiString),
            (3, TdhInType::Int8),
            (4, TdhInType::UInt8),
            (5, TdhInType::Int16),
            (6, TdhInType::UInt16),
            (7, TdhInType::Int32),
            (8, TdhInType::UInt32),
            (9, TdhInType::Int64),
            (10, TdhInType::UInt64),
            (11, TdhInType::Float),
            (12, TdhInType::Double),
            (13, TdhInType::Boolean),
            (14, TdhInType::Binary),
            (15, TdhInType::Guid),
            (16, TdhInType::Pointer),
            (17, TdhInType::FileTime),
            (18, TdhInType::SystemTime),
            (19, TdhInType::Sid),
            (20, TdhInType::HexInt32),
            (21, TdhInType::HexInt64),
            (22, TdhInType::ManifestCountedString),
            (23, TdhInType::ManifestCountedAnsiString),
            (25, TdhInType::ManifestCountedBinary),
            (300, TdhInType::CountedString),
            (301, TdhInType::CountedAnsiString),
            (302, TdhInType::ReversedCountedString),
            (303, TdhInType::ReversedCountedAnsiString),
            (304, TdhInType::NonNullTerminatedString),
            (305, TdhInType::NonNullTerminatedAnsiString),
            (306, TdhInType::UnicodeChar),
            (307, TdhInType::AnsiChar),
            (308, TdhInType::SizeT),
            (309, TdhInType::HexDump),
            (310, TdhInType::WbemSid),
        ];
        for &(raw, variant) in cases {
            assert_eq!(TdhInType::from_raw(raw), variant, "from_raw({raw})");
            assert_eq!(variant.raw_value(), raw, "raw_value({variant:?})");
        }
        // Struct sentinel (u16::MAX): from_raw doesn't decode it back, but
        // raw_value() must produce u16::MAX.
        assert_eq!(TdhInType::Struct.raw_value(), u16::MAX);
        // Unknown round-trip.
        let u = TdhInType::from_raw(9999);
        assert_eq!(u, TdhInType::Unknown(9999));
        assert_eq!(u.raw_value(), 9999);
        // Reserved value 24 → Unknown(24)
        assert_eq!(TdhInType::from_raw(24), TdhInType::Unknown(24));
    }

    // =========================================================================
    // WideStrRef unaligned fallback paths
    // =========================================================================

    /// Builds a backing buffer together with the offset at which `payload`
    /// starts on an odd address.
    ///
    /// `Vec<u8>` only guarantees an alignment of 1, so the allocation base may
    /// itself be odd. The system allocator happens to hand back over-aligned
    /// blocks, which made a single filler byte sufficient in practice, but Miri
    /// honours the declared alignment and does not. Pad by however many filler
    /// bytes it actually takes instead of assuming one is enough.
    fn unaligned_wide_bytes(payload: &[u8]) -> (Vec<u8>, usize) {
        // Reserve up front so the pushes below cannot reallocate and invalidate
        // the base address the offset is derived from.
        let mut buf = Vec::with_capacity(payload.len() + 2);
        buf.push(0xFFu8);
        // Base address already odd → one filler lands the payload back on even,
        // so a second is needed.
        if !(buf.as_ptr() as usize).is_multiple_of(2) {
            buf.push(0xFFu8);
        }
        let offset = buf.len();
        buf.extend_from_slice(payload);
        (buf, offset)
    }

    #[test]
    fn wide_str_ref_decode_utf16_unaligned_path() {
        // "Hi" UTF-16LE = [0x48, 0x00, 0x69, 0x00]
        let (backing, offset) = unaligned_wide_bytes(&[0x48, 0x00, 0x69, 0x00]);
        let slice = &backing[offset..];
        // Sanity: slice must actually be unaligned for u16.
        assert_ne!(slice.as_ptr() as usize % 2, 0, "expected odd-address slice");
        let w = WideStrRef::new(slice);
        let s = w.decode_utf16().expect("decode_utf16 should succeed");
        assert_eq!(s, "Hi");
    }

    #[test]
    fn wide_str_ref_decode_utf16_unaligned_invalid_surrogate_errs() {
        // Lone high-surrogate on the unaligned path → error (decode_utf16 is
        // strict; the lossy path is tested separately).
        let (backing, offset) = unaligned_wide_bytes(&[0x00, 0xD8]);
        let slice = &backing[offset..];
        assert_ne!(slice.as_ptr() as usize % 2, 0);
        let w = WideStrRef::new(slice);
        assert!(w.decode_utf16().is_err());
    }

    #[test]
    fn wide_str_ref_to_string_lossy_unaligned_path() {
        // "Hi" UTF-16LE
        let (backing, offset) = unaligned_wide_bytes(&[0x48, 0x00, 0x69, 0x00]);
        let slice = &backing[offset..];
        assert_ne!(slice.as_ptr() as usize % 2, 0);
        let w = WideStrRef::new(slice);
        assert_eq!(w.to_string_lossy(), "Hi");
    }

    #[test]
    fn wide_str_ref_to_string_lossy_unaligned_invalid_surrogate_replaced() {
        // Lone high-surrogate 0xD800 — not paired, should become U+FFFD on the
        // unaligned path.
        let (backing, offset) = unaligned_wide_bytes(&[0x00, 0xD8]);
        let slice = &backing[offset..];
        assert_ne!(slice.as_ptr() as usize % 2, 0);
        let w = WideStrRef::new(slice);
        assert!(
            w.to_string_lossy().contains('\u{FFFD}'),
            "expected replacement char for lone surrogate"
        );
    }

    #[test]
    fn wide_str_ref_to_os_string_preserves_lone_surrogate() {
        use std::os::windows::ffi::OsStrExt;
        let units = [0x48, 0xD800, 0x69];
        let owned = WideString::from_vec(units.to_vec());
        let w = owned.as_wide_str();
        assert!(w.as_wide_slice().is_some(), "expected aligned path");
        assert!(w.decode_utf16().is_err());
        assert_eq!(w.to_os_string().encode_wide().collect::<Vec<_>>(), units);
        assert_eq!(owned.to_os_string(), w.to_os_string());
    }

    #[test]
    fn wide_str_ref_to_os_string_unaligned_preserves_lone_surrogate() {
        use std::os::windows::ffi::OsStrExt;
        let (backing, offset) = unaligned_wide_bytes(&[0x48, 0x00, 0x00, 0xD8]);
        let slice = &backing[offset..];
        assert_ne!(slice.as_ptr() as usize % 2, 0);
        let w = WideStrRef::new(slice);
        assert_eq!(
            w.to_os_string().encode_wide().collect::<Vec<_>>(),
            [0x48, 0xD800]
        );
    }

    #[test]
    fn wide_str_ref_to_os_string_empty() {
        assert!(WideStrRef::new(&[]).to_os_string().is_empty());
    }
}
