# TDH Type Implementation & Test Coverage

Complete reference for all TDH (Trace Data Helper) types in etw-rs, their
implementation status across both parser APIs, and test coverage.

This file tracks **what etw-rs implements**. For the wire format itself — how each InType's size
is determined, which types are pointer-size dependent, and which the SDK deprecates — see the
per-variant rustdoc on `TdhInType` in `src/types.rs`, which is the authoritative summary of the
`_TDH_IN_TYPE` definition in the Windows SDK `<tdh.h>`. Keep the two in step: a size rule stated
here and nowhere else will drift.

## Overview

etw-rs has **two independent parsers**:

| Parser | API Surface | Schema Source |
|--------|-------------|---------------|
| **Dynamic** (`EventParser`) | `get()`, `as_ref()`, `Property` iteration | Runtime TDH lookup (`EventSchema` + `ParserCache`) |
| **Static** (`event_schema!`) | Generated accessor methods via `from_bytes()` | Compile-time proc macro |

Both parse the same raw `UserData` buffer but use different type systems:
- Dynamic parser maps `TdhInType` → Rust types via `FromProperty` / `FromPropertyRef` traits
- Static parser maps Rust field types → byte offsets via `FromBytes` trait

---

## TdhInType Coverage Matrix

Position Tests: **D** = dynamic parser, checked against TDH in `tests/differential_offline.rs`, or —
for types a manifest cannot declare — in `tests/differential_tracelogging.rs` (`Counted*`) and
`src/parser.rs::position_tests` (`WbemSid`, `ReversedCounted*`). **S** = `tests/static_schema_positions.rs`.

### Fixed-Size Types

| TdhInType | Value | Size | Dynamic `FromProperty` | Dynamic `FromPropertyRef` | Static Schema Type | Display | Position Tests |
|-----------|-------|------|------------------------|---------------------------|---------------------|---------|----------------|
| `UInt8` | 4 | 1 | `u8` | — | `u8` | Yes | D+S |
| `Int8` | 3 | 1 | `i8` | — | `i8` | Yes | D+S |
| `UInt16` | 6 | 2 | `u16` | — | `u16` | Yes | D+S |
| `Int16` | 5 | 2 | `i16` | — | `i16` | Yes | D+S |
| `UInt32` | 8 | 4 | `u32`, `Ipv4Addr` | — | `u32` | Yes | D+S |
| `Int32` | 7 | 4 | `i32`, `Ipv4Addr` | — | `i32` | Yes | D+S |
| `HexInt32` | 20 | 4 | `u32`, `Ipv4Addr` | — | `u32` | `0x{:X}` | D |
| `UInt64` | 10 | 8 | `u64` | — | `u64` | Yes | D+S |
| `Int64` | 9 | 8 | `i64` | — | `i64` | Yes | D+S |
| `HexInt64` | 21 | 8 | `u64` | — | `u64` | `0x{:X}` | D |
| `Float` | 11 | 4 | `f32` | — | `f32` | Yes | D+S |
| `Double` | 12 | 8 | `f64` | — | `f64` | Yes | D+S |
| `Boolean` | 13 | 4 | `bool` | — | `bool` (4-byte + 1-byte fallback) | Yes | D+S |
| `Pointer` | 16 | 4/8* | `usize`, `u64` | — | `usize`, `isize @ tdh(Pointer)` | `0x{:X}` | D+S |
| `Guid` | 15 | 16 | `Guid`, `Ipv6Addr` | — | `Guid` | Yes | D+S |
| `SystemTime` | 18 | 16 | `SystemTime` | — | `SystemTime` | `YYYY-MM-DDThh:mm:ss.mmm0000` | D+S |
| `FileTime` | 17 | 8 | `Timestamp` | — | `u64` | `Timestamp` (`YYYY-MM-DDThh:mm:ss.fffffffZ`; negative → raw `i64`) | D |
| `SizeT` | 308 | 4/8* | `usize`, `u64` | — | `usize` | `0x{:X}` | — (same codepath as Pointer) |

\* Pointer and SizeT follow the event's pointer size — 4 bytes for a 32-bit event, 8 for a 64-bit
one — via `TdhInType::fixed_size(pointer_size)`. The static parser reads them with `parse_pointer`
(`parse_signed_pointer` for `isize`) for the same reason; `usize`/`isize` have no `FromBytes`
impl. `u32` rejects both.

The static column lists the Rust type a field of that InType is declared as; `@ tdh(...)` pins the
exact InType where one Rust type covers several (e.g. `u64 @ tdh(FileTime)`).

### Variable-Size Types

| TdhInType | Value | Size | Dynamic `FromProperty` | Dynamic `FromPropertyRef` | Static Schema Type | Display | Position Tests |
|-----------|-------|------|------------------------|---------------------------|---------------------|---------|----------------|
| `UnicodeString` | 1 | Null-terminated UTF-16 | `WideString`, `OsString`, `String` | `WideStrRef` | `WideStrRef` | Yes | D+S |
| `AnsiString` | 2 | Null-terminated ANSI | `AnsiString`, `String` | `AnsiStrRef` | `AnsiStrRef` | Yes | D+S |
| `Sid` | 19 | 8 + sub_auth×4 | `Sid` | `SidRef` | `SidRef` | Yes | D+S |
| `WbemSid` | 310 | TOKEN_USER(16 on 64-bit, 8 on 32-bit) + SID | `Sid` | `SidRef` | `WbemSidRef` | Yes | D |
| `NonNullTerminatedString` | 304 | Declared length or `PropertyParamLength` only | `WideString`, `OsString`, `String` | `WideStrRef` | — | Yes | — |
| `NonNullTerminatedAnsiString` | 305 | Declared length or `PropertyParamLength` only | `AnsiString`, `String` | `AnsiStrRef` | — | Yes | — |
| `Binary` | 14 | Declared length or `PropertyParamLength`; neither is a parse error | `Vec<u8>`, `SocketAddr`, `Ipv4Addr`, `Ipv6Addr` | `&[u8]` | `u8 @ length(..)` / `fixed_length(..)` / `count_bytes(..)` → `&[u8]` | Hex bytes | D |

The dynamic parser sizes `WbemSid` from the event's pointer size, but its decoding (`Sid`, `SidRef`,
`Display`) always skips a 16-byte header; the static `WbemSidRef` both sizes and decodes with that
fixed 16 bytes. Either way a 32-bit event's SID is misread or rejected.

`Binary` does not apply the `<tdh.h>` rule that an `Ipv6` out-type implies 16 bytes
(`compute_variable_element_size`). `NonNullTerminated*` are not sized as "rest of the event": with
no declared length they fail with "Cannot determine size".

### Counted Types (2-byte length prefix)

| TdhInType | Value | Size | Dynamic `FromProperty` | Dynamic `FromPropertyRef` | Static Schema Type | Display | Position Tests |
|-----------|-------|------|------------------------|---------------------------|---------------------|---------|----------------|
| `ManifestCountedString` | 22 | 2 + byte_count | `WideString`, `OsString`, `String` | `WideStrRef` | `CountedWideStrRef` | Yes | S |
| `ManifestCountedAnsiString` | 23 | 2 + byte_count | `AnsiString`, `String` | `AnsiStrRef` | `CountedAnsiStrRef` | Yes | S |
| `ManifestCountedBinary` | 25 | 2 + byte_count | — | `&[u8]` | `CountedBinaryRef` | Hex bytes (prefix included) | S |
| `CountedString` | 300 | 2 + byte_count | `WideString`, `OsString`, `String` | `WideStrRef` | — | Yes | D |
| `CountedAnsiString` | 301 | 2 + byte_count | `AnsiString`, `String` | `AnsiStrRef` | — | Yes | D |
| `ReversedCountedString` | 302 | 2 + byte_count (BE prefix) | `WideString`, `OsString`, `String` | `WideStrRef` | — | Yes | D |
| `ReversedCountedAnsiString` | 303 | 2 + byte_count (BE prefix) | `AnsiString`, `String` | `AnsiStrRef` | — | Yes | D |

Every prefix in this table counts **bytes**, not characters — including the UTF-16 ones. The
`Reversed*` variants byte-swap only the count; the payload stays little-endian.

### Unsupported / Passthrough Types

| TdhInType | Value | Notes |
|-----------|-------|-------|
| `Null` | 0 | Sentinel, never appears in real properties |
| `UnicodeChar` | 306 | 2 bytes, or a declared-length WCHAR array. No `FromProperty` impl; `Display` decodes every code unit as UTF-16, so NUL padding in an array is shown, not trimmed. Static: `u16`. No manifest registered on Windows 11 26200 declares this in-type (973 providers scanned), so whether real MOF or TraceLogging events pad it is unverified. |
| `AnsiChar` | 307 | 1 byte. No `FromProperty` impl; `Display` shows hex bytes. Static: `u8`. |
| `HexDump` | 309 | No `FromProperty` impl and no size rule: needs a declared length. `Display` shows hex bytes. |

---

## TdhOutType Display Overrides

When `TdhOutType` is non-null, the `Property` `Display` impl overrides the
default format. These are **display-only** — they do not affect `get()` or
`as_ref()` parsing.

| TdhOutType | Value | Display Format |
|------------|-------|----------------|
| `HexInt8` | 16 | `0x{:02X}` |
| `HexInt16` | 17 | `0x{:04X}` |
| `HexInt32` | 18 | `0x{:08X}` |
| `HexInt64` | 19 | `0x{:016X}` |
| `NtStatus` | 31 | `0x{:08X}` |
| `HResult` | 32 | `0x{:08X}` |
| `Pid` / `Tid` | 20/21 | Decimal u32 |
| `Win32Error` | 30 | Decimal u32 |
| `Port` | 22 | `ntohs()` → decimal |
| `Ipv4` | 23 | Dotted-quad from 4 bytes |
| `Ipv6` | 24 | Standard IPv6 notation from 16 bytes |
| `CodePointer` | 37 | `0x{:X}` (Pointer/SizeT in-types only) |
| `Boolean` | 13 | `true` if any byte is non-zero, else `false` |
| `Guid` | 14 | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` (lower case, no braces) |
| `NoPrint` | 301 | Suppressed (empty) |

All other `TdhOutType` values fall through to the default `TdhInType`-based
display.

---

## Property Flag Variants

The dynamic parser inspects exactly three of the `PROPERTY_FLAGS` bits, via
`PropertyInfo::is_struct()`, `has_param_length()`, and `has_param_count()`:

- `PropertyStruct` — nested struct; sized by `compute_struct_size()`, members exposed through
  `struct_members()`.
- `PropertyParamLength` — length is held in another property; resolved at parse time.
- `PropertyParamCount` — array count is held in another property; array iteration supported.

The remaining bits are not read anywhere in the tree. The static parser reads no flags when parsing;
its TDH validation (`validate_schema`) checks the same three against the layout each field declares.

Names and values come from the `PROPERTY_FLAGS` constants in the `windows-sys` crate — the accessors
above test against those symbols directly, so there is no value table to keep in step here.

---

## Static Schema Type Mapping

The `event_schema!` macro maps Rust types to TDH types at compile time:

| Rust Type | TDH InType | Size | Category |
|-----------|------------|------|----------|
| `u8` | UInt8 | 1 | Fixed |
| `u16` | UInt16 | 2 | Fixed |
| `u32` | UInt32 | 4 | Fixed |
| `u64` | UInt64 | 8 | Fixed |
| `i8` | Int8 | 1 | Fixed |
| `i16` | Int16 | 2 | Fixed |
| `i32` | Int32 | 4 | Fixed |
| `i64` | Int64 | 8 | Fixed |
| `usize` | SizeT | 4/8 (event pointer size) | Fixed |
| `isize` | IntPtr (not a `TdhInType` name) | 4/8 (event pointer size) | Fixed |
| `bool` | Boolean | 4 | Fixed |
| `f32` | Float | 4 | Fixed |
| `f64` | Double | 8 | Fixed |
| `Guid` / `GUID` | Guid | 16 | Fixed |
| `SystemTime` / `SYSTEMTIME` | SystemTime | 16 | Fixed |
| `WideStrRef` / `WideString` | UnicodeString | Variable | Null-terminated UTF-16 |
| `AnsiStrRef` / `AnsiString` | AnsiString | Variable | Null-terminated ANSI |
| `SidRef` / `Sid` / `SID` | Sid | Variable | 8 + sub_auth×4 |
| `WbemSidRef` | WbemSid | Variable | TOKEN_USER + SID |
| `CountedWideStrRef` | ManifestCountedString | Variable | 2-byte prefix + UTF-16 |
| `CountedAnsiStrRef` | ManifestCountedAnsiString | Variable | 2-byte prefix + ANSI |
| `CountedBinaryRef` | ManifestCountedBinary | Variable | 2-byte prefix + bytes |
| `u8 @ length(..)` / `fixed_length(..)` / `count_bytes(..)` | Binary | Variable | `&[u8]` |

---

## Test Coverage Summary

### Position Test Matrix

Tests verify correct parsing at each of these positions. Dynamic positions are the shapes and
linkage fixtures in `tests/differential_offline.rs`.

| Position | Description | Static Tests | Dynamic Tests |
|----------|-------------|:------------:|:-------------:|
| **First** | Offset 0 | Yes | Yes (`First`) |
| **After fixed (odd)** | After u8 prefix | Yes | Yes (`Fixed`) |
| **After fixed (even)** | After u16 prefix | Yes | After u32 only (`position_tests`) |
| **After variable (wide)** | After UnicodeString | Yes | Yes (`Dynamic`) |
| **After variable (ANSI)** | After AnsiString | Yes | Yes (`AnsiThenUnicode`, `UnicodeThenAnsi`, and the `AnsiString` shapes' `Sentinel`) |
| **Last field** | Final property | Yes | Yes (`Last`) |
| **Complex mixed** | Multiple variable + fixed | Yes | Yes (linkage fixtures) |
| **Arrays** | Static and `PropertyParamCount` | — | Yes (`ArrayFixed`, `ArrayParamCount`) |
| **Struct member** | Inside a `PropertyStruct` | — | Yes (`StructMember`) |

### Unit Tests by Category

| Category | Location |
|----------|----------|
| `FromProperty` / `FromPropertyRef` per type, truncation, strict type matching (`test_strict_*` rejections), string encoding (CP1252, UTF-16) | `src/parser.rs` (`tests`) |
| Parser mechanism (hints, arrays, structs, `Display`) and types no oracle reaches | `src/parser.rs` (`position_tests`) |
| Dynamic offsets and lengths against TDH | `tests/differential_offline.rs`, `tests/differential_tracelogging.rs` |
| `Timestamp` against `FileTimeToSystemTime` | `tests/differential_filetime.rs` |
| `TdhInType::fixed_size`, `from_raw` / `raw_value` | `src/types.rs` |
| Static positions | `tests/static_schema_positions.rs` |
| Static pointer-sized fields (32- and 64-bit events) | `tests/static_schema_pointer_size.rs` |
| Static sequential offset caching | `tests/static_schema_parser_struct.rs` |
| Multi-version `provider_schema!` | `tests/static_schema_multi_version.rs` |
| Static parse helpers, `FromBytes`, `tdh_types_compatible` | `src/static_schema.rs` (`tests`) |
| `event_schema!` field parsing (`@ tdh(...)`, offsets) | `etw-rs-macros/src/schema.rs` |

### Coverage Gaps

| Gap | Severity | Notes |
|-----|----------|-------|
| `NonNullTerminated*` sizing | Low | Rare (WPP/legacy). Readable only with a declared length or `PropertyParamLength`. |
| `UnicodeChar` / `AnsiChar` / `HexDump` | Low | Rare (legacy). No `FromProperty` impl. |
| `WbemSid` from 32-bit events | Low | Dynamic: sized correctly, decoded with a 64-bit `TOKEN_USER` header. Static `WbemSidRef`: sized and decoded with it. |
| 32-bit `Pointer` / `SizeT` offline | Low | `TdhLoadManifest` bakes in 8 bytes; covered live by `tests/32bit_events.rs` and `tests/mixed_bitness_events.rs`. |
