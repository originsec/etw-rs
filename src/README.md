# src/

Library source for etw-rs. The public API is re-exported from `lib.rs`.

## Modules

| File | Purpose |
|------|---------|
| `lib.rs` | Crate root — re-exports, `Error`/`Result`, utility functions |
| `event.rs` | `RawEvent` wrapper around Win32 `EVENT_RECORD`, extended data, timestamps |
| `parser.rs` | Dynamic TDH-based parser (`EventParser`, `Property`, `FromProperty` and `FromPropertyRef` traits) |
| `resolve.rs` | Provider name/GUID lookup (`provider_guid_from_name`, `provider_name_from_guid`) |
| `processing_context.rs` | Caches TDH `TRACE_EVENT_INFO` lookups by (GUID, discriminator, version, pointer size, classic flag) |
| `static_schema.rs` | Zero-cost compile-time parsing via `event_schema!` macro |
| `types.rs` | Core types: `TdhInType`, `TdhOutType`, `WideStrRef`, `AnsiStrRef`, `Guid`, `Sid`, `SystemTime` |

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `session/` | Trace session management (`Trace`, shared infrastructure) |
| `session/system_logger/` | System logger mode (group masks, PMC profiling, LBR) |

## Two Parsing Paths

1. **Dynamic** (`EventParser` + `ProcessingContext`): Runtime TDH lookup, ~20ns per property. Flexible, works with any provider.
2. **Static** (`event_schema!` macro): Compile-time offsets, ~10ns per property, ~1ns when every field is fixed width. Use for high-frequency events.

Per-property costs are rough averages over the [BENCHMARKS.md](../BENCHMARKS.md) table.

## Key Invariants

### Buffer Alignment
- UserData is **8-byte aligned** for all manifest and kernel system logger events (not WPP).
- `EVENT_RECORD.UserData` is a zero-copy direct pointer into the ETW buffer — no memcpy.
- Stack trace and LBR data must be 8-byte aligned for zero-copy `u64` address access.

### Schema Cache Key Packing
- Manifest events keyed by `(Provider GUID, Event ID, Version, pointer size)`.
- Classic (MOF) events keyed by `(Class GUID, Opcode, Version, pointer size)`.
- Event ID and Opcode are *alternative* discriminators — never both load-bearing — so they share one 16-bit slot, selected by `EVENT_HEADER_FLAG_CLASSIC_HEADER`. That flag is itself keyed, so one event's Id cannot collide with another's opcode.
- **Pointer size is part of the key.** TDH sizes `Pointer` and `SizeT` properties from the bitness of the event that triggered the lookup, so a 64-bit schema reused for a 32-bit event silently corrupts every offset after the first pointer. Keying on it makes the mismatch unrepresentable.
- Everything but the GUID packs into a single `u32` — `Discriminator(16) | Version(8) | flags at bits 24, 25, 27`; the GUID sits beside it in the `SchemaKey` struct. Changing the packing layout silently causes wrong schema lookups, so a `const` assertion pins it: widening the flag mask below bit 5 would land inside `Version` and stop the build.
- Only the two bitness bits and `CLASSIC_HEADER` are keyed; no other flag bit distinguishes schemas that reach this cache.
- **TraceLogging (self-describing) events cannot use this key** — their `Id`/`Version`/`Opcode` are ~always 0, so every event from a provider would collide. They live in a **separate cache** keyed by the raw `EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL` metadata blob **bytes** (the blob *is* the schema; the bytes, not a hash, so distinct schemas never collide). Pointer size still matters, so — mirroring the manifest key's bitness bit — the cache is split into a 32-bit and a 64-bit map. The blob is looked up borrowed so hits allocate nothing; the owned key is built only on a miss.
- **The caller states which regime applies**: `context.parser()` goes straight to the manifest/MOF cache, `context.tracelogging_parser()` to the blob-keyed one. A provider is one or the other as a fixed property, known when it is enabled, so neither path inspects extended data to work it out per event. A TraceLogging event reaching `parser()` would collide on an empty `EventDescriptor`; a `debug_assert!` catches that in debug builds and costs the release hot path nothing.

### Parser Cache State Machine
- Properties split into fixed prefix (cached once per schema) and variable suffix (recomputed per event).
- `current_offset` tracks the next unparsed byte. If it gets out of sync, all subsequent properties read garbage.
- The out-type is not cached in `PropertyLocation`. `get()` reads it from the schema only when `FromProperty::reads_out_type` says the type needs it for that in-type (today `String` on an ANSI string). Caching it in each location measured 4–9% slower on `get()`.
- A property's length is per element: its size is length × element count, whether each comes from the schema or from another property (`PropertyParamLength` / `PropertyParamCount`). Measured against TDH by the `ParamLengthAndCount` and `ParamLengthStaticCount` differential fixtures.

### ETW Truncation Handling
- ETW can omit trailing zero bytes for numeric fields. Always zero-extend when reading.
- ETW can drop the trailing NULL on the last string property. The parser uses remaining buffer bytes instead of scanning.

### Type System
- `TdhInType::fixed_size()` is the single source of truth for whether a property is fixed or variable length. Adding a new type requires updating this match, `from_raw()`, and — for a variable-length type — `compute_variable_element_size()` in `parser.rs`.
- A wide string in-type reads as `OsString` (owned, lossless), `WideStrRef` (borrowed) or `String` (lossy: an unpaired surrogate becomes U+FFFD, so distinct names can collide). `OsString` and `String` share `wide_string_payload` and `null_terminated_len`, so they differ only in that replacement; malformed counted prefixes are an error in both.
- The per-variant rustdoc on `TdhInType` carries each type's size rule, distilled from `_TDH_IN_TYPE` in the Windows SDK `<tdh.h>`. Read it before touching sizing code; `docs/tdh_type_coverage.md` tracks *implementation* status, not the wire format.
- `Binary` has no intrinsic size: it must declare a length or a `PropertyParamLength`. One with neither is a parse error in `compute_variable_element_size()`, whatever its `TdhOutType` — `<tdh.h>` implies an `Ipv6` out-type means 16 bytes, but no registered manifest relies on that.
- MOF (classic) providers use `class_guid` as `ProviderId`, not the provider GUID. The real provider GUID is in `TRACE_EVENT_INFO.ProviderGuid`.
