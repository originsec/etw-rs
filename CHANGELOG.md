# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `ProcessingContext::tracelogging_parser()` and `get_or_lookup_tracelogging()` decode
  TraceLogging (self-describing) events through a cache keyed by each event's
  `EVENT_SCHEMA_TL` metadata blob. Every event from a TraceLogging provider has
  `EventDescriptor.Id` 0, so `parser()` would decode them all with the first
  event's schema; use `tracelogging_parser()` for TraceLogging providers.
- `RawEvent::tracelogging_metadata()` returns that metadata blob.
- `WideStrRef::to_os_string()`, `WideString::to_os_string()` and `FromProperty for OsString`
  convert UTF-16 without loss.
- `@ out(String | Xml | Json | Utf8)` field annotation for ANSI string fields in
  `event_schema!` and `provider_schema!`. `generate-provider` emits it from the manifest, and
  `validate_schema` fails a field whose annotation disagrees
  (`SchemaMismatch::FieldOutType`).
- `TdhOutType::ansi_code_page()` maps an out-type to the code page an ANSI string is in.
- `WideStrRef::starts_with_ascii_ignore_case()`, `ends_with_ascii_ignore_case()` and
  `contains_ascii_ignore_case()` match a borrowed UTF-16 string without allocating, for
  filtering on names such as file paths.

### Changed

- **Breaking:** `FromProperty::from_property` takes the property's `TdhOutType` as a third
  argument. An implementation that reads it must override the new
  `FromProperty::reads_out_type`, or the parser passes it `TdhOutType::Null`.
- **Breaking:** the owned accessor `event_schema!` generates for a wide-string field
  (`WideStrRef`, `CountedWideStrRef`) returns `OsString` rather than `String`. Windows permits
  unpaired surrogates in file names, registry keys and similar identifiers; the `String`
  accessor rejected such events. Use the `_ref()` accessor with `decode_utf16()` or
  `to_string_lossy()` for a `String`.
- **Breaking:** `get::<String>()` on a wide-string property (`UnicodeString`,
  `NonNullTerminatedString` and the counted string in-types) decodes lossily: an unpaired
  surrogate becomes U+FFFD rather than failing the read. Distinct names can therefore
  collide; read an `OsString` (owned, lossless) or borrow a `WideStrRef` when the exact
  value matters. `FromProperty for WideString` and `Property::to_wide_string()` are
  removed — copy a `WideStrRef` into a `WideString` when the UTF-16 code units must
  outlive the event.
- `get::<OsString>()` decodes straight from the event buffer instead of copying into a
  `WideString` first, one allocation fewer per call.
- `AnsiStrRef::decode(CP_UTF8)` decodes without a round trip through Win32 and UTF-16,
  2–3.7× faster. Results and errors are unchanged.

### Fixed

- ANSI string properties decode by their TDH out-type: `Utf8`, `Json` and `Xml` as UTF-8,
  anything else with the ANSI code page. Every ANSI string used to be decoded with `CP_ACP`,
  so UTF-8 fields such as Kernel-EventTracing event 31 `EventName` came back mis-decoded or
  as an error. Applies to `get::<String>()`, the static owned accessor and `Property`'s
  `Display`.
- A wide string with an odd byte length no longer loses its last character when decoded
  from a borrow (`as_ref::<WideStrRef>()`, the static wide accessors, `get()`): the final
  two bytes straddle a code unit and a stray byte, and were mistaken for a terminator.
  `41 00 42 00 00` decoded as `"A"` rather than `"AB"`.

## [0.1.0] - 2026-10-23

Initial release.

[0.1.0]: https://github.com/originsec/etw-rs/releases/tag/v0.1.0
