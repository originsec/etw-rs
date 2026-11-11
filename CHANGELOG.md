# Changelog

## [Unreleased]

### Added

- `ProcessingContext::tracelogging_parser()` for TraceLogging events.
- `get::<OsString>()` decodes wide strings losslessly.
- `WideStrRef::{starts_with,ends_with,contains}_ascii_ignore_case()`.
- `Trace::set_flush_timer_ms()` for sub-second realtime delivery, via the
  undocumented `EVENT_TRACE_USE_MS_FLUSH_TIMER` mode bit.

### Changed

- **Breaking:** static wide-string accessors return `OsString`.
- **Breaking:** `get::<String>()` decodes wide strings lossily.
- **Breaking:** `Sid`'s fields are private; use `Sid::new` and its accessors.
- **Breaking:** an invalid SID is read rather than rejected. `is_valid()` reports
  it, and it displays as hex, as `TdhFormatProperty` does.
- SID authorities above `u32::MAX` display in hex, as Windows does.

### Fixed

- ANSI strings decode as UTF-8 when their out-type is `Utf8`, `Json` or `Xml`.
- An invalid SID, or a `WbemSid` carrying no SID, no longer misplaces the
  properties after it. The latter reads as missing (`is_missing()`) and displays
  as `0`.
- `array_elements()` returns an error instead of panicking on a truncated SID.

## [0.1.0] - 2026-10-23

Initial release.
