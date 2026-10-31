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

### Fixed

- ANSI strings decode as UTF-8 when their out-type is `Utf8`, `Json` or `Xml`.

## [0.1.0] - 2026-10-23

Initial release.
