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

## [0.1.0] - 2026-10-23

Initial release.

[0.1.0]: https://github.com/originsec/etw-rs/releases/tag/v0.1.0
