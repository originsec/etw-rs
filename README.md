# etw-rs

Low-level Rust bindings for Event Tracing for Windows (ETW) with minimal abstraction.

## Overview

`etw-rs` provides a thin Rust wrapper around the Win32 ETW APIs and a performant wrapper around the Win32 TDH APIs.

This gives you near direct control over ETW session management and event consumption behind a safe API.

## Features

- **Minimal Abstraction**: API surface closely mirrors Win32 ETW APIs
- **Performance**: Efficient event parsing options
  - **Dynamic Schema Parser**: Runtime TDH schema guided parsing (<100ns per field)
  - **Static Schema Parser**: Zero-cost field access with compile-time offsets for known versions (<50ns per field)
- **Direct Control**: Full access to ETW session configuration and event buffers
- **Safety**: a safe API over the Win32 calls. Internally, `unsafe` is confined to FFI calls, reads of Win32 structures and `unsafe impl Send for Trace`, each with a `// SAFETY:` comment; the two public `unsafe fn`s, `RawEvent::from_ptr` and `Trace::properties_mut`, are opt-in raw escape hatches

## Requirements

- Windows 11 or later (design target); Windows 10, version 1703 is the minimum
  supported floor. Some features require later builds — see the per-feature
  support matrix in [DESIGN.md](DESIGN.md#3-just-enough-backwards-compatibility).
  - Not yet tested on ARM64
- Administrator for kernel providers and system logger sessions (including the
  Quick Start below); `Performance Log Users` membership is enough only for
  user-mode providers
- Rust 1.88 or later

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
etw-rs = "0.1"
```

To use the static schema parser, generate provider definitions with the
companion `generate-provider` CLI:

```bash
cargo install etw-rs-generate-provider
generate-provider Microsoft-Windows-Kernel-Process
```

## Quick Start

```rust
use etw::{Guid, Trace};

// Microsoft-Windows-Kernel-Process provider
const PROCESS_GUID: Guid = Guid::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716);

fn main() -> etw::Result<()> {
    let mut trace = Trace::new("MyTraceSession")?;
    trace.start()?;
    const PROCESS: u64 = 0x10;
    trace.enable_provider(PROCESS_GUID, PROCESS)?;

    trace.set_event_callback(|event, context| {
        let mut parser = context.parser(event)?;
        let pid: u32 = parser.get("ProcessID")?;
        println!("Process ID: {pid}");
        Ok(())
    });

    trace.start_processing_thread()?;
    sleep(Duration::from_secs(10));
    Ok(())
}
```

See the [`examples/`](examples/) directory for more detail.

## API Mapping

This table shows how `etw-rs` APIs map to the underlying Win32 ETW functions.

Compared to C/C++ Win32 development, you should be calling equivalent APIs in roughly the same order.

| etw-rs | Win32 API |
|--------|-----------|
| `Trace::new()` | Initialises `EVENT_TRACE_PROPERTIES_V2` |
| `Trace::start()` | `StartTraceW` (with extensions if system logger mode) |
| `Trace::enable_provider()` | `EnableTraceEx2` |
| `Trace::enable_provider_ex()` | `EnableTraceEx2` with `ENABLE_TRACE_PARAMETERS` and optional `EVENT_FILTER_DESCRIPTOR` |
| `Trace::capture_state()` | `EnableTraceEx2(EVENT_CONTROL_CODE_CAPTURE_STATE)` |
| `Trace::set_events()` | Builds `ETW_EXT_ENABLE_FLAGS` for `StartTraceW` (system logger mode) |
| `Trace::set_enable_flags()` | Sets `EnableFlags` directly in `EVENT_TRACE_PROPERTIES` for `StartTraceW` (system logger mode) |
| `Trace::set_stack_walking()` | Builds `ETW_EXT_STACKWALK_FILTER` array for `StartTraceW` (system logger mode) |
| `Trace::set_pool_tag_filter()` | Builds `ETW_EXT_POOLTAG_FILTER` for `StartTraceW` (system logger mode) |
| `Trace::send_file_rundown_code()` | `EnableTraceEx2(EVENT_CONTROL_CODE_ENABLE_PROVIDER)` with kernel rundown GUID (system logger mode) |
| `Trace::enable_lbr()` | `TraceSetInformation(TraceLbrConfigurationInfo)` + `TraceSetInformation(TraceLbrEventListInfo)` (system logger mode) |
| `Trace::enable_pmc()` | `TraceSetInformation(TracePmcCounterListInfo)` + `TraceSetInformation(TracePmcEventListInfo)` (system logger mode) |
| `Trace::enable_object_type_filter()` | `NtSetSystemInformation(SystemPerformanceTraceInformation)` with `EventTraceObjectTypeFilterInformation` (system logger mode) |
| `Trace::set_event_callback()` | Sets `EventRecordCallback` in `EVENT_TRACE_LOGFILE` |
| `Trace::start_processing_thread()` | `OpenTraceW` + `CreateThread` + `ProcessTrace` |
| `Trace::query()` | `ControlTraceW(EVENT_TRACE_CONTROL_QUERY)` |
| `Trace::stop()` | `ControlTraceW(EVENT_TRACE_CONTROL_STOP)` |
| `ProcessingContext::parser()` | `TdhGetEventInformation` - but cached |
| `EventParser::get()` | `TdhFormatProperty` - but nicer and faster |


## Documentation

- [API Documentation](https://docs.rs/etw-rs)
- [Design Document](DESIGN.md) - Architecture and design decisions
- [Contributing](CONTRIBUTING.md) for development setup, code quality requirements, and contribution guidelines.

## TODO

### Features
- [ ] Add TraceLogging support
  - Schema cache must key on the event's schema blob — TraceLogging events can all share EventId=0/Version=0
- [ ] Add system logger User Mode Global Logger (UMGL) support
- [ ] Add support for attaching to existing trace sessions (e.g. Security-Auditing)
- [ ] Add SYSTEM_MEMORY_POOL_FILTER_ID schematized filter support


## Acknowledgments

Inspired by:
- [krabsetw](https://github.com/microsoft/krabsetw) - Microsoft's C++ ETW library
- [ferrisetw](https://github.com/n4r1b/ferrisetw) - Rust port of krabsetw
- [perfview](https://github.com/microsoft/perfview) - Performance profiling with ETW
- [windows-rs](https://github.com/microsoft/windows-rs) - Rust Windows API bindings

## Resources

- [ETW Documentation](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing)
- [Consuming Events](https://learn.microsoft.com/en-us/windows/win32/etw/consuming-events)
- [Controlling Sessions](https://learn.microsoft.com/en-us/windows/win32/etw/controlling-event-tracing-sessions)
- [Windows Providers](https://github.com/jdu2600/Windows10EtwEvents)
