# examples/

Numbered examples demonstrating etw-rs features. All require Administrator privileges for kernel providers.

Run with:
```bash
cargo run --example 01_simple_trace
```

## Examples

| Example | What It Shows |
|---------|---------------|
| `01_simple_trace` | Basic `Trace` setup, provider enablement, TDH parsing |
| `02_static_schema` | Compile-time parsing via `provider_schema!` macro |
| `03_typical_trace` | Production-style trace with multiple providers |
| `04_extended_data` | Extended data items (SID, process start key, stack traces) |
| `05_delayed_stack_walks` | Deferred stack walk collection |
| `06_rundown_events` | Rundown events for process/assembly state enumeration |
| `07_manual` | Low-level Win32 API usage (direct `EnableTraceEx2`, raw UserData) |

### System Logger Mode

| Example | What It Shows |
|---------|---------------|
| `10_simple_system_trace` | Basic system logger with legacy `set_enable_flags()` |
| `11_typical_system_trace` | GroupMask mode with stack walking on process start events |
| `12_last_branch_records` | LBR (Last Branch Record) capture on sampled CPU profile events |
| `13_system_logger_rundown` | System logger rundown: automatic DC_START/DC_END and explicit file rundown |
| `14_system_providers` | System providers (keyword enablement, `SYSTEM_LOGGER_MODE`) alongside a manifest provider |
| `15_combined_trace` | System logger GroupMasks and a manifest provider in a single session |

## Notes for Contributors

- Examples may use a file-level `#![expect(clippy::print_stdout, …, reason = "...")]` (plus `unwrap_used`/`expect_used` where needed) — this is acceptable.
- Each example should be self-contained and runnable with `cargo run --example`.
