# ETW Benchmarks

This directory contains benchmarks comparing ETW parsing performance across multiple implementations.

## Overview

- **Rust benchmarks** (`live_events.rs`) - Benchmarks etw-rs static/get/get_hinted parsers, plus ferrisetw
- **C++ benchmarks** (`cpp_benchmarks.cpp`) - Benchmarks krabsetw, TdhFormatProperty, and TdhGetProperty
- **Export/replay system** - Capture live events once, replay in multiple languages

## Quick Start

### Run Rust Benchmarks

```bash
cargo bench --bench live_events
```

On first run this captures live ETW events (requires admin) and saves them
to `captured_*.bin` files. Subsequent runs replay from the saved files —
delete them to force a fresh capture.

Benchmarks:
- etw-rs static parser - handles all declared versions + dynamic fallback
- etw-rs get parser - schema lookup with learnt hints
- etw-rs get_hinted parser - schema lookup with fixed field hints (`#[doc(hidden)]`)
- etw-rs get parser on a subset (`etw-rs-get-subset`, Thread Start only) - five of ten
  fields, non-consecutive, to check a realistic access pattern still learns its hints
- ferrisetw

### Run C++ Benchmarks

`cargo bench --bench live_events` builds and runs these itself when cmake and MSVC
are available. To run them by hand, from the repository root (where the
`captured_*.bin` files from a prior `live_events` run are written):

```powershell
cmake -B benches\build -S benches
cmake --build benches\build --config Release
benches\build\Release\cpp_benchmarks.exe captured_process_events.bin
```

## Benchmark Results Summary

Run `cargo bench --bench live_events` on your own hardware to get representative
numbers. Results vary significantly across CPU architectures and Windows builds.

**Typical relative cost** (Process Start events, 16 properties; per-event time as a
multiple of the static parser's, from the [BENCHMARKS.md](../BENCHMARKS.md) table):

| Parser | Relative Cost |
|--------|---------------|
| **etw-rs (static)** | **1.0×** (baseline) |
| etw-rs (get) | ~1.5× |
| TdhFormatProperty | ~2.4× |
| krabsetw 4.4.9 | ~3.7× |
| TdhFormatProperty (naive) | ~5.5× |
| ferrisetw | ~11× |
| TdhGetProperty | ~17× |

**Key takeaways:**
- etw-rs static parser is the recommended API — handles all declared versions with near-static performance plus automatic dynamic fallback
- consistently ~10× faster than ferrisetw for events with variable-width properties
- `provider_schema!` macro generates everything from the schema definition

### Other Event Types

Similar speedups across Thread, File, Registry, and RPC events. See [BENCHMARKS.md](../BENCHMARKS.md) for full results.

## Architecture Comparison

### etw-rs Static Parser (recommended)
```
EVENT_RECORD → version match → concrete static parser → zero-copy field access → typed result
               ↳ One match at construction    ↳ Direct pointer arithmetic into UserData
               ↳ Dynamic fallback for          ↳ No allocations
                 unknown future versions       ↳ ~10-220ns per event (depends on field mix)
```

### etw-rs Dynamic Parser
```
EVENT_RECORD → schema → property lookup → parse by type → typed result
                         ↳ Learnt index hint; hash lookup by name on a miss
                         ↳ Type checking + parsing
                         ↳ ~75-330ns per event
```

## Why is etw-rs faster?

1. The static parser uses a compile-time schema
  - Property offsets computed at compile time where possible
  - No property name string comparisons needed

2. The dynamic parser does maximum upfront work
  - Fixed property offsets are cached once per event version
  - Property index access order is learnt at runtime and optimistically checked first
  - Property name comparisons use shorter UTF-8 strings

## Files

### Rust Benchmarks
- `live_events.rs` - Main benchmark suite (Rust), hand-timed
- Captures live events from:
  - Process Start (Microsoft-Windows-Kernel-Process)
  - Thread Start (Microsoft-Windows-Kernel-Thread)
  - File Create (Microsoft-Windows-Kernel-File)
  - Registry CreateKey (Microsoft-Windows-Kernel-Registry)
  - RPC Client Call (Microsoft-Windows-RPC)
  - TcpIp DataSent IPv6 (Microsoft-Windows-Kernel-Network), Rust only
- `parsing.rs` - Schema cache hits, per-type property parsing, sequential vs random access (criterion)
- `comparison.rs` - Mock events: schema cache vs direct TDH calls, `get()` vs `get_hinted()`; no admin (criterion)
- `parser_comparison.rs` - Independent field accessors vs the sequential caching parser (criterion)
- `rundown_parsing.rs` - etw-rs static parser vs ferrisetw over captured File rundown events; needs admin (criterion)
- `bench_util.rs` - Shared helpers (CPU pinning, power throttling), not a bench target
- `round_robin.py` - A/B driver for comparing two builds; see [Comparing two builds](#comparing-two-builds)

### C++ Benchmarks
- `cpp_benchmarks.cpp` - C++ benchmark implementation
- `captured_events.h` - Binary file reader for C++
- `CMakeLists.txt` - CMake build configuration
- `CPP_BENCHMARK_GUIDE.md` - Detailed C++ setup guide

### Export/Replay System
- Binary format: `"ETWCAP01"` + event count + serialised events
- Enables deterministic, reproducible benchmarks
- Same events tested across Rust and C++ implementations

## Event Types Benchmarked

1. **Process Start** - 16 properties (integers + strings)
2. **Thread Start** - 10 properties (mostly integers + pointers)
3. **File Create** - 7 properties (integers + long file path string)
4. **Registry CreateKey** - 6 properties (integers + registry path strings)
5. **RPC Client Call** - 9 properties (GUID + integers + strings)
6. **TcpIp DataSent IPv6** - 10 properties; two `win:Binary` addresses put themselves and
   the six fields after them onto the per-event sizing path. `etw-rs (static)` and
   `etw-rs (get)` only, reported outside the summary table
7. **Mixed Stream** - all six types above interleaved one per type, so per-schema
   caches are cold on almost every event. `etw-rs (get)` only

## Methodology

- **Harness**: The Rust arms are hand-timed by `measure` in `live_events.rs`, not by
  criterion, mirroring `benchmark_parser` in `cpp_benchmarks.cpp`
- **Warm-up**: 10 passes over the captured events before timing
- **Samples**: each arm is timed as two series of 1000 samples (`SAMPLES`), one
  through a direct call and one through `dyn FnMut`, and the series with the lower
  minimum is kept. A sample covers enough passes to last at least 250µs
  (`SAMPLE_TARGET_NS`), since `Instant` resolves to a 100ns QPC tick
- **Statistics**: Median per-event cost, the same statistic the C++ arms report
- **Passes**: The whole suite runs 3 times (`ETW_BENCH_PASSES`); each cell is the
  median pass, and cells whose passes disagree are listed as unstable
- **Event counts**: at least 100 events per type (`CAPTURE_MINIMUM`), captured for up
  to 120 seconds
- **Environment**: Pinned to the performance cores with power throttling disabled;
  Rust and C++ arms run in one invocation over the same events

## Comparing two builds

Running one build after the other cannot resolve a small parser change: a single
arm's per-run median drifts 5–13% between runs, and the drift is on a seconds
timescale, so pairing both arms inside one process does not help either. Use
`round_robin.py`, which runs a paired design:

- **ABBA ordering.** Base-then-candidate on odd rounds, candidate-then-base on even
  ones. The second arm of a back-to-back pair runs roughly 1% slow on a warmer
  machine; a fixed order hands that penalty to the same arm every round.
- **Per-run medians.** Each arm contributes its run's median, and the delta is the
  mean of the paired `cand/base` ratios. For the criterion targets the minimum is
  the worst choice: Linear sampling makes the low-iteration samples
  timer-quantised.
- **Enough pairs, with the standard error reported.** The per-pair ratio has a
  stdev of about 3.8%, so 15 pairs (the default) buys about ±1%. A delta within
  two standard errors is reported as `within noise`.

```bash
# Keep the baseline binary out of target/release/deps/ before rebuilding.
python benches/round_robin.py \
    --baseline  target/baseline-live_events.exe \
    --candidate target/release/deps/live_events-<hash>.exe \
    --filter "registry_create_key/etw-rs-static" \
    --pairs 15
```

The driver sets `ETW_BENCH_SKIP_CPP=1` and `ETW_BENCH_PASSES=1`, because the C++
arms and the built-in pass repetition add nothing to a Rust-vs-Rust comparison.
The machine must be otherwise idle. A concurrent build makes the standard error
jump several-fold, and that jump is the signal not to trust the delta.

## Contributing

To add a new event type, in `live_events.rs`:

1. Take the provider GUID and keywords from `example-providers/`, or declare them in a
   local module
2. Add a `provider_schema!` block for the static parser
3. Add a `get_captured_*_events()` that calls `load_or_capture_events` with its own
   `captured_*_events.bin`
4. Add a `preflight_*` check to `run_preflight_checks()`
5. Add one benchmark function per `PARSER_COLUMNS` arm, each timed with `measure`
6. Call them from a `*_benches()` function in `main`, and add the row to `event_types()`
7. For the C++ columns, add the file to `CPP_BIN_GROUPS` and the parsers to
   `cpp_benchmarks.cpp`
8. Run `cargo bench --bench live_events` and update `BENCHMARKS.md` from its
   markdown summary. The published table is a subset of the summary's columns plus
   a second krabsetw run, so merge the new row rather than pasting the table over
   it; `BENCHMARKS.md` states which columns come from where

## Further Reading

- [BENCHMARKS.md](../BENCHMARKS.md) - Detailed benchmark results
- [CPP_BENCHMARK_GUIDE.md](CPP_BENCHMARK_GUIDE.md) - C++ setup guide
- [etw-rs documentation](https://docs.rs/etw-rs) - Library documentation
