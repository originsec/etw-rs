# C++ Benchmark Setup Guide

This guide explains how to build and run the C++ benchmarks (krabsetw, TdhFormatProperty, TdhGetProperty) against the same captured events used by the Rust benchmarks.

## Overview

The Rust benchmarks (`cargo bench --bench live_events`) capture live ETW events and save them to `captured_*.bin` files in the repository root. The C++ benchmarks replay these same events, enabling apples-to-apples cross-language comparison.

`cargo bench --bench live_events` already builds and runs the C++ benchmarks itself (if cmake and MSVC are available) and folds their results into its combined table. The manual steps below are only needed to run the C++ harness on its own. Set `ETW_BENCH_SKIP_CPP=1` to skip the C++ arm.

## Quick Start

```powershell
# 1. Capture events (first run requires admin; subsequent runs use saved files)
# From the repository root
cargo bench --bench live_events

# 2. Build C++ benchmarks
cmake -B benches\build -S benches
cmake --build benches\build --config Release

# 3. Run C++ benchmarks (from the repository root, where the .bin files are)
benches\build\Release\cpp_benchmarks.exe captured_process_events.bin
```

## Step 1: Capture Events

Run the Rust benchmarks to capture live events and save to `.bin` files:

```bash
cargo bench --bench live_events
```

First run captures live events (requires admin) and saves to disk.
Subsequent runs load from disk automatically. Delete `captured_*_events.bin`
to force a fresh capture.

This produces, in the repository root:
- `captured_process_events.bin` - Process Start events (v4 only)
- `captured_thread_events.bin` - Thread Start events
- `captured_file_events.bin` - File Create events
- `captured_registry_events.bin` - Registry CreateKey events
- `captured_rpc_events.bin` - RPC Client Call events (v1 only)
- `captured_network_ipv6_events.bin` - TcpIp DataSent IPv6 events (Rust benchmarks only)

Capture stops once at least 100 events of that type have arrived, or after 120 seconds.
100 is a floor, not a cap: high-rate providers often deliver many more.

## Step 2: Build C++ Benchmarks

### Option A: Using CMake (Recommended)

```powershell
cd benches

# krabsetw is enabled automatically if cloned into benches\krabsetw
cmake -B build
cmake --build build --config Release

# With krabsetw elsewhere
cmake -B build -DUSE_KRABSETW=ON -DKRABSETW_DIR=path\to\krabsetw
cmake --build build --config Release
```

### Option B: Using MSVC Directly

```powershell
cd benches

# Without krabsetw
cl /EHsc /std:c++17 /O2 /W4 cpp_benchmarks.cpp tdh.lib advapi32.lib

# With krabsetw
cl /EHsc /std:c++17 /O2 /W4 /DHAVE_KRABSETW /DUNICODE /D_UNICODE /I path\to\krabsetw\krabs cpp_benchmarks.cpp tdh.lib advapi32.lib
```

### Installing krabsetw (Optional)

krabsetw is Microsoft's C++ ETW library. `cargo bench --bench live_events` shallow-clones
it into `benches\krabsetw` if it is missing. To clone it yourself (auto-detected by CMake):

```powershell
git clone --depth 1 https://github.com/microsoft/krabsetw.git benches\krabsetw
```

## Step 3: Run Benchmarks

```powershell
# From the repository root
benches\build\Release\cpp_benchmarks.exe captured_process_events.bin
```

The event type is chosen from the file name, which must contain `process`, `thread`,
`file`, `registry` or `rpc`. With no argument it reads `captured_process_events.bin`
from the current directory.

## Step 4: Compare with Rust Results

`cargo bench --bench live_events` prints Rust and C++ results in one combined table.
See [BENCHMARKS.md](../BENCHMARKS.md) for the published results.

The Rust benchmarks include:
- **etw-rs (static)** — compile-time schema, zero-copy parsing
- **etw-rs (get_hinted)** — dynamic parsing with index hints
- **etw-rs (get)** — dynamic parsing by field name
- **ferrisetw** — Rust TDH wrapper (third-party)

The C++ benchmarks include:
- **TdhFormatProperty** — Windows API, sequential walk, schema fetched per event
- **TdhFmtProp (cached)** — as above, with a keyed schema cache
- **TdhFmtProp (naive)** — TdhFormatProperty called for every field
- **TdhGetProperty** — Windows API, random access by name
- **krabsetw** — Microsoft's C++ ETW library (optional)

## Binary Format Details

Each file has this format (little-endian):

```
Header:
  magic: "ETWCAP01" (8 bytes)
  event_count: uint64_t

For each event:
  total_size: uint32_t
  record_blob_len: uint32_t
  record_blob: [uint8_t; record_blob_len]  // EVENT_RECORD; only its EVENT_HEADER is read
  user_data_offset: uint64_t
  user_data_len: uint64_t
```

The `record_blob` contains a complete EVENT_RECORD structure at the start, followed by user data.

## Implementation Notes

For relative performance, see [BENCHMARKS.md](../BENCHMARKS.md).

### TdhFormatProperty
- **Sequential iteration**: Walks properties in order (0, 1, 2, ...)
- **Direct reads for fixed-size fields**: Integers are copied straight from the payload; TdhFormatProperty is only called for strings and SIDs
- **Naive variant**: Calls TdhFormatProperty for every field, returning all types (integers, strings, GUIDs) as UTF-16 text

### TdhGetProperty
- **Random access**: Access properties by name
- **Returns raw bytes**: Integers are read into typed values; strings stay UTF-16; SIDs are converted with `ConvertSidToStringSidW`

### krabsetw
- **Built on TDH**: Uses TdhGetEventInformation for schemas, then parses the payload itself
- **Schema caching**: Caches schemas via `schema_locator`

## Files

- `captured_events.h` - C++ header with `EventFileReader` class
- `cpp_benchmarks.cpp` - Complete benchmark implementation
- `CMakeLists.txt` - CMake build configuration
- `captured_*.bin` - Binary event files (generated by Rust, in the repository root)

## Troubleshooting

**"Error: Failed to open file: captured_process_events.bin"**
- Run `cargo bench --bench live_events` first (requires admin on first run)
- Run from the repository root, or pass the path to the file

**"krabsetw not found. Set KRABSETW_DIR or clone it into benches/krabsetw."**
- Either clone krabsetw into `benches\krabsetw` or set `-DKRABSETW_DIR=path\to\krabsetw`
- Or build without krabsetw: the TDH benchmarks will still run

**Compilation errors with TDH**
- Make sure you're using the Windows SDK with TDH support
- Link `tdh.lib` and `advapi32.lib`

**Performance seems wrong**
- Make sure you built in Release mode: `cmake --build benches\build --config Release` (from the repository root)
- Run benchmarks multiple times to ensure consistent results
- Close other applications to reduce system noise
