# etw-rs Performance Benchmarks

This document outlines the performance characteristics of etw-rs compared to other approaches.

## Running Benchmarks

```bash
# Headline comparison — Rust & C++
# C++ benchmarks (krabsetw, TdhFormatProperty, TdhGetProperty) are built and
# run automatically if cmake + MSVC are available; gracefully skipped otherwise.
# Events are captured live on the first run and saved to `.bin` files - requires admin.
# Subsequent runs load from disk, ensuring identical data across benchmark iterations.
# Delete the `captured_*_events.bin` files to force a fresh capture.
cargo bench --bench live_events

# Mock event benchmarks (synthetic data built from TDH schemas) — Rust only, no admin.
cargo bench --bench comparison
```

## Performance

Simple non-scientific performance comparison using an exemplar collection of ETW events on a single machine.

Each approach has performance trade-offs that are dependent on event shape, especially variable length property location(s) and sizes.
The comparison covers five event types:
- **Process Start** — 16 properties, a mixture of fixed and long variable width (3 wide strings, 1 SID)
- **RPC Client Call** — 9 properties, a mixture of fixed and short variable width
- **Registry CreateKey** — 6 properties, final two properties are variable width
- **File Create** — 7 properties, final property is variable width
- **Thread Start** — 10 properties, all fixed width

All measurements are per-event medians processing the same events on an Intel Core Ultra 7 268V:
| Event Type | etw-rs (static) | etw-rs (get) | ferrisetw 1.2.0 | krabsetw 4.4.9 | krabsetw 4.4.6 | TdhFormatProperty | TdhFormatProperty (naive) | TdhGetProperty |
|--|--|--|--|--|--|--|--|--|
| **Process Start** (16 properties) | **221ns** | 327ns | 2503ns | 815ns | 2522ns | 541ns | 1218ns | 3684ns |
| **RPC Client Call** (9 properties) | **127ns** | 227ns | 1213ns | 302ns | 771ns | 338ns | 481ns | 1755ns |
| **Registry CreateKey** (6 properties) | **70ns** | 133ns | 749ns | 233ns | 467ns | 548ns | 700ns | 1577ns |
| **File Create** (7 properties) | **85ns** | 145ns | 867ns | 258ns | 872ns | 294ns | 489ns | 1146ns |
| **Thread Start** (10 properties) | **9ns** | 75ns | 905ns | 279ns | 1055ns | 201ns | 849ns | 1482ns |

The table is assembled from `cargo bench --bench live_events` summaries rather than copied from one.
The harness reports a single `krabsetw` column, built from whatever `benches/krabsetw` holds:
**krabsetw 4.4.9** is that column with the default clone of krabsetw `master` (4.4.9, which includes
[#273](https://github.com/microsoft/krabsetw/pull/273) and
[#275](https://github.com/microsoft/krabsetw/pull/275)), and **krabsetw 4.4.6** comes from a second
run with `benches/krabsetw` checked out at `1b26db4`, the 4.4.6 release — so that column was not
measured in the same run as the rest of its row. The harness clones with `--depth 1`, so run
`git -C benches/krabsetw fetch --unshallow` before that checkout. The `etw-rs (get_hinted)` and
`TdhFormatProperty (cached)` columns the harness also prints are omitted.

Note: The Rust timings include the additional cost of converting Windows wide strings into Rust UTF-8 strings.

**Speedup vs ferrisetw (primary Rust alternative):**
- **Process Start:** 11.3× faster (static) / 7.7× faster (get)
- **RPC Client Call:** 9.6× faster (static) / 5.3× faster (get)
- **Registry CreateKey:** 10.7× faster (static) / 5.6× faster (get)
- **File Create:** 10.2× faster (static) / 6.0× faster (get)
- **Thread Start:** ~100× faster (static) / 12× faster (get)

Key Observations:
- etw-rs's static `provider_schema!` parser is consistently **~10× faster** than ferrisetw for events with variable-width properties, and exceptionally **~100×** faster for simple fixed width events. Automatically handles all declared event versions plus dynamic fallback for unknown future versions.
  - :warning: requires updates for each OS provider update to maintain performance, mitigated by `validate_all_schemas()` runtime check
- etw-rs's `get()` convenience parser provides **5–8× speedup** over ferrisetw (12× for fixed width events)

### Parsing Improvement Evolution

**TdhGetProperty (Vista+, deprecated)**
 - [Poor ergonomics](https://learn.microsoft.com/en-us/windows/win32/etw/using-tdhgetproperty-to-consume-event-data).
 - Inefficient for manifest-based providers as it requires scanning all event properties each time the API was called.

**TdhFormatProperty (Windows 7+)**
- [Poor ergonomics](https://learn.microsoft.com/en-us/windows/win32/etw/using-tdhformatproperty-to-consume-event-data).
- :warning: Allows a single pass through the event's properties - but implicitly converts all data into wide strings if naively called.
- Can be performant with care.

**krabsetw (2016)**
- [excellent ergonomics](https://github.com/microsoft/krabsetw/blob/master/examples/NativeExamples/user_trace_001.cpp) for standard use cases
- Adds a schema cache, so each event type's schema is fetched once rather than per event.
- No locks since ETW's processing architecture is single-threaded.
- Expressive predicate based filtering.
- ~~:warning: O(N²) per-event property cache miss scan! This optimisation is for the uncommon pattern of **repeated** access of the same property in an event, but actually makes the common case much slower.~~
- ~~:warning: wstring temporaries for long property names - per event instead of per schema.~~
- These issues were [easily resolved](https://github.com/microsoft/krabsetw/pull/275) though - allowing performance to approach etw-rs.

**ferrisetw (2021)**
- Rust port of krabsetw with similar performance.
- Converts ETW's wide strings to Rust UTF-8 strings.
- :warning: String clone per property visited.
- :warning: mutex lock per property access. ETW processing is single-threaded - the mutex is never contended.
- These issues are [easily resolved](https://github.com/n4r1b/ferrisetw/pull/161), though performance is still well behind etw-rs.

**etw-rs (2026)**
- Excellent ergonomics for [standard use cases](examples/03_typical_trace.rs) and [researchers](examples/07_manual.rs). :wink:
- Native ETW filtering only.
- No locks since ETW's processing architecture is single-threaded.
- `provider_schema!` static parser handles all declared versions with compile-time offsets, plus automatic dynamic fallback for unknown future versions. Runtime `validate_all_schemas()` check detects schema changes in new OS versions.
- Dynamic parser pre-converts wide string property names to UTF-8 and caches these alongside the schema.
- Dynamic parser pre-calculates offsets for all fixed offset properties and caches these alongside the schema.
- Dynamic parser learns, per schema, which property each `get()` call position resolved to, and checks that index first; a miss falls back to the name lookup and records the answer for the next event.
