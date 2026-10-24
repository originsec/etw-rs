# etw-rs Design

## Overview

`etw-rs` is a Rust library for real-time Event Tracing for Windows (ETW) event parsing that prioritises direct control and performance.

## Design Philosophy

### 1. Minimal Abstraction

**Problem**: Existing Rust ETW libraries (e.g. `ferrisetw`) use abstractions over the Win32 API calls and structures. Each ETW feature must then be explicitly wrapped before use, and then official MSDN documentation is difficult to reference during troubleshooting.

**Solution**: Our API surface mirrors the Win32 ETW APIs closely:

```rust
// Win32 style with Rust safety

let mut trace = Trace::new("MySession")?;

trace.set_event_callback(|event, context| {
    // TdhGetEventInformation with cache
    let mut parser = context.parser(event)?;
    // "TdhGetProperty" - but with ergonomics and performance
    let pid: u32 = parser.get("ProcessID")?;
    Ok(())
});

// EVENT_TRACE_PROPERTIES_V2 setters, then StartTraceW
trace.set_log_file_mode(EVENT_TRACE_SECURE_MODE).start()?;
// EnableTraceEx2(EVENT_CONTROL_CODE_ENABLE_PROVIDER)
trace.enable_provider(kernel::process::GUID, kernel::process::keyword::PROCESS)?;

// CreateThread + OpenTraceW + ProcessTrace with ergonomics
trace.start_processing_thread()?;
```

**Key Principles**:
- Rust flavoured direct-ish mappings from Win32
  - APIs - `StartTraceW()` → `trace.start()`
  - Structures - `EVENT_RECORD` → `RawEvent`
- Configuration has sensible, documented defaults

### 1.a Escape Hatches

**Problem**: Sometimes your use case doesn't exactly match those already supported by the Rust API. Since we're (mostly) mirroring the Win32 APIs, you could theoretically make additional direct Win32 calls. This is primarily to support research and prototyping.

**Solution**: Direct access to underlying Win32 structures. See `examples/07_manual.rs`.

```rust
let mut trace = Trace::new("MySession")?;
// ...raw access to the EVENT_TRACE_PROPERTIES_V2 configuration
// SAFETY: fields that disagree with the crate's own settings are the caller's problem.
let _properties = unsafe { trace.properties_mut() };

trace.set_event_callback(|event, context| {
    // ...direct access to EVENT_RECORD.UserData
    let user_data = event.user_data();
    let _pid = u32::from_le_bytes(*user_data.first_chunk::<4>().unwrap());

    Ok(())
});

trace.start()?;
// ...the CONTROLTRACE_HANDLE value, for direct EnableTraceEx2 / ControlTraceW calls
let _session_id: Option<u64> = trace.session_id();
```

### 2. Performance

**Problem**: Parsing with the Trace Data Helper (TDH) Win32 API requires a lot of boilerplate, and it is easy to do it in a non-performant way.

**Solution**:
- Build on the `krabsetw` approach
  - TDH schema lookup with caching
  - Stateful parsing
- Additional schema pre-processing - also cached
  - Pre-calculate all fixed offset property locations
  - Pre-convert wide string property names to UTF-8
  - HashMap lookups rather than linear scans
  - Learn each event type's property access order, and try that index before hashing
- Compile-time static parsers (`event_schema!` / `provider_schema!`) for high-frequency events
- No hidden costs

```rust
// Schema-guided parsing
let mut parser = context.parser(event)?;

// Access to properties by name
let pid: u32 = parser.get("ProcessID")?;
let parent: u32 = parser.get("ParentProcessID")?;

// Variable-length fields can be borrowed from the event buffer instead of copied.
let image: WideStrRef<'_> = parser.as_ref("ImageName")?;
```

**Parser Internals**:
- Fixed property locations are pre-computed and cached alongside the schema
- Variable property locations are computed lazily and stored in a `Vec<PropertyLocation>`
- ETW payloads are densely packed; to reach a variable-length field, the variable-length fields before it must be sized first
- Fixed-size types use schema metadata; variable-size types (strings, SIDs) may require buffer scanning
- Once located, subsequent access is an O(1) index lookup

### 3. Just Enough Backwards Compatibility

- **Designed for Windows 11 and Windows Server 2022.**
- **Minimum supported: Windows 10, version 1703.** The crate always emits
  `EVENT_TRACE_PROPERTIES_V2`; on older Windows ETW silently reinterprets it as
  `EVENT_TRACE_PROPERTIES` and drops the V2 options, so 1703 is the floor for
  correct behaviour. Sub-1703 is unsupported.
- No Windows 7 or Vista — the kernel-logger model differs (single NT Kernel
  Logger vs. the Windows 8+ system-logger sessions this crate assumes).

Per-feature minimums (verified against Microsoft Learn):

| Feature | Minimum |
|---|---|
| Core: real-time tracing, TDH + static-schema parsing, provider enable, kernel stackwalks (`TraceStackTracingInfo`), PMC counters, capture-state rundown, classic system logger via group masks | Windows 10, 1703 (crate floor) |
| Provider event-ID / stackwalk filtering (`EnableTraceEx2`) | Windows 10, 1709 |
| Last Branch Record (LBR) tracing (`TraceLbrConfigurationInfo`) | Windows 10, 1903 (+ Skylake / Zen CPU) |
| Manifest system providers (`SystemProcessProviderGuid`, …) | Windows 11 / Server 2022 (build 20348) |

The crate performs no runtime OS-version detection — these minimums are a
documented contract. Above the 1703 floor, unsupported features surface an ETW
error (e.g. LBR on pre-1903) rather than degrading silently.

### 4. Safety By Design

Rust safety guarantees without runtime cost:
- Lifetimes ensure event data isn't accessed after the callback returns
- Callback lifetime tied to processing thread lifetime
- Type safety for GUIDs, handles, and enums
- RAII for automatic cleanup
- `unsafe` confined to FFI calls, reads of Win32 structures and `unsafe impl Send for Trace`, each with a `// SAFETY:` comment; the two public `unsafe fn`s, `RawEvent::from_ptr` and `Trace::properties_mut`, are opt-in raw escape hatches
- Panics in the event callback are caught before they reach the `extern "system"` boundary; what happens next is a caller-installed policy (`panic_policy.rs`)

## Architecture

### Module Organisation

> See [`src/README.md`](src/README.md) and [`src/session/README.md`](src/session/README.md) for module responsibilities and key invariants.

```
etw-rs/
├── src/
│   ├── lib.rs              # Public API surface, Error/Result
│   ├── event.rs            # RawEvent, Timestamp, extended data helpers
│   ├── parser.rs           # EventParser, FromProperty / FromPropertyRef traits
│   ├── processing_context.rs # ProcessingContext, EventSchema, TDH schema lookup
│   ├── resolve.rs          # Provider name/GUID lookup
│   ├── static_schema.rs    # Zero-cost compile-time parsing
│   ├── types.rs            # Core types: TdhInType, WideStrRef, Guid, Sid, etc.
│   └── session/            # Trace session management
│       ├── mod.rs          # Shared types (callbacks, statistics, clock resolution), re-exports
│       ├── trace.rs        # Trace - unified session type
│       ├── common.rs       # Shared types, FFI declarations, callback infrastructure
│       ├── enumerate.rs    # Enumerating the sessions running on the machine
│       ├── panic_policy.rs # Policy for panics escaping the event callback
│       └── system_logger/  # System logger mode (PERFINFO_GROUPMASK)
│           ├── mod.rs      # System logger impl methods on Trace
│           ├── stack_walk.rs # StackWalkData, LbrData, hook ID → GUID mapping
│           ├── masks.rs    # Performance group mask constants
│           └── profiling.rs # CPU sampling interval configuration
├── etw-rs-macros/          # event_schema! / provider_schema! proc macros
├── example-providers/      # Provider definitions for examples and tests
├── tools/generate-provider/ # CLI generating provider_schema! definitions from TDH/WMI metadata
├── examples/
├── tests/                  # Integration tests (see tests/README.md)
└── benches/                # Benchmarks (see benches/README.md)
```

### Core Components

#### 1. Trace (trace.rs)

Unified ETW trace session type. Supports both provider-based tracing via
`EnableTraceEx2` and system logger tracing via `PERFINFO_GROUPMASK`. System
logger mode is activated automatically when system logger APIs are called
(e.g. `set_events()`, `set_stack_walking()`). Maps to:
- `StartTraceW` - session creation (with extensions if system logger mode)
- `ControlTraceW` - session control (stop, query)
- `EnableTraceEx2` - provider enable/disable, and file rundown via the kernel rundown GUID (system logger mode)
- `OpenTraceW` / `ProcessTrace` - event consumption (integrated)
- `ETW_EXT_ENABLE_FLAGS` for enabling event groups (system logger mode)
- `ETW_EXT_STACKWALK_FILTER` for stack walk configuration
- `TraceSetInformation(TraceLbrConfigurationInfo)` + `TraceSetInformation(TraceLbrEventListInfo)` for LBR
- `TraceSetInformation(TracePmcCounterListInfo)` + `TraceSetInformation(TracePmcEventListInfo)` for PMC
- `TraceSetInformation(TraceSystemTraceEnableFlagsInfo)` / `TraceSetInformation(TraceStackTracingInfo)` for `update_events()` / `update_stack_walking()` on a running session
- `NtSetSystemInformation(SystemPerformanceTraceInformation)` for `enable_object_type_filter()`

**Key Design**:
- Single type for both provider-based and system logger sessions
- Real-time only: `EVENT_TRACE_REAL_TIME_MODE` is always set, and no log file is
  opened or consumed
- Owns the session (`CONTROLTRACE_HANDLE` value) and the consumer (`OpenTraceW` handle)
- RAII cleanup in `Drop`
- Callback-based event processing on a dedicated thread
- Methods mirror Win32 control codes
- System logger configuration is split by when ETW accepts it. Group masks
  (`set_events()`), stack walking and pool tag filters are passed atomically to
  `StartTraceW`, so they must be set before `start()`. LBR, PMC and object type
  filters (`enable_lbr()`, `enable_pmc()`, `enable_object_type_filter()`), the
  `update_*()` methods and `send_file_rundown_code()` act on a running session, so
  they require `start()` first — and `send_file_rundown_code()` also requires
  `start_processing_thread()`

#### 2. RawEvent (event.rs)

Zero-copy view of `EVENT_RECORD`. Provides:
- Header access (provider GUID, event ID, timestamp, etc.)
- User data access via `user_data()` slice
- Extended data access (SID, stack trace, process start key)

**Key Design**:
- `#[repr(transparent)]` over `EVENT_RECORD`, handed to the callback as
  `&RawEvent` pointing at ETW's own record
- Callback-based API (no iterator abstraction)
- Zero-copy access to event buffers

#### 3. EventParser (parser.rs)

Schema-guided event parsing with lazy evaluation and caching:

```rust
pub struct EventParser<'a> {
    data: &'a [u8],              // Raw event payload
    schema: &'a EventSchema,     // TDH schema (cached)
    cache: &'a mut ParserCache,  // Borrowed from ProcessingContext
    pointer_size: usize,         // 4 or 8, from the event header
    position: u32,               // How many get/as_ref calls this event has made
}

struct ParserCache {
    locations: Vec<PropertyLocation>,  // Parsed property offsets
    decoded_lengths: Vec<Option<u16>>, // Per-event memoised length/count values
    current_offset: usize,             // Next unparsed position
    first_variable_index: u32,         // First variable-length property
    fixed_prefix_size: usize,          // Pre-computed size of fixed properties
    learned_hints: Vec<u32>,           // Per call position: index resolved on earlier events
}
```

**Key Design Decisions**:
- Uses `Vec` for location cache (not `HashMap`) since property indices are always 0..N contiguous
- Capacity pre-allocated from schema's `top_level_property_count`
- `get()` / `as_ref()` take `&mut self`: they advance the location cache and the call position
- Learned hints: the Nth `get` on an event tries the index the Nth `get` resolved to on
  the previous event of that type. Every hint is checked against the property's name, so a
  stale hint costs one failed comparison and falls back to the hash lookup — never a wrong
  property. Hints and the fixed prefix survive between events; variable-length locations
  and decoded lengths are reset per event
- `get_hinted()` / `as_ref_hinted()` take a caller-supplied index hint; macro-generated code uses them
- `FromProperty` trait handles type conversion from raw bytes. Each Rust type accepts only
  the TDH in-types it represents — no cross-signedness or `u64`-as-`Timestamp` reads
- Cache borrowed from `ProcessingContext` - no interior mutability needed
- Each cache is pointer-size-specific: `first_variable_index` and `fixed_prefix_size` differ between 32-bit and 64-bit events, which is why pointer size is part of the schema cache key

**Type Naming Convention**:
| Type | Reference (zero-copy) | Owned |
|------|----------------------|-------|
| UTF-16 | `WideStrRef<'a>` | `WideString` |
| ANSI | `AnsiStrRef<'a>` | `AnsiString` |
| SID | `SidRef<'a>` | `Sid` |

All borrowed/reference types use the `Ref` suffix for explicit clarity.

**Access Patterns**:
| Pattern | Performance |
|---------|-------------|
| Same order on every event | Optimal - learned hint hits, no hashing |
| Sequential (0, 1, 2, ...) | Each variable-length field sized once |
| Sparse (only field 15) | Must size the variable-length fields before 15 |
| Out-of-order (10, then 5) | Field 5 already located |
| Repeated access | O(1) Vec index lookup |

#### 4. ProcessingContext (processing_context.rs)

Runtime schema discovery with caching. Each schema is paired with a `ParserCache`
for efficient parsing across events of the same type:

```rust
pub struct ProcessingContext {
    // Manifest/MOF events, keyed by the packed SchemaKey (pointer size included).
    cache: FxHashMap<SchemaKey, (EventSchema, ParserCache)>,
    // TraceLogging (self-describing) events. Id/Version/Opcode are ~always 0, so
    // they cannot share the SchemaKey space; keyed instead by the raw
    // EVENT_SCHEMA_TL metadata blob bytes. Split into a 32-bit and a 64-bit map,
    // since pointer size still sizes Pointer/SizeT properties.
    tlg_cache: [FxHashMap<Box<[u8]>, (EventSchema, ParserCache)>; 2],
}

pub struct EventSchema {
    buffer: AlignedSchemaBuffer,             // Raw TRACE_EVENT_INFO, 8-byte aligned
    property_count: u32,
    top_level_property_count: u32,
    property_names: Vec<Box<str>>,           // Pre-converted UTF-8 names
    name_to_index: FxHashMap<Box<str>, u32>, // O(1) lookup by name
}
```

**Key Features**:
- Schema looked up via `TdhGetEventInformation` on first encounter
- Cached by (provider GUID, discriminator, version, pointer size, classic flag)
  - Event ID and opcode are alternative discriminators sharing one slot, selected by `EVENT_HEADER_FLAG_CLASSIC_HEADER`
  - Pointer size is keyed because TDH sizes `Pointer`/`SizeT` properties from the bitness of the event that triggered the lookup — a shared schema would corrupt every offset after the first pointer
- Each schema paired with a `ParserCache` for efficient reuse
- Fixed-size property locations pre-computed once, reused across events
- Variable-length locations reset per event, computed lazily
- The cache needs no interior mutability or locking: the single-threaded ETW callback
  receives `&mut ProcessingContext`. Its `unsafe` is confined to the TDH calls and to
  reading `TRACE_EVENT_INFO` / `EVENT_PROPERTY_INFO` (unions and trailing arrays) out of
  the schema buffer

#### 5. Event ID Filtering (trace.rs)

Kernel-level event filtering via `EVENT_FILTER_DESCRIPTOR`:

```rust
// Only receive specific events - filtered by kernel, not callback
trace.enable_provider_ex(
    dns_client::GUID,
    TRACE_LEVEL_VERBOSE,
    ALL_KEYWORDS,
    0,
    Some(ProviderFilter::new().event_ids(EventIdFilter::include(&[3006, 3008]))),
)?;

// Combine event ID filtering with stack walk filtering
trace.enable_provider_ex(
    dns_client::GUID,
    TRACE_LEVEL_VERBOSE,
    ALL_KEYWORDS,
    EnableProperty::STACK_TRACE,
    Some(ProviderFilter::new()
        .event_ids(EventIdFilter::include(&[3006, 3008]))
        .stack_walk(EventIdFilter::include(&[3006]))),
)?;
```

More efficient than callback filtering since unwanted events never reach userspace.

#### 6. Extended Data (event.rs)

Access to `EVENT_HEADER_EXTENDED_DATA_ITEM` array:

```rust
// Enable extended data collection
trace.enable_provider_ex(
    provider_guid,
    level,
    keywords,
    EnableProperty::SID | EnableProperty::PROCESS_START_KEY | EnableProperty::STACK_TRACE,
    None,
)?;

// Access in callback - each returns Err(Error::NotPresent { kind }) when the item is absent
let sid: SidRef<'_> = event.sid()?;
let key: u64 = event.process_start_key()?;
let stack: StackTrace<'_> = event.stack_trace()?;

// Generic access for other extended data types
if let Some(data) = event.find_extended_data(extended_data_type::TS_ID) {
    let session_id = u32::from_le_bytes(data[..4].try_into().unwrap());
}
```

**Design**: Convenience methods for common types (SID, process start key, stack trace); generic `find_extended_data()` for manual parsing of others.

## API Design Decisions

### 1. Handles and Lifetimes

`Trace` owns both ETW handles: the session, as the `u64` `CONTROLTRACE_HANDLE` value
exposed by `session_id()`, and the `OpenTraceW` consumer handle. It also owns the
properties buffer, the boxed callback state the consumer thread dispatches into,
the enabled-provider list and any system logger configuration.

`RawEvent` is only ever handed out by reference, borrowed for the duration of one
callback invocation, so event data cannot outlive the buffer ETW owns.

### 2. Error Handling

```rust
#[non_exhaustive]
pub enum Error {
    Win32Error(u32),                                      // Display resolves the message
    InvalidParameter { parameter: &'static str, problem: ParameterProblem },
    ParseError { location: Option<Box<ParseLocation>>, message: Cow<'static, str> },
    PropertyNotFound { name: String, context: EventContext },
    UnsupportedVersion { version: u8, minimum: u8 },
    NotPresent { kind: u16 },                             // extended data item absent
    SchemaValidationError { context: EventContext, mismatch: Box<SchemaMismatch> },
    ProviderNotFound { name: String },                    // name not in the TDH registry
    ProviderAmbiguous { name: String },                   // name matches several registrations
    ProviderNotEnabled { provider: Guid, name: Option<String> },
    ThreadError { reason: ThreadFailure },                // processing thread spawn or exit
    LimitExceeded { operation: &'static str, limit: u32 },
    NtError(i32),                                         // NTSTATUS; Display resolves the message
}

pub type Result<T> = std::result::Result<T, Error>;
```

Variants carry their data as fields rather than pre-formatted strings, so callers
can branch on them. `ParseError`'s message is the exception: it describes byte-level
malformations that are logged, not branched on.

**Panic vs error boundary:** Methods panic when the call violates session state or call
order (not started, already processing, configuration changed after `start()`) — the
caller's code is wrong whatever the data. A single tuning value with a fixed documented
limit, such as a buffer size below 4 KB, may panic too: it is almost always a constant
in the caller's code. Anything about a collection's contents returns
`Err(InvalidParameter)`, because contents can come from runtime data: empty lists, too
many entries, duplicate entries, unrecognised values. A check that relates two tuning
values, such as maximum against minimum buffers, panics in `start()` once both are
final. Missing providers and Win32/NT failures are `Err` too.

### 3. Callback vs Iterator

**Decision**: Use callbacks, not iterators.

**Rationale**:
- `ProcessTrace` is inherently blocking and callback-based
- Iterators would require complex state machines
- Callbacks are more efficient and match Win32 semantics
- Users can implement their own buffering if needed

```rust
trace.set_event_callback(|event, context| {
    // Handle event
    Ok(())
});
```

### 4. String Encoding

ETW uses UTF-16 (wide strings) extensively. Design:
- Zero-copy borrowed views (`WideStrRef`, `AnsiStrRef`) into the event buffer
- Owned types (`WideString`, `AnsiString`) when the data must outlive the callback
- Wide strings convert to `OsString` by default — the static schema's owned accessor
  returns it — because Windows permits unpaired surrogates that `String` cannot hold
- Conversion to Rust `String` on request, via `FromProperty for String` or
  `WideStrRef::decode_utf16`

### 5. Win32 Bindings

**Decision**: The library declares its Win32 APIs through `windows-sys` 0.61, not the
`windows` crate.

**Rationale**:
- `windows` 0.62 is a heavy dependency to impose on consumers: ten crates, two of
  them proc macros, mostly WinRT machinery this crate never touches. `windows-sys`
  generates the same declarations as raw FFI and brings only `windows-link`
- The 0.100 generation isn't a usable alternative yet. It is only partially
  published (as of October 2026): `windows-core` and `windows-bindgen` 0.100 are out,
  `windows` and `windows-sys` 0.100 are not. Its new header-derived metadata also
  changes item names and constant types (e.g. `ERROR_*` become `i32`)
- Microsoft's guidance
  ([windows-rs#4867](https://github.com/microsoft/windows-rs/issues/4867)) is that
  both umbrella crates, `windows-sys` included, are a poor fit for reusable libraries:
  depend on the small shared crates, then generate any other required APIs locally
  with `windows-bindgen`. For ETW that means `windows-bindgen` for the declarations.
  Revisit that route once 0.100 settles
- No `windows-sys` type crosses the public API: error codes are plain integers, and
  `Guid` is self-contained. Changing how the bindings are produced is therefore not a
  breaking change
- `Guid` deliberately departs from that guidance. The `windows-core` guide says a
  library whose public API names `GUID` should depend on `windows-core` and use
  `windows_core::GUID`. But `windows-core` takes a semver-breaking bump with each
  windows-rs release, and two versions' `GUID`s are distinct types, so every bump
  would force a breaking etw-rs release. Interop goes through `Guid::to_u128` /
  `Guid::from_u128` instead; an optional `From` impl behind a version-named feature
  can be added if users ask

Tests, benches, examples and `generate-provider` keep `windows` 0.62 as a dev or tool
dependency for its conveniences. Consumers of the library never see it: the `lint`
step of `ci/check.ps1` fails if any Win32 crate other than `windows-sys` reaches the
normal dependency graph of `etw-rs`, `etw-rs-macros` or `example-providers`.

## Non-Goals

What this library explicitly does NOT aim to provide:
- High-level event abstractions (use wrapper crates)
- Event correlation or analysis
- Built-in filtering beyond Win32 capabilities
- ETL file consumption or writing (real-time sessions only)

## References

- [ETW Documentation](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing)
- [krabsetw](https://github.com/microsoft/krabsetw)
- [ferrisetw](https://github.com/n4r1b/ferrisetw)
- [windows-rs](https://github.com/microsoft/windows-rs)
