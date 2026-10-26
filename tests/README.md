# Tests

Integration and unit tests for etw-rs.

## Running Tests

```bash
# Fast pass: unit + integration tests, ignoring tests tagged #[ignore = "slow"].
cargo test --workspace

# Full pass including the slow tests. CI runs this form.
cargo test --workspace --lib --tests -- --include-ignored
```

These tests need Administrator. `Performance Log Users` membership is **not**
enough — it covers session creation and user-mode providers but not the kernel
providers or system-logger sessions most of the suite depends on (details below).
CI always runs elevated. Without Administrator each test binary that includes
`tests/common` fails a single `common::can_enable_kernel_provider` test, because
the alternative — passing with most of the coverage silently gone — is worse
than a visible failure:

```bash
# Accept the reduced coverage deliberately:
ETW_RS_ALLOW_SKIPS=1 cargo test --workspace
```

Under that variable the privilege-gated work soft-skips via
`common::skip_or_panic` and the rest of the suite runs. The `Skipping:` lines it
prints are **not** visible in a default run — libtest captures the stdout of
passing tests — so add `--nocapture` to see which operations were skipped.

The suites that need no privilege (`static_schema_*`, `validate_*`,
`differential_offline`, `differential_filetime`) do not include `common/mod.rs`
and pass without the variable.

The guard probes **enabling a kernel provider**, because that is the narrowest
capability separating a host that can run these tests from one that only looks
able. Measured on four token shapes:

| token | `is_elevated()` | realtime session | enable kernel provider |
|---|---|---|---|
| elevated Administrator | true | starts | **allowed** |
| Safer-restricted (`runas /trustlevel:0x20000`) | true | starts | denied |
| medium IL + `Performance Log Users` | false | starts | denied |
| plain unprivileged | false | denied | denied |

`Performance Log Users` is worth understanding, since it is easy to assume it is
enough. It grants session creation and user-mode providers — `dns_client` really
does pass on such a host — but **not** kernel providers and not
`MSNT_SystemTrace`, so `kernel_process`, `field_types`, `kernel_file` and every
system-logger suite still skip. A probe that only created a session would pass on
that host and prove nothing; the elevation flag is worse, since a restricted token
reports `true`.

Not probed, deliberately: `MSNT_SystemTrace` (Windows caps concurrent
system-logger traces at 8 with 2 reserved, and a machine at that cap would fail
the probe in every binary while blaming privilege — suite-wide flakiness was
the worse trade), and `SeSystemProfilePrivilege`, so PMC and LBR can still skip on
`ERROR_NOT_ALL_ASSIGNED`.

An elevated host short-circuits before probing, so CI and ordinary dev boxes
create no session. The price of that shortcut is row two: a token claiming
elevation is believed. Note also that a `Performance Log Users` host fails the
guard even in `dns_client`, which would have run — `ETW_RS_ALLOW_SKIPS=1` is the
answer there.

For related reasons `skip_or_panic` keys off the returned Win32 code rather than
the token — except under `CI`, where privilege is guaranteed and a privilege
error is therefore a defect that must not be skipped.

Hardware is not guaranteed anywhere, CI included. `lbr.rs` therefore also skips,
outside `skip_or_panic`, when `enable_lbr` returns `ERROR_NOT_SUPPORTED`
because the CPU lacks LBR. On a hosted runner that depends on the CPU it lands
on, so a green run does not prove LBR was exercised.

`session_enumeration.rs` likewise skips outside `skip_or_panic`, CI included,
when it cannot start a session with an over-long name or log path, or cannot
build the over-long directory tree. A green CI run does not prove those
over-the-cap cases ran.

The lib tests of `query_sessions`' growth paths (`src/session/enumerate.rs`) need
more than one session in view, and a non-admin token's view is filtered — 2 of
61 sessions on one host, sometimes 1. They skip only after failing *and*
re-querying shows at most one visible, and never under `CI`, so `unit` stays
runnable without Administrator.

## Conventions

- `#[ignore = "slow"]` is the only ignore reason, and it means what it says:
  more than ~10 s. Everything else runs by default, so `cargo test --workspace`
  is the honest fast pass rather than an arbitrary subset. Currently tagged:
  `system_logger_rundown::test_system_logger_file_rundown_and_filename_parsing`
  and `userdata_alignment::test_userdata_alignment`.
- Being over the bar is not on its own a reason to tag. The curated
  provider-generation tests cover the shapes most likely to break the generator,
  so they run every time even though `generate_provider::curated_windows_kernel_trace`
  takes ~23 s. Weigh what the test catches against what it costs, rather than
  timing it alone.
- Before adding `#[ignore]` for any other reason, don't. If a test is awkward to
  run by default, that is usually a fact about the test worth fixing. CI enforces
  this: any `#[ignore]` whose reason is not `"slow"` fails the `docs` job.
  `#[cfg_attr(miri, ignore = "…")]` is exempt — it names the Win32 call that
  would abort the Miri run, and is not an exclusion from the normal pass.
- `#[serial_test::serial(system_logger)]` is applied to tests that use the
  MSNT_SystemTrace (system-logger mode), so that we don't exhaust the system
  logger slots — Windows allows 8 concurrent, 2 of them reserved.
  Manifest-provider tests run in parallel as usual.

  Two separate things keep those tests apart, and it is worth knowing which is
  which. The `serial` key is an **in-process** lock, so it only orders tests
  inside one test binary; `serial_test`'s cross-process `file_locks` feature is
  not enabled and `#[file_serial]` is not used anywhere. Tests in *different*
  binaries stay apart only because `cargo test` runs test binaries one at a
  time. That means the safety depends on the runner: a runner that executes
  tests from different binaries concurrently (`cargo nextest`, which also gives
  each test its own process and so voids the in-process lock entirely) would put
  every system-logger test in flight at once and they would fail with
  `ERROR_NO_SYSTEM_RESOURCES`. Adopting one means grouping these tests in the
  runner's own configuration — for nextest, a `test-group` with
  `max-threads = 1`.
- The `common` module (`tests/common/mod.rs`) provides `skip_or_panic` for
  the soft-skip pattern. Imported per file with
  `#[path = "common/mod.rs"] mod common;`. Including it also brings in the
  `can_enable_kernel_provider` guard test, so include it only in binaries that
  genuinely need a privileged session.

## Test Files

### Provider Integration Tests

These tests create live ETW sessions, trigger real system activity, and
validate event capture and parsing.

| File | Provider | Events Tested |
|------|----------|---------------|
| `dns_client.rs` | Microsoft-Windows-DNS-Client | Event 3008 under a kernel-side event-ID filter, with the callback keeping only the test thread's queries; two per hostname (A + AAAA) |
| `kernel_process.rs` | Microsoft-Windows-Kernel-Process | ProcessStart, ProcessStop |
| `kernel_file.rs` | Microsoft-Windows-Kernel-File | File I/O events |
| `32bit_events.rs` | DNS-Client + DotNETRuntime | 32-bit event parsing; Pointer fields from 32-bit process (requires 32-bit PowerShell) |
| `mixed_bitness_events.rs` | DotNETRuntime | Schema cache keyed on pointer size: 32-bit and 64-bit events in one session, both cache-population orders (requires 32-bit PowerShell) |
| `tracelogging_schema_cache.rs` | Self-registered TraceLogging provider | Schema cache keyed on the TraceLogging metadata blob: three event shapes, all with `EventDescriptor.Id` 0, each resolve to their own schema through one shared context |
| `system_process.rs` | System logger (PERF_PROCESS) | Kernel process events via system logger mode |
| `system_network.rs` | System logger (PERF_NETWORK) | TCP/UDP events via system logger mode |
| `system_object.rs` | System logger (PERF_OB_HANDLE) | Object manager handle create/close events |
| `system_virtual_alloc.rs` | System logger (PERF_VIRTUAL_ALLOC) | Virtual memory allocation events |
| `system_logger_rundown.rs` | System logger (PERF_PROC_THREAD, PERF_LOADER, PERF_FILENAME) | Automatic DC_START/DC_END rundown; `send_file_rundown_code()` FileRundown events and file name parsing (slow) |

### Extended Data & Alignment Tests (Require Admin)

| File | What It Tests |
|------|---------------|
| `extended_data.rs` | Extended data items: SID, PROCESS_START_KEY, STACK_TRACE |
| `field_types.rs` | TDH field type parsing against real kernel providers |
| `network_addr_parsing.rs` | `SocketAddr`, `Ipv4Addr`, `Ipv6Addr` parsing from TCPIP and Kernel-Network providers |
| `runtime_config.rs` | Runtime provider enable/disable after session start; system-logger `update_events()` / `update_stack_walking()` on a running session; pre-start API misuse panics |
| `trace_properties.rs` | Buffer size/count configuration round-trip through `start()`; taking over an existing session name; `session_id()` after start |
| `userdata_alignment.rs` | Runtime alignment probe validating 8-byte UserData alignment (slow) |

### Session Control & Filtering Tests (Require Admin)

| File | What It Tests |
|------|---------------|
| `capture_state.rs` | `capture_state()` makes Kernel-Process emit process rundown events, before and after `start_processing_thread()` |
| `modern_stack_walk_filter.rs` | `ProviderFilter` carrying both `event_ids` and `stack_walk` filters on a manifest provider, driven by a localhost TCP connection |
| `object_type_filter.rs` | `enable_object_type_filter()` configuration and PERF_OB_HANDLE capture (which tags arrive is not checked) |
| `panic_policy.rs` | Callback panic policy against a live DNS-Client session: default stop, `Continue`, `StopTrace` hook payload, and a panicking hook degrading to stop |
| `pid_filter.rs` | `EVENT_FILTER_TYPE_PID` scopes a self-registered user-mode provider to the listed PID |
| `session_enumeration.rs` | `query_sessions()` lists a running system logger and well-known sessions; ETW's logger-name and log-file-path caps still match the buffer layout |
| `stack_walk_legacy.rs` | System logger stack walks on process start parse into consistent `StackWalkData` |

### Profiling Tests (Require Admin, x86_64)

| File | What It Tests |
|------|---------------|
| `lbr.rs` | `enable_lbr` configuration, LBR record capture and `LbrData` parsing |
| `pmc.rs` | `enable_pmc` configuration, `SAMPLED_PROFILE` capture under load, and argument rejection before the session's once-only counter list is used |

### Differential Tests (etw-rs vs Microsoft's own implementation)

These compare etw-rs against the Microsoft code it reimplements: **TDH**, the
decoder for the format etw-rs parses, and **`FileTimeToSystemTime`**, the
Win32 conversion `Timestamp`'s calendar arithmetic reimplements. Neither shares
code with etw-rs, so they cannot agree by way of a shared misconception. Full
rationale in the module docs of `tests/common/differential.rs`.

| File | What It Tests | Admin? |
|------|---------------|--------|
| `differential_offline.rs` | Every manifest-expressible TDH in-type except the three counted types (Unicode string, ANSI string, binary), in seven shapes across three axes (offset, multiplicity, container), plus linkage shapes and zero-length edge cases. Asserts byte-for-byte agreement with TDH on every property, array element and struct member. | No |
| `differential_tracelogging.rs` | The TraceLogging decode path, including `TDH_INTYPE_COUNTEDSTRING`, which manifests cannot express. Payloads are encoded by `tracelogging_dynamic` (Microsoft's own encoder), so the value handed to the encoder is ground truth by construction. | Yes |
| `differential_filetime.rs` | `Timestamp`'s pure-Rust calendar arithmetic against `FileTimeToSystemTime`. The accept/reject boundary is found by bisection rather than taken from the documentation, since the raw-`i64` fallback must trigger on exactly the inputs Win32 refuses. Then every day from 1601 to 2600 — a leap day either side of every century boundary in range — and 100k fixed-seed pseudorandom values. | No |

Three mechanisms make a wrong answer hard to hide in the TDH suites:

- **The TDH oracle.** Expected values come from Microsoft's decoder, not from a
  helper written alongside the parser.
- **The sentinel.** `SENTINEL` is a fixed magic checked on every fixture, so an
  over- or under-read corrupts it instead of landing silently in a field nobody
  asserted on. `LEAD` forces the subject to an odd offset.
- **Seven shapes per type.** The parser's offset fold, its per-property size
  computation, and its container walks fail independently, so each shape varies one
  axis from a baseline rather than forming a cross-product:

  | Axis | Shape | Layout | What only this shape catches |
  |---|---|---|---|
  | offset | `First` | `Subject \| Sentinel` | offset zero, naturally aligned, no predecessor |
  | offset | `Fixed` | `Lead \| Subject \| Sentinel` | a constant but odd offset |
  | offset | `Dynamic` | `Lead \| Pad(str) \| Subject \| Sentinel` | an offset depending on a run-time length |
  | offset | `Last` | `Lead \| Sentinel \| Subject` | a trailing field run to the end of the buffer |
  | multiplicity | `ArrayFixed` | `Lead \| Subject[3] \| Sentinel` | element striding at a constant count |
  | multiplicity | `ArrayParamCount` | `Lead \| Count \| Subject[Count] \| Sentinel` | striding at a run-time count, and `count == 0` |
  | container | `StructMember` | `Lead \| { MemberU32, Subject } \| Sentinel` | the `struct_members` walk |

  They are measurably not redundant. Injecting a 2-byte over-read into the
  `UnicodeString` length calculation is caught by `First` and `Fixed` only in
  their own `UnicodeString` fixture, but by every `Dynamic` fixture, whose `Pad`
  string precedes the subject. And a 1-byte error in array
  element striding is caught by `array_elements_agree_with_tdh` **alone**: the
  whole-property byte comparison and the sentinel both survive it, because a wrong
  stride can still sum to the right total.

`differential_offline.rs` needs no ETW session and no elevation:
`TdhLoadManifest` loads `tests/fixtures/differential.man` into the test process
only — no `wevtutil im`, no machine-global state — and TDH will then decode an
`EVENT_RECORD` assembled in memory.

#### Adding a case

`tests/fixtures/differential.man` is **generated**, so that all seven shapes stay
in step for every type. To add an in-type:

1. Add it to `TYPES` in `tests/fixtures/generate_differential_manifest.py` and to
   `subjects()` in `differential_offline.rs` — *in the same order*, since event ids
   are `BASE_ID + type_index * len(SHAPES) + shape_index`, with `BASE_ID` = 100
   and seven shapes.
2. Add its shapes' payload layout only if you are adding a *shape*; adding a type
   needs no layout work, since shapes are generated for every type.
3. Regenerate from the repo root and re-validate:

   ```bash
   python tests/fixtures/generate_differential_manifest.py
   mc.exe -um tests/fixtures/differential.man -r <tmp> -h <tmp>
   ```

   The manifest is kept `mc.exe`-clean; it is the only check that catches an
   inexpressible declaration, such as `win:Binary` with no length.
4. The property-count assertions are derived from the tables, so they need no
   manual edit.

`subject_in_types_match_the_manifest` asks TDH which in-type it actually resolved
for each fixture, so a table that drifts out of step with the manifest fails loudly
rather than quietly testing the wrong type.

Do **not** widen a byte comparison to make a new type pass. etw-rs and TDH agree
exactly on every fixture property, with exactly one stated exception: TDH refuses
to return a **zero-length** property (`ERROR_INVALID_PARAMETER`) where etw-rs reports
an empty slice. They agree the extent is zero and differ only on whether zero is a
returnable value. That allowance is asserted from both sides in
`zero_length_properties_are_empty_not_missing`, so it is a contract rather than a
tolerance — anything else is a finding to understand.

### Parser & Schema Tests (No Admin)

These are unit-level tests that validate parsing and schema logic using synthetic
data, or live TDH metadata without a session.

> **When is a synthetic test acceptable?** The question is not "is the data
> synthetic" but **"where did the expected value come from?"** A payload encoded by
> a helper and decoded by the parser proves nothing if both were written from the
> same understanding.
>
> The claims that need an outside oracle are the ones about **offsets and
> lengths**, because a wrong belief there is invisible from inside. Those live in
> the differential tests. Synthetic remains right for:
>
> - **rejection paths** — truncation, odd byte counts, an unsized `Binary`,
>   unsupported combinations; no
>   real provider will emit them, and the assertion is that we refuse, not that we
>   decode;
> - **etw-rs's own behaviour** — hint fallback, cache paths, `Display` output;
> - **fixed-width value conversion** — `[0xFE] → -2i8` is self-evident from the
>   spec, and moving it elsewhere would not make it stronger;
> - **types no oracle can reach** — `WbemSid` and `ReversedCountedString`, which
>   are MOF-only. Weakest tests in the tree; captured classic-kernel events are
>   what would fix them.
>
> Before deleting a synthetic offset test as redundant, check the shape is
> actually covered by the differential fixtures — `shape_records()`, `edge_records()` and `linkage_records()`.
>
> **32-bit pointers** are not covered offline: `TdhLoadManifest` resolves the
> manifest in the test process, so `win:Pointer` gets a declared length of 8 baked
> into the schema, and setting the 32-bit header flag does not undo it (measured:
> etw-rs and TDH *agree* on reading 8 bytes). Real coverage lives in
> `tests/32bit_events.rs` and, more thoroughly, in `tests/mixed_bitness_events.rs`.

| File | What It Tests |
|------|---------------|
| `static_schema_positions.rs` | Static schema parser (`event_schema!`) position tests across buffer offsets |
| `static_schema_pointer_size.rs` | Static schema pointer-sized field offsets for 32-bit (WOW64) and 64-bit events |
| `static_schema_parser_struct.rs` | Sequential parser offset caching with `event_schema!` macro |
| `static_schema_multi_version.rs` | Multi-version `provider_schema!` dispatch, superset trait, dynamic fallback |
| `validate_all_schemas.rs` | `__register_schema_validator` enqueues validators and `validate_all_schemas()` runs them, propagating the first error |
| `validate_next_version_hints.rs` | N+1 canary — TDH check that stale index hints are detected |

Provider generation is tested in its own crate, in
`tools/generate-provider/tests/generate_provider.rs`: the generation pipeline and
`generate_full_file()` output.

## Test Structure

Provider integration tests follow this pattern:

1. **Session** - Create a `Trace`
2. **Guard** - Pass `trace.start()` through `common::skip_or_panic`, which
   soft-skips on a privilege code and panics on anything else
3. **Trigger** - Spawn real system activity (DNS queries, processes, file I/O, network connections)
4. **Capture** - Collect events via callback with `Arc<AtomicUsize>` counting
5. **Validate** - Assert event IDs, parse fields, check values

Individual tests do not need their own privilege check: the per-binary
`can_enable_kernel_provider` guard already fails the run when the capability is
missing, so `skip_or_panic` only has to keep the remaining tests from panicking
one by one.

## Adding New Provider Tests

1. Add the provider definition to `example-providers/` (or use `cargo run -p etw-rs-generate-provider -- <provider>`)
2. Create a new test file in `tests/`
3. Implement:
   - `#[path = "common/mod.rs"] mod common;` for the per-binary privilege guard, and `trace.start()` passed through `common::skip_or_panic` (see Test Structure above)
   - Event trigger function to generate real system activity
   - Event callback that captures and parses events
   - Assertions on event IDs and parsed field values

## Troubleshooting

### "Access Denied" Errors

Most of the suite needs Administrator: `Performance Log Users` can create a
session but not enable kernel providers or start a system logger (see Running
Tests). Run your terminal as Administrator.

### No Events Captured

Some providers may not be active or may require specific system activity:
- DNS Client: Ensure network connectivity and perform actual DNS queries
- Kernel providers: May require specific system operations
- Try increasing the capture duration

### Event Parsing Failures

If event parsing fails:
1. Check the event schema definition matches the actual event format
2. Verify the provider GUID is correct
3. Check the event version - schemas may vary by version
4. Use the raw hex dump to debug the data format
