# session/

Trace session management for ETW tracing.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Re-exports, shared types (`TraceStatistics`, `ClockResolution`) |
| `enumerate.rs` | `query_sessions()` — the ETW sessions running on the machine (`SessionProperties`) |
| `common.rs` | Shared infrastructure: callback types, FFI declarations, provider filter types |
| `panic_policy.rs` | Caller-installed policy for callback panics (`PanicPayload`, `PanicResponse`) |
| `trace.rs` | `Trace` — unified session type for both provider-based and system logger tracing; `EnableProperty`, `ProcessTraceMode` |

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `system_logger/` | System logger mode: group masks, stack walking, pool tag filtering, LBR, PMC |

## Key Invariants

### Session Lifecycle

Setters for the session properties `StartTraceW` consumes — buffers, flush timer, clock, log mode, kernel-stack exclusion and the system-logger setters — assert `!is_started()`: the properties reach the kernel only in `start()`, so a later change would be silently ignored. `set_process_trace_mode()`, `set_processing_thread_priority()`, `set_processing_thread_description()` and the callbacks take effect at `start_processing_thread()`, so they assert only that processing has not begun; the two `set_processing_thread_*_timeout()` setters can be called at any time. Running sessions change through dedicated methods instead (`enable_provider()`, `update_events()`, `update_stack_walking()`, `enable_object_type_filter()`, `enable_lbr()`); `enable_pmc()` sets each of its lists once per session. The required call order is:

```
1. new()
2. set_buffer_size(), set_minimum_buffers(), etc.  [config phase]
3. set_events(), set_stack_walking(), etc.          [system logger config, optional]
4. start()                                          [optional — see below]
5. enable_provider()                                [add providers]
6. set_event_callback()
6b. set_panic_callback()                            [optional panic policy]
7. capture_state()                                  [optional, any time the session is running]
8. start_processing_thread()
9. [events flow to callback]
10. stop()
```

`enable_provider()` and `start_processing_thread()` each call `start()` if the session is not yet running. `start()` asserts the session is *not* running, so an explicit `start()` must come before the first `enable_provider()`, never after it.

### Stop Before Close (Critical)

`stop()` must stop the trace session **before** closing the processing handle. If you close first, rundown events generated at shutdown cannot be processed because `ProcessTrace` is no longer draining the buffer. The `stop()` method enforces this order.

### Callback Safety

- The event callback is wrapped in `std::panic::catch_unwind()` to prevent panics unwinding through the FFI boundary (requires `panic = "unwind"`; see `panic_policy.rs`).
- On a callback panic the **panic policy** decides what happens next. By default (no hook) the trace is *stopped*: the panic is logged, later events are drained without dispatch, and `ProcessTrace` returns. Install a hook via `set_panic_callback()` to choose `PanicResponse::Continue` (keep dispatching) instead. Poll `Trace::is_poisoned()` to detect a trace that went dark. See `panic_policy.rs`.
- `CallbackState` is heap-allocated (`Box`) for a stable pointer in `EVENT_TRACE_LOGFILEW.Context`; the poison flag is a separate `Arc`-shared `PoisonFlag` so the owner can read/reset it without aliasing the consumer thread's `&mut CallbackState`.

### Thread Safety

`Trace` is `Send` but not `Sync`. Do not share across threads — only move it.
