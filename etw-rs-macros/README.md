# etw-rs-macros

Procedural macros for [etw-rs](https://crates.io/crates/etw-rs). Don't depend on
this crate directly: `etw-rs` re-exports both macros.

- `event_schema!` — defines a static parser for one event version, with field
  offsets computed at compile time.
- `provider_schema!` — defines several events under one provider, expanding to
  multiple `event_schema!` invocations.

Most definitions don't need writing by hand:
[`etw-rs-generate-provider`](https://crates.io/crates/etw-rs-generate-provider)
generates `provider_schema!` blocks from a provider's registered metadata.

## Example

```rust
use etw::{Guid, event_schema};

const GUID: Guid = Guid::from_u128(0xedd08927_9cc4_4e65_b970_c2560fb5c289);

event_schema! {
    guid: GUID,
    name: "FileCreate",
    id: 12,
    version: 1,
    fields: {
        Irp: usize,
        FileObject: usize,
        IssuingThreadId: u32,
        FileName: WideStrRef,
    }
}
```

This generates `FileCreateV1Parser`, with a typed accessor per field
(`parser.IssuingThreadId()?`, `parser.FileName()?`).
