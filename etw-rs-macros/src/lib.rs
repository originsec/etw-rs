//! Proc macros for etw-rs
//!
//! This crate provides:
//! - `event_schema!` macro for zero-cost static schema event parsing
//! - `provider_schema!` macro for defining multiple events under one provider

// The `unsafe` tokens emitted inside `quote!{}` compile in the consumer crate,
// not here.
#![forbid(unsafe_code)]

use proc_macro::TokenStream;

mod multi_version;
mod provider;
mod schema;

/// Defines a zero-cost schema for ETW event parsing.
///
/// This macro generates a sequential parser struct with compile-time constant
/// offsets for maximum performance. Field offsets are automatically calculated
/// from field types, and variable-length field offsets are cached incrementally.
///
/// # Example
///
/// ```no_run
/// use etw::{Guid, event_schema};
///
/// const GUID: Guid = Guid::from_u128(0xedd08927_9cc4_4e65_b970_c2560fb5c289);
///
/// event_schema! {
///     guid: GUID,
///     name: "FileCreate",
///     id: 12,
///     version: 1,
///     fields: {
///         Irp: usize,
///         FileObject: usize,
///         IssuingThreadId: u32,
///         FileName: WideStrRef,
///     }
/// }
/// ```
///
/// This creates `FileCreateV1Parser` with typed accessor methods:
///
/// ```no_run
/// # use etw::{Guid, RawEvent, event_schema};
/// # const GUID: Guid = Guid::from_u128(0xedd08927_9cc4_4e65_b970_c2560fb5c289);
/// # event_schema! {
/// #     guid: GUID, name: "FileCreate", id: 12, version: 1,
/// #     fields: {
/// #         Irp: usize, FileObject: usize,
/// #         IssuingThreadId: u32, FileName: WideStrRef,
/// #     }
/// # }
/// # fn demo(event: &RawEvent) -> etw::Result<()> {
/// let mut parser = FileCreateV1Parser::new(event);
/// let thread_id = parser.IssuingThreadId()?;
/// let filename = parser.FileName()?;
/// # Ok(()) }
/// ```
#[proc_macro]
pub fn event_schema(input: TokenStream) -> TokenStream {
    schema::expand_event_schema(input)
}

/// Defines multiple events for a single provider, reducing duplication.
///
/// This macro allows you to define provider information once and then specify
/// multiple events. It expands to multiple `event_schema!` invocations.
///
/// See [`etw::provider_schema`](https://docs.rs/etw-rs/latest/etw/macro.provider_schema.html) for examples.
#[proc_macro]
pub fn provider_schema(input: TokenStream) -> TokenStream {
    provider::expand_provider_schema(input)
}
