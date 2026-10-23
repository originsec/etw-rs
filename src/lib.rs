//! # etw-rs
//!
//! Low-level Rust bindings for Event Tracing for Windows (ETW) with minimal abstraction.
//!
//! This library provides a thin wrapper around the Win32 ETW APIs, giving you direct control
//! over ETW session management and event consumption while providing a safe-by-default public API.
//!
//! ## Design Philosophy
//!
//! - **Minimal Abstraction**: API surface closely mirrors Win32 ETW APIs
//! - **Performance**: Zero-cost abstractions, efficient event parsing without TDH when possible
//! - **Control**: Direct access to ETW session configuration and event buffers
//! - **Safety**: Rust safety guarantees without sacrificing low-level access
//!
//! ## Example
//!
//! ```no_run
//! use etw::{ALL_KEYWORDS, Guid, Trace};
//!
//! // Microsoft-Windows-Kernel-Process provider
//! const PROCESS_GUID: Guid = Guid::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716);
//! const PROCESS_KEYWORD: u64 = 0x10;
//!
//! fn main() -> etw::Result<()> {
//!     let mut trace = Trace::new("MySession")?;
//!     trace.start()?;
//!     trace.enable_provider(PROCESS_GUID, PROCESS_KEYWORD)?;
//!
//!     trace.set_event_callback(|event, context| {
//!         let mut parser = context.parser(event)?;
//!         let pid: u32 = parser.get("ProcessID")?;
//!         println!("Process event: PID={}", pid);
//!         Ok(())
//!     });
//!
//!     trace.start_processing_thread()?;
//!     std::thread::sleep(std::time::Duration::from_secs(5));
//!     trace.stop()?;
//!     Ok(())
//! }
//! ```

#![cfg(windows)]

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("etw-rs supports only x86_64 and aarch64 on Windows.");

// Macro output names this crate as `::etw::…`; this resolves it when
// provider_schema! is invoked by the crate's own tests.
#[cfg(test)]
extern crate self as etw;

pub mod event;
pub use session::{system_logger, system_logger::stack_walk};
pub mod parser;
pub mod processing_context;
pub mod resolve;
pub mod session;
pub mod static_schema;
pub mod types;

// Re-export macros for static schema event parsing
/// Defines a zero-cost schema for ETW event parsing.
///
/// This macro generates a sequential parser struct with compile-time constant
/// offsets for maximum performance. Field offsets are automatically calculated
/// from field types, and variable-length field offsets are cached incrementally.
///
/// Accessors keep the manifest's spelling, so `ImageName` is read as
/// `parser.ImageName()`, and the borrowed form of a reference-typed field is
/// `parser.ImageName_ref()`.
///
/// # Field annotations
///
/// A field may carry `@` annotations after its type, in any order:
///
/// | Annotation | Meaning |
/// |---|---|
/// | `@ length("Field")` | byte length comes from another field |
/// | `@ fixed_length(N)` | compile-time byte length |
/// | `@ count("Field")` | element count comes from another field |
/// | `@ count_bytes("Field", N)` | element count times a fixed element size |
/// | `@ tdh(InType)` | the field's TDH in-type |
///
/// `@ tdh(...)` changes no parsing — the field is read exactly as its Rust type
/// says. It states which TDH in-type the manifest specifies, which the Rust type
/// cannot: `u64` covers `UInt64`, `FileTime` and `HexInt64`, and `usize` covers
/// `Pointer` and `SizeT`. Without it the accessor's documentation names whichever
/// member of the group is the default, and
/// [`validate_schema`](static_schema::validate_schema) can only check that the
/// manifest's type is *compatible* rather than equal.
///
/// ```text
/// CreateTime: u64 @ tdh(FileTime),
/// FileKey:    usize @ tdh(Pointer),
/// ```
///
/// # Example
///
/// ```no_run
/// use etw::{Guid, RawEvent, event_schema};
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
///
/// // Creates FileCreateV1Parser with typed accessor methods:
/// fn handle_event(event: &RawEvent) -> etw::Result<()> {
///     let mut parser = FileCreateV1Parser::new(event);
///     let thread_id = parser.IssuingThreadId()?;
///     let filename = parser.FileName()?;
///     Ok(())
/// }
/// ```
#[doc(inline)]
pub use etw_rs_macros::event_schema;
/// Defines multiple events for a single provider, reducing duplication.
///
/// This macro allows you to define provider information once and then specify
/// multiple events. It expands to multiple [`event_schema!`] invocations.
///
/// # Example
///
/// ```no_run
/// use etw::{Guid, provider_schema};
///
/// const GUID: Guid = Guid::from_u128(0xedd08927_9cc4_4e65_b970_c2560fb5c289);
///
/// provider_schema! {
///     guid: GUID,
///     events: {
///         event {
///             id: 12,
///             name: "FileCreate",
///             version { 0, fields: {
///                 Irp: usize,
///                 ThreadId: usize,
///                 FileObject: usize,
///                 CreateOptions: u32,
///                 FileName: WideStrRef,
///             }}
///             version { 1, fields: {
///                 Irp: usize,
///                 FileObject: usize,
///                 IssuingThreadId: u32,
///                 CreateOptions: u32,
///                 FileName: WideStrRef,
///             }}
///         }
///     }
/// }
/// ```
#[doc(inline)]
pub use etw_rs_macros::provider_schema;
#[doc(inline)]
pub use event::{ExtendedDataItem, RawEvent, StackTrace, Timestamp};
#[doc(inline)]
pub use parser::{EventParser, FromProperty, FromPropertyRef, Property, PropertyIter};
#[doc(inline)]
pub use processing_context::EventContext;
#[doc(inline)]
pub use session::{
    ALL_KEYWORDS, ClockResolution, EnableProperty, EventIdFilter, PanicPayload, PanicResponse,
    ProcessTraceMode, ProviderFilter, SessionProperties, Trace, TraceStatistics, query_sessions,
    system_logger::LbrConfig,
};
#[doc(inline)]
pub use types::{
    AnsiStrRef, AnsiString, Guid, Sid, SidRef, SystemTime, TdhInType, TdhOutType, WideStrRef,
    WideString,
};
use windows_sys::Win32::Foundation::{ERROR_MR_MID_NOT_FOUND, NTSTATUS, WIN32_ERROR};
// A plain `u32` value, not a nominal `windows` type — safe to re-export
// without coupling the public API to a `windows` version.
pub use windows_sys::Win32::Globalization::CP_ACP;

/// Convert a 4-byte pool tag `tag` to a `u32` value.
///
/// Pool tags are typically 4 ASCII characters stored as a little-endian `u32`.
/// Pass the result to [`Trace::set_pool_tag_filter()`].
///
/// # Panics
///
/// Panics if `tag` is not exactly 4 bytes.
///
/// # Example
///
/// ```
/// use etw::pool_tag;
///
/// let proc_tag = pool_tag(b"Proc");
/// assert_eq!(proc_tag, 0x636F_7250); // 'Proc' in little-endian
/// ```
#[must_use]
pub const fn pool_tag(tag: &[u8; 4]) -> u32 {
    u32::from_le_bytes(*tag)
}

/// Check if the current process has administrator privileges.
#[must_use]
pub fn is_elevated() -> bool {
    use windows_sys::Win32::{
        Foundation::HANDLE,
        Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    // SAFETY: All Win32 calls are made with valid handles and properly sized buffers.
    unsafe {
        let mut token_handle: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token_handle) == 0 {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut return_length = 0u32;
        let result = GetTokenInformation(
            token_handle,
            TokenElevation,
            (&raw mut elevation).cast::<std::ffi::c_void>(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &raw mut return_length,
        );

        let _ = windows_sys::Win32::Foundation::CloseHandle(token_handle);

        result != 0 && elevation.TokenIsElevated != 0
    }
}

/// Function pointer type for schema validators.
type ValidatorFn = fn() -> std::result::Result<(), Error>;

/// Schema validators registered by each [`provider_schema!`] invocation.
///
/// Each entry is pushed by a Windows CRT constructor (`.CRT$XCU` section)
/// that runs before `main()`. The list is therefore complete by the time
/// [`validate_all_schemas()`] is called at startup.
static __SCHEMA_VALIDATORS: std::sync::Mutex<Vec<ValidatorFn>> = std::sync::Mutex::new(Vec::new());

/// Register a schema validator to be called by [`validate_all_schemas()`].
///
/// This is an implementation detail called from CRT constructors generated by
/// [`provider_schema!`]. Do not call it directly.
#[doc(hidden)]
pub fn __register_schema_validator(f: ValidatorFn) {
    __SCHEMA_VALIDATORS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(f);
}

/// Success cache for [`validate_all_schemas()`].
///
/// Flips to `true` only after every registered validator has returned `Ok`.
/// On failure the flag stays `false`, so subsequent calls re-run validation
/// and propagate the full typed [`Error`] — this keeps the return value
/// independent of call order, at the cost of re-running validation on the
/// failure path (which is expected to be rare).
static __SCHEMA_VALIDATION_PASSED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Validates every schema registered via [`provider_schema!`] against the
/// Windows TDH registry.
///
/// Each [`provider_schema!`] invocation automatically registers its validator
/// via a Windows CRT constructor that runs before `main()` — it is
/// structurally impossible to add a provider schema and forget to include it
/// in this check.
///
/// Once validation has succeeded the result is cached: subsequent calls short
/// circuit on a single atomic load. [`Trace::new()`](session::Trace::new)
/// calls this implicitly so every live session is preceded by a validation
/// check. Callers who want to surface validation errors earlier or with
/// dedicated handling can still call it explicitly.
///
/// # Errors
///
/// Returns the first validation error encountered across all registered
/// schemas. On failure nothing is cached — the next call re-runs validation
/// and returns the same typed error.
pub fn validate_all_schemas() -> Result<()> {
    use std::sync::atomic::Ordering;
    if __SCHEMA_VALIDATION_PASSED.load(Ordering::Acquire) {
        return Ok(());
    }
    let validators: Vec<ValidatorFn> = __SCHEMA_VALIDATORS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .copied()
        .collect();
    run_validators(&validators)?;
    __SCHEMA_VALIDATION_PASSED.store(true, Ordering::Release);
    Ok(())
}

fn run_validators(validators: &[ValidatorFn]) -> Result<()> {
    for f in validators {
        f()?;
    }
    Ok(())
}

/// Run a slice of validator functions in order, returning the first error.
///
/// This is an implementation detail exposed for integration tests. Do not call
/// it directly — use [`validate_all_schemas()`] instead.
#[doc(hidden)]
pub fn __run_validators(validators: &[fn() -> Result<()>]) -> Result<()> {
    run_validators(validators)
}

#[cfg(test)]
mod schema_validator_tests {
    use super::*;

    #[expect(
        clippy::unnecessary_wraps,
        reason = "signature must match `ValidatorFn = fn() -> Result<(), Error>`"
    )]
    fn ok_validator() -> Result<()> {
        Ok(())
    }

    fn err_invalid_param() -> Result<()> {
        Err(Error::InvalidParameter {
            parameter: "sentinel",
            problem: ParameterProblem::Empty,
        })
    }

    fn err_parse() -> Result<()> {
        Err(Error::parse("sentinel"))
    }

    #[test]
    fn empty_validators_returns_ok() {
        assert!(run_validators(&[]).is_ok());
    }

    #[test]
    fn all_ok_validators_returns_ok() {
        assert!(run_validators(&[ok_validator, ok_validator]).is_ok());
    }

    #[test]
    fn single_failing_validator_propagates_err() {
        assert!(run_validators(&[err_invalid_param]).is_err());
    }

    #[test]
    fn failing_validator_after_ok_propagates_err() {
        assert!(run_validators(&[ok_validator, err_invalid_param]).is_err());
    }

    #[test]
    #[expect(clippy::unwrap_used, reason = "test-only error inspection")]
    fn short_circuits_on_first_failure() {
        // Proves short-circuit: if both ran, we'd get the second error (Other).
        // Getting InvalidParameter confirms iteration stopped at the first failure.
        let err = run_validators(&[err_invalid_param, err_parse]).unwrap_err();
        assert!(
            matches!(err, Error::InvalidParameter { .. }),
            "expected first validator's error, got: {err:?}"
        );
    }
}

#[cfg(test)]
mod dynamic_parser_tests {
    use crate::{
        TdhInType, TdhOutType, parser::EventParser, processing_context::mock::MockSchemaBuilder,
        provider_schema,
    };

    // V0: [Alpha: u32, Beta: u32]
    // V1 (extends V0): adds Gamma — resolved V1 layout is [Alpha, Beta, Gamma] at [0, 1, 2].
    //
    // build_superset assigns hint_index from the latest version that has each field:
    //   Alpha → 0, Beta → 1, Gamma → 2  (all from V1).
    // DynamicUnitTestDynamicParser bakes these hints for O(1) field access on N+1 events.
    provider_schema! {
        guid: crate::Guid::from_u128(0x0000_0000_0000_0000_0000_aabb_ccdd_0001),
        events: {
            event {
                id: 1,
                name: "DynamicUnitTest",
                version { 0, fields: {
                    Alpha: u32,
                    Beta: u32,
                }}
                version { 1, extends_version: 0, fields: {
                    Gamma: u64,
                }}
            }
        }
    }

    #[test]
    #[expect(clippy::unwrap_used, reason = "test-only assertions")]
    fn dynamic_parser_reads_latest_version_fields_using_hints() {
        // Simulate a V2 event that has the same field layout as V1 — the assumption
        // DynamicParser makes using its baked-in V1 hints.
        let (schema, mut cache) = MockSchemaBuilder::new()
            .add("Alpha", TdhInType::UInt32, TdhOutType::Null)
            .add("Beta", TdhInType::UInt32, TdhOutType::Null)
            .add("Gamma", TdhInType::UInt64, TdhOutType::Null)
            .build_with_cache();

        let mut data = Vec::new();
        data.extend_from_slice(&42u32.to_le_bytes());
        data.extend_from_slice(&99u32.to_le_bytes());
        data.extend_from_slice(&12345u64.to_le_bytes());

        // Construct via private field — same-module access permits this.
        // DynamicParser::new requires a real RawEvent+ProcessingContext; from_raw_parts bypasses
        // that.
        let inner = EventParser::from_raw_parts(&data, &schema, &mut cache);
        let mut parser = DynamicUnitTestDynamicParser { inner };

        assert_eq!(parser.Alpha().unwrap(), 42u32);
        assert_eq!(parser.Beta().unwrap(), 99u32);
        assert_eq!(parser.Gamma().unwrap(), 12345u64);
    }
}

/// Common result type for ETW operations
pub type Result<T> = std::result::Result<T, Error>;

/// Maps a `WIN32_ERROR` or `NTSTATUS` to a human-readable message string.
///
/// Resolution is deferred to the moment the message is rendered (Display or
/// Debug); errors that are caught and handled without ever being formatted
/// pay no `FormatMessageW` cost.
pub(crate) trait ResolveMessage {
    /// Returns the human-readable description of this error code, with no
    /// numeric prefix. NTSTATUS values that have no Win32 mapping return
    /// `"<unmapped>"`.
    fn resolve_message(&self) -> String;
}

impl ResolveMessage for WIN32_ERROR {
    fn resolve_message(&self) -> String {
        format_message(*self)
    }
}

/// Renders a Win32 error code via `FormatMessageW`, trimming trailing
/// whitespace. Returns an empty string when the system has no message.
fn format_message(code: u32) -> String {
    use windows_sys::Win32::System::Diagnostics::Debug::{
        FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS, FormatMessageW,
    };
    let mut buf = [0u16; 512];
    // SAFETY: the buffer pointer and length are valid for the call, and
    // IGNORE_INSERTS means no caller-supplied arguments are read.
    let len = unsafe {
        FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            std::ptr::null(),
            code,
            0, // default language
            buf.as_mut_ptr(),
            buf.len() as u32,
            std::ptr::null(),
        )
    };
    String::from_utf16_lossy(&buf[..len as usize])
        .trim_end()
        .to_owned()
}

impl ResolveMessage for NTSTATUS {
    fn resolve_message(&self) -> String {
        // SAFETY: `RtlNtStatusToDosError` is a documented ntdll routine with
        // no preconditions on the input value.
        let dos = unsafe { RtlNtStatusToDosError(*self) };
        if dos == ERROR_MR_MID_NOT_FOUND {
            return "<unmapped>".to_owned();
        }
        // `RtlNtStatusToDosError` doesn't always signal "unmapped" via the
        // explicit MID_NOT_FOUND sentinel — for some inputs it returns a code
        // that `FormatMessageW` has no string for. Treat an empty resolved
        // message the same way.
        let msg = format_message(dos);
        if msg.is_empty() {
            "<unmapped>".to_owned()
        } else {
            msg
        }
    }
}

#[link(name = "ntdll")]
unsafe extern "system" {
    /// Maps an NTSTATUS to a Win32 error code via ntdll's lookup table.
    ///
    /// Returns `ERROR_MR_MID_NOT_FOUND` (317) when no mapping exists.
    fn RtlNtStatusToDosError(status: NTSTATUS) -> u32;
}

/// The SDK constant's name for a Win32 code this crate is known to encounter,
/// without the `ERROR_` prefix the `WIN32_ERROR(...)` context already states.
///
/// Partial by design — grown as codes are met; unknown codes render without a
/// name. Unlike [`ResolveMessage`] the name is locale-independent and costs no
/// FFI, so it survives systems where `FormatMessageW` text is unhelpful.
const fn win32_name(code: WIN32_ERROR) -> Option<&'static str> {
    use windows_sys::Win32::Foundation as F;
    Some(match code {
        // Unreachable through this crate's guarded paths, so if it renders it
        // names the construction bug that produced it.
        F::ERROR_SUCCESS => "SUCCESS",
        F::ERROR_ACCESS_DENIED => "ACCESS_DENIED",
        F::ERROR_INVALID_HANDLE => "INVALID_HANDLE",
        F::ERROR_NOT_ENOUGH_MEMORY => "NOT_ENOUGH_MEMORY",
        F::ERROR_BAD_LENGTH => "BAD_LENGTH",
        F::ERROR_NOT_SUPPORTED => "NOT_SUPPORTED",
        F::ERROR_DEV_NOT_EXIST => "DEV_NOT_EXIST",
        F::ERROR_INVALID_PARAMETER => "INVALID_PARAMETER",
        F::ERROR_INSUFFICIENT_BUFFER => "INSUFFICIENT_BUFFER",
        F::ERROR_ALREADY_EXISTS => "ALREADY_EXISTS",
        F::ERROR_MORE_DATA => "MORE_DATA",
        F::ERROR_MR_MID_NOT_FOUND => "MR_MID_NOT_FOUND",
        F::ERROR_NO_UNICODE_TRANSLATION => "NO_UNICODE_TRANSLATION",
        F::ERROR_NOT_FOUND => "NOT_FOUND",
        F::ERROR_CANCELLED => "CANCELLED",
        F::ERROR_NOT_ALL_ASSIGNED => "NOT_ALL_ASSIGNED",
        F::ERROR_PRIVILEGE_NOT_HELD => "PRIVILEGE_NOT_HELD",
        F::ERROR_NO_SYSTEM_RESOURCES => "NO_SYSTEM_RESOURCES",
        F::ERROR_INCORRECT_SIZE => "INCORRECT_SIZE",
        F::ERROR_WMI_GUID_NOT_FOUND => "WMI_GUID_NOT_FOUND",
        F::ERROR_WMI_INSTANCE_NOT_FOUND => "WMI_INSTANCE_NOT_FOUND",
        F::ERROR_WMI_ALREADY_ENABLED => "WMI_ALREADY_ENABLED",
        F::ERROR_CTX_CLOSE_PENDING => "CTX_CLOSE_PENDING",
        _ => return None,
    })
}

/// The SDK constant's name for an NTSTATUS this crate is known to encounter,
/// without the `STATUS_` prefix the `NTSTATUS(...)` context already states.
///
/// Partial by design, as for [`win32_name`].
const fn ntstatus_name(status: NTSTATUS) -> Option<&'static str> {
    use windows_sys::Win32::Foundation as F;
    Some(match status {
        // As for ERROR_SUCCESS: only a construction bug can render this.
        F::STATUS_SUCCESS => "SUCCESS",
        F::STATUS_UNSUCCESSFUL => "UNSUCCESSFUL",
        F::STATUS_INFO_LENGTH_MISMATCH => "INFO_LENGTH_MISMATCH",
        F::STATUS_ACCESS_DENIED => "ACCESS_DENIED",
        F::STATUS_BUFFER_TOO_SMALL => "BUFFER_TOO_SMALL",
        F::STATUS_INVALID_PARAMETER => "INVALID_PARAMETER",
        F::STATUS_PRIVILEGE_NOT_HELD => "PRIVILEGE_NOT_HELD",
        F::STATUS_INSUFFICIENT_RESOURCES => "INSUFFICIENT_RESOURCES",
        F::STATUS_NOT_FOUND => "NOT_FOUND",
        F::STATUS_NOT_SUPPORTED => "NOT_SUPPORTED",
        _ => return None,
    })
}

/// Renders `, <name>` when a code has a known symbolic name, nothing otherwise.
struct NameSuffix(Option<&'static str>);

impl std::fmt::Display for NameSuffix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(name) => write!(f, ", {name}"),
            None => Ok(()),
        }
    }
}

/// Errors that can occur during ETW operations
///
/// # Width
///
/// `Error` is 48 bytes, so every `Result<T, Error>` in the crate is at least
/// that. Do not shrink it for performance: measured, the width does not matter.
///
/// A padding variant was used to widen `Error` from 40 to 128 bytes — 3.2x —
/// leaving everything else identical, and the two builds were run round-robin
/// (alternating, so thermal drift hits both arms equally; comparing sequential
/// runs on a laptop cannot resolve this) over the 2836-event registry capture:
///
/// ```text
/// etw-rs-get          40B: median 1350.7us  min 1284.9us
///                    128B: median 1329.0us  min 1284.0us
/// etw-rs-get-hinted   40B: median  852.6us  min  807.0us
///                    128B: median  833.3us  min  807.2us
/// ```
///
/// The minima — the least contaminated runs — match to within 0.1%. Each
/// accessor does hundreds of nanoseconds of real work (hash lookup, offset
/// computation, UTF-16 to UTF-8 transcoding), against which a wider return slot
/// is nothing, and on x86-64 Windows every one of these sizes is returned
/// through a hidden pointer anyway, so no size crosses a calling-convention
/// boundary. Boxing variants, or moving to a `Box<ErrorKind>` newtype, buys
/// nothing here.
///
/// What *is* worth keeping narrow is anything genuinely large:
/// [`Error::ParseError`] and [`Error::SchemaValidationError`] box their oversized
/// payloads so a 64-byte `SchemaMismatch` does not set the width for everyone.
/// `clippy::result_large_err` (enabled here via `clippy::all`, threshold 128
/// bytes) is the backstop, and it is silent at the current size.
#[derive(thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Win32 API error, carrying the raw Win32 error code.
    #[error("WIN32_ERROR({}{}): {}", _0, NameSuffix(win32_name(*_0)), _0.resolve_message())]
    Win32Error(u32),

    /// A caller-supplied argument was rejected before reaching ETW.
    #[error("{parameter} {problem}")]
    InvalidParameter {
        /// Which argument was rejected.
        parameter: &'static str,
        /// What was wrong with it.
        problem: ParameterProblem,
    },

    /// Event data did not match what the schema said to expect.
    ///
    /// `message` stays free-form prose: these describe byte-level malformations
    /// that callers log rather than branch on, so naming each as its own variant
    /// would add API surface without giving anyone a decision to make. It is a
    /// [`Cow`](std::borrow::Cow) so the many fixed descriptions cost no
    /// allocation on a path that runs per event.
    #[error("{}{message}", LocationPrefix(location.as_deref()))]
    ParseError {
        /// Event and property this happened in, when known.
        ///
        /// `None` for the byte-level parsers, which are event-agnostic. Boxed so
        /// the common `None` costs a pointer instead of carrying a
        /// [`ParseLocation`] inline.
        ///
        /// Not a speed optimisation — see the note on [`Error`], which measured
        /// `Result` width to be free on the parse path. Keep the box because it
        /// keeps the variant tidy, not in the belief that unboxing would cost
        /// throughput.
        location: Option<Box<ParseLocation>>,
        /// What was wrong with the bytes.
        message: std::borrow::Cow<'static, str>,
    },

    /// Requested property does not exist in this event's schema.
    #[error("{context} property '{name}' not found")]
    PropertyNotFound {
        /// The property name that was looked up.
        name: String,
        /// Identity of the event whose schema was searched.
        context: EventContext,
    },

    /// Event version is below the minimum supported by this parser
    #[error("Event version {version} is not supported (minimum: {minimum})")]
    UnsupportedVersion {
        /// The event's actual version
        version: u8,
        /// The minimum version this parser supports
        minimum: u8,
    },

    /// Requested extended data is not attached to this event.
    #[error("event has no extended data of type {kind} ({})", event::extended_data_type::name(*kind))]
    NotPresent {
        /// `EVENT_HEADER_EXT_TYPE_*` code, as named in
        /// [`extended_data_type`](crate::event::extended_data_type).
        kind: u16,
    },

    /// Static schema does not match what TDH reports for this event.
    #[error("schema validation failed for {context}: {mismatch}")]
    SchemaValidationError {
        /// Identity of the event being validated.
        context: EventContext,
        /// How the schema and TDH disagreed.
        ///
        /// Boxed because [`SchemaMismatch`] is 64 bytes on its own — inline it
        /// and this variant alone would be most of `Error`. It only ever occurs
        /// at startup, so the indirection costs nothing that matters.
        ///
        /// This keeps `Error` clear of `clippy::result_large_err`'s 128-byte
        /// threshold, which is the only size constraint that actually bites; see
        /// the note on [`Error`] for the measurement.
        mismatch: Box<SchemaMismatch>,
    },

    /// Provider name is not registered on this system.
    #[error("Provider '{name}' not found")]
    ProviderNotFound {
        /// The provider name that was looked up.
        name: String,
    },

    /// Provider name resolves to more than one registration, so it does not
    /// identify a single GUID. Distinct from [`Error::ProviderNotFound`]: the
    /// name matched too many providers rather than none.
    #[error("Provider '{name}' matches multiple registrations")]
    ProviderAmbiguous {
        /// The ambiguous provider name.
        name: String,
    },

    /// The operation requires a provider that is enabled on this session.
    #[error("provider {} is not enabled on this session", ProviderLabel(name.as_deref(), provider))]
    ProviderNotEnabled {
        /// The provider that was not enabled.
        provider: Guid,
        /// The provider's registered name, when the caller supplied one.
        name: Option<String>,
    },

    /// Processing thread failed to start, or exited when it should not have.
    #[error("processing thread {reason}")]
    ThreadError {
        /// Which stage failed, and what it carried.
        reason: ThreadFailure,
    },

    /// A retry or size guard was exhausted.
    #[error("{operation} exceeded its limit of {limit}")]
    LimitExceeded {
        /// The operation that gave up.
        operation: &'static str,
        /// The limit it reached.
        limit: u32,
    },

    /// NT API failure — raw NTSTATUS values that are not `NT_SUCCESS` (i.e. high bit set).
    #[error("NTSTATUS(0x{:08X}{}): {}", *_0 as u32, NameSuffix(ntstatus_name(*_0)), _0.resolve_message())]
    NtError(i32),
}

/// Where a parse failure happened.
///
/// The byte-level parsers are event-agnostic and carry no location at all —
/// [`Error::ParseError`]'s `location` is `None` for them. When a property
/// accessor attaches one on the way out, both parts are known, so the fields
/// are plain rather than optional. Carried as fields so the identity is not
/// fused into the message, which is what made the old payload impossible to
/// read back.
#[derive(Debug, Clone)]
pub struct ParseLocation {
    /// Identity of the event being parsed.
    context: EventContext,
    /// Property being read.
    property: String,
}

impl ParseLocation {
    /// Identity of the event being parsed.
    #[must_use]
    pub const fn context(&self) -> EventContext {
        self.context
    }

    /// Name of the property being read.
    #[must_use]
    pub fn property(&self) -> &str {
        &self.property
    }
}

/// Renders an optional [`ParseLocation`] prefix, without allocating for the
/// absent case.
struct LocationPrefix<'a>(Option<&'a ParseLocation>);

impl std::fmt::Display for LocationPrefix<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(location) => location.fmt(f),
            None => Ok(()),
        }
    }
}

impl std::fmt::Display for ParseLocation {
    /// Renders a trailing-space prefix: `<context> property '<name>': `.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} property '{}': ", self.context, self.property)
    }
}

/// Renders a provider as its registered name when known, its GUID otherwise.
struct ProviderLabel<'a>(Option<&'a str>, &'a Guid);

impl std::fmt::Display for ProviderLabel<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(name) => f.write_str(name),
            None => write!(f, "{}", self.1),
        }
    }
}

/// How a static schema disagreed with what TDH reports.
///
/// Carried by [`Error::SchemaValidationError`] alongside the event's identity,
/// so the field index and the two sides of the mismatch stay addressable rather
/// than being assembled into a sentence at the point of failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SchemaMismatch {
    /// `TdhGetEventInformation` failed while reporting its buffer size.
    #[error("TdhGetEventInformation sizing failed (Win32 {status})")]
    TdhSizingFailed {
        /// Raw Win32 code returned by TDH.
        status: u32,
    },

    /// `TdhGetEventInformation` failed while filling the buffer.
    #[error("TdhGetEventInformation retrieval failed (Win32 {status})")]
    TdhRetrievalFailed {
        /// Raw Win32 code returned by TDH.
        status: u32,
    },

    /// A truncated schema declared more fields than TDH reports.
    #[error("expected at least {expected} fields, got {actual}")]
    TooFewFields {
        /// Fields the static schema declares.
        expected: usize,
        /// Fields TDH reports.
        actual: usize,
    },

    /// The schema and TDH disagree on how many fields the event has.
    #[error("expected {expected} fields, got {actual}")]
    FieldCount {
        /// Fields the static schema declares.
        expected: usize,
        /// Fields TDH reports.
        actual: usize,
    },

    /// A field is named differently in the schema and in TDH.
    #[error("field {index} name mismatch: expected '{expected}', got '{actual}'")]
    FieldName {
        /// Zero-based field position.
        index: usize,
        /// Name the static schema declares.
        expected: &'static str,
        /// Name TDH reports.
        actual: String,
    },

    /// An index hint carried forward from the latest known version points past
    /// the end of the next version's fields.
    #[error(
        "canary hint index {index} for field '{field}' is out of bounds (only {property_count} fields)"
    )]
    CanaryHintOutOfBounds {
        /// The stale hint index.
        index: usize,
        /// Field the hint was meant to reach.
        field: String,
        /// Fields the next version actually has.
        property_count: usize,
    },

    /// An index hint carried forward from the latest known version resolves to a
    /// different field in the next version.
    #[error(
        "canary hint index {index} is '{actual}', expected '{expected}' — index hints from the latest known version are stale"
    )]
    CanaryHintStale {
        /// The stale hint index.
        index: usize,
        /// Field the hint was meant to reach.
        expected: String,
        /// Field actually found there.
        actual: String,
    },

    /// A field's declared type does not match the TDH `InType`.
    #[error("field {index} ('{field}') type mismatch: expected '{expected}', got '{actual}'")]
    FieldType {
        /// Zero-based field position.
        index: usize,
        /// The field's name.
        field: &'static str,
        /// Type the static schema declares.
        expected: &'static str,
        /// Type TDH reports.
        actual: &'static str,
    },

    /// A field's TDH property flags lack bits its declared layout requires
    /// (`PropertyStruct` 0x1, `PropertyParamLength` 0x2, `PropertyParamCount` 0x4).
    #[error("field {index} ('{field}') flags {actual:#x} missing required {required:#x}")]
    FieldFlags {
        /// Zero-based field position.
        index: usize,
        /// The field's name.
        field: &'static str,
        /// Property flag bits the layout requires.
        required: u32,
        /// Flags TDH reports.
        actual: u32,
    },
}

/// What was wrong with a caller-supplied argument.
///
/// Carried by [`Error::InvalidParameter`] alongside the parameter's name, so
/// the limit and the offending value stay readable as data rather than being
/// baked into a sentence.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ParameterProblem {
    /// An argument that must not be empty was empty.
    #[error("must not be empty")]
    Empty,

    /// A collection argument exceeded its fixed ETW capacity.
    #[error("has {count} entries, exceeding the maximum of {max}")]
    TooMany {
        /// Entries supplied.
        count: usize,
        /// Most entries ETW accepts.
        max: usize,
    },

    /// A collection argument repeated an entry that must be unique.
    #[error("contains duplicate entries")]
    Duplicates,

    /// A scalar argument was above its permitted maximum.
    #[error("is {value}, exceeding the maximum of {max}")]
    TooLarge {
        /// Value supplied.
        value: u64,
        /// Largest accepted value.
        max: u64,
    },

    /// A string argument was longer than its permitted maximum. Distinct from
    /// [`ParameterProblem::TooLarge`]: the length is over the limit, not the
    /// value itself.
    #[error("is {length} bytes long, exceeding the maximum of {max}")]
    TooLong {
        /// Bytes supplied.
        length: usize,
        /// Most bytes accepted.
        max: usize,
    },

    /// A value did not correspond to anything ETW defines.
    #[error("contains unrecognised value 0x{value:04X}")]
    Unrecognised {
        /// The value that did not resolve.
        value: u32,
    },

    /// A value broke a documented format rule for its parameter.
    #[error("must be {requirement}")]
    Malformed {
        /// The rule that was broken.
        requirement: &'static str,
    },
}

/// Which stage of the processing thread's life failed.
///
/// Carried by [`Error::ThreadError`]. The stage is the useful signal — a spawn
/// failure is an OS resource problem, an early exit is a callback problem — so
/// it is a variant rather than a sentence.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ThreadFailure {
    /// The OS refused to create the thread.
    ///
    /// The [`io::Error`](std::io::Error) is rendered into the message rather
    /// than exposed via `source()`, matching the crate's self-contained
    /// Display and keeping chain-walking reporters from printing it twice.
    #[error("could not be spawned: {0}")]
    SpawnFailed(std::io::Error),

    /// The thread died before signalling that it had initialised.
    #[error("exited before initialisation completed")]
    ExitedBeforeReady,

    /// The event callback panicked on an early event and the panic policy
    /// stopped the trace before startup finished.
    #[error("stopped during startup: the event callback panicked on an early event")]
    PanicDuringStartup,

    /// The thread exited on its own with a non-success code.
    #[error("exited unexpectedly with code {code}")]
    ExitedWithCode {
        /// The thread's exit code.
        code: u32,
    },
}

impl Error {
    /// Builds a [`Error::ParseError`] with no location attached.
    ///
    /// Takes `impl Into<Cow<'static, str>>` so a fixed description passes
    /// through borrowed and only an interpolated one allocates.
    ///
    /// Public because `event_schema!` generates parsers in the caller's crate
    /// and they raise this on a malformed event.
    #[must_use]
    pub fn parse(message: impl Into<std::borrow::Cow<'static, str>>) -> Self {
        Self::ParseError {
            location: None,
            message: message.into(),
        }
    }

    /// Attaches the event and property to a [`Error::ParseError`], leaving any
    /// other error untouched.
    ///
    /// Sets fields rather than rewriting the message, so the identity stays
    /// readable back off the error.
    pub(crate) fn at_property(self, context: EventContext, property: &str) -> Self {
        match self {
            Self::ParseError { message, .. } => Self::ParseError {
                location: Some(Box::new(ParseLocation {
                    context,
                    property: property.to_owned(),
                })),
                message,
            },
            other => other,
        }
    }
}

impl Error {
    /// Internal conversion from a `windows` error type. Deliberately not a
    /// `From` impl: trait impls are public API, and no `windows` type may
    /// cross the public boundary.
    pub(crate) const fn from_win32(err: WIN32_ERROR) -> Self {
        Self::Win32Error(err)
    }

    /// Internal conversion — see [`Error::from_win32`].
    pub(crate) const fn from_ntstatus(status: NTSTATUS) -> Self {
        Self::NtError(status)
    }
}

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Custom Debug renders the Win32 and NT variants as
        //   Win32Error(5, ACCESS_DENIED, "Access is denied.")
        //   NtError(0xC0000022, ACCESS_DENIED, "Access is denied.")
        // — numeric code, symbolic name when known, resolved message — instead
        // of the noisier `WIN32_ERROR(5)` / `NTSTATUS(-1073741790)` derived form.
        // All other variants delegate to the obvious tuple/struct Debug.
        match self {
            Self::Win32Error(code) => {
                let mut t = f.debug_tuple("Win32Error");
                t.field(code);
                if let Some(name) = win32_name(*code) {
                    t.field(&format_args!("{name}"));
                }
                t.field(&code.resolve_message()).finish()
            }
            Self::NtError(status) => {
                let mut t = f.debug_tuple("NtError");
                t.field(&format_args!("0x{:08X}", *status as u32));
                if let Some(name) = ntstatus_name(*status) {
                    t.field(&format_args!("{name}"));
                }
                t.field(&status.resolve_message()).finish()
            }
            Self::InvalidParameter { parameter, problem } => f
                .debug_struct("InvalidParameter")
                .field("parameter", parameter)
                .field("problem", problem)
                .finish(),
            Self::ParseError { location, message } => {
                // Most parse errors come from event-agnostic byte parsers and
                // carry no location; printing an empty field for them is noise.
                let mut s = f.debug_struct("ParseError");
                if let Some(location) = location {
                    s.field("location", &format_args!("{location}"));
                }
                s.field("message", message).finish()
            }
            Self::PropertyNotFound { name, context } => f
                .debug_struct("PropertyNotFound")
                .field("name", name)
                .field("context", &format_args!("{context}"))
                .finish(),
            Self::UnsupportedVersion { version, minimum } => f
                .debug_struct("UnsupportedVersion")
                .field("version", version)
                .field("minimum", minimum)
                .finish(),
            Self::NotPresent { kind } => f.debug_struct("NotPresent").field("kind", kind).finish(),
            Self::SchemaValidationError { context, mismatch } => f
                .debug_struct("SchemaValidationError")
                .field("context", &format_args!("{context}"))
                .field("mismatch", mismatch)
                .finish(),
            Self::ProviderNotFound { name } => f
                .debug_struct("ProviderNotFound")
                .field("name", name)
                .finish(),
            Self::ProviderAmbiguous { name } => f
                .debug_struct("ProviderAmbiguous")
                .field("name", name)
                .finish(),
            Self::ProviderNotEnabled { provider, name } => f
                .debug_struct("ProviderNotEnabled")
                .field("provider", &format_args!("{provider}"))
                .field("name", name)
                .finish(),
            Self::ThreadError { reason } => f
                .debug_struct("ThreadError")
                .field("reason", reason)
                .finish(),
            Self::LimitExceeded { operation, limit } => f
                .debug_struct("LimitExceeded")
                .field("operation", operation)
                .field("limit", limit)
                .finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Error::{NtError, Win32Error},
        *,
    };

    /// Event identity for the error cases below; the values are arbitrary but
    /// non-zero so `id`/`op` actually render.
    const TEST_CONTEXT: EventContext = EventContext::new(Guid::from_u128(0), 12, 3, 1);

    /// The identity is carried as data so callers can read it back without
    /// parsing Display output — so the accessors, not just the fields, matter.
    #[test]
    fn test_event_context_accessors_return_constructed_identity() {
        assert_eq!(TEST_CONTEXT.provider(), Guid::from_u128(0));
        assert_eq!(TEST_CONTEXT.id(), 12);
        assert_eq!(TEST_CONTEXT.opcode(), 3);
        assert_eq!(TEST_CONTEXT.version(), 1);
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls FormatMessageW (Win32)")]
    fn test_error_display_for_win32() {
        let err = Error::from_win32(5);
        let msg = format!("{err}");
        // Known codes carry their SDK constant's name: it is locale-stable
        // where the FormatMessageW text is not, and it is what the reader
        // greps the docs for.
        assert!(
            msg.starts_with("WIN32_ERROR(5, ACCESS_DENIED):"),
            "got: {msg}"
        );
        assert!(msg.contains("Access is denied"), "got: {msg}");

        // A code outside the partial name table renders as before.
        let unknown = Error::from_win32(59); // ERROR_UNEXP_NET_ERR
        let msg = format!("{unknown}");
        assert!(msg.starts_with("WIN32_ERROR(59):"), "got: {msg}");
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls FormatMessageW (Win32)")]
    fn test_error_debug_for_win32() {
        let err = Error::from_win32(5);
        let msg = format!("{err:?}");
        // Should look like: Win32Error(5, ACCESS_DENIED, "Access is denied.")
        assert!(
            msg.starts_with("Win32Error(5, ACCESS_DENIED,"),
            "got: {msg}"
        );
        assert!(msg.contains("Access is denied"), "got: {msg}");
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls FormatMessageW (Win32)")]
    fn test_error_display_for_nterror() {
        // STATUS_ACCESS_DENIED = 0xC0000022 — has a Win32 mapping (5).
        let err = Error::from_ntstatus(0xC000_0022_u32 as i32);
        let msg = format!("{err}");
        assert!(
            msg.starts_with("NTSTATUS(0xC0000022, ACCESS_DENIED):"),
            "got: {msg}"
        );
        assert!(msg.contains("Access is denied"), "got: {msg}");
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls FormatMessageW (Win32)")]
    fn test_error_debug_for_nterror() {
        let err = Error::from_ntstatus(0xC000_0022_u32 as i32);
        let msg = format!("{err:?}");
        // Should look like: NtError(0xC0000022, ACCESS_DENIED, "Access is denied.")
        assert!(
            msg.starts_with("NtError(0xC0000022, ACCESS_DENIED,"),
            "got: {msg}"
        );
        assert!(msg.contains("Access is denied"), "got: {msg}");
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls FormatMessageW (Win32)")]
    fn test_nterror_unmapped_falls_back() {
        // Pick a deliberately invalid NTSTATUS whose only ntdll mapping is
        // ERROR_MR_MID_NOT_FOUND. Reserved-facility values like 0xE0000001
        // (severity=Error, customer-defined) reliably have no Win32 mapping.
        let err = Error::from_ntstatus(0xE000_0001_u32 as i32);
        let msg = format!("{err}");
        assert!(msg.contains("<unmapped>"), "got: {msg}");
    }

    #[test]
    fn test_win32_error_code_is_readable_back() {
        let err = Error::from_win32(5);
        assert!(matches!(err, Win32Error(5)));
        assert!(!matches!(err, Win32Error(6)));
    }

    /// The point of carrying identity as data is that a caller can read it back
    /// without parsing Display output. Without accessors these structs would be
    /// write-only, which is the defect this shape exists to remove — so assert
    /// the round-trip rather than trusting that the fields are stored.
    #[test]
    fn test_carried_identity_is_readable_without_formatting() {
        let err = Error::parse("bad bytes").at_property(TEST_CONTEXT, "Pid");
        let Error::ParseError { location, .. } = &err else {
            panic!("expected ParseError, got {err:?}");
        };
        let Some(location) = location.as_deref() else {
            panic!("at_property must attach a location");
        };
        assert_eq!(location.property(), "Pid");
        assert_eq!(
            location.context().version(),
            1,
            "the event version must survive as data, not only in the message"
        );

        // A parse error raised by a byte-level parser carries no location, and
        // that absence must not cost an allocation.
        let bare = Error::parse("bad bytes");
        assert!(
            matches!(bare, Error::ParseError { location: None, .. }),
            "got {bare:?}"
        );
    }

    /// Guards the one size constraint that actually bites: `clippy::all` enables
    /// `clippy::result_large_err`, whose threshold is 128 bytes, so a variant
    /// that pushes `Error` past that turns every `Result<T, Error>` in the crate
    /// into a lint failure under CI's `-D warnings`.
    ///
    /// Deliberately not pinned to the current 48 bytes. Width was measured to be
    /// free on the parse path (see the `# Width` note on [`Error`]), so a snug
    /// bound would only manufacture failures for changes that cost nothing;
    /// this asserts the limit that has a real consequence.
    #[test]
    fn test_error_stays_under_result_large_err_threshold() {
        assert!(
            size_of::<Error>() <= 128,
            "Error is {} bytes; clippy::result_large_err's limit is 128 — box the offending payload",
            size_of::<Error>()
        );
    }

    #[test]
    fn test_error_debug_covers_every_arm() {
        // Exercises the hand-written Debug arms. Each case pins a fragment of
        // its own payload, so an arm that printed the wrong field — or dropped
        // one — fails here rather than silently degrading diagnostics.
        let cases: &[(Error, &str)] = &[
            (
                Error::InvalidParameter {
                    parameter: "PID filter",
                    problem: ParameterProblem::TooMany { count: 9, max: 8 },
                },
                "TooMany { count: 9, max: 8 }",
            ),
            // No location: the field is omitted rather than printed empty.
            (Error::parse("p"), "ParseError { message: \"p\" }"),
            (
                Error::parse("p").at_property(TEST_CONTEXT, "Pid"),
                "location: provider",
            ),
            (
                Error::PropertyNotFound {
                    name: "p".to_owned(),
                    context: TEST_CONTEXT,
                },
                "name: \"p\"",
            ),
            (Error::NotPresent { kind: 2 }, "NotPresent { kind: 2 }"),
            (
                Error::SchemaValidationError {
                    context: TEST_CONTEXT,
                    mismatch: Box::new(SchemaMismatch::FieldCount {
                        expected: 4,
                        actual: 3,
                    }),
                },
                "FieldCount { expected: 4, actual: 3 }",
            ),
            (
                Error::ProviderNotFound {
                    name: "p".to_owned(),
                },
                "ProviderNotFound { name: \"p\" }",
            ),
            (
                Error::ProviderAmbiguous {
                    name: "p".to_owned(),
                },
                "ProviderAmbiguous { name: \"p\" }",
            ),
            (
                Error::ProviderNotEnabled {
                    provider: Guid::from_u128(0),
                    name: Some("p".to_owned()),
                },
                "provider: 00000000-0000-0000-0000-000000000000, name: Some(\"p\")",
            ),
            (
                Error::ThreadError {
                    reason: ThreadFailure::ExitedWithCode { code: 3 },
                },
                "ExitedWithCode { code: 3 }",
            ),
            (
                Error::LimitExceeded {
                    operation: "op",
                    limit: 8,
                },
                "LimitExceeded { operation: \"op\", limit: 8 }",
            ),
        ];
        for (err, expected) in cases {
            let s = format!("{err:?}");
            assert!(s.contains(expected), "expected {expected:?} in: {s}");
        }
    }

    #[test]
    fn test_error_debug_for_unsupported_version() {
        let err = Error::UnsupportedVersion {
            version: 1,
            minimum: 2,
        };
        let s = format!("{err:?}");
        assert!(s.contains("UnsupportedVersion"), "got: {s}");
        assert!(s.contains("version: 1"), "got: {s}");
        assert!(s.contains("minimum: 2"), "got: {s}");
    }

    #[test]
    fn test_nterror_code_is_readable_back() {
        let err = Error::from_ntstatus(0xC000_0022_u32 as i32);
        assert!(matches!(err, NtError(s) if s == 0xC000_0022_u32 as i32));
        assert!(!matches!(err, NtError(s) if s == 0xC000_0001_u32 as i32));
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls FormatMessageW (Win32)")]
    fn test_resolve_message_trait_for_win32() {
        let m = 5u32.resolve_message();
        assert!(m.contains("Access is denied"), "got: {m}");
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls FormatMessageW (Win32)")]
    fn test_resolve_message_trait_for_ntstatus() {
        let m = (0xC000_0022_u32 as i32).resolve_message();
        assert!(m.contains("Access is denied"), "got: {m}");
    }

    #[test]
    fn test_pool_tag_encodes_bytes_as_le_u32() {
        // ASCII tags: 'T', 'C', 'P', 'I' → 0x49504354 (little-endian)
        assert_eq!(pool_tag(b"TCPI"), 0x4950_4354);
        // Four NUL bytes → 0
        assert_eq!(pool_tag(b"\0\0\0\0"), 0);
        // Round-trip: same bytes as little-endian u32
        assert_eq!(pool_tag(b"ABCD"), u32::from_le_bytes(*b"ABCD"));
    }

    #[test]
    fn test_error_debug_string_variants() {
        let cases: &[(Error, &str)] = &[
            (
                Error::PropertyNotFound {
                    name: "Pid".to_owned(),
                    context: TEST_CONTEXT,
                },
                "PropertyNotFound { name: \"Pid\"",
            ),
            (
                Error::UnsupportedVersion {
                    version: 3,
                    minimum: 4,
                },
                "UnsupportedVersion",
            ),
            (Error::NotPresent { kind: 2 }, "NotPresent { kind: 2 }"),
            (
                Error::SchemaValidationError {
                    context: TEST_CONTEXT,
                    mismatch: Box::new(SchemaMismatch::TdhSizingFailed { status: 87 }),
                },
                "SchemaValidationError",
            ),
            (
                Error::ProviderNotFound {
                    name: "Microsoft-Foo".to_owned(),
                },
                "ProviderNotFound",
            ),
            (
                Error::ProviderAmbiguous {
                    name: "Microsoft-Foo".to_owned(),
                },
                "ProviderAmbiguous",
            ),
            (
                Error::ProviderNotEnabled {
                    provider: Guid::from_u128(0),
                    name: Some("Microsoft-Foo".to_owned()),
                },
                "ProviderNotEnabled",
            ),
            (
                Error::ThreadError {
                    reason: ThreadFailure::ExitedBeforeReady,
                },
                "ThreadError",
            ),
            (
                Error::LimitExceeded {
                    operation: "op",
                    limit: 256,
                },
                "LimitExceeded",
            ),
        ];
        for (err, expected_prefix) in cases {
            let s = format!("{err:?}");
            assert!(
                s.contains(expected_prefix),
                "expected '{expected_prefix}' in Debug output, got: {s}"
            );
        }
    }

    #[test]
    fn test_error_display_string_variants() {
        // Display must render both the name and the event identity, since the
        // identity is now carried as data rather than pre-formatted into the name.
        let not_found = Error::PropertyNotFound {
            name: "Pid".to_owned(),
            context: TEST_CONTEXT,
        }
        .to_string();
        assert!(not_found.contains("Pid"), "got: {not_found}");
        assert!(not_found.contains("id:12"), "got: {not_found}");
        assert!(not_found.contains("v1"), "got: {not_found}");
        assert!(Error::parse("bad data").to_string().contains("bad data"));
        // Display must surface both the operation and the limit, since both are
        // now fields rather than a pre-formatted sentence.
        let limit = Error::LimitExceeded {
            operation: "TdhEnumerateProviders retry",
            limit: 8,
        }
        .to_string();
        assert!(
            limit.contains("TdhEnumerateProviders retry"),
            "got: {limit}"
        );
        assert!(limit.contains('8'), "got: {limit}");
        // NotPresent names the extended-data type, so a log reader does not
        // have to look the code up.
        let not_present = Error::NotPresent { kind: 2 }.to_string();
        assert!(not_present.contains("(SID)"), "got: {not_present}");
        // ProviderNotEnabled renders the name when known and the GUID otherwise,
        // and stays operation-neutral: disable_provider and capture_state both
        // raise it.
        let by_name = Error::ProviderNotEnabled {
            provider: Guid::from_u128(1),
            name: Some("Microsoft-Foo".to_owned()),
        }
        .to_string();
        assert!(by_name.contains("Microsoft-Foo"), "got: {by_name}");
        assert!(!by_name.contains("disable"), "got: {by_name}");
        let by_guid = Error::ProviderNotEnabled {
            provider: Guid::from_u128(1),
            name: None,
        }
        .to_string();
        assert!(
            by_guid.contains("00000000-0000-0000-0000-000000000001"),
            "got: {by_guid}"
        );
    }
}
