//! Integration tests for the out-type check in static schema validation.
//!
//! An ANSI string field decodes as UTF-8 or as the ANSI code page depending on its
//! TDH out-type, which a static schema declares with `@ out(...)`. `validate_schema`
//! must fail a schema whose declaration disagrees with the manifest, or the static
//! accessor silently decodes with the wrong encoding.
//!
//! Requires Microsoft-Windows-Kernel-EventTracing event 31 (Lost TraceLogging Event,
//! Windows 11 21H2 and later), whose `EventName` is an `AnsiString` with out-type
//! `Utf8`.

#![cfg(windows)]

use etw::{
    Error, Guid, SchemaMismatch, TdhOutType,
    static_schema::{StaticFieldInfo, StaticVersionInfo, validate_schema},
};

const EVENT_TRACING_GUID: Guid = Guid::from_u128(0xb675ec37_bdb6_4648_bc92_f3fdc74d3ca2);
const LOST_TRACE_LOGGING_EVENT: u16 = 31;

fn validate_event_name(declared: TdhOutType) -> etw::Result<()> {
    let fields = Vec::leak(vec![
        StaticFieldInfo {
            name: "ProviderId",
            expected_tdh_type: None,
            expected_out_type: None,
            required_property_flags: 0,
        },
        StaticFieldInfo {
            name: "StatusCode",
            expected_tdh_type: None,
            expected_out_type: None,
            required_property_flags: 0,
        },
        StaticFieldInfo {
            name: "EventName",
            expected_tdh_type: Some("AnsiString"),
            expected_out_type: Some(declared),
            required_property_flags: 0,
        },
    ]);
    validate_schema(
        &EVENT_TRACING_GUID,
        LOST_TRACE_LOGGING_EVENT,
        0,
        false,
        &[StaticVersionInfo {
            version: 0,
            fields,
            truncated: true,
        }],
        &[],
    )
}

#[test]
#[cfg_attr(miri, ignore = "validate_schema queries live TDH (Win32)")]
fn missing_utf8_out_type_fails_validation() {
    match validate_event_name(TdhOutType::String) {
        Err(Error::SchemaValidationError { mismatch, .. }) => assert!(
            matches!(
                *mismatch,
                SchemaMismatch::FieldOutType {
                    index: 2,
                    field: "EventName",
                    expected: TdhOutType::String,
                    actual: TdhOutType::Utf8,
                }
            ),
            "expected an out-type mismatch on EventName, got {mismatch:?}"
        ),
        other => panic!(
            "an unannotated UTF-8 field must fail validation; got {other:?} \
             (Ok means Kernel-EventTracing event 31 is not registered on this host)"
        ),
    }
}

#[test]
#[cfg_attr(miri, ignore = "validate_schema queries live TDH (Win32)")]
fn matching_utf8_out_type_passes_validation() -> etw::Result<()> {
    validate_event_name(TdhOutType::Utf8)
}
