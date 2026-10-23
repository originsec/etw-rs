//! Integration tests for the N+1 canary check in static schema validation.
//!
//! `validate_schema` checks that index hints from the latest known event version
//! still correctly identify field names in the next version (N+1). These tests
//! verify that stale hints are detected as errors when a newer version inserts or
//! removes fields, and that stable hints pass cleanly when a newer version only
//! appends fields.
//!
//! ## Test design
//!
//! Error-case tests use `StaticVersionInfo { fields: &[], truncated: true }` for every
//! known version, making the version check a no-op. Only the canary (`validate_next_version_hints`)
//! can then cause `validate_schema` to return `Err`. A test that asserts `is_err()` therefore
//! fails unconditionally if the canary logic is broken — the bug cannot hide behind a
//! coincidental version-check failure from mismatched field names.
//!
//! Requires the following providers to be registered (always present on Windows 10+):
//! - Microsoft-Windows-Kernel-File (`edd08927-9cc4-4e65-b970-c2560fb5c289`)
//! - Microsoft-Windows-Kernel-Process (`22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716`)

#![cfg(windows)]
#![expect(
    clippy::expect_used,
    reason = "test binary: printing aids diagnosis and panics are the failure mode"
)]

use etw::{
    Guid, provider_schema,
    static_schema::{StaticFieldInfo, StaticVersionInfo, validate_schema},
};

const PROCESS_GUID: Guid = Guid::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716);
#[cfg(debug_assertions)]
const FILE_GUID: Guid = Guid::from_u128(0xedd08927_9cc4_4e65_b970_c2560fb5c289);

fn leak<T>(v: Vec<T>) -> &'static [T] {
    Vec::leak(v)
}

/// A `StaticVersionInfo` with no fields and `truncated: true`.
///
/// Using this for all known-version entries makes the version check a no-op:
/// `validate_single_version` always returns `Ok(())` regardless of the actual
/// TDH schema. Only `validate_next_version_hints` (the canary) can then return
/// `Err`, so the test result is fully determined by canary correctness.
#[cfg(debug_assertions)]
const fn version_stub(v: u8) -> StaticVersionInfo {
    StaticVersionInfo {
        version: v,
        fields: &[],
        truncated: true,
    }
}

// ── Kernel-File Create (event 12) ───────────────────────────────────────────

/// Kernel-File Create V0 only: ThreadId is at index 1 in V0, but V1 replaces it with
/// FileObject. The stale hint ("ThreadId", 1) should be detected by the canary.
///
/// Only runs in debug builds: in release the canary logs a warning and returns `Ok`.
#[cfg(debug_assertions)]
#[test]
#[cfg_attr(miri, ignore = "validate_schema queries live TDH (Win32)")]
fn file_create_stale_v0_hints_detected_by_v1_canary() {
    let result = validate_schema(
        &FILE_GUID,
        12,
        0,
        false,
        &[version_stub(0)],
        // V0[1] = ThreadId, V1[1] = FileObject → stale
        &[("ThreadId", 1)],
    );
    assert!(
        result.is_err(),
        "canary must detect stale hint: V0[1]=ThreadId but V1[1]=FileObject; got Ok(())"
    );
}

// ── Microsoft-Windows-Kernel-Process ProcessStart (event 1) ─────────────────

/// ProcessStart V0 only: ImageName is at index 4 in V0, but V1 inserted Flags at
/// index 4, pushing ImageName to index 5.
///
/// Only runs in debug builds: in release the canary logs a warning and returns `Ok`.
#[cfg(debug_assertions)]
#[test]
#[cfg_attr(miri, ignore = "validate_schema queries live TDH (Win32)")]
fn process_start_stale_v0_hints_detected_by_v1_canary() {
    let result = validate_schema(
        &PROCESS_GUID,
        1,
        0,
        false,
        &[version_stub(0)],
        // V0[4] = ImageName, V1[4] = Flags → stale
        &[("ImageName", 4)],
    );
    assert!(
        result.is_err(),
        "canary must detect stale hint: V0[4]=ImageName but V1[4]=Flags; got Ok(())"
    );
}

/// ProcessStart V0-V2: V3 inserted ProcessSequenceNumber at index 1, shifting
/// CreateTime from index 1 to index 2.
///
/// Only runs in debug builds: in release the canary logs a warning and returns `Ok`.
#[cfg(debug_assertions)]
#[test]
#[cfg_attr(miri, ignore = "validate_schema queries live TDH (Win32)")]
fn process_start_stale_v2_hints_detected_by_v3_canary() {
    let result = validate_schema(
        &PROCESS_GUID,
        1,
        0,
        false,
        &[version_stub(0), version_stub(1), version_stub(2)],
        // V2[1] = CreateTime, V3[1] = ProcessSequenceNumber → stale
        &[("CreateTime", 1)],
    );
    assert!(
        result.is_err(),
        "canary must detect stale hint: V2[1]=CreateTime but V3[1]=ProcessSequenceNumber; got Ok(())"
    );
}

/// ProcessStart V3-only: V4 only appends SecurityMitigations, so all V3 index
/// hints remain valid. The canary should pass cleanly.
///
/// Uses full V3 fields (not a stub) so the version check also exercises the
/// field-name and type validation path, giving broader coverage.
#[test]
#[cfg_attr(miri, ignore = "validate_schema queries live TDH (Win32)")]
fn process_start_stable_v3_hints_pass_v4_canary() {
    let result = validate_schema(
        &PROCESS_GUID,
        1,
        0,
        false,
        &[StaticVersionInfo {
            version: 3,
            fields: leak(vec![
                StaticFieldInfo {
                    name: "ProcessID",
                    expected_tdh_type: Some("UInt32"),
                    required_property_flags: 0,
                },
                StaticFieldInfo {
                    name: "ProcessSequenceNumber",
                    expected_tdh_type: Some("UInt64"),
                    required_property_flags: 0,
                },
                StaticFieldInfo {
                    name: "CreateTime",
                    expected_tdh_type: Some("FileTime"),
                    required_property_flags: 0,
                },
                StaticFieldInfo {
                    name: "ParentProcessID",
                    expected_tdh_type: Some("UInt32"),
                    required_property_flags: 0,
                },
                StaticFieldInfo {
                    name: "ParentProcessSequenceNumber",
                    expected_tdh_type: Some("UInt64"),
                    required_property_flags: 0,
                },
                StaticFieldInfo {
                    name: "SessionID",
                    expected_tdh_type: Some("UInt32"),
                    required_property_flags: 0,
                },
                StaticFieldInfo {
                    name: "Flags",
                    expected_tdh_type: Some("UInt32"),
                    required_property_flags: 0,
                },
                StaticFieldInfo {
                    name: "ProcessTokenElevationType",
                    expected_tdh_type: Some("UInt32"),
                    required_property_flags: 0,
                },
                StaticFieldInfo {
                    name: "ProcessTokenIsElevated",
                    expected_tdh_type: Some("UInt32"),
                    required_property_flags: 0,
                },
                StaticFieldInfo {
                    name: "MandatoryLabel",
                    expected_tdh_type: Some("SID"),
                    required_property_flags: 0,
                },
                StaticFieldInfo {
                    name: "ImageName",
                    expected_tdh_type: Some("UnicodeString"),
                    required_property_flags: 0,
                },
                StaticFieldInfo {
                    name: "ImageChecksum",
                    expected_tdh_type: Some("UInt32"),
                    required_property_flags: 0,
                },
                StaticFieldInfo {
                    name: "TimeDateStamp",
                    expected_tdh_type: Some("UInt32"),
                    required_property_flags: 0,
                },
                StaticFieldInfo {
                    name: "PackageFullName",
                    expected_tdh_type: Some("UnicodeString"),
                    required_property_flags: 0,
                },
                StaticFieldInfo {
                    name: "PackageRelativeAppId",
                    expected_tdh_type: Some("UnicodeString"),
                    required_property_flags: 0,
                },
            ]),
            truncated: false,
        }],
        // All 15 V3 fields are at the same indices in V4 (V4 only appends SecurityMitigations).
        &[
            ("ProcessID", 0),
            ("ProcessSequenceNumber", 1),
            ("CreateTime", 2),
            ("ParentProcessID", 3),
            ("ParentProcessSequenceNumber", 4),
            ("SessionID", 5),
            ("Flags", 6),
            ("ProcessTokenElevationType", 7),
            ("ProcessTokenIsElevated", 8),
            ("MandatoryLabel", 9),
            ("ImageName", 10),
            ("ImageChecksum", 11),
            ("TimeDateStamp", 12),
            ("PackageFullName", 13),
            ("PackageRelativeAppId", 14),
        ],
    );
    assert!(
        result.is_ok(),
        "stable V3 hints against V4 should pass; got: {result:?}"
    );
}

// ── Macro-path test ──────────────────────────────────────────────────────────
//
// The tests above call `validate_schema` directly. This test goes through the
// full `provider_schema!` → `{Name}Parser::validate_schema()` path to confirm
// the macro actually wires its generated hints into the call (regression guard
// against the macro silently emitting `&[]`).
//
// A V3-only schema is used because both the auto-generated `.unwrap()` test and
// this assertion expect `Ok`: V3 fields are correct and V4 only appends.
// Error-case schemas cannot be used here because `provider_schema!` always
// generates `#[test] fn validate_schema() { ... .unwrap(); }`, which would
// panic for a schema that is intentionally missing the latest version.

provider_schema! {
    guid: Guid::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716),
    events: {
        event {
            id: 1,
            name: "ProcessStartV3MacroTest",
            version { 3, fields: {
                ProcessID: u32,
                ProcessSequenceNumber: u64,
                CreateTime: u64,
                ParentProcessID: u32,
                ParentProcessSequenceNumber: u64,
                SessionID: u32,
                Flags: u32,
                ProcessTokenElevationType: u32,
                ProcessTokenIsElevated: u32,
                MandatoryLabel: SidRef,
                ImageName: WideStrRef,
                ImageChecksum: u32,
                TimeDateStamp: u32,
                PackageFullName: WideStrRef,
                PackageRelativeAppId: WideStrRef,
            }}
        }
    }
}

/// Exercises the macro-generated `validate_schema()` method end-to-end.
///
/// `provider_schema!` emits V3 hints from `last.fields` and passes them to
/// `etw::static_schema::validate_schema`. The V4 canary should pass because
/// V4 only appends SecurityMitigations at the end.
#[test]
#[cfg_attr(miri, ignore = "validate_schema queries live TDH (Win32)")]
fn macro_generated_hints_pass_v4_canary() {
    ProcessStartV3MacroTestParser::validate_schema()
        .expect("macro-generated V3 hints should be valid for V4 canary");
}
