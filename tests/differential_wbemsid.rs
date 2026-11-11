//! Offline differential tests for `TDH_INTYPE_WBEMSID`: etw-rs versus TDH on the
//! kernel's classic Process events, with no ETW session.
//!
//! A WBEMSID cannot be declared in a manifest, so `differential_offline.rs` cannot
//! reach it. The kernel's MOF Process class can: TDH resolves it from the WMI
//! repository for an `EVENT_RECORD` assembled in memory.
//!
//! The fixtures are Process/Start version 3, whose `UserSID` sits ahead of the two
//! strings, so a mis-sized `UserSID` drifts `ImageFileName` and `CommandLine`. They
//! cover the TOKEN_USER-plus-SID form, invalid SIDs behind it, and the 4-byte
//! no-SID form.

#![cfg(not(miri))]
#![expect(
    clippy::expect_used,
    reason = "test binary: panics are the failure mode"
)]

#[path = "common/differential.rs"]
mod differential;

use differential::{Regime, TestRecord, compare_event_with_tdh, tdh_format_property, utf16z};
use etw::{AnsiStrRef, Sid, SidRef, TdhInType, processing_context::ProcessingContext};
use windows::core::GUID;

/// The kernel's classic Process class.
const PROCESS_CLASS: GUID = GUID::from_u128(0x3D6F_A8D0_FE05_11D0_9DDA_00C0_4FD7_BA7C);
const PROCESS_V3: u8 = 3;
const OPCODE_START: u8 = 1;

const LOCAL_SYSTEM: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];

/// A Process/Start v3 payload carrying `user_sid` as its `UserSID` field.
fn process_start(user_sid: &[u8]) -> TestRecord {
    let mut p = Vec::new();
    p.extend_from_slice(&0x1111_2222_3333_4444u64.to_le_bytes()); // UniqueProcessKey
    p.extend_from_slice(&100u32.to_le_bytes()); // ProcessId
    p.extend_from_slice(&4u32.to_le_bytes()); // ParentId
    p.extend_from_slice(&1u32.to_le_bytes()); // SessionId
    p.extend_from_slice(&0i32.to_le_bytes()); // ExitStatus
    p.extend_from_slice(&0x5555_6666_7777_8888u64.to_le_bytes()); // DirectoryTableBase
    p.extend_from_slice(user_sid);
    p.extend_from_slice(b"notepad.exe\0");
    p.extend_from_slice(&utf16z("cmd"));
    TestRecord::new_classic(PROCESS_CLASS, PROCESS_V3, OPCODE_START, p)
}

/// A non-NULL 64-bit TOKEN_USER followed by `sid`.
fn token_user_then(sid: &[u8]) -> Vec<u8> {
    let mut v = vec![0xFF; 16];
    v.extend_from_slice(sid);
    v
}

/// Each fixture: its label, the record, and the text etw-rs should give `UserSID`.
fn fixtures() -> Vec<(&'static str, TestRecord, String)> {
    let mut revision_0 = LOCAL_SYSTEM;
    revision_0[0] = 0;
    let mut count_16 = vec![1u8, 16, 0, 0, 0, 0, 0, 5];
    count_16.extend(std::iter::repeat_n(1u32.to_le_bytes(), 16).flatten());

    vec![
        (
            "LocalSystem",
            process_start(&token_user_then(&LOCAL_SYSTEM)),
            "S-1-5-18".to_owned(),
        ),
        // The kernel's missing SID, and invalid SIDs, all read; their text is what
        // TdhFormatProperty gives, checked by `user_sid_display_agrees_with_tdh`.
        ("Missing", process_start(&[0; 4]), "0".to_owned()),
        (
            "Revision0",
            process_start(&token_user_then(&revision_0)),
            "0x000100000000000512000000".to_owned(),
        ),
        (
            "Count16",
            process_start(&token_user_then(&count_16)),
            format!("0x0110000000000005{}", "01000000".repeat(16)),
        ),
    ]
}

/// Every property of every fixture must decode to exactly the bytes TDH gives.
#[test]
fn every_property_agrees_with_tdh() {
    let mut problems = Vec::new();
    for (label, record, _) in fixtures() {
        let mut ctx = ProcessingContext::new();
        problems.extend(compare_event_with_tdh(
            label,
            record.as_raw_event(),
            &mut ctx,
            Regime::ManifestOrMof,
        ));
    }
    assert!(
        problems.is_empty(),
        "etw-rs disagrees with TDH:\n{}",
        problems.join("\n")
    );
}

/// Asserts the intended values, so an encoder mistake cannot pass by fooling both
/// decoders the same way.
#[test]
fn user_sid_and_following_strings_read_as_intended() {
    for (label, record, user_sid) in fixtures() {
        let mut ctx = ProcessingContext::new();
        let mut parser = ctx
            .parser(record.as_raw_event())
            .unwrap_or_else(|e| panic!("{label}: parser construction failed: {e}"));

        let sid: Sid = parser
            .get("UserSID")
            .unwrap_or_else(|e| panic!("{label}: UserSID unreadable: {e}"));
        assert_eq!(sid.to_string(), user_sid, "{label}");
        let sid_ref: SidRef<'_> = parser
            .as_ref("UserSID")
            .unwrap_or_else(|e| panic!("{label}: UserSID unreadable: {e}"));
        assert_eq!(sid_ref.to_string(), user_sid, "{label}");

        let image = parser
            .as_ref::<AnsiStrRef<'_>>("ImageFileName")
            .unwrap_or_else(|e| panic!("{label}: ImageFileName unreadable: {e}"));
        assert_eq!(image.as_bytes(), b"notepad.exe", "{label}");
        let command_line: String = parser
            .get("CommandLine")
            .unwrap_or_else(|e| panic!("{label}: CommandLine unreadable: {e}"));
        assert_eq!(command_line, "cmd", "{label}");
    }
}

/// `UserSID` displays as `TdhFormatProperty` renders it, for every fixture but
/// `LocalSystem`: TDH renders a valid SID as an account name looked up on this
/// machine, which etw-rs deliberately does not.
#[test]
fn user_sid_display_agrees_with_tdh() {
    let mut checked = 0usize;
    for (label, record, _) in fixtures() {
        if label == "LocalSystem" {
            continue;
        }
        let mut ctx = ProcessingContext::new();
        let mut parser = ctx
            .parser(record.as_raw_event())
            .unwrap_or_else(|e| panic!("{label}: parser construction failed: {e}"));
        let props = parser
            .named_properties()
            .unwrap_or_else(|e| panic!("{label}: named_properties failed: {e}"));
        let (_, user_sid) = props
            .iter()
            .find(|(name, _)| name == "UserSID")
            .unwrap_or_else(|| panic!("{label}: no UserSID property"));
        let tdh = tdh_format_property(record.as_raw_event(), "UserSID")
            .unwrap_or_else(|status| panic!("{label}: TdhFormatProperty failed (Win32 {status})"));
        assert_eq!(user_sid.to_string(), tdh, "{label}");
        checked += 1;
    }
    assert_eq!(
        checked, 3,
        "expected every non-LocalSystem fixture compared"
    );
}

/// Guards against a vacuous pass: TDH must resolve `UserSID` as a WBEMSID. A Windows
/// build with a different Process v3 layout fails here rather than comparing
/// something else.
#[test]
fn user_sid_resolves_as_wbemsid() {
    let (label, record, _) = fixtures().swap_remove(0);
    let mut ctx = ProcessingContext::new();
    let schema = ctx
        .get_or_lookup(record.as_raw_event())
        .unwrap_or_else(|e| panic!("{label}: schema lookup failed: {e}"));
    let index = schema
        .property_index("UserSID")
        .expect("Process v3 has a UserSID property");
    let info = schema.property(index).expect("UserSID is in the schema");
    assert_eq!(TdhInType::from_raw(info.in_type()), TdhInType::WbemSid);
}
