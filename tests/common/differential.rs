//! Offline differential-testing harness: etw-rs versus TDH, with no ETW session.
//!
//! Imported per test file with `#[path = "common/differential.rs"] mod differential;`.
//!
//! # Why this exists
//!
//! The parser's older unit tests hand-encoded a payload with a helper, decoded it
//! with the parser, and asserted the round trip. Encoder and decoder were written
//! from the same mental model, so a wrong belief about the wire format was encoded
//! twice and asserted against itself. `TDH_INTYPE_COUNTEDSTRING`'s length prefix is
//! a byte count, not a character count; both sides believed "characters", and the
//! test passed while the parser over-read the field and drifted every property
//! after it.
//!
//! A test is only worth its runtime if the expected value comes from somewhere
//! other than the code under test. This harness supplies two such sources:
//!
//! 1. **TDH** — Microsoft's own decoder for the format etw-rs implements. A disagreement between
//!    the two means one of them is wrong; neither can hide a shared misconception, because they
//!    share no code.
//! 2. **A sentinel** — every fixture event ends with a `UInt32` of known value, so an over- or
//!    under-read anywhere earlier corrupts it. Drift cannot pass silently by landing in a field
//!    nobody asserted on.
//!
//! Payloads here are still built in Rust, so the harness also asserts the intended
//! value. That closes the remaining gap: a decoder bug breaks the TDH comparison, an
//! encoder bug breaks the intent comparison, and no single wrong belief satisfies
//! both.
//!
//! # Why it needs no session and no elevation
//!
//! `TdhLoadManifest` registers a manifest for the calling process only — it needs
//! no `wevtutil im`, leaves no machine-global state, and works from a medium
//! integrity token. TDH will then resolve and decode an `EVENT_RECORD` assembled in
//! memory that never came from a trace session. So the whole type-and-ordering
//! matrix runs as ordinary `cargo test` unit tests: no Administrator, no logger
//! slots, no `#[serial]`, deterministic.

#![expect(
    dead_code,
    reason = "shared across test binaries; only some use each item"
)]
#![expect(
    unreachable_pub,
    reason = "leaf module of each integration test binary"
)]

use etw::RawEvent;
use std::{ffi::c_void, sync::OnceLock};
use windows::{
    Win32::System::Diagnostics::Etw::{
        EVENT_DESCRIPTOR, EVENT_RECORD, PROPERTY_DATA_DESCRIPTOR, TdhGetProperty,
        TdhGetPropertySize, TdhLoadManifest,
    },
    core::{GUID, PCWSTR},
};

/// Provider GUID declared by `tests/fixtures/differential.man`.
pub const PROVIDER: GUID = GUID::from_u128(0x6f5b3a21_9c4e_4d17_b8a6_2e7f10c4d983);

/// Trailing `UInt32` on every fixture event. Chosen to be asymmetric under byte
/// reversal and to contain no zero byte, so a truncated or shifted read cannot
/// coincidentally reproduce it.
pub const SENTINEL: u32 = 0x5A5A_A5A5;

/// Leading `UInt8` on every fixture event. Its only job is to push the field under
/// test to an odd offset, so a parser that assumes natural alignment fails here
/// rather than in production.
pub const LEAD: u8 = 0xC3;

/// `EVENT_HEADER_FLAG_64_BIT_HEADER` — selects 8-byte `win:Pointer` fields.
pub const FLAG_64_BIT: u16 = 0x0200;

/// `EVENT_HEADER_FLAG_32_BIT_HEADER`.
///
/// No offline fixture uses this, and one cannot usefully: `TdhLoadManifest` resolves
/// the manifest in *this* process, so `win:Pointer` gets a concrete declared length
/// of 8 baked into the schema. Setting the 32-bit header flag does not undo that —
/// measured, with the flag set and a 4-byte pointer payload, etw-rs and TDH *agree*
/// on reading 8 bytes and both then run past the end. So the flag changes nothing
/// here and a 32-bit fixture would only be testing the harness.
///
/// Real 32-bit pointer coverage belongs where the record genuinely comes from a
/// 32-bit process: `tests/32bit_events.rs`, and `tests/mixed_bitness_events.rs`,
/// which covers the schema-cache key that once let the first bitness seen decide
/// the offsets for both.
pub const FLAG_32_BIT: u16 = 0x0040;

/// Loads the fixture manifest into this process, once.
///
/// # Panics
///
/// Panics if `TdhLoadManifest` fails, which would make every test in the file
/// meaningless rather than merely failing.
pub fn load_fixture_manifest() {
    static LOADED: OnceLock<()> = OnceLock::new();
    LOADED.get_or_init(|| {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            r"\tests\fixtures\differential.man"
        );
        let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: `wide` is a NUL-terminated UTF-16 path that outlives the call.
        let status = unsafe { TdhLoadManifest(PCWSTR(wide.as_ptr())) };
        assert_eq!(
            status, 0,
            "TdhLoadManifest({path}) failed with Win32 {status}"
        );
    });
}

/// An `EVENT_RECORD` assembled in memory, owning its own payload.
///
/// The record's `UserData` points into `payload`. `payload` is boxed and never
/// mutated after construction, so the pointer stays valid for the lifetime of the
/// `TestRecord` even if the `TestRecord` itself is moved.
pub struct TestRecord {
    payload: Box<[u8]>,
    record: EVENT_RECORD,
}

impl std::fmt::Debug for TestRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestRecord")
            .field("event_id", &self.record.EventHeader.EventDescriptor.Id)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

impl TestRecord {
    /// Assembles a record for `event_id` carrying `payload`, with the pointer size
    /// selected by `header_flags` ([`FLAG_64_BIT`] or [`FLAG_32_BIT`]).
    pub fn new(event_id: u16, payload: Vec<u8>, header_flags: u16) -> Self {
        let payload = payload.into_boxed_slice();
        let mut record = EVENT_RECORD::default();
        record.EventHeader.ProviderId = PROVIDER;
        record.EventHeader.EventDescriptor = EVENT_DESCRIPTOR {
            Id: event_id,
            Version: 0,
            Channel: 0,
            Level: 4, // win:Informational, matching the manifest
            Opcode: 0,
            Task: 0,
            Keyword: 0,
        };
        record.EventHeader.Flags = header_flags;
        record.UserDataLength = u16::try_from(payload.len()).expect("fixture payload exceeds u16");

        let mut this = Self { payload, record };
        // `as_mut_ptr`, not `&mut payload[0]`: an event with no user data is a
        // legitimate fixture, and indexing would panic on the empty slice. With
        // UserDataLength at 0 the pointer is never dereferenced.
        this.record.UserData = this.payload.as_mut_ptr().cast::<c_void>();
        this
    }

    /// Assembles a 64-bit record. The common case; 32-bit needs an explicit flag.
    pub fn new_64bit(event_id: u16, payload: Vec<u8>) -> Self {
        Self::new(event_id, payload, FLAG_64_BIT)
    }

    /// Borrows the record as an etw-rs [`RawEvent`], the same type a live callback
    /// receives, so tests run the production parsing path rather than a test-only
    /// entry point.
    pub const fn as_raw_event(&self) -> &RawEvent {
        // SAFETY: `self.record` is a fully initialised EVENT_RECORD whose UserData
        // points at `self.payload`; both live as long as `&self`, and the returned
        // reference is bounded by that borrow.
        unsafe { RawEvent::from_ptr(std::ptr::from_ref(&self.record).cast()) }
    }
}

/// What TDH says a single property occupies, as raw bytes.
///
/// Takes a [`RawEvent`] so the same oracle serves both the offline fixtures and
/// events arriving in a live session callback — the comparison must not differ
/// between the two, or the offline tests would be checking a different thing from
/// the one production hits.
///
/// Returns `Err(status)` with the Win32 error if TDH declines to decode the
/// property, which is itself a meaningful signal: etw-rs should not succeed where
/// TDH fails, nor the reverse.
pub fn tdh_property_bytes(event: &RawEvent, name: &str) -> Result<Vec<u8>, u32> {
    tdh_property_bytes_at(event, name, u32::MAX)
}

/// Reads one element of an array property, as TDH sees it. `u32::MAX` selects the
/// whole property rather than an element.
pub fn tdh_property_bytes_at(event: &RawEvent, name: &str, index: u32) -> Result<Vec<u8>, u32> {
    let wname: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let desc = PROPERTY_DATA_DESCRIPTOR {
        PropertyName: wname.as_ptr() as u64,
        ArrayIndex: index,
        ..Default::default()
    };
    // etw-rs hands back its own (windows-sys) EVENT_RECORD; the layout is
    // identical to this test's `windows` crate type, so cast at the seam.
    let record = std::ptr::from_ref(event.as_raw()).cast::<EVENT_RECORD>();

    let mut size: u32 = 0;
    // SAFETY: `desc` names a property by a NUL-terminated UTF-16 string that
    // outlives the call; `record` is valid for the borrow of `event`.
    let status = unsafe { TdhGetPropertySize(record, None, &[desc], &raw mut size) };
    if status != 0 {
        return Err(status);
    }

    let mut buf = vec![0u8; size as usize];
    // SAFETY: `buf` is sized by the probe immediately above; same descriptor
    // validity as the size call.
    let status = unsafe { TdhGetProperty(record, None, &[desc], &mut buf) };
    if status != 0 {
        return Err(status);
    }
    Ok(buf)
}

/// What TDH says one member of a struct occupies.
///
/// A struct member is addressed by a two-element descriptor path — the struct, then
/// the member — not by a bare name, so this cannot go through
/// [`tdh_property_bytes`]. Without it the struct walk
/// (`struct_start_index`/`struct_member_count`) has no oracle and only the struct's
/// total extent gets checked.
pub fn tdh_struct_member_bytes(
    event: &RawEvent,
    struct_name: &str,
    member_name: &str,
) -> Result<Vec<u8>, u32> {
    let wstruct: Vec<u16> = struct_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let wmember: Vec<u16> = member_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let path = [
        PROPERTY_DATA_DESCRIPTOR {
            PropertyName: wstruct.as_ptr() as u64,
            ArrayIndex: 0,
            ..Default::default()
        },
        PROPERTY_DATA_DESCRIPTOR {
            PropertyName: wmember.as_ptr() as u64,
            ArrayIndex: 0,
            ..Default::default()
        },
    ];
    // etw-rs hands back its own (windows-sys) EVENT_RECORD; the layout is
    // identical to this test's `windows` crate type, so cast at the seam.
    let record = std::ptr::from_ref(event.as_raw()).cast::<EVENT_RECORD>();

    let mut size: u32 = 0;
    // SAFETY: both descriptors name properties by NUL-terminated UTF-16 strings that
    // outlive the call; `record` is valid for the borrow of `event`.
    let status = unsafe { TdhGetPropertySize(record, None, &path, &raw mut size) };
    if status != 0 {
        return Err(status);
    }
    let mut buf = vec![0u8; size as usize];
    // SAFETY: `buf` sized by the probe above; same descriptor validity.
    let status = unsafe { TdhGetProperty(record, None, &path, &mut buf) };
    if status != 0 {
        return Err(status);
    }
    Ok(buf)
}

/// Compares every property etw-rs finds against TDH's view of the same event.
///
/// Returns one description per disagreement. Shared by the offline fixtures and
/// the live TraceLogging test so both apply an identical standard.
pub fn compare_event_with_tdh(
    label: &str,
    event: &RawEvent,
    ctx: &mut etw::processing_context::ProcessingContext,
) -> Vec<String> {
    let mut problems = Vec::new();

    let mut parser = match ctx.parser(event) {
        Ok(p) => p,
        Err(e) => {
            problems.push(format!("{label}: etw-rs could not build a parser: {e}"));
            return problems;
        }
    };
    let props = match parser.named_properties() {
        Ok(p) => p,
        Err(e) => {
            problems.push(format!("{label}: etw-rs named_properties failed: {e}"));
            return problems;
        }
    };

    for (name, prop) in &props {
        match tdh_property_bytes(event, name) {
            Ok(tdh) if prop.data() == tdh.as_slice() => {}
            Ok(tdh) => problems.push(format!(
                "{label}.{name}: etw-rs {:02x?} != TDH {:02x?}",
                prop.data(),
                tdh
            )),
            // TDH refuses to hand back a zero-byte property, reporting
            // ERROR_INVALID_PARAMETER. That is an API convention, not a disagreement
            // about extent: a `count == 0` array or a PropertyParamLength of 0
            // genuinely occupies no bytes, which is exactly what etw-rs reports. This
            // is deliberately narrow — the refusal counts as agreement only when
            // etw-rs also says empty, so a refusal paired with non-empty data still
            // fails. `zero_length_properties_are_empty_not_missing` pins the contract
            // directly so it is visible rather than buried here.
            Err(ERROR_INVALID_PARAMETER) if prop.data().is_empty() => {}
            Err(status) => problems.push(format!(
                "{label}.{name}: TDH declined to decode (Win32 {status}); etw-rs gave {:02x?}",
                prop.data()
            )),
        }
    }

    problems
}

/// `ERROR_INVALID_PARAMETER` — what TDH returns for a property of zero length.
pub const ERROR_INVALID_PARAMETER: u32 = 87;

// ============================================================================
// Payload construction
//
// Deliberately dumb: no shared "encode a counted string" helper that the parser
// could agree with by construction. Each fixture spells out its own bytes, and
// TDH is what says whether those bytes mean what the test claims.
// ============================================================================

/// Starts a payload with the lead byte that forces an odd subject offset.
pub fn payload() -> Vec<u8> {
    vec![LEAD]
}

/// Appends the trailing sentinel that detects drift in everything before it.
pub fn with_sentinel(mut p: Vec<u8>) -> Vec<u8> {
    p.extend_from_slice(&SENTINEL.to_le_bytes());
    p
}

/// UTF-16LE, NUL-terminated — the `win:UnicodeString` wire form.
pub fn utf16z(s: &str) -> Vec<u8> {
    let mut v = Vec::new();
    for unit in s.encode_utf16() {
        v.extend_from_slice(&unit.to_le_bytes());
    }
    v.extend_from_slice(&[0, 0]);
    v
}

/// Single-byte, NUL-terminated — the `win:AnsiString` wire form.
pub fn ansiz(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

/// A well-formed NT-authority SID with the given sub-authorities.
pub fn sid(sub_authorities: &[u32]) -> Vec<u8> {
    let mut v = vec![1u8]; // revision
    v.push(u8::try_from(sub_authorities.len()).expect("too many sub-authorities"));
    v.extend_from_slice(&[0, 0, 0, 0, 0, 5]); // SECURITY_NT_AUTHORITY
    for sa in sub_authorities {
        v.extend_from_slice(&sa.to_le_bytes());
    }
    v
}
