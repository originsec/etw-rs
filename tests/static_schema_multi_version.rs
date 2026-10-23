//! Integration tests for multi-version parser generation.
//!
//! Verifies that `provider_schema!` with multiple event versions correctly
//! generates the superset accessor trait, per-version trait impls, and
//! the dispatch macro.

#![cfg(windows)]
#![expect(
    clippy::unwrap_used,
    reason = "test binary: printing aids diagnosis and panics are the failure mode"
)]

use etw::{Error, Guid, provider_schema};

// Two provider_schema! invocations in the same module — previously caused a
// `validate_all_schemas` name collision; now resolved via the CRT constructor
// approach, which generates a uniquely named static per invocation.

// Two independent versions with different fields (no extends_version).
provider_schema! {
    guid: Guid::from_u128(0x00000000_0000_0000_0000_100000000001),
    events: {
        event {
            id: 1,
            name: "Independent",
            version { 0, fields: {
                Common: u32,
                OnlyV0: u32,
            }}
            version { 1, fields: {
                Common: u32,
                OnlyV1: u64,
            }}
        }
    }
}

// Version chain with extends_version.
provider_schema! {
    guid: Guid::from_u128(0x00000000_0000_0000_0000_100000000002),
    events: {
        event {
            id: 1,
            name: "Extended",
            version { 0, fields: {
                Base: u32,
                BaseTwo: u32,
            }}
            version { 1, extends_version: 0, fields: {
                Extra: u64,
            }}
        }
    }
}

// ---------------------------------------------------------------------------
// Synthetic data constructors
// ---------------------------------------------------------------------------

fn make_independent_v0() -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&42u32.to_le_bytes()); // Common
    data.extend_from_slice(&99u32.to_le_bytes()); // OnlyV0
    data
}

fn make_independent_v1() -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&42u32.to_le_bytes()); // Common
    data.extend_from_slice(&12345u64.to_le_bytes()); // OnlyV1
    data
}

fn make_extended_v0() -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&10u32.to_le_bytes()); // Base
    data.extend_from_slice(&20u32.to_le_bytes()); // BaseTwo
    data
}

fn make_extended_v1() -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&10u32.to_le_bytes()); // Base
    data.extend_from_slice(&20u32.to_le_bytes()); // BaseTwo
    data.extend_from_slice(&999u64.to_le_bytes()); // Extra
    data
}

// ---------------------------------------------------------------------------
// Independent versions — trait on per-version parsers
// ---------------------------------------------------------------------------

#[test]
fn independent_v0_present_fields() -> etw::Result<()> {
    let data = make_independent_v0();
    let mut p = IndependentV0Parser::from_bytes(&data);
    assert_eq!(IndependentAccessors::Common(&mut p)?, 42);
    assert_eq!(IndependentAccessors::OnlyV0(&mut p)?, 99);
    Ok(())
}

#[test]
fn independent_v0_absent_field_returns_property_not_found() {
    let data = make_independent_v0();
    let mut p = IndependentV0Parser::from_bytes(&data);
    let err = IndependentAccessors::OnlyV1(&mut p).unwrap_err();
    assert!(
        matches!(err, Error::PropertyNotFound { ref name, .. } if name == "OnlyV1"),
        "expected PropertyNotFound for OnlyV1, got: {err}"
    );
    // The generated context must describe *this* parser's version, not some
    // other version of the same event.
    assert!(err.to_string().contains("v0"), "got: {err}");
}

#[test]
fn independent_v1_present_fields() -> etw::Result<()> {
    let data = make_independent_v1();
    let mut p = IndependentV1Parser::from_bytes(&data);
    assert_eq!(IndependentAccessors::Common(&mut p)?, 42);
    assert_eq!(IndependentAccessors::OnlyV1(&mut p)?, 12345);
    Ok(())
}

#[test]
fn independent_v1_absent_field_returns_property_not_found() {
    let data = make_independent_v1();
    let mut p = IndependentV1Parser::from_bytes(&data);
    let err = IndependentAccessors::OnlyV0(&mut p).unwrap_err();
    assert!(
        matches!(err, Error::PropertyNotFound { ref name, .. } if name == "OnlyV0"),
        "expected PropertyNotFound for OnlyV0, got: {err}"
    );
    assert!(err.to_string().contains("v1"), "got: {err}");
}

// ---------------------------------------------------------------------------
// Extended versions — trait on per-version parsers
// ---------------------------------------------------------------------------

#[test]
fn extended_v0_present_fields() -> etw::Result<()> {
    let data = make_extended_v0();
    let mut p = ExtendedV0Parser::from_bytes(&data);
    assert_eq!(ExtendedAccessors::Base(&mut p)?, 10);
    assert_eq!(ExtendedAccessors::BaseTwo(&mut p)?, 20);
    Ok(())
}

#[test]
fn extended_v0_absent_field_returns_property_not_found() {
    let data = make_extended_v0();
    let mut p = ExtendedV0Parser::from_bytes(&data);
    let err = ExtendedAccessors::Extra(&mut p).unwrap_err();
    assert!(
        matches!(err, Error::PropertyNotFound { ref name, .. } if name == "Extra"),
        "expected PropertyNotFound for Extra, got: {err}"
    );
    assert!(err.to_string().contains("v0"), "got: {err}");
}

#[test]
fn extended_v1_has_all_fields() -> etw::Result<()> {
    let data = make_extended_v1();
    let mut p = ExtendedV1Parser::from_bytes(&data);
    // Base fields inherited via extends_version
    assert_eq!(ExtendedAccessors::Base(&mut p)?, 10);
    assert_eq!(ExtendedAccessors::BaseTwo(&mut p)?, 20);
    // V1-only field
    assert_eq!(ExtendedAccessors::Extra(&mut p)?, 999);
    Ok(())
}

// ---------------------------------------------------------------------------
// Dispatch macro — verify it compiles with a named generic handler
// ---------------------------------------------------------------------------

fn handle_independent<'a>(p: &mut impl IndependentAccessors<'a>) -> etw::Result<u32> {
    p.Common()
}

fn handle_extended<'a>(p: &mut impl ExtendedAccessors<'a>) -> etw::Result<u32> {
    p.Base()
}

#[test]
fn dispatch_macro_compiles_with_static_parser() -> etw::Result<()> {
    // Call the generic handler directly on a V0Parser to verify the dispatch
    // macro's monomorphisation pattern compiles. Full dispatch via
    // event.version() requires a real EVENT_RECORD, so we test the shape only.
    let data = make_independent_v0();
    let mut p = IndependentV0Parser::from_bytes(&data);
    assert_eq!(handle_independent(&mut p)?, 42);

    let data = make_extended_v1();
    let mut p = ExtendedV1Parser::from_bytes(&data);
    assert_eq!(handle_extended(&mut p)?, 10);

    Ok(())
}
