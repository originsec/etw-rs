//! Test for sequential parser with offset caching.

#![cfg(windows)]

use etw::event_schema;

// Schema with a bool field (TDH Boolean = 4 bytes) to verify offset calculations.
// If the proc macro incorrectly maps bool to 1 byte, FieldAfterBool will read from
// the wrong offset and return garbage.
event_schema! {
    name: "BoolOffsetTest",
    id: 200,
    version: 0,
    fields: {
        Flags: u32,
        Active: bool,
        Value: u32,
    }
}

// Simple test schema with interleaved fields
event_schema! {
    name: "TestParser",
    id: 100,
    version: 1,
    fields: {
        // Fixed fields
        FieldA: u32,
        FieldB: u32,

        // Variable field
        FieldC: WideStrRef ,

        // Fixed after variable
        FieldD: u32,
        FieldE: u32,

        // More variable fields
        FieldF: WideStrRef ,
        FieldG: WideStrRef ,

        // Final fixed field
        FieldH: u32,
    }
}

#[test]
fn test_parser_struct_basic() -> etw::Result<()> {
    // Create mock event data
    let mut data = Vec::new();

    // Fixed fields
    data.extend_from_slice(&100_u32.to_le_bytes()); // FieldA
    data.extend_from_slice(&200_u32.to_le_bytes()); // FieldB

    // Variable field C
    for ch in "Hello".encode_utf16() {
        data.extend_from_slice(&ch.to_le_bytes());
    }
    data.extend_from_slice(&[0u8, 0u8]);

    // Fixed fields after variable
    data.extend_from_slice(&300_u32.to_le_bytes()); // FieldD
    data.extend_from_slice(&400_u32.to_le_bytes()); // FieldE

    // More variable fields
    for ch in "World".encode_utf16() {
        data.extend_from_slice(&ch.to_le_bytes());
    }
    data.extend_from_slice(&[0u8, 0u8]); // FieldF

    for ch in "Test".encode_utf16() {
        data.extend_from_slice(&ch.to_le_bytes());
    }
    data.extend_from_slice(&[0u8, 0u8]); // FieldG

    // Final fixed field
    data.extend_from_slice(&500_u32.to_le_bytes()); // FieldH

    // Test the generated parser struct
    let mut parser = TestParserV1Parser::from_bytes(&data);

    // Access fixed fields (should be fast, no scanning)
    assert_eq!(parser.FieldA()?, 100);
    assert_eq!(parser.FieldB()?, 200);

    // Access variable field (will scan)
    let field_c = parser.FieldC()?;
    assert_eq!(field_c, "Hello");

    // Access fixed fields after variable (uses cached offset from field_c)
    assert_eq!(parser.FieldD()?, 300);
    assert_eq!(parser.FieldE()?, 400);

    // Access more variable fields (uses cached offsets)
    let field_f = parser.FieldF()?;
    assert_eq!(field_f, "World");

    let field_g = parser.FieldG()?;
    assert_eq!(field_g, "Test");

    // Access final fixed field (uses cached offsets)
    assert_eq!(parser.FieldH()?, 500);

    Ok(())
}

#[test]
fn test_parser_struct_random_access() -> etw::Result<()> {
    // Create same mock data
    let mut data = Vec::new();
    data.extend_from_slice(&100_u32.to_le_bytes());
    data.extend_from_slice(&200_u32.to_le_bytes());
    for ch in "Hello".encode_utf16() {
        data.extend_from_slice(&ch.to_le_bytes());
    }
    data.extend_from_slice(&[0u8, 0u8]);
    data.extend_from_slice(&300_u32.to_le_bytes());
    data.extend_from_slice(&400_u32.to_le_bytes());
    for ch in "World".encode_utf16() {
        data.extend_from_slice(&ch.to_le_bytes());
    }
    data.extend_from_slice(&[0u8, 0u8]);
    for ch in "Test".encode_utf16() {
        data.extend_from_slice(&ch.to_le_bytes());
    }
    data.extend_from_slice(&[0u8, 0u8]);
    data.extend_from_slice(&500_u32.to_le_bytes());

    let mut parser = TestParserV1Parser::from_bytes(&data);

    // Access fields in random order - first access computes, subsequent reuse cache
    assert_eq!(parser.FieldH()?, 500); // Scans everything to reach FieldH
    assert_eq!(parser.FieldD()?, 300); // Should use cached offset
    assert_eq!(parser.FieldA()?, 100); // Fixed field, always fast
    assert_eq!(parser.FieldH()?, 500); // Second access, uses cache

    Ok(())
}

#[test]
fn test_bool_field_uses_4_bytes() -> etw::Result<()> {
    // TDH Boolean is a 4-byte Win32 BOOL. If the proc macro maps bool to 1 byte,
    // the field after the bool will read from the wrong offset.
    let mut data = Vec::new();
    data.extend_from_slice(&0x0000_00FF_u32.to_le_bytes()); // Flags
    data.extend_from_slice(&0x0000_0001_u32.to_le_bytes()); // Active (4-byte BOOL = true)
    data.extend_from_slice(&42_u32.to_le_bytes()); // Value

    let parser = BoolOffsetTestV0Parser::from_bytes(&data);
    assert_eq!(parser.Flags()?, 0xFF);
    assert!(parser.Active()?);
    assert_eq!(parser.Value()?, 42); // Would be wrong if bool was 1 byte

    Ok(())
}
