//! Tests for static schema parser with pointer-sized fields (WOW64 support).
//!
//! Verifies that `usize`/`isize` fields are parsed correctly for both 64-bit
//! and 32-bit (WOW64) events, with correct offset calculations for fields
//! following pointer-sized fields.

#![cfg(windows)]
#![expect(
    clippy::unwrap_used,
    reason = "test binary: printing aids diagnosis and panics are the failure mode"
)]

use etw::event_schema;

// Schema with pointer-sized fields in the fixed prefix.
// Layout varies by pointer size:
//   64-bit: Irp(8) + FileObject(8) + ThreadId(4) + Options(4) = 24 bytes
//   32-bit: Irp(4) + FileObject(4) + ThreadId(4) + Options(4) = 16 bytes
event_schema! {
    name: "PointerTest",
    id: 1,
    version: 0,
    fields: {
        Irp: usize,
        FileObject: usize,
        ThreadId: u32,
        Options: u32,
    }
}

// Schema with pointer fields followed by a variable-length string.
// Tests that fixed_end_offset is correctly computed for both pointer sizes.
event_schema! {
    name: "PointerWithString",
    id: 2,
    version: 0,
    fields: {
        Address: usize,
        Size: u32,
        Name: WideStrRef,
    }
}

// Schema with a mix of fixed and pointer fields where some fields
// precede the first pointer field (their offsets should be identical).
event_schema! {
    name: "MixedPointer",
    id: 3,
    version: 0,
    fields: {
        ProcessId: u32,
        ThreadId: u32,
        BaseAddress: usize,
        RegionSize: usize,
        Flags: u32,
    }
}

#[test]
fn test_64bit_pointer_fields() -> etw::Result<()> {
    // Build 64-bit event data: Irp=0xDEAD, FileObject=0xBEEF, ThreadId=42, Options=7
    let mut data = Vec::new();
    data.extend_from_slice(&0xDEAD_u64.to_le_bytes()); // Irp (8 bytes)
    data.extend_from_slice(&0xBEEF_u64.to_le_bytes()); // FileObject (8 bytes)
    data.extend_from_slice(&42_u32.to_le_bytes()); // ThreadId
    data.extend_from_slice(&7_u32.to_le_bytes()); // Options

    let parser = PointerTestV0Parser::from_bytes(&data);

    assert_eq!(parser.Irp()?, 0xDEAD);
    assert_eq!(parser.FileObject()?, 0xBEEF);
    assert_eq!(parser.ThreadId()?, 42);
    assert_eq!(parser.Options()?, 7);

    Ok(())
}

#[test]
fn test_32bit_pointer_fields() -> etw::Result<()> {
    // Build 32-bit event data: Irp=0xDEAD, FileObject=0xBEEF, ThreadId=42, Options=7
    let mut data = Vec::new();
    data.extend_from_slice(&0xDEAD_u32.to_le_bytes()); // Irp (4 bytes)
    data.extend_from_slice(&0xBEEF_u32.to_le_bytes()); // FileObject (4 bytes)
    data.extend_from_slice(&42_u32.to_le_bytes()); // ThreadId
    data.extend_from_slice(&7_u32.to_le_bytes()); // Options

    let parser = PointerTestV0Parser::from_bytes_with_pointer_size(&data, 4);

    assert_eq!(parser.Irp()?, 0xDEAD);
    assert_eq!(parser.FileObject()?, 0xBEEF);
    assert_eq!(parser.ThreadId()?, 42);
    assert_eq!(parser.Options()?, 7);

    Ok(())
}

#[test]
fn test_32bit_pointer_with_variable_string() -> etw::Result<()> {
    // Build 32-bit event data: Address=0x1234, Size=100, Name="test.dll"
    let mut data = Vec::new();
    data.extend_from_slice(&0x1234_u32.to_le_bytes()); // Address (4 bytes, 32-bit)
    data.extend_from_slice(&100_u32.to_le_bytes()); // Size

    // Name: null-terminated UTF-16 string
    for ch in "test.dll".encode_utf16() {
        data.extend_from_slice(&ch.to_le_bytes());
    }
    data.extend_from_slice(&[0u8, 0u8]); // null terminator

    let mut parser = PointerWithStringV0Parser::from_bytes_with_pointer_size(&data, 4);

    assert_eq!(parser.Address()?, 0x1234);
    assert_eq!(parser.Size()?, 100);
    assert_eq!(parser.Name()?, "test.dll");

    Ok(())
}

#[test]
fn test_64bit_pointer_with_variable_string() -> etw::Result<()> {
    // Build 64-bit event data: Address=0x7FFF_DEAD_BEEF, Size=100, Name="test.dll"
    let mut data = Vec::new();
    data.extend_from_slice(&0x7FFF_DEAD_BEEF_u64.to_le_bytes()); // Address (8 bytes)
    data.extend_from_slice(&100_u32.to_le_bytes()); // Size

    // Name: null-terminated UTF-16 string
    for ch in "test.dll".encode_utf16() {
        data.extend_from_slice(&ch.to_le_bytes());
    }
    data.extend_from_slice(&[0u8, 0u8]); // null terminator

    let mut parser = PointerWithStringV0Parser::from_bytes_with_pointer_size(&data, 8);

    assert_eq!(parser.Address()?, 0x7FFF_DEAD_BEEF);
    assert_eq!(parser.Size()?, 100);
    assert_eq!(parser.Name()?, "test.dll");

    Ok(())
}

#[test]
fn test_mixed_pointer_offsets() -> etw::Result<()> {
    // Fields before pointer fields should have identical offsets for both sizes.
    // Fields after pointer fields should have different offsets.

    // 64-bit layout: ProcessId(4) + ThreadId(4) + BaseAddress(8) + RegionSize(8) + Flags(4)
    let mut data_64 = Vec::new();
    data_64.extend_from_slice(&1000_u32.to_le_bytes()); // ProcessId
    data_64.extend_from_slice(&2000_u32.to_le_bytes()); // ThreadId
    data_64.extend_from_slice(&0xFFFF_0000_u64.to_le_bytes()); // BaseAddress
    data_64.extend_from_slice(&0x1000_u64.to_le_bytes()); // RegionSize
    data_64.extend_from_slice(&0x42_u32.to_le_bytes()); // Flags

    let parser = MixedPointerV0Parser::from_bytes_with_pointer_size(&data_64, 8);
    assert_eq!(parser.ProcessId()?, 1000);
    assert_eq!(parser.ThreadId()?, 2000);
    assert_eq!(parser.BaseAddress()?, 0xFFFF_0000);
    assert_eq!(parser.RegionSize()?, 0x1000);
    assert_eq!(parser.Flags()?, 0x42);

    // 32-bit layout: ProcessId(4) + ThreadId(4) + BaseAddress(4) + RegionSize(4) + Flags(4)
    let mut data_32 = Vec::new();
    data_32.extend_from_slice(&1000_u32.to_le_bytes()); // ProcessId
    data_32.extend_from_slice(&2000_u32.to_le_bytes()); // ThreadId
    data_32.extend_from_slice(&0xFFFF_0000_u32.to_le_bytes()); // BaseAddress (4 bytes)
    data_32.extend_from_slice(&0x1000_u32.to_le_bytes()); // RegionSize (4 bytes)
    data_32.extend_from_slice(&0x42_u32.to_le_bytes()); // Flags

    let parser = MixedPointerV0Parser::from_bytes_with_pointer_size(&data_32, 4);
    assert_eq!(parser.ProcessId()?, 1000);
    assert_eq!(parser.ThreadId()?, 2000);
    assert_eq!(parser.BaseAddress()?, 0xFFFF_0000);
    assert_eq!(parser.RegionSize()?, 0x1000);
    assert_eq!(parser.Flags()?, 0x42);

    Ok(())
}

#[test]
fn test_32bit_would_fail_without_pointer_size_support() {
    // Demonstrate that using from_bytes (64-bit default) on 32-bit data produces wrong results.
    // The data is laid out as 32-bit but parsed assuming 64-bit pointers.
    let mut data_32 = Vec::new();
    data_32.extend_from_slice(&0xDEAD_u32.to_le_bytes()); // Irp (4 bytes)
    data_32.extend_from_slice(&0xBEEF_u32.to_le_bytes()); // FileObject (4 bytes)
    data_32.extend_from_slice(&42_u32.to_le_bytes()); // ThreadId
    data_32.extend_from_slice(&7_u32.to_le_bytes()); // Options

    // from_bytes defaults to 64-bit, so the parser expects 8-byte pointers.
    // Irp reads bytes 0..8 (which is Irp + FileObject concatenated) — wrong value.
    let parser = PointerTestV0Parser::from_bytes(&data_32);
    let irp = parser.Irp().unwrap();

    // On 64-bit host: reads 8 bytes from offset 0 = 0x0000BEEF_0000DEAD (little-endian)
    // This is NOT 0xDEAD, proving the 64-bit assumption is wrong for 32-bit data.
    assert_ne!(
        irp, 0xDEAD,
        "should NOT match — 64-bit parse of 32-bit data gives wrong value"
    );
}
