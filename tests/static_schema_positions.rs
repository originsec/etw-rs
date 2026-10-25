//! Position tests for the static schema parser (`event_schema!` + `from_bytes()`).
//!
//! Verifies that every field type parses correctly at various positions:
//! first, after even/odd fixed prefix, after variable fields, and last.

#![cfg(windows)]
#![expect(
    clippy::unwrap_used,
    reason = "test binary: printing aids diagnosis and panics are the failure mode"
)]

use etw::event_schema;

// =============================================================================
// Buffer helpers
// =============================================================================

fn wide_str_bytes(s: &str) -> Vec<u8> {
    let mut v = Vec::new();
    for ch in s.encode_utf16() {
        v.extend_from_slice(&ch.to_le_bytes());
    }
    v.extend_from_slice(&[0u8, 0u8]); // null terminator
    v
}

fn ansi_str_bytes(s: &str) -> Vec<u8> {
    let mut v: Vec<u8> = s.as_bytes().to_vec();
    v.push(0); // null terminator
    v
}

fn sid_bytes(sub_auth_count: u8, sub_auths: &[u32]) -> Vec<u8> {
    assert_eq!(sub_auth_count as usize, sub_auths.len());
    let mut v = Vec::new();
    v.push(1); // revision
    v.push(sub_auth_count);
    v.extend_from_slice(&[0, 0, 0, 0, 0, 5]); // NT Authority
    for &sa in sub_auths {
        v.extend_from_slice(&sa.to_le_bytes());
    }
    v
}

fn counted_wide_bytes(s: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    for ch in s.encode_utf16() {
        payload.extend_from_slice(&ch.to_le_bytes());
    }
    let byte_count = payload.len() as u16;
    let mut v = byte_count.to_le_bytes().to_vec();
    v.extend_from_slice(&payload);
    v
}

fn counted_ansi_bytes(s: &str) -> Vec<u8> {
    let payload = s.as_bytes();
    let byte_count = payload.len() as u16;
    let mut v = byte_count.to_le_bytes().to_vec();
    v.extend_from_slice(payload);
    v
}

fn counted_binary_bytes(data: &[u8]) -> Vec<u8> {
    let byte_count = data.len() as u16;
    let mut v = byte_count.to_le_bytes().to_vec();
    v.extend_from_slice(data);
    v
}

fn guid_bytes(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&data1.to_le_bytes());
    buf.extend_from_slice(&data2.to_le_bytes());
    buf.extend_from_slice(&data3.to_le_bytes());
    buf.extend_from_slice(&data4);
    buf
}

fn system_time_bytes(fields: [u16; 8]) -> Vec<u8> {
    let mut buf = Vec::new();
    for &field in &fields {
        buf.extend_from_slice(&field.to_le_bytes());
    }
    buf
}

// =============================================================================
// Fixed types at first position (offset 0)
// =============================================================================

event_schema! { name: "U8First", id: 1, version: 0, fields: { Target: u8, Pad: u8 }}
event_schema! { name: "I8First", id: 2, version: 0, fields: { Target: i8, Pad: u8 }}
event_schema! { name: "U16First", id: 3, version: 0, fields: { Target: u16, Pad: u16 }}
event_schema! { name: "I16First", id: 4, version: 0, fields: { Target: i16, Pad: u16 }}
event_schema! { name: "U32First", id: 5, version: 0, fields: { Target: u32 }}
event_schema! { name: "I32First", id: 6, version: 0, fields: { Target: i32 }}
event_schema! { name: "F32First", id: 7, version: 0, fields: { Target: f32 }}
event_schema! { name: "BoolFirst", id: 8, version: 0, fields: { Target: bool }}
event_schema! { name: "U64First", id: 9, version: 0, fields: { Target: u64 }}
event_schema! { name: "I64First", id: 10, version: 0, fields: { Target: i64 }}
event_schema! { name: "F64First", id: 11, version: 0, fields: { Target: f64 }}
event_schema! { name: "UsizeFirst", id: 12, version: 0, fields: { Target: usize }}
event_schema! { name: "IsizeFirst", id: 13, version: 0, fields: { Target: isize }}
event_schema! { name: "GuidFirst", id: 14, version: 0, fields: { Target: Guid }}
event_schema! { name: "SysTimeFirst", id: 15, version: 0, fields: { Target: SystemTime }}

#[test]
fn fixed_types_at_first_position() -> etw::Result<()> {
    // u8
    let data = [42u8, 0];
    assert_eq!(U8FirstV0Parser::from_bytes(&data).Target()?, 42u8);

    // i8
    let data = [(-5i8 as u8), 0];
    assert_eq!(I8FirstV0Parser::from_bytes(&data).Target()?, -5i8);

    // u16
    let data = [0x34, 0x12, 0, 0];
    assert_eq!(U16FirstV0Parser::from_bytes(&data).Target()?, 0x1234u16);

    // i16
    let mut d = Vec::new();
    d.extend_from_slice(&(-1000i16).to_le_bytes());
    d.extend_from_slice(&[0, 0]);
    assert_eq!(I16FirstV0Parser::from_bytes(&d).Target()?, -1000i16);

    // u32
    let d = 0xDEAD_BEEFu32.to_le_bytes();
    assert_eq!(U32FirstV0Parser::from_bytes(&d).Target()?, 0xDEAD_BEEF);

    // i32
    let d = (-999_999i32).to_le_bytes();
    assert_eq!(I32FirstV0Parser::from_bytes(&d).Target()?, -999_999);

    // f32
    let d = std::f32::consts::PI.to_le_bytes();
    let val = F32FirstV0Parser::from_bytes(&d).Target()?;
    assert!((val - std::f32::consts::PI).abs() < f32::EPSILON);

    // bool (Win32 BOOL = 4 bytes)
    let d = 1u32.to_le_bytes();
    assert!(BoolFirstV0Parser::from_bytes(&d).Target()?);
    let d = 0u32.to_le_bytes();
    assert!(!BoolFirstV0Parser::from_bytes(&d).Target()?);

    // u64
    let d = 0x0123_4567_89AB_CDEFu64.to_le_bytes();
    assert_eq!(
        U64FirstV0Parser::from_bytes(&d).Target()?,
        0x0123_4567_89AB_CDEF
    );

    // i64
    let d = (-1_000_000_000_000i64).to_le_bytes();
    assert_eq!(
        I64FirstV0Parser::from_bytes(&d).Target()?,
        -1_000_000_000_000
    );

    // f64
    let d = std::f64::consts::E.to_le_bytes();
    let val = F64FirstV0Parser::from_bytes(&d).Target()?;
    assert!((val - std::f64::consts::E).abs() < f64::EPSILON);

    // usize (8 bytes on 64-bit)
    let d = 0xAAAA_BBBB_CCCC_DDDDusize.to_le_bytes();
    assert_eq!(
        UsizeFirstV0Parser::from_bytes(&d).Target()?,
        0xAAAA_BBBB_CCCC_DDDD
    );

    // isize
    let d = (-42isize).to_le_bytes();
    assert_eq!(IsizeFirstV0Parser::from_bytes(&d).Target()?, -42);

    // Guid (16 bytes)
    let d = guid_bytes(0x12345678, 0xABCD, 0xEF01, [1, 2, 3, 4, 5, 6, 7, 8]);
    let g = GuidFirstV0Parser::from_bytes(&d).Target()?;
    assert_eq!(format!("{g}"), "12345678-abcd-ef01-0102-030405060708");

    // SystemTime (16 bytes)
    let d = system_time_bytes([2025, 6, 3, 15, 10, 30, 45, 500]);
    let st = SysTimeFirstV0Parser::from_bytes(&d).Target()?;
    assert_eq!(st.year, 2025);
    assert_eq!(st.month, 6);
    assert_eq!(st.day, 15);
    assert_eq!(st.hour, 10);
    assert_eq!(st.minute, 30);
    assert_eq!(st.second, 45);
    assert_eq!(st.milliseconds, 500);

    Ok(())
}

// =============================================================================
// Fixed types after u8 prefix (odd offset)
// =============================================================================

event_schema! { name: "U16AfterU8", id: 20, version: 0, fields: { Prefix: u8, Target: u16 }}
event_schema! { name: "U32AfterU8", id: 21, version: 0, fields: { Prefix: u8, Target: u32 }}
event_schema! { name: "U64AfterU8", id: 22, version: 0, fields: { Prefix: u8, Target: u64 }}
event_schema! { name: "F32AfterU8", id: 23, version: 0, fields: { Prefix: u8, Target: f32 }}
event_schema! { name: "F64AfterU8", id: 24, version: 0, fields: { Prefix: u8, Target: f64 }}
event_schema! { name: "GuidAfterU8", id: 25, version: 0, fields: { Prefix: u8, Target: Guid }}
event_schema! { name: "SysTimeAfterU8", id: 26, version: 0, fields: { Prefix: u8, Target: SystemTime }}

#[test]
fn fixed_types_at_odd_offset() -> etw::Result<()> {
    // u16 at offset 1
    let mut d = vec![0xFFu8];
    d.extend_from_slice(&0x1234u16.to_le_bytes());
    assert_eq!(U16AfterU8V0Parser::from_bytes(&d).Target()?, 0x1234u16);

    // u32 at offset 1
    let mut d = vec![0xFFu8];
    d.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    assert_eq!(U32AfterU8V0Parser::from_bytes(&d).Target()?, 0xDEAD_BEEF);

    // u64 at offset 1
    let mut d = vec![0xFFu8];
    d.extend_from_slice(&0x0123_4567_89AB_CDEFu64.to_le_bytes());
    assert_eq!(
        U64AfterU8V0Parser::from_bytes(&d).Target()?,
        0x0123_4567_89AB_CDEF
    );

    // f32 at offset 1
    let mut d = vec![0xFFu8];
    d.extend_from_slice(&std::f32::consts::PI.to_le_bytes());
    let val = F32AfterU8V0Parser::from_bytes(&d).Target()?;
    assert!((val - std::f32::consts::PI).abs() < f32::EPSILON);

    // f64 at offset 1
    let mut d = vec![0xFFu8];
    d.extend_from_slice(&std::f64::consts::E.to_le_bytes());
    let val = F64AfterU8V0Parser::from_bytes(&d).Target()?;
    assert!((val - std::f64::consts::E).abs() < f64::EPSILON);

    // Guid at offset 1
    let mut d = vec![0xFFu8];
    d.extend_from_slice(&guid_bytes(
        0x11223344,
        0x5566,
        0x7788,
        [9, 10, 11, 12, 13, 14, 15, 16],
    ));
    let g = GuidAfterU8V0Parser::from_bytes(&d).Target()?;
    assert_eq!(format!("{g}"), "11223344-5566-7788-090a-0b0c0d0e0f10");

    // SystemTime at offset 1
    let mut d = vec![0xFFu8];
    d.extend_from_slice(&system_time_bytes([2024, 12, 0, 25, 8, 0, 0, 0]));
    let st = SysTimeAfterU8V0Parser::from_bytes(&d).Target()?;
    assert_eq!(st.year, 2024);
    assert_eq!(st.day, 25);

    Ok(())
}

// =============================================================================
// Fixed types after u16 prefix (even non-zero offset)
// =============================================================================

event_schema! { name: "U32AfterU16", id: 30, version: 0, fields: { Prefix: u16, Target: u32 }}
event_schema! { name: "U64AfterU16", id: 31, version: 0, fields: { Prefix: u16, Target: u64 }}

#[test]
fn fixed_types_at_even_offset() -> etw::Result<()> {
    let mut d = 0xAAAAu16.to_le_bytes().to_vec();
    d.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    assert_eq!(U32AfterU16V0Parser::from_bytes(&d).Target()?, 0xDEAD_BEEF);

    let mut d = 0xBBBBu16.to_le_bytes().to_vec();
    d.extend_from_slice(&0x0123_4567_89AB_CDEFu64.to_le_bytes());
    assert_eq!(
        U64AfterU16V0Parser::from_bytes(&d).Target()?,
        0x0123_4567_89AB_CDEF
    );

    Ok(())
}

// =============================================================================
// Variable types at first position
// =============================================================================

event_schema! { name: "WideFirst", id: 40, version: 0, fields: { Target: WideStrRef, Sentinel: u32 }}
event_schema! { name: "AnsiFirst", id: 41, version: 0, fields: { Target: AnsiStrRef, Sentinel: u32 }}
event_schema! { name: "SidFirst", id: 42, version: 0, fields: { Target: SidRef, Sentinel: u32 }}
event_schema! { name: "CWideFirst", id: 43, version: 0, fields: { Target: CountedWideStrRef, Sentinel: u32 }}
event_schema! { name: "CAnsiFirst", id: 44, version: 0, fields: { Target: CountedAnsiStrRef, Sentinel: u32 }}
event_schema! { name: "CBinFirst", id: 45, version: 0, fields: { Target: CountedBinaryRef, Sentinel: u32 }}

#[test]
fn variable_types_at_first_position() -> etw::Result<()> {
    // WideStrRef
    let mut d = wide_str_bytes("Hello");
    d.extend_from_slice(&0xCAFEu32.to_le_bytes());
    let mut p = WideFirstV0Parser::from_bytes(&d);
    assert_eq!(p.Target()?, "Hello");
    assert_eq!(p.Sentinel()?, 0xCAFE);

    // AnsiStrRef
    let mut d = ansi_str_bytes("world");
    d.extend_from_slice(&0xBEEFu32.to_le_bytes());
    let mut p = AnsiFirstV0Parser::from_bytes(&d);
    assert_eq!(p.Target()?, "world");
    assert_eq!(p.Sentinel()?, 0xBEEF);

    // SidRef (S-1-5-21-100)
    let mut d = sid_bytes(2, &[21, 100]);
    d.extend_from_slice(&0xDEADu32.to_le_bytes());
    let mut p = SidFirstV0Parser::from_bytes(&d);
    let sid = p.Target_ref()?;
    assert_eq!(sid.revision(), 1);
    assert_eq!(sid.sub_authority_count(), 2);
    assert_eq!(sid.sub_authority(0), Some(21));
    assert_eq!(sid.sub_authority(1), Some(100));
    assert_eq!(p.Sentinel()?, 0xDEAD);

    // CountedWideStrRef
    let mut d = counted_wide_bytes("Test");
    d.extend_from_slice(&0x1111u32.to_le_bytes());
    let mut p = CWideFirstV0Parser::from_bytes(&d);
    assert_eq!(p.Target()?, "Test");
    assert_eq!(p.Sentinel()?, 0x1111);

    // CountedAnsiStrRef
    let mut d = counted_ansi_bytes("abc");
    d.extend_from_slice(&0x2222u32.to_le_bytes());
    let mut p = CAnsiFirstV0Parser::from_bytes(&d);
    assert_eq!(p.Target()?, "abc");
    assert_eq!(p.Sentinel()?, 0x2222);

    // CountedBinaryRef
    let mut d = counted_binary_bytes(&[0xAA, 0xBB, 0xCC]);
    d.extend_from_slice(&0x3333u32.to_le_bytes());
    let mut p = CBinFirstV0Parser::from_bytes(&d);
    assert_eq!(p.Target()?, &[0xAA, 0xBB, 0xCC]);
    assert_eq!(p.Sentinel()?, 0x3333);

    Ok(())
}

#[test]
fn wide_owned_accessors_keep_lone_surrogate() -> etw::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    let payload = [0x48u8, 0x00, 0x00, 0xD8];

    let mut d = payload.to_vec();
    d.extend_from_slice(&[0, 0]);
    d.extend_from_slice(&0xCAFEu32.to_le_bytes());
    let mut p = WideFirstV0Parser::from_bytes(&d);
    let s: std::ffi::OsString = p.Target()?;
    assert_eq!(s.encode_wide().collect::<Vec<_>>(), [0x48, 0xD800]);
    assert_eq!(p.Sentinel()?, 0xCAFE);

    let mut d = 4u16.to_le_bytes().to_vec();
    d.extend_from_slice(&payload);
    d.extend_from_slice(&0x1111u32.to_le_bytes());
    let mut p = CWideFirstV0Parser::from_bytes(&d);
    let s: std::ffi::OsString = p.Target()?;
    assert_eq!(s.encode_wide().collect::<Vec<_>>(), [0x48, 0xD800]);
    assert_eq!(p.Sentinel()?, 0x1111);

    Ok(())
}

// =============================================================================
// Fixed types after variable field (WideStrRef — even offset after null)
// =============================================================================

event_schema! { name: "U32AfterWide", id: 50, version: 0, fields: {
    Prefix: WideStrRef, Target: u32,
}}
event_schema! { name: "U64AfterWide", id: 51, version: 0, fields: {
    Prefix: WideStrRef, Target: u64,
}}
event_schema! { name: "GuidAfterWide", id: 52, version: 0, fields: {
    Prefix: WideStrRef, Target: Guid,
}}

#[test]
fn fixed_types_after_wide_string() -> etw::Result<()> {
    // "AB" = 4 code units (A, B) + null = 6 bytes → even offset
    let mut d = wide_str_bytes("AB");
    d.extend_from_slice(&42u32.to_le_bytes());
    assert_eq!(U32AfterWideV0Parser::from_bytes(&d).Target()?, 42);

    let mut d = wide_str_bytes("AB");
    d.extend_from_slice(&0x1234_5678_9ABC_DEF0u64.to_le_bytes());
    assert_eq!(
        U64AfterWideV0Parser::from_bytes(&d).Target()?,
        0x1234_5678_9ABC_DEF0
    );

    let mut d = wide_str_bytes("AB");
    d.extend_from_slice(&guid_bytes(
        0xAABBCCDD,
        0x1122,
        0x3344,
        [5, 6, 7, 8, 9, 10, 11, 12],
    ));
    let g = GuidAfterWideV0Parser::from_bytes(&d).Target()?;
    assert_eq!(format!("{g}"), "aabbccdd-1122-3344-0506-0708090a0b0c");

    Ok(())
}

// =============================================================================
// Fixed types after AnsiStrRef (odd offset if string has even char count)
// =============================================================================

event_schema! { name: "U32AfterAnsi", id: 55, version: 0, fields: {
    Prefix: AnsiStrRef, Target: u32,
}}
event_schema! { name: "U64AfterAnsi", id: 56, version: 0, fields: {
    Prefix: AnsiStrRef, Target: u64,
}}

#[test]
fn fixed_types_after_ansi_string() -> etw::Result<()> {
    // "ABC" = 3 chars + null = 4 bytes → even offset
    let mut d = ansi_str_bytes("ABC");
    d.extend_from_slice(&99u32.to_le_bytes());
    assert_eq!(U32AfterAnsiV0Parser::from_bytes(&d).Target()?, 99);

    // "AB" = 2 chars + null = 3 bytes → odd offset
    let mut d = ansi_str_bytes("AB");
    d.extend_from_slice(&0xFEDC_BA98_7654_3210u64.to_le_bytes());
    assert_eq!(
        U64AfterAnsiV0Parser::from_bytes(&d).Target()?,
        0xFEDC_BA98_7654_3210
    );

    Ok(())
}

// =============================================================================
// Variable types after fixed prefix
// =============================================================================

event_schema! { name: "WideAfterU32", id: 60, version: 0, fields: {
    Prefix: u32, Target: WideStrRef,
}}
event_schema! { name: "AnsiAfterU8", id: 61, version: 0, fields: {
    Prefix: u8, Target: AnsiStrRef,
}}
event_schema! { name: "SidAfterU16", id: 62, version: 0, fields: {
    Prefix: u16, Target: SidRef,
}}

#[test]
fn variable_types_after_fixed_prefix() -> etw::Result<()> {
    // WideStrRef after u32 (offset 4)
    let mut d = 0xAAAAu32.to_le_bytes().to_vec();
    d.extend_from_slice(&wide_str_bytes("data"));
    let s = WideAfterU32V0Parser::from_bytes(&d).Target()?;
    assert_eq!(s, "data");

    // AnsiStrRef after u8 (offset 1 — odd)
    let mut d = vec![0xBBu8];
    d.extend_from_slice(&ansi_str_bytes("test"));
    let s = AnsiAfterU8V0Parser::from_bytes(&d).Target()?;
    assert_eq!(s, "test");

    // SidRef after u16 (offset 2)
    let mut d = 0xCCCCu16.to_le_bytes().to_vec();
    d.extend_from_slice(&sid_bytes(1, &[42]));
    let sid = SidAfterU16V0Parser::from_bytes(&d).Target_ref()?;
    assert_eq!(sid.sub_authority(0), Some(42));

    Ok(())
}

// =============================================================================
// Variable types after variable prefix
// =============================================================================

event_schema! { name: "WideAfterAnsi", id: 70, version: 0, fields: {
    Prefix: AnsiStrRef, Target: WideStrRef, Sentinel: u32,
}}
event_schema! { name: "AnsiAfterWide", id: 71, version: 0, fields: {
    Prefix: WideStrRef, Target: AnsiStrRef, Sentinel: u32,
}}
event_schema! { name: "SidAfterWide", id: 72, version: 0, fields: {
    Prefix: WideStrRef, Target: SidRef, Sentinel: u32,
}}

#[test]
fn variable_types_after_variable_prefix() -> etw::Result<()> {
    // WideStrRef after AnsiStrRef
    let mut d = ansi_str_bytes("hi");
    d.extend_from_slice(&wide_str_bytes("world"));
    d.extend_from_slice(&0xAAAAu32.to_le_bytes());
    let mut p = WideAfterAnsiV0Parser::from_bytes(&d);
    assert_eq!(p.Target()?, "world");
    assert_eq!(p.Sentinel()?, 0xAAAA);

    // AnsiStrRef after WideStrRef
    let mut d = wide_str_bytes("foo");
    d.extend_from_slice(&ansi_str_bytes("bar"));
    d.extend_from_slice(&0xBBBBu32.to_le_bytes());
    let mut p = AnsiAfterWideV0Parser::from_bytes(&d);
    assert_eq!(p.Target()?, "bar");
    assert_eq!(p.Sentinel()?, 0xBBBB);

    // SidRef after WideStrRef
    let mut d = wide_str_bytes("x");
    d.extend_from_slice(&sid_bytes(1, &[99]));
    d.extend_from_slice(&0xCCCCu32.to_le_bytes());
    let mut p = SidAfterWideV0Parser::from_bytes(&d);
    assert_eq!(p.Target_ref()?.sub_authority(0), Some(99));
    assert_eq!(p.Sentinel()?, 0xCCCC);

    Ok(())
}

// =============================================================================
// Types as last field
// =============================================================================

event_schema! { name: "U32Last", id: 80, version: 0, fields: {
    Prefix: WideStrRef, Target: u32,
}}
event_schema! { name: "WideLast", id: 81, version: 0, fields: {
    Prefix: u32, Target: WideStrRef,
}}
event_schema! { name: "AnsiLast", id: 82, version: 0, fields: {
    Prefix: u32, Target: AnsiStrRef,
}}
event_schema! { name: "SidLast", id: 83, version: 0, fields: {
    Prefix: u32, Target: SidRef,
}}

#[test]
fn types_as_last_field() -> etw::Result<()> {
    // u32 as last field after variable
    let mut d = wide_str_bytes("Z");
    d.extend_from_slice(&777u32.to_le_bytes());
    assert_eq!(U32LastV0Parser::from_bytes(&d).Target()?, 777);

    // WideStrRef as last field after fixed
    let mut d = 0u32.to_le_bytes().to_vec();
    d.extend_from_slice(&wide_str_bytes("final"));
    let s = WideLastV0Parser::from_bytes(&d).Target()?;
    assert_eq!(s, "final");

    // AnsiStrRef as last field
    let mut d = 0u32.to_le_bytes().to_vec();
    d.extend_from_slice(&ansi_str_bytes("end"));
    let s = AnsiLastV0Parser::from_bytes(&d).Target()?;
    assert_eq!(s, "end");

    // SidRef as last field
    let mut d = 0u32.to_le_bytes().to_vec();
    d.extend_from_slice(&sid_bytes(3, &[1, 2, 3]));
    let sid = SidLastV0Parser::from_bytes(&d).Target_ref()?;
    assert_eq!(sid.sub_authority_count(), 3);
    assert_eq!(sid.sub_authority(2), Some(3));

    Ok(())
}

// =============================================================================
// Complex multi-field schemas
// =============================================================================

event_schema! { name: "MixedAll", id: 90, version: 0, fields: {
    A_u8: u8,
    B_u16: u16,
    C_u32: u32,
    D_wide: WideStrRef,
    E_u64: u64,
    F_ansi: AnsiStrRef,
    G_i32: i32,
    H_sid: SidRef,
    I_bool: bool,
}}

#[test]
fn complex_mixed_field_schema() -> etw::Result<()> {
    let mut d = Vec::new();
    d.push(42u8); // A_u8
    d.extend_from_slice(&1000u16.to_le_bytes()); // B_u16
    d.extend_from_slice(&0xDEADu32.to_le_bytes()); // C_u32
    d.extend_from_slice(&wide_str_bytes("hello")); // D_wide
    d.extend_from_slice(&9999u64.to_le_bytes()); // E_u64
    d.extend_from_slice(&ansi_str_bytes("test")); // F_ansi
    d.extend_from_slice(&(-42i32).to_le_bytes()); // G_i32
    d.extend_from_slice(&sid_bytes(1, &[7])); // H_sid
    d.extend_from_slice(&1u32.to_le_bytes()); // I_bool

    let mut p = MixedAllV0Parser::from_bytes(&d);
    assert_eq!(p.A_u8()?, 42);
    assert_eq!(p.B_u16()?, 1000);
    assert_eq!(p.C_u32()?, 0xDEAD);
    assert_eq!(p.D_wide()?, "hello");
    assert_eq!(p.E_u64()?, 9999);
    assert_eq!(p.F_ansi()?, "test");
    assert_eq!(p.G_i32()?, -42);
    assert_eq!(p.H_sid_ref()?.sub_authority(0), Some(7));
    assert!(p.I_bool()?);

    Ok(())
}

// =============================================================================
// Counted types at various positions
// =============================================================================

event_schema! { name: "CWideAfterU8", id: 100, version: 0, fields: {
    Prefix: u8, Target: CountedWideStrRef, Sentinel: u32,
}}
event_schema! { name: "CAnsiAfterWide", id: 101, version: 0, fields: {
    Prefix: WideStrRef, Target: CountedAnsiStrRef, Sentinel: u32,
}}
event_schema! { name: "CBinAfterU32", id: 102, version: 0, fields: {
    Prefix: u32, Target: CountedBinaryRef, Sentinel: u32,
}}

#[test]
fn counted_types_at_various_positions() -> etw::Result<()> {
    // CountedWideStrRef after u8 (odd offset)
    let mut d = vec![0xFFu8];
    d.extend_from_slice(&counted_wide_bytes("hi"));
    d.extend_from_slice(&0xAAAAu32.to_le_bytes());
    let mut p = CWideAfterU8V0Parser::from_bytes(&d);
    assert_eq!(p.Target()?, "hi");
    assert_eq!(p.Sentinel()?, 0xAAAA);

    // CountedAnsiStrRef after WideStrRef
    let mut d = wide_str_bytes("X");
    d.extend_from_slice(&counted_ansi_bytes("YZ"));
    d.extend_from_slice(&0xBBBBu32.to_le_bytes());
    let mut p = CAnsiAfterWideV0Parser::from_bytes(&d);
    assert_eq!(p.Target()?, "YZ");
    assert_eq!(p.Sentinel()?, 0xBBBB);

    // CountedBinaryRef after u32
    let mut d = 0u32.to_le_bytes().to_vec();
    d.extend_from_slice(&counted_binary_bytes(&[1, 2, 3, 4, 5]));
    d.extend_from_slice(&0xCCCCu32.to_le_bytes());
    let mut p = CBinAfterU32V0Parser::from_bytes(&d);
    assert_eq!(p.Target()?, &[1, 2, 3, 4, 5]);
    assert_eq!(p.Sentinel()?, 0xCCCC);

    Ok(())
}

// =============================================================================
// Edge case tests for pub parsing functions
// =============================================================================

#[test]
fn wbem_sid_sized_rejects_undersize() {
    // size_bytes < 16 (WBEM_SID_TOKEN_USER_SIZE) should return an error,
    // not panic from an out-of-bounds slice.
    let data = [0u8; 32];
    let result = etw::static_schema::parse_wbem_sid_sized(&data, 0, 8);
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("too small"), "unexpected error: {msg}");
}

#[test]
fn counted_wide_string_rejects_odd_byte_count() {
    // ManifestCounted wide string with odd payload byte count should error.
    // Build a buffer: 2-byte length prefix (3 = odd) + 3 payload bytes.
    let mut data = Vec::new();
    data.extend_from_slice(&3u16.to_le_bytes()); // length prefix: 3 bytes
    data.extend_from_slice(&[0x41, 0x00, 0x42]); // 3 bytes of "payload"
    let size_bytes = 2 + 3; // prefix + payload
    let result = etw::static_schema::parse_counted_wide_string_sized(&data, 0, size_bytes);
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("odd byte count"), "unexpected error: {msg}");
}

#[test]
fn sid_rejects_invalid_revision() {
    // SID with revision 0 should be rejected by SidRef::new().
    let mut data = [0u8; 12]; // 8-byte header + 4-byte sub-authority
    data[0] = 0; // Invalid revision (should be 1)
    data[1] = 1; // SubAuthorityCount = 1
    assert!(etw::SidRef::new(&data).is_none());

    // Also rejected by parse_following_sid.
    let result = etw::static_schema::parse_following_sid(&data, 0);
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("revision"), "unexpected error: {msg}");

    // And by scan_past_sid.
    let result = etw::static_schema::scan_past_sid(&data, 0);
    assert!(result.is_err());
}

#[test]
fn sid_accepts_valid_revision() {
    // SID with revision 1 should be accepted.
    let mut data = [0u8; 12]; // 8-byte header + 4-byte sub-authority
    data[0] = 1; // Valid revision
    data[1] = 1; // SubAuthorityCount = 1
    data[2..8].copy_from_slice(&[0, 0, 0, 0, 0, 5]); // NT Authority
    data[8..12].copy_from_slice(&18u32.to_le_bytes()); // SECURITY_LOCAL_SYSTEM_RID
    assert!(etw::SidRef::new(&data).is_some());
}

#[test]
fn wbem_sid_rejects_invalid_revision() {
    // Build a WbemSid buffer: 16-byte TOKEN_USER header + SID with invalid revision.
    let mut data = [0u8; 28]; // 16 (TOKEN_USER) + 12 (SID header + 1 sub-authority)
    // SID starts at offset 16. Set revision to 0 (invalid) and sub_authority_count to 1.
    data[16] = 0; // Invalid revision (should be 1)
    data[17] = 1; // SubAuthorityCount = 1

    let result = etw::static_schema::compute_wbem_sid_size(&data, 0);
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("revision"), "unexpected error: {msg}");

    let result = etw::static_schema::parse_wbem_sid(&data, 0);
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("revision"), "unexpected error: {msg}");
}
