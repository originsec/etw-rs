//! Offline differential parser tests: etw-rs versus TDH, no ETW session required.
//!
//! See `tests/common/differential.rs` for why this harness exists and how it avoids
//! the shared-oracle flaw that let the `CountedString` byte-count bug pass a green
//! suite.
//!
//! # The shape matrix
//!
//! The parser does three separable things, and they fail independently:
//!
//! * the **offset** of a property, a fold over the sizes of everything before it;
//! * the **size** of one property, from its in-type, declared length, flags and payload prefix;
//! * the **container** walk, for struct members and array elements.
//!
//! So every manifest-expressible in-type appears in seven shapes, each varying one
//! axis from a baseline rather than a cross-product:
//!
//! | Shape | Layout | What only this shape catches |
//! |---|---|---|
//! | `First` | `Subject \| Sentinel` | offset zero, naturally aligned, no predecessor |
//! | `Fixed` | `Lead \| Subject \| Sentinel` | a constant but odd offset |
//! | `Dynamic` | `Lead \| Pad(str) \| Subject \| Sentinel` | an offset that depends on a run-time length |
//! | `Last` | `Lead \| Sentinel \| Subject` | a trailing field run to the end of the buffer |
//! | `ArrayFixed` | `Lead \| Subject[3] \| Sentinel` | element striding at a constant count |
//! | `ArrayParamCount` | `Lead \| Count \| Subject[Count] \| Sentinel` | striding at a run-time count, and `count == 0` |
//! | `StructMember` | `Lead \| { MemberU32, Subject } \| Sentinel` | the struct walk |
//!
//! Twelve further fixtures cover shapes that are not single types (length/count linkage,
//! structs first and after a variable field, string-pair ordering), and a handful
//! cover zero-length variable fields, which are the classic off-by-one trigger.

#![cfg(not(miri))]
#![expect(
    clippy::print_stdout,
    clippy::expect_used,
    reason = "test binary: printing aids diagnosis and panics are the failure mode"
)]

#[path = "common/differential.rs"]
mod differential;

use differential::{
    ERROR_INVALID_PARAMETER, LEAD, Regime, SENTINEL, TestRecord, ansiz, compare_event_with_tdh,
    load_fixture_manifest, payload, sid, tdh_property_bytes, tdh_property_bytes_at,
    tdh_struct_member_bytes, utf16z, with_sentinel,
};
use etw::{TdhInType, processing_context::ProcessingContext};

/// First event id of the shape matrix. Event id is
/// `BASE_ID + type_index * Shape::ALL.len() + shape_index`, matching
/// `tests/fixtures/generate_differential_manifest.py`.
const BASE_ID: u16 = 100;

/// Element count used by the `ArrayFixed` shape; must match the generator.
const ARRAY_COUNT: usize = 3;

/// Filler ahead of the subject in the `Dynamic` shape. Its run-time length is what
/// makes the subject's offset non-constant.
const PAD: &str = "pad";

/// Fixed member that precedes the subject inside the `StructMember` struct.
const STRUCT_MEMBER_U32: u32 = 0xFEED_FACE;

/// Ids of the linkage fixtures, which are shapes rather than single types.
#[expect(unreachable_pub, reason = "leaf module of an integration test binary")]
mod linkage {
    pub const PARAM_LENGTH: u16 = 40;
    pub const PARAM_COUNT: u16 = 41;
    pub const TWO_STRINGS: u16 = 42;
    pub const ANSI_THEN_UNICODE: u16 = 43;
    pub const STRING_THEN_SID: u16 = 44;
    pub const STRUCT_AFTER_VARIABLE: u16 = 45;
    pub const UNICODE_THEN_ANSI: u16 = 53;
    pub const PARAM_LENGTH_AFTER_VARIABLE: u16 = 54;
    pub const PARAM_COUNT_AFTER_VARIABLE: u16 = 55;
    pub const STRUCT_FIRST: u16 = 56;
    pub const PARAM_LENGTH_AND_COUNT: u16 = 57;
    pub const PARAM_LENGTH_STATIC_COUNT: u16 = 58;
}

/// One in-type under test: its label, the in-type TDH should report, and the wire
/// bytes for a single element of it.
struct Subject {
    label: &'static str,
    in_type: TdhInType,
    bytes: Vec<u8>,
}

const fn subject(label: &'static str, in_type: TdhInType, bytes: Vec<u8>) -> Subject {
    Subject {
        label,
        in_type,
        bytes,
    }
}

/// The in-types under test, **in the same order as the generator's `TYPES`**.
///
/// Order matters: event ids are derived from the index. That coupling is checked by
/// [`subject_in_types_match_the_manifest`], so a table that drifts out of step with
/// the manifest fails loudly instead of quietly testing the wrong type.
fn subjects() -> Vec<Subject> {
    let mut guid = Vec::new();
    guid.extend_from_slice(&0x1234_5678u32.to_le_bytes());
    guid.extend_from_slice(&0xABCDu16.to_le_bytes());
    guid.extend_from_slice(&0xEF01u16.to_le_bytes());
    guid.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);

    let mut systemtime = Vec::new();
    for field in [2026u16, 8, 1, 3, 15, 30, 45, 500] {
        systemtime.extend_from_slice(&field.to_le_bytes());
    }

    vec![
        subject("Int8", TdhInType::Int8, vec![0xFE]),
        subject("UInt8", TdhInType::UInt8, vec![0x42]),
        subject("Int16", TdhInType::Int16, (-2i16).to_le_bytes().to_vec()),
        subject(
            "UInt16",
            TdhInType::UInt16,
            0xBEEFu16.to_le_bytes().to_vec(),
        ),
        subject("Int32", TdhInType::Int32, (-2i32).to_le_bytes().to_vec()),
        subject(
            "UInt32",
            TdhInType::UInt32,
            0xDEAD_BEEFu32.to_le_bytes().to_vec(),
        ),
        subject("Int64", TdhInType::Int64, (-2i64).to_le_bytes().to_vec()),
        subject(
            "UInt64",
            TdhInType::UInt64,
            0x1122_3344_5566_7788u64.to_le_bytes().to_vec(),
        ),
        subject("Float", TdhInType::Float, 1.5f32.to_le_bytes().to_vec()),
        subject("Double", TdhInType::Double, 2.25f64.to_le_bytes().to_vec()),
        // win:Boolean is a 4-byte Win32 BOOL on the wire, not a single byte.
        subject("Boolean", TdhInType::Boolean, 1u32.to_le_bytes().to_vec()),
        subject("Guid", TdhInType::Guid, guid),
        // Every fixture sets the 64-bit header flag, so win:Pointer is 8 bytes here.
        // A 32-bit variant is not reachable offline — see FLAG_32_BIT.
        subject(
            "Pointer",
            TdhInType::Pointer,
            0x7FFF_1234_5678u64.to_le_bytes().to_vec(),
        ),
        subject(
            "FileTime",
            TdhInType::FileTime,
            133_000_000_000_000_000u64.to_le_bytes().to_vec(),
        ),
        subject("SystemTime", TdhInType::SystemTime, systemtime),
        subject("Sid", TdhInType::Sid, sid(&[32, 544])),
        subject(
            "HexInt32",
            TdhInType::HexInt32,
            0xCAFE_BABEu32.to_le_bytes().to_vec(),
        ),
        subject(
            "HexInt64",
            TdhInType::HexInt64,
            0x0BAD_F00D_DEAD_BEEFu64.to_le_bytes().to_vec(),
        ),
        subject("UnicodeString", TdhInType::UnicodeString, utf16z("hello")),
        subject("AnsiString", TdhInType::AnsiString, ansiz("hello")),
        subject(
            "BinaryFixed",
            TdhInType::Binary,
            vec![0x01, 0x02, 0x03, 0x04],
        ),
    ]
}

/// The seven shapes, in the generator's order.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Shape {
    First,
    Fixed,
    Dynamic,
    Last,
    ArrayFixed,
    ArrayParamCount,
    StructMember,
}

impl Shape {
    const ALL: [Self; 7] = [
        Self::First,
        Self::Fixed,
        Self::Dynamic,
        Self::Last,
        Self::ArrayFixed,
        Self::ArrayParamCount,
        Self::StructMember,
    ];

    const fn index(self) -> u16 {
        match self {
            Self::First => 0,
            Self::Fixed => 1,
            Self::Dynamic => 2,
            Self::Last => 3,
            Self::ArrayFixed => 4,
            Self::ArrayParamCount => 5,
            Self::StructMember => 6,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::First => "First",
            Self::Fixed => "Fixed",
            Self::Dynamic => "Dynamic",
            Self::Last => "Last",
            Self::ArrayFixed => "ArrayFixed",
            Self::ArrayParamCount => "ArrayParamCount",
            Self::StructMember => "StructMember",
        }
    }

    /// Top-level properties the shape declares. A struct counts once: TDH lists its
    /// members in the flat property array, but `named_properties` yields the struct.
    const fn property_count(self) -> usize {
        match self {
            // Subject, Sentinel
            Self::First => 2,
            // Lead, Subject, Sentinel — or Lead, Nested, Sentinel
            Self::Fixed | Self::Last | Self::ArrayFixed | Self::StructMember => 3,
            // Lead, Pad|SubjectCount, Subject, Sentinel
            Self::Dynamic | Self::ArrayParamCount => 4,
        }
    }

    /// Whether the shape carries a `Lead` byte.
    const fn has_lead(self) -> bool {
        !matches!(self, Self::First)
    }

    /// Lays `element` out in this shape. `count` applies to the array shapes.
    fn payload_for(self, element: &[u8], count: usize) -> Vec<u8> {
        match self {
            Self::First => with_sentinel(element.to_vec()),
            Self::Fixed => {
                let mut p = payload();
                p.extend_from_slice(element);
                with_sentinel(p)
            }
            Self::Dynamic => {
                let mut p = payload();
                p.extend_from_slice(&utf16z(PAD));
                p.extend_from_slice(element);
                with_sentinel(p)
            }
            // Sentinel ahead of the subject: nothing may follow a trailing field.
            Self::Last => {
                let mut p = with_sentinel(payload());
                p.extend_from_slice(element);
                p
            }
            Self::ArrayFixed => {
                let mut p = payload();
                for _ in 0..ARRAY_COUNT {
                    p.extend_from_slice(element);
                }
                with_sentinel(p)
            }
            Self::ArrayParamCount => {
                let mut p = payload();
                p.extend_from_slice(&u16::try_from(count).expect("count fits u16").to_le_bytes());
                for _ in 0..count {
                    p.extend_from_slice(element);
                }
                with_sentinel(p)
            }
            Self::StructMember => {
                let mut p = payload();
                p.extend_from_slice(&STRUCT_MEMBER_U32.to_le_bytes());
                p.extend_from_slice(element);
                with_sentinel(p)
            }
        }
    }
}

/// A fixture: its label, the record, and enough context for the shape-specific tests.
struct Fixture {
    label: String,
    record: TestRecord,
    shape: Option<Shape>,
    in_type: Option<TdhInType>,
    /// Element count for the array shapes.
    count: usize,
}

/// The shape matrix: every in-type in every shape.
fn shape_records() -> Vec<Fixture> {
    let mut out = Vec::new();
    for (i, s) in subjects().iter().enumerate() {
        for shape in Shape::ALL {
            let id = BASE_ID
                + u16::try_from(i).expect("type index fits u16")
                    * u16::try_from(Shape::ALL.len()).expect("shape count fits u16")
                + shape.index();
            let count = if shape == Shape::ArrayParamCount {
                ARRAY_COUNT
            } else {
                0
            };
            out.push(Fixture {
                label: format!("{}{}", s.label, shape.name()),
                record: TestRecord::new_64bit(
                    id,
                    shape.payload_for(&s.bytes, ARRAY_COUNT.max(count)),
                ),
                shape: Some(shape),
                in_type: Some(s.in_type),
                count: if shape == Shape::ArrayFixed || shape == Shape::ArrayParamCount {
                    ARRAY_COUNT
                } else {
                    0
                },
            });
        }
    }
    out
}

/// Edge cases layered onto existing events: an empty variable-length field, and an
/// array whose run-time count is zero. Both are classic off-by-one triggers and
/// neither needs its own manifest entry.
fn edge_records() -> Vec<Fixture> {
    let all = subjects();
    let index_of = |label: &str| {
        all.iter()
            .position(|s| s.label == label)
            .unwrap_or_else(|| panic!("no subject labelled {label}"))
    };
    let id_for = |label: &str, shape: Shape| {
        BASE_ID
            + u16::try_from(index_of(label)).expect("index fits u16")
                * u16::try_from(Shape::ALL.len()).expect("shape count fits u16")
            + shape.index()
    };

    let mut out = Vec::new();

    // Zero-length variable fields, in the Fixed shape so the sentinel still follows.
    for (label, empty) in [
        // A UTF-16 string that is nothing but its terminator.
        ("UnicodeString", vec![0u8, 0]),
        ("AnsiString", vec![0u8]),
        // Revision + sub-authority count of zero + authority: the smallest valid SID.
        ("Sid", sid(&[])),
    ] {
        out.push(Fixture {
            label: format!("{label}Empty"),
            record: TestRecord::new_64bit(
                id_for(label, Shape::Fixed),
                Shape::Fixed.payload_for(&empty, 0),
            ),
            shape: Some(Shape::Fixed),
            in_type: None,
            count: 0,
        });
    }

    // count == 0 on a run-time-counted array: one fixed-size element type, one
    // variable-size, one self-describing.
    for label in ["UInt32", "UnicodeString", "Sid"] {
        out.push(Fixture {
            label: format!("{label}ArrayCountZero"),
            record: TestRecord::new_64bit(
                id_for(label, Shape::ArrayParamCount),
                Shape::ArrayParamCount.payload_for(&[], 0),
            ),
            shape: Some(Shape::ArrayParamCount),
            in_type: None,
            count: 0,
        });
    }

    // A PropertyParamLength Binary declaring zero bytes.
    let mut zero_len = payload();
    zero_len.extend_from_slice(&0u16.to_le_bytes());
    out.push(Fixture {
        label: "ParamLengthZero".to_owned(),
        record: TestRecord::new_64bit(linkage::PARAM_LENGTH, with_sentinel(zero_len)),
        shape: None,
        in_type: None,
        count: 0,
    });

    out
}

/// Shapes that are not single in-types: length/count linkage, structs, string pairs.
fn linkage_records() -> Vec<Fixture> {
    fn fixture(label: &str, id: u16, body: Vec<u8>) -> Fixture {
        Fixture {
            label: label.to_owned(),
            record: TestRecord::new_64bit(id, with_sentinel(body)),
            shape: None,
            in_type: None,
            count: 0,
        }
    }

    let mut param_length = payload();
    param_length.extend_from_slice(&3u16.to_le_bytes());
    param_length.extend_from_slice(&[0xDE, 0xAD, 0xBE]);

    let mut param_count = payload();
    param_count.extend_from_slice(&2u16.to_le_bytes());
    param_count.extend_from_slice(&0x1111_1111u32.to_le_bytes());
    param_count.extend_from_slice(&0x2222_2222u32.to_le_bytes());

    let mut two_strings = payload();
    two_strings.extend_from_slice(&utf16z("alpha"));
    two_strings.extend_from_slice(&utf16z("beta"));

    let mut ansi_then_unicode = payload();
    ansi_then_unicode.extend_from_slice(&ansiz("ansi"));
    ansi_then_unicode.extend_from_slice(&utf16z("wide"));

    let mut unicode_then_ansi = payload();
    unicode_then_ansi.extend_from_slice(&utf16z("wide-first"));
    unicode_then_ansi.extend_from_slice(&ansiz("ansi-second"));

    let mut string_then_sid = payload();
    string_then_sid.extend_from_slice(&utf16z("before-sid"));
    string_then_sid.extend_from_slice(&sid(&[32, 544]));

    let mut struct_after_variable = payload();
    struct_after_variable.extend_from_slice(&utf16z("lead-str"));
    struct_after_variable.extend_from_slice(&0xFEED_FACEu32.to_le_bytes());
    struct_after_variable.extend_from_slice(&utf16z("member"));

    let mut param_length_after_variable = payload();
    param_length_after_variable.extend_from_slice(&utf16z("before-len"));
    param_length_after_variable.extend_from_slice(&4u16.to_le_bytes());
    param_length_after_variable.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);

    let mut param_count_after_variable = payload();
    param_count_after_variable.extend_from_slice(&utf16z("before-count"));
    param_count_after_variable.extend_from_slice(&3u16.to_le_bytes());
    for v in [0xAAAA_AAAAu32, 0xBBBB_BBBB, 0xCCCC_CCCC] {
        param_count_after_variable.extend_from_slice(&v.to_le_bytes());
    }

    // Length 3, count 2: per-element sizing puts the sentinel 6 bytes on, not 3.
    let mut param_length_and_count = payload();
    param_length_and_count.extend_from_slice(&3u16.to_le_bytes());
    param_length_and_count.extend_from_slice(&2u16.to_le_bytes());
    param_length_and_count.extend_from_slice(&[0xA1, 0xA2, 0xA3, 0xB1, 0xB2, 0xB3]);

    // Length 3, static count 2 in the manifest.
    let mut param_length_static_count = payload();
    param_length_static_count.extend_from_slice(&3u16.to_le_bytes());
    param_length_static_count.extend_from_slice(&[0xC1, 0xC2, 0xC3, 0xD1, 0xD2, 0xD3]);

    // No lead byte: the struct must start at offset zero.
    let mut struct_first = Vec::new();
    struct_first.extend_from_slice(&0x0BAD_F00Du32.to_le_bytes());
    struct_first.extend_from_slice(&utf16z("first-member"));

    vec![
        fixture("ParamLength", linkage::PARAM_LENGTH, param_length),
        fixture("ParamCount", linkage::PARAM_COUNT, param_count),
        fixture("TwoStrings", linkage::TWO_STRINGS, two_strings),
        fixture(
            "AnsiThenUnicode",
            linkage::ANSI_THEN_UNICODE,
            ansi_then_unicode,
        ),
        fixture(
            "UnicodeThenAnsi",
            linkage::UNICODE_THEN_ANSI,
            unicode_then_ansi,
        ),
        fixture("StringThenSid", linkage::STRING_THEN_SID, string_then_sid),
        fixture(
            "StructAfterVariable",
            linkage::STRUCT_AFTER_VARIABLE,
            struct_after_variable,
        ),
        fixture(
            "ParamLengthAfterVariable",
            linkage::PARAM_LENGTH_AFTER_VARIABLE,
            param_length_after_variable,
        ),
        fixture(
            "ParamCountAfterVariable",
            linkage::PARAM_COUNT_AFTER_VARIABLE,
            param_count_after_variable,
        ),
        fixture("StructFirst", linkage::STRUCT_FIRST, struct_first),
        fixture(
            "ParamLengthAndCount",
            linkage::PARAM_LENGTH_AND_COUNT,
            param_length_and_count,
        ),
        fixture(
            "ParamLengthStaticCount",
            linkage::PARAM_LENGTH_STATIC_COUNT,
            param_length_static_count,
        ),
    ]
}

/// Every fixture.
fn all_records() -> Vec<Fixture> {
    let mut out = shape_records();
    out.extend(linkage_records());
    out.extend(edge_records());
    out
}

/// Every property of every fixture must decode to exactly the bytes TDH gives.
///
/// The comparison is byte-for-byte with no per-type allowances. That is measured, not
/// assumed: etw-rs and TDH agree on the extent of every shape here, including the NUL
/// of a `win:UnicodeString` and the sub-authority tail of a `win:SID`. A future type
/// needing an allowance is a finding to understand, not a tolerance to widen.
#[test]
fn every_property_agrees_with_tdh() {
    load_fixture_manifest();

    let mut problems = Vec::new();
    for f in all_records() {
        let mut ctx = ProcessingContext::new();
        problems.extend(compare_event_with_tdh(
            &f.label,
            f.record.as_raw_event(),
            &mut ctx,
            Regime::ManifestOrMof,
        ));
    }

    assert!(
        problems.is_empty(),
        "etw-rs disagrees with TDH on {} propert{}:\n{}",
        problems.len(),
        if problems.len() == 1 { "y" } else { "ies" },
        problems.join("\n")
    );
}

/// Each array element must match TDH element for element.
///
/// Whole-array agreement is not enough: a stride computed from the wrong element size
/// can still add up to the right total, and for variable-size elements the parser has
/// to re-scan per element rather than multiply.
#[test]
fn array_elements_agree_with_tdh() {
    load_fixture_manifest();

    let mut problems = Vec::new();
    let mut checked = 0usize;
    for f in all_records() {
        if f.count == 0 {
            continue;
        }
        let mut ctx = ProcessingContext::new();
        let mut parser = match ctx.parser(f.record.as_raw_event()) {
            Ok(p) => p,
            Err(e) => {
                problems.push(format!("{}: parser construction failed: {e}", f.label));
                continue;
            }
        };
        let elements = match parser.array_elements("Subject") {
            Ok(e) => e,
            Err(e) => {
                problems.push(format!("{}: array_elements failed: {e}", f.label));
                continue;
            }
        };
        if elements.len() != f.count {
            problems.push(format!(
                "{}: etw-rs found {} elements, fixture wrote {}",
                f.label,
                elements.len(),
                f.count
            ));
            continue;
        }
        for (i, element) in elements.iter().enumerate() {
            let index = u32::try_from(i).expect("element index fits u32");
            match tdh_property_bytes_at(f.record.as_raw_event(), "Subject", index) {
                Ok(tdh) if element.data() == tdh.as_slice() => checked += 1,
                Ok(tdh) => problems.push(format!(
                    "{}[{i}]: etw-rs {:02x?} != TDH {:02x?}",
                    f.label,
                    element.data(),
                    tdh
                )),
                Err(status) => problems.push(format!(
                    "{}[{i}]: TDH declined to decode (Win32 {status})",
                    f.label
                )),
            }
        }
    }

    assert!(
        problems.is_empty(),
        "array element mismatches:\n{}",
        problems.join("\n")
    );
    // 21 types x 2 array shapes x 3 elements. If this drops, elements stopped being
    // compared and the test above would pass while checking nothing.
    assert_eq!(
        checked,
        subjects().len() * 2 * ARRAY_COUNT,
        "expected every array element of every type to be compared"
    );
}

/// Struct members must match TDH member for member.
///
/// The struct walk goes through `struct_start_index`/`struct_member_count`, a
/// different path from the top-level one, and TDH addresses a member by a two-element
/// descriptor path. Comparing only the struct's total extent would miss a member
/// boundary in the wrong place.
#[test]
fn struct_members_agree_with_tdh() {
    load_fixture_manifest();

    let mut problems = Vec::new();
    let mut checked = 0usize;
    for f in all_records() {
        if f.shape != Some(Shape::StructMember) {
            continue;
        }
        let mut ctx = ProcessingContext::new();
        let mut parser = match ctx.parser(f.record.as_raw_event()) {
            Ok(p) => p,
            Err(e) => {
                problems.push(format!("{}: parser construction failed: {e}", f.label));
                continue;
            }
        };
        let members = match parser.struct_members("Nested") {
            Ok(m) => m,
            Err(e) => {
                problems.push(format!("{}: struct_members failed: {e}", f.label));
                continue;
            }
        };
        if members.len() != 2 {
            problems.push(format!(
                "{}: expected 2 struct members, got {}",
                f.label,
                members.len()
            ));
            continue;
        }
        for (member, name) in members.iter().zip(["MemberU32", "Subject"]) {
            match tdh_struct_member_bytes(f.record.as_raw_event(), "Nested", name) {
                Ok(tdh) if member.data() == tdh.as_slice() => checked += 1,
                Ok(tdh) => problems.push(format!(
                    "{}.{name}: etw-rs {:02x?} != TDH {:02x?}",
                    f.label,
                    member.data(),
                    tdh
                )),
                Err(status) => problems.push(format!(
                    "{}.{name}: TDH declined to decode (Win32 {status})",
                    f.label
                )),
            }
        }
    }

    assert!(
        problems.is_empty(),
        "struct member mismatches:\n{}",
        problems.join("\n")
    );
    assert_eq!(
        checked,
        subjects().len() * 2,
        "expected both members of every StructMember fixture to be compared"
    );
}

/// Pins the one place etw-rs and TDH legitimately differ.
///
/// A `count == 0` array, or a `PropertyParamLength` of zero, occupies no bytes.
/// etw-rs reports an empty slice; TDH refuses to hand back a 0-byte buffer and
/// returns `ERROR_INVALID_PARAMETER` instead. They agree the extent is zero and
/// disagree only on whether zero is a returnable value, so
/// `compare_event_with_tdh` treats that exact pairing as agreement.
///
/// This test exists so that allowance is a stated contract rather than a tolerance
/// hidden in the comparison: it asserts *both* halves, so if TDH ever starts
/// returning empty buffers, or etw-rs starts reporting something non-empty for a
/// zero-length field, this fails and the allowance gets revisited.
#[test]
fn zero_length_properties_are_empty_not_missing() {
    load_fixture_manifest();

    let zero_length: Vec<&str> = vec![
        "UInt32ArrayCountZero",
        "UnicodeStringArrayCountZero",
        "SidArrayCountZero",
        "ParamLengthZero",
    ];

    let mut checked = 0usize;
    for f in all_records() {
        if !zero_length.contains(&f.label.as_str()) {
            continue;
        }
        let mut ctx = ProcessingContext::new();
        let mut parser = ctx
            .parser(f.record.as_raw_event())
            .unwrap_or_else(|e| panic!("{}: parser construction failed: {e}", f.label));
        let props = parser
            .named_properties()
            .unwrap_or_else(|e| panic!("{}: named_properties failed: {e}", f.label));
        let (_, subject) = props
            .iter()
            .find(|(name, _)| name == "Subject")
            .unwrap_or_else(|| panic!("{}: no Subject property", f.label));

        assert!(
            subject.data().is_empty(),
            "{}: etw-rs should report a zero-length Subject as empty, got {:02x?}",
            f.label,
            subject.data()
        );
        assert_eq!(
            tdh_property_bytes(f.record.as_raw_event(), "Subject"),
            Err(ERROR_INVALID_PARAMETER),
            "{}: TDH is expected to refuse a zero-length property; if it now returns \
             one, the allowance in compare_event_with_tdh should be removed",
            f.label
        );
        // The sentinel after it must still be found, which is the real point: a
        // zero-length field must advance the cursor by zero, not by some minimum.
        assert_eq!(
            parser.get::<u32>("Sentinel").ok(),
            Some(SENTINEL),
            "{}: sentinel drifted after a zero-length field",
            f.label
        );
        checked += 1;
    }

    assert_eq!(
        checked,
        zero_length.len(),
        "every zero-length fixture should have been checked"
    );
}

/// The sentinel is the drift detector: if any earlier property over- or under-reads,
/// the parser lands somewhere other than the sentinel's true offset and this fails.
/// Asserted on every fixture, so no shape gets drift coverage by accident.
#[test]
fn sentinel_survives_every_fixture() {
    load_fixture_manifest();

    let mut failures = Vec::new();
    for f in all_records() {
        let mut ctx = ProcessingContext::new();
        let mut parser = match ctx.parser(f.record.as_raw_event()) {
            Ok(p) => p,
            Err(e) => {
                failures.push(format!("{}: parser construction failed: {e}", f.label));
                continue;
            }
        };
        match parser.get::<u32>("Sentinel") {
            Ok(v) if v == SENTINEL => {}
            Ok(v) => failures.push(format!(
                "{}: sentinel {v:#010x} != {SENTINEL:#010x}",
                f.label
            )),
            Err(e) => failures.push(format!("{}: sentinel unreadable: {e}", f.label)),
        }
    }

    assert!(
        failures.is_empty(),
        "property-offset drift detected in {} fixture(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// The lead byte must decode as itself everywhere it appears. A parser that started
/// at the wrong offset fails here before any subject-specific assertion can mislead.
#[test]
fn lead_byte_reads_correctly_in_every_fixture() {
    load_fixture_manifest();

    let mut checked = 0usize;
    let mut skipped = 0usize;
    for f in all_records() {
        // The First shape and StructFirst deliberately have no Lead: their subject
        // must start at offset zero, which is itself a case worth covering.
        let has_lead = f.shape.is_none_or(Shape::has_lead) && f.label != "StructFirst";
        if !has_lead {
            skipped += 1;
            continue;
        }
        let mut ctx = ProcessingContext::new();
        let mut parser = ctx
            .parser(f.record.as_raw_event())
            .unwrap_or_else(|e| panic!("{}: parser construction failed: {e}", f.label));
        let lead: u8 = parser
            .get("Lead")
            .unwrap_or_else(|e| panic!("{}: Lead unreadable: {e}", f.label));
        assert_eq!(lead, LEAD, "{}: lead byte mis-read", f.label);
        checked += 1;
    }

    // One First fixture per type, plus StructFirst.
    assert_eq!(
        skipped,
        subjects().len() + 1,
        "only the First shapes and StructFirst should lack a Lead"
    );
    assert_eq!(
        checked,
        all_records().len() - skipped,
        "every other fixture should carry a Lead"
    );
}

/// Guards the coupling between [`subjects`] and the generated manifest.
///
/// Event ids are derived from a type's index in `subjects()`, so if the two lists
/// drift the fixtures still decode — against the wrong type — and every other test
/// here keeps passing while checking nothing it claims to. Asking TDH which in-type
/// it actually resolved makes that impossible.
#[test]
fn subject_in_types_match_the_manifest() {
    load_fixture_manifest();

    let mut problems = Vec::new();
    let mut checked = 0usize;
    for f in all_records() {
        let Some(expected) = f.in_type else {
            continue;
        };
        let mut ctx = ProcessingContext::new();
        let schema = match ctx.get_or_lookup(f.record.as_raw_event()) {
            Ok(s) => s,
            Err(e) => {
                problems.push(format!("{}: schema lookup failed: {e}", f.label));
                continue;
            }
        };
        // A struct member is not reachable through `EventSchema::property`: that
        // accessor bounds on `top_level_property_count`, while members live past it.
        // `struct_members()` is the supported route.
        let actual = if f.shape == Some(Shape::StructMember) {
            let mut member_ctx = ProcessingContext::new();
            let Ok(mut parser) = member_ctx.parser(f.record.as_raw_event()) else {
                problems.push(format!("{}: parser construction failed", f.label));
                continue;
            };
            match parser.struct_members("Nested") {
                Ok(members) if members.len() == 2 => members[1].in_type(),
                Ok(members) => {
                    problems.push(format!(
                        "{}: expected 2 struct members, got {}",
                        f.label,
                        members.len()
                    ));
                    continue;
                }
                Err(e) => {
                    problems.push(format!("{}: struct_members failed: {e}", f.label));
                    continue;
                }
            }
        } else {
            let Some(index) = schema.property_index("Subject") else {
                problems.push(format!("{}: schema has no property named Subject", f.label));
                continue;
            };
            let Some(info) = schema.property(index) else {
                problems.push(format!("{}: property {index} missing from schema", f.label));
                continue;
            };
            TdhInType::from_raw(info.in_type())
        };
        if actual == expected {
            checked += 1;
        } else {
            problems.push(format!(
                "{}: manifest declares {actual:?} but the fixture table says \
                 {expected:?} — table and manifest have drifted",
                f.label
            ));
        }
    }

    assert!(
        problems.is_empty(),
        "fixture table is out of step with the manifest:\n{}",
        problems.join("\n")
    );
    assert_eq!(
        checked,
        subjects().len() * Shape::ALL.len(),
        "every type in every shape should have had its in-type verified"
    );
}

/// Guards the guard: the fixture set must actually be exercising properties.
///
/// Without this, a change that made `named_properties()` return an empty list, or
/// made every fixture fail to build a parser, would leave the comparisons above
/// checking nothing and passing — the exact failure mode this harness exists to
/// eliminate. Every count here is derived from the tables rather than hardcoded, so
/// adding a type or a shape needs no edit.
#[test]
fn fixture_set_covers_the_expected_surface() {
    load_fixture_manifest();

    let types = subjects().len();
    let shapes = shape_records();
    assert_eq!(
        shapes.len(),
        types * Shape::ALL.len(),
        "shape matrix should be every in-type in every shape"
    );
    assert_eq!(linkage_records().len(), 12, "linkage fixture count changed");
    assert_eq!(edge_records().len(), 7, "edge-case fixture count changed");

    let per_type: usize = Shape::ALL.iter().map(|s| s.property_count()).sum();
    // ParamLength 4, ParamCount 4, TwoStrings 4, AnsiThenUnicode 4, UnicodeThenAnsi 4,
    // StringThenSid 4, StructAfterVariable 4, StructFirst 2,
    // ParamLengthAfterVariable 5, ParamCountAfterVariable 5, ParamLengthAndCount 5,
    // ParamLengthStaticCount 4.
    let expected_linkage = 49usize;
    // Three empty variable fields in the Fixed shape (3 each), three count == 0
    // arrays in the ArrayParamCount shape (4 each), one zero-length ParamLength (4).
    let expected_edge =
        3 * Shape::Fixed.property_count() + 3 * Shape::ArrayParamCount.property_count() + 4;

    let mut compared = 0usize;
    for f in all_records() {
        let mut ctx = ProcessingContext::new();
        let mut parser = ctx
            .parser(f.record.as_raw_event())
            .unwrap_or_else(|e| panic!("{}: parser construction failed: {e}", f.label));
        let props = parser
            .named_properties()
            .unwrap_or_else(|e| panic!("{}: named_properties failed: {e}", f.label));
        assert!(
            props.len() >= 2,
            "{}: expected at least a subject and a sentinel, got {}",
            f.label,
            props.len()
        );
        for (name, prop) in &props {
            let decodable = match tdh_property_bytes(f.record.as_raw_event(), name) {
                Ok(_) => true,
                // A zero-length property is genuinely empty; TDH just will not return
                // a 0-byte buffer. Still counted as covered — see
                // `zero_length_properties_are_empty_not_missing`.
                Err(ERROR_INVALID_PARAMETER) => prop.data().is_empty(),
                Err(_) => false,
            };
            assert!(
                decodable,
                "{}.{name}: TDH could not decode it, so the comparison is vacuous",
                f.label
            );
            compared += 1;
        }
    }

    let expected = types * per_type + expected_linkage + expected_edge;
    assert_eq!(
        compared, expected,
        "expected {expected} properties compared against TDH; a fixture was added, \
         removed, or stopped decoding"
    );
    println!(
        "{compared} properties compared against TDH across {} fixtures",
        all_records().len()
    );
}
