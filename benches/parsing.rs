#![expect(
    clippy::unwrap_used,
    missing_docs,
    reason = "benchmark harness prioritises measurement workflow over strict style rules"
)]
//! Parsing performance benchmarks for etw-rs.
//!
//! Run with: `cargo bench --bench parsing`
//!
//! These benchmarks measure the performance of:
//! - Schema cache lookups (hot path)
//! - Property parsing by type
//! - Sequential vs random property access
//!
//! Note: Cold schema lookups (TDH calls) require admin privileges and are
//! tested separately in integration tests.

// Benchmark files have different lint requirements than library code
#![expect(
    clippy::semicolon_if_nothing_returned,
    clippy::undocumented_unsafe_blocks,
    clippy::missing_const_for_fn,
    clippy::redundant_closure_for_method_calls,
    clippy::as_ptr_cast_mut,
    reason = "benchmark harness prioritises measurement workflow over strict style rules"
)]

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group};
use std::hint::black_box as bb;
use windows::{
    Win32::System::Diagnostics::Etw::{EVENT_HEADER_FLAG_64_BIT_HEADER, EVENT_RECORD},
    core::GUID,
};

// =============================================================================
// Mock Event Helpers
// =============================================================================

/// Create a mock EVENT_RECORD with the given user data.
///
/// This creates a minimal valid event for benchmarking property parsing.
fn make_mock_event(
    user_data: &[u8],
    provider_guid: GUID,
    event_id: u16,
    version: u8,
) -> EVENT_RECORD {
    // SAFETY: EVENT_RECORD is a C struct, zeroing is valid initialization
    let mut record: EVENT_RECORD = unsafe { std::mem::zeroed() };
    record.EventHeader.ProviderId = provider_guid;
    record.EventHeader.EventDescriptor.Id = event_id;
    record.EventHeader.EventDescriptor.Version = version;
    record.EventHeader.Flags = EVENT_HEADER_FLAG_64_BIT_HEADER as u16;
    record.UserData = user_data.as_ptr() as *mut _;
    record.UserDataLength = user_data.len() as u16;
    record
}

// =============================================================================
// FromProperty Type Parsing Benchmarks
// =============================================================================

/// Benchmark raw type parsing using FromProperty trait.
///
/// These benchmarks measure the cost of parsing individual property types
/// from raw bytes, independent of schema lookup.
fn bench_type_parsing(c: &mut Criterion) {
    use etw::{
        parser::FromProperty,
        types::{AnsiString, TdhInType, WideString},
    };

    let mut group = c.benchmark_group("type_parsing");

    // u32 parsing
    let u32_data = 0x1234_5678u32.to_le_bytes();
    group.bench_function("u32", |b| {
        b.iter(|| {
            let result: u32 =
                FromProperty::from_property(bb(&u32_data), TdhInType::UInt32).unwrap();
            bb(result)
        })
    });

    // u64 parsing
    let u64_data = 0x1234_5678_9ABC_DEF0u64.to_le_bytes();
    group.bench_function("u64", |b| {
        b.iter(|| {
            let result: u64 =
                FromProperty::from_property(bb(&u64_data), TdhInType::UInt64).unwrap();
            bb(result)
        })
    });

    // Pointer (8 bytes on 64-bit)
    group.bench_function("pointer", |b| {
        b.iter(|| {
            let result: u64 =
                FromProperty::from_property(bb(&u64_data), TdhInType::Pointer).unwrap();
            bb(result)
        })
    });

    // GUID parsing (16 bytes)
    let guid_data: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, // Data1
        0x05, 0x06, // Data2
        0x07, 0x08, // Data3
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, // Data4
    ];
    group.bench_function("guid", |b| {
        b.iter(|| {
            let result: etw::Guid =
                FromProperty::from_property(bb(&guid_data), TdhInType::Guid).unwrap();
            bb(result)
        })
    });

    // Unicode string parsing (null-terminated UTF-16)
    let unicode_str: Vec<u8> = "Hello, World!"
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .chain([0, 0]) // Null terminator
        .collect();
    group.bench_function("unicode_string_short", |b| {
        b.iter(|| {
            let result: WideString =
                FromProperty::from_property(bb(unicode_str.as_slice()), TdhInType::UnicodeString)
                    .unwrap();
            bb(result)
        })
    });

    // Longer unicode string
    let long_str =
        "This is a longer string for benchmarking purposes, testing performance with more data";
    let unicode_long: Vec<u8> = long_str
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .chain([0, 0])
        .collect();
    group.throughput(Throughput::Bytes(unicode_long.len() as u64));
    group.bench_function("unicode_string_long", |b| {
        b.iter(|| {
            let result: WideString =
                FromProperty::from_property(bb(unicode_long.as_slice()), TdhInType::UnicodeString)
                    .unwrap();
            bb(result)
        })
    });

    // ANSI string parsing
    let ansi_str: Vec<u8> = b"Hello, World!\0".to_vec();
    group.throughput(Throughput::Bytes(ansi_str.len() as u64));
    group.bench_function("ansi_string_short", |b| {
        b.iter(|| {
            let result: AnsiString =
                FromProperty::from_property(bb(ansi_str.as_slice()), TdhInType::AnsiString)
                    .unwrap();
            bb(result)
        })
    });

    // Binary blob (pass-through)
    let binary_data: Vec<u8> = (0..256).map(|i| i as u8).collect();
    group.throughput(Throughput::Bytes(binary_data.len() as u64));
    group.bench_function("binary_256", |b| {
        b.iter(|| {
            let result: Vec<u8> =
                FromProperty::from_property(bb(binary_data.as_slice()), TdhInType::Binary).unwrap();
            bb(result)
        })
    });

    // Boolean parsing
    let bool_data = [1u8, 0, 0, 0]; // Win32 BOOL is 4 bytes
    group.throughput(Throughput::Bytes(bool_data.len() as u64));
    group.bench_function("bool", |b| {
        b.iter(|| {
            let result: bool =
                FromProperty::from_property(bb(&bool_data), TdhInType::Boolean).unwrap();
            bb(result)
        })
    });

    // SystemTime parsing (16 bytes)
    group.throughput(Throughput::Bytes(16));
    let systemtime_data: [u8; 16] = [
        0xE8, 0x07, // wYear = 2024
        0x01, 0x00, // wMonth = 1
        0x01, 0x00, // wDayOfWeek = 1 (Monday)
        0x0F, 0x00, // wDay = 15
        0x0A, 0x00, // wHour = 10
        0x1E, 0x00, // wMinute = 30
        0x00, 0x00, // wSecond = 0
        0x00, 0x00, // wMilliseconds = 0
    ];
    group.bench_function("systemtime", |b| {
        b.iter(|| {
            let result: etw::SystemTime =
                FromProperty::from_property(bb(&systemtime_data), TdhInType::SystemTime).unwrap();
            bb(result)
        })
    });

    group.finish();
}

// =============================================================================
// Schema Cache Benchmarks
// =============================================================================

/// Benchmark schema cache operations.
///
/// Note: These benchmark cache hits only. Cold lookups require real ETW events
/// and admin privileges, so are tested in integration tests.
fn bench_processing_context(c: &mut Criterion) {
    use etw::processing_context::ProcessingContext;

    let mut group = c.benchmark_group("processing_context");

    // Benchmark cache creation
    group.bench_function("new", |b| {
        b.iter(|| {
            let cache = ProcessingContext::new();
            bb(cache)
        })
    });

    // Benchmark cache with capacity
    group.bench_function("with_capacity_100", |b| {
        b.iter(|| {
            let cache = ProcessingContext::with_capacity(100);
            bb(cache)
        })
    });

    // Note: Cache hit benchmarks require a populated cache with real schemas.
    // Since TDH lookup requires admin privileges and real events, we can't
    // easily create synthetic schemas. The cache hit path is simple HashMap
    // lookup, which is already well-optimized.

    group.finish();
}

// =============================================================================
// RawEvent Access Benchmarks
// =============================================================================

/// Benchmark RawEvent field access.
fn bench_raw_event_access(c: &mut Criterion) {
    use etw::event::RawEvent;

    let mut group = c.benchmark_group("raw_event");

    // Create a mock event with some user data
    let user_data: Vec<u8> = (0..128).collect();
    let guid = GUID::from_u128(0x12345678_9ABC_DEF0_1234_56789ABCDEF0);
    let record = make_mock_event(&user_data, guid, 42, 1);
    let event = unsafe { RawEvent::from_ptr(std::ptr::from_ref(&record).cast()) };

    // Benchmark header field access
    group.bench_function("provider_guid", |b| b.iter(|| bb(event.provider_guid())));

    group.bench_function("event_id", |b| b.iter(|| bb(event.id())));

    group.bench_function("opcode", |b| b.iter(|| bb(event.opcode())));

    group.bench_function("timestamp", |b| b.iter(|| bb(event.timestamp())));

    group.bench_function("process_id", |b| b.iter(|| bb(event.process_id())));

    group.bench_function("thread_id", |b| b.iter(|| bb(event.thread_id())));

    // Benchmark user data access
    group.bench_function("user_data", |b| b.iter(|| bb(event.user_data())));

    group.bench_function("user_data_len", |b| b.iter(|| bb(event.user_data().len())));

    group.finish();
}

// =============================================================================
// Timestamp Benchmarks
// =============================================================================

/// Benchmark Timestamp operations.
fn bench_timestamp(c: &mut Criterion) {
    use etw::event::Timestamp;

    let mut group = c.benchmark_group("timestamp");

    let ts = Timestamp::new(133_500_000_000_000_000); // ~2024

    group.bench_function("raw", |b| b.iter(|| bb(ts.raw())));

    group.bench_function("display", |b| b.iter(|| bb(format!("{ts}"))));

    group.bench_function("debug", |b| b.iter(|| bb(format!("{ts:?}"))));

    group.finish();
}

// =============================================================================
// Throughput Benchmarks
// =============================================================================

/// Benchmark event processing throughput with synthetic events.
fn bench_throughput(c: &mut Criterion) {
    use etw::event::RawEvent;

    let mut group = c.benchmark_group("throughput");

    // Create a batch of events
    let user_data: Vec<u8> = vec![0u8; 64];
    let guid = GUID::from_u128(0x12345678_9ABC_DEF0_1234_56789ABCDEF0);

    // Measure events per second for basic field access
    for batch_size in [100, 1000, 10000] {
        let records: Vec<_> = (0..batch_size)
            .map(|i| make_mock_event(&user_data, guid, i as u16, 1))
            .collect();

        group.throughput(Throughput::Elements(batch_size as u64));
        group.bench_with_input(
            BenchmarkId::new("field_access", batch_size),
            &records,
            |b, records| {
                b.iter(|| {
                    let mut sum = 0u64;
                    for record in records {
                        let event =
                            unsafe { RawEvent::from_ptr(std::ptr::from_ref(record).cast()) };
                        sum = sum.wrapping_add(event.id() as u64);
                        sum = sum.wrapping_add(event.process_id() as u64);
                        sum = sum.wrapping_add(event.thread_id() as u64);
                    }
                    bb(sum)
                })
            },
        );
    }

    group.finish();
}

// =============================================================================
// Main
// =============================================================================

criterion_group!(
    benches,
    bench_type_parsing,
    bench_processing_context,
    bench_raw_event_access,
    bench_timestamp,
    bench_throughput,
);

#[path = "bench_util.rs"]
mod bench_util;

fn main() {
    bench_util::pin_to_performance_cores();
    benches();
    criterion::Criterion::default()
        .configure_from_args()
        .final_summary();
}
