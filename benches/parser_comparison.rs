#![expect(
    clippy::unwrap_used,
    missing_docs,
    reason = "benchmark harness prioritises measurement workflow over strict style rules"
)]
//! Benchmark comparing independent field accessors vs sequential parser with caching.

use criterion::{Criterion, black_box, criterion_group};
use etw::event_schema;

// Test schema with interleaved fixed and variable fields
event_schema! {
    name: "Bench",
    id: 1,
    version: 1,
    fields: {
        // Fixed fields
        ProcessId: u32,
        ThreadId: u32,

        // Variable field
        ImageName: WideStrRef ,

        // Fixed after variable
        Checksum: u32,
        Timestamp: u64,

        // More variable fields
        CommandLine: WideStrRef ,
        UserName: WideStrRef ,

        // Final fixed field
        Flags: u32,
    }
}

fn create_test_data() -> Vec<u8> {
    let mut data = Vec::new();

    // Fixed fields
    data.extend_from_slice(&1234_u32.to_le_bytes());
    data.extend_from_slice(&5678_u32.to_le_bytes());

    // ImageName
    for ch in "C:\\Windows\\System32\\notepad.exe".encode_utf16() {
        data.extend_from_slice(&ch.to_le_bytes());
    }
    data.extend_from_slice(&[0u8, 0u8]);

    // Fixed after variable
    data.extend_from_slice(&0xABCDEF12_u32.to_le_bytes());
    data.extend_from_slice(&0x123456789ABCDEF0_u64.to_le_bytes());

    // CommandLine
    for ch in "notepad.exe C:\\Users\\test\\document.txt".encode_utf16() {
        data.extend_from_slice(&ch.to_le_bytes());
    }
    data.extend_from_slice(&[0u8, 0u8]);

    // UserName
    for ch in "DOMAIN\\TestUser".encode_utf16() {
        data.extend_from_slice(&ch.to_le_bytes());
    }
    data.extend_from_slice(&[0u8, 0u8]);

    // Flags
    data.extend_from_slice(&0xFFFFFFFF_u32.to_le_bytes());

    data
}

fn bench_parser_access_all_fields(c: &mut Criterion) {
    let data = create_test_data();

    c.bench_function("parser_access_all_fields", |b| {
        b.iter(|| {
            // Parser caches offsets after first access (no RefCell overhead!)
            let mut parser = BenchV1Parser::from_bytes(&data);

            let pid = parser.ProcessId().unwrap();
            let tid = parser.ThreadId().unwrap();
            let image = parser.ImageName().unwrap();
            let checksum = parser.Checksum().unwrap();
            let timestamp = parser.Timestamp().unwrap();
            let cmdline = parser.CommandLine().unwrap();
            let username = parser.UserName().unwrap();
            let flags = parser.Flags().unwrap();

            black_box((
                pid, tid, &image, checksum, timestamp, &cmdline, &username, flags,
            ));
        });
    });
}

fn bench_parser_access_two_fields(c: &mut Criterion) {
    let data = create_test_data();

    c.bench_function("parser_access_two_fields", |b| {
        b.iter(|| {
            let parser = BenchV1Parser::from_bytes(&data);

            let pid = parser.ProcessId().unwrap();
            let tid = parser.ThreadId().unwrap();

            black_box((pid, tid));
        });
    });
}

fn bench_parser_access_single_string(c: &mut Criterion) {
    let data = create_test_data();

    c.bench_function("parser_access_single_string", |b| {
        b.iter(|| {
            let mut parser = BenchV1Parser::from_bytes(&data);
            let image = parser.ImageName().unwrap();
            black_box(image);
        });
    });
}

criterion_group!(
    benches,
    bench_parser_access_all_fields,
    bench_parser_access_two_fields,
    bench_parser_access_single_string,
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
