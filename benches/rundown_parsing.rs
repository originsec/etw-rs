//! Apples-to-apples benchmark: etw-rs vs ferrisetw on identical captured events
//!
//! This benchmark captures File rundown events once using etw-rs, then benchmarks
//! both etw-rs static parser and ferrisetw TDH parser on the same captured data.
//!
//! This eliminates variance from:
//! - Different trace sessions generating different numbers of events
//! - Different event timing between benchmark iterations
//! - System state changes between runs
//!
//! Rundown events enumerate existing system state (open files). Typical systems
//! have ~50,000 open file handles, making this a realistic large-batch benchmark.
//!
//! # Requirements
//!
//! Must be run as Administrator for kernel tracing.
//!
//! # Usage
//!
//! ```bash
//! cargo bench --bench rundown_parsing
//! ```

#![expect(
    clippy::print_stderr,
    clippy::unwrap_used,
    missing_docs,
    clippy::missing_const_for_fn,
    clippy::semicolon_outside_block,
    reason = "benchmark harness prioritises measurement workflow over strict style rules"
)]

use criterion::{Criterion, black_box, criterion_group};
use etw::{Trace, event_schema, system_logger::masks::PERF_FILENAME, types::WideString};
use example_providers::classic::kernel_trace::file_io;
use std::{
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};
use windows::Win32::System::Diagnostics::Etw::EVENT_RECORD;

// Define static schema for File rundown events (etw-rs)
// Schema matches Microsoft-Windows-Kernel-File FileRundown event (opcode 36)
event_schema! {
    name: "FileRundown",
    id: 0,  // System providers use opcode, not event ID
    version: 2,
    fields: {
        FileObject: u64,
        FileName: WideStrRef,
    }
}

/// Captured event data for apples-to-apples comparison (zero-copy)
#[derive(Clone)]
struct CapturedEvent {
    /// Raw EVENT_RECORD bytes (contains EVENT_HEADER at start)
    record_blob: Vec<u8>,
    /// Offset to user_data within record_blob
    user_data_offset: usize,
    /// Length of user_data
    user_data_len: usize,
}

impl CapturedEvent {
    /// Get a temporary EVENT_RECORD with valid pointers (reconstructed on each call)
    fn as_event_record(&self) -> EVENT_RECORD {
        // SAFETY: The blob was originally written from a valid EVENT_RECORD struct.
        // Reading it back reconstructs the original header fields.
        let mut record =
            unsafe { std::ptr::read(self.record_blob.as_ptr().cast::<EVENT_RECORD>()) };
        // Fix up UserData pointer to point into current blob location
        // SAFETY: user_data_offset is within the blob bounds (set during capture).
        record.UserData = unsafe {
            self.record_blob
                .as_ptr()
                .add(self.user_data_offset)
                .cast_mut()
                .cast()
        };
        record.UserDataLength = self.user_data_len as u16;
        record
    }

    /// Get the user data slice (zero-copy)
    fn user_data(&self) -> &[u8] {
        &self.record_blob[self.user_data_offset..self.user_data_offset + self.user_data_len]
    }

    /// Get provider GUID for validation
    fn provider_guid(&self) -> etw::Guid {
        let record_ptr = self.record_blob.as_ptr().cast::<EVENT_RECORD>();
        // SAFETY: The blob contains a valid EVENT_RECORD at offset 0.
        etw::Guid::from_u128(unsafe { (*record_ptr).EventHeader.ProviderId }.to_u128())
    }

    /// Get opcode for validation
    fn opcode(&self) -> u8 {
        let record_ptr = self.record_blob.as_ptr().cast::<EVENT_RECORD>();
        // SAFETY: The blob contains a valid EVENT_RECORD at offset 0.
        unsafe { (*record_ptr).EventHeader.EventDescriptor.Opcode }
    }

    /// Get version for validation
    fn version(&self) -> u8 {
        let record_ptr = self.record_blob.as_ptr().cast::<EVENT_RECORD>();
        // SAFETY: The blob contains a valid EVENT_RECORD at offset 0.
        unsafe { (*record_ptr).EventHeader.EventDescriptor.Version }
    }
}

/// Parsed File rundown data for etw-rs (static and TDH parsers)
#[derive(Clone)]
#[expect(dead_code, reason = "fields accessed via black_box in the benchmark")]
struct ParsedFileRundownEtwRs {
    timestamp: i64,
    file_object: u64,
    file_name: WideString, // Native UTF-16
}

/// Parsed File rundown data for ferrisetw
#[derive(Clone)]
#[expect(dead_code, reason = "fields accessed via black_box in the benchmark")]
struct ParsedFileRundownFerris {
    timestamp: i64,
    file_object: u64,
    file_name: String, // ferrisetw outputs UTF-8 String
}

/// Capture File rundown events ONCE for reuse across all benchmarks.
/// Uses OnceLock to ensure we only capture once per benchmark run.
fn get_captured_events() -> &'static Vec<CapturedEvent> {
    static CAPTURED: OnceLock<Vec<CapturedEvent>> = OnceLock::new();

    CAPTURED.get_or_init(|| {
        eprintln!("\n=== Capturing File rundown events for benchmarking ===");

        let events = Arc::new(Mutex::new(Vec::with_capacity(60000)));
        let events_clone = Arc::clone(&events);

        // Create system trace session
        let mut trace = Trace::new("ApplesToApplesBench").unwrap();

        // Enable file I/O events (PERF_FILENAME includes File rundown events)
        trace.set_events(&[PERF_FILENAME]);
        trace.start().unwrap();

        // Set callback to capture rundown events (store entire EVENT_RECORD + user_data)
        trace.set_event_callback(move |event, _cache| {
            // Only capture File rundown events (opcode 36 = FILE_RUNDOWN)
            if event.provider_guid() == file_io::GUID
                && event.opcode() == file_io::opcode::FILE_RUNDOWN
            {
                let user_data = event.user_data();

                // Capture EVENT_RECORD structure + user_data in one blob
                let header_size = size_of::<EVENT_RECORD>();
                let total_size = header_size + user_data.len();
                let mut blob = vec![0u8; total_size];

                // SAFETY: Copy EVENT_RECORD header bytes from the live event pointer.
                // The event pointer is valid for the duration of the callback.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        std::ptr::from_ref(event).cast::<u8>(),
                        blob.as_mut_ptr(),
                        header_size,
                    );
                }

                // Copy user_data
                blob[header_size..].copy_from_slice(user_data);

                // SAFETY: blob is large enough and was just written with a valid EVENT_RECORD.
                let record = unsafe { &mut *(blob.as_mut_ptr().cast::<EVENT_RECORD>()) };
                // SAFETY: header_size offset is within the blob and points to user data.
                record.UserData = unsafe { blob.as_ptr().add(header_size).cast_mut().cast() };
                record.UserDataLength = user_data.len() as u16;

                let captured = CapturedEvent {
                    record_blob: blob,
                    user_data_offset: header_size,
                    user_data_len: user_data.len(),
                };

                events_clone.lock().unwrap().push(captured);
            }
            Ok(())
        });

        // Start processing
        trace.start_processing_thread().unwrap();

        // Stop the trace to trigger FILE_RUNDOWN events
        trace.stop().unwrap();

        let captured = events.lock().unwrap().clone();

        // Calculate total size of captured events
        let header_size = size_of::<EVENT_RECORD>();
        let total_user_data_size: usize = captured.iter().map(|e| e.user_data_len).sum();
        let total_headers_size = captured.len() * header_size;
        let total_size = total_headers_size + total_user_data_size;

        eprintln!("Captured {} File rundown events", captured.len());
        eprintln!("  Event headers: {total_headers_size} bytes ({header_size} bytes per event)");
        #[expect(clippy::cast_precision_loss, reason = "f64 is fine for display stats")]
        let avg_user_data = total_user_data_size as f64 / captured.len() as f64;
        eprintln!(
            "  User data:     {total_user_data_size} bytes ({avg_user_data:.0} bytes avg per event)"
        );
        #[expect(clippy::cast_precision_loss, reason = "f64 is fine for display stats")]
        let total_mb = total_size as f64 / 1_048_576.0;
        eprintln!("  Total size:    {total_size} bytes ({total_mb:.2} MB)");
        eprintln!("=== Event capture complete ===\n");

        captured
    })
}

/// Prints the per-event summary for one parser arm.
///
/// Silent when no samples were collected. `counts` and `times` are filled inside
/// `b.iter`, but this summary runs unconditionally after it, so any criterion
/// filter that excludes the benchmark leaves both empty. Dividing a `Duration`
/// sum by a zero count panics, which failed the whole `cargo bench` invocation
/// rather than quietly skipping the benchmark the filter had already skipped.
fn report_parse_stats(label: &str, counts: &[usize], times: &[Duration]) {
    if counts.is_empty() || times.is_empty() {
        return;
    }

    #[expect(clippy::cast_precision_loss, reason = "f64 for display stats")]
    let avg_events = counts.iter().sum::<usize>() as f64 / counts.len() as f64;
    let avg_parse_time = times.iter().sum::<Duration>() / times.len() as u32;

    eprintln!("\n{label}:");
    eprintln!("  Events parsed: {avg_events:.0}");
    eprintln!("  Parse time (total): {avg_parse_time:?}");
    #[expect(clippy::cast_precision_loss, reason = "f64 for display stats")]
    let per_event_us = avg_parse_time.as_micros() as f64 / avg_events;
    eprintln!("  Parse time (per event): {per_event_us:.2}us");
}
fn bench_etw_rs_static_parser(c: &mut Criterion) {
    let events = get_captured_events();

    if events.is_empty() {
        eprintln!("WARNING: No events captured. Skipping etw-rs benchmark.");
        return;
    }

    let counts = Arc::new(Mutex::new(Vec::with_capacity(100)));
    let counts_clone = Arc::clone(&counts);
    let parse_times = Arc::new(Mutex::new(Vec::with_capacity(100)));
    let parse_times_clone = Arc::clone(&parse_times);

    c.bench_function("etw-rs-static-parser", |b| {
        b.iter(|| {
            let mut results = Vec::with_capacity(events.len());

            let parse_start = Instant::now();
            for event in events {
                // Validate event metadata matches what static parser expects
                assert_eq!(
                    event.provider_guid(),
                    file_io::GUID,
                    "Provider GUID mismatch"
                );
                assert_eq!(
                    event.opcode(),
                    file_io::opcode::FILE_RUNDOWN,
                    "Opcode mismatch"
                );
                assert_eq!(event.version(), 2, "Ver mismatch");

                // Parse with etw-rs static parser (zero-copy user_data access)
                let mut parser = FileRundownV2Parser::from_bytes(event.user_data());

                let record = event.as_event_record();
                let parsed = ParsedFileRundownEtwRs {
                    timestamp: record.EventHeader.TimeStamp,
                    file_object: parser.FileObject().unwrap(),
                    file_name: WideString::from(parser.FileName_ref().unwrap()),
                };

                results.push(parsed);
            }

            let parse_elapsed = parse_start.elapsed();
            let count = results.len();
            counts_clone.lock().unwrap().push(count);
            parse_times_clone.lock().unwrap().push(parse_elapsed);

            black_box(count)
        });
    });

    report_parse_stats(
        "etw-rs static parser",
        &counts.lock().unwrap(),
        &parse_times.lock().unwrap(),
    );
}

fn bench_tdh_parser(c: &mut Criterion) {
    let events = get_captured_events();

    if events.is_empty() {
        eprintln!("WARNING: No events captured. Skipping TDH benchmark.");
        return;
    }

    let counts = Arc::new(Mutex::new(Vec::with_capacity(100)));
    let counts_clone = Arc::clone(&counts);
    let parse_times = Arc::new(Mutex::new(Vec::with_capacity(100)));
    let parse_times_clone = Arc::clone(&parse_times);

    c.bench_function("etw-rs dynamic parser", |b| {
        b.iter(|| {
            let mut results = Vec::with_capacity(events.len());
            // Fresh cache per iteration — first event incurs a cold TDH lookup,
            // but it's negligible across ~50K events per batch.
            let mut parser_cache = etw::processing_context::ProcessingContext::new();

            let parse_start = Instant::now();
            for event in events {
                // Validate event metadata
                assert_eq!(
                    event.provider_guid(),
                    file_io::GUID,
                    "Provider GUID mismatch"
                );
                assert_eq!(
                    event.opcode(),
                    file_io::opcode::FILE_RUNDOWN,
                    "Opcode mismatch"
                );

                // Reconstruct EVENT_RECORD with valid pointers
                let record = event.as_event_record();
                // SAFETY: record is a valid EVENT_RECORD reconstructed from captured data.
                let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };

                // Parse using TDH-based dynamic parser (schema lookup + parsing)
                if let Ok(mut parser) = parser_cache.parser(raw_event) {
                    // Use get_hinted with property index hints for better performance
                    // FileObject is index 0, FileName is index 1
                    let file_object: u64 = parser.get_hinted("FileObject", 0).unwrap_or(0);
                    let file_name = parser
                        .as_ref_hinted::<etw::WideStrRef>("FileName", 1)
                        .map(WideString::from)
                        .unwrap_or_default();

                    let parsed = ParsedFileRundownEtwRs {
                        timestamp: record.EventHeader.TimeStamp,
                        file_object,
                        file_name,
                    };

                    results.push(parsed);
                }
            }

            let parse_elapsed = parse_start.elapsed();
            let count = results.len();
            counts_clone.lock().unwrap().push(count);
            parse_times_clone.lock().unwrap().push(parse_elapsed);

            black_box(count)
        });
    });

    report_parse_stats(
        "etw-rs dynamic parser",
        &counts.lock().unwrap(),
        &parse_times.lock().unwrap(),
    );
}

fn bench_ferrisetw_parser(c: &mut Criterion) {
    let events = get_captured_events();

    if events.is_empty() {
        eprintln!("WARNING: No events captured. Skipping ferrisetw benchmark.");
        return;
    }

    let counts = Arc::new(Mutex::new(Vec::with_capacity(100)));
    let counts_clone = Arc::clone(&counts);
    let parse_times = Arc::new(Mutex::new(Vec::with_capacity(100)));
    let parse_times_clone = Arc::clone(&parse_times);

    c.bench_function("ferrisetw-parser", |b| {
        b.iter(|| {
            let mut results = Vec::with_capacity(events.len());
            // SchemaLocator::new() is private, use Default
            let schema_locator = ferrisetw::schema_locator::SchemaLocator::default();

            let parse_start = Instant::now();
            for event in events {
                // Validate event metadata
                assert_eq!(
                    event.provider_guid(),
                    file_io::GUID,
                    "Provider GUID mismatch"
                );
                assert_eq!(
                    event.opcode(),
                    file_io::opcode::FILE_RUNDOWN,
                    "Opcode mismatch"
                );

                // Reconstruct EVENT_RECORD with valid pointers
                let record = event.as_event_record();

                // SAFETY: Cast to ferrisetw::EventRecord (transparent wrapper over EVENT_RECORD).
                let ferris_record =
                    unsafe { &*(&raw const record).cast::<ferrisetw::EventRecord>() };

                if let Ok(schema) = schema_locator.event_schema(ferris_record) {
                    let parser = ferrisetw::parser::Parser::create(ferris_record, &schema);

                    let file_object: u64 = parser.try_parse("FileObject").unwrap_or(0);
                    let file_name: String = parser.try_parse("FileName").unwrap_or_default();

                    let parsed = ParsedFileRundownFerris {
                        timestamp: ferris_record.raw_timestamp(),
                        file_object,
                        file_name,
                    };

                    results.push(parsed);
                }
            }

            let parse_elapsed = parse_start.elapsed();
            let count = results.len();
            counts_clone.lock().unwrap().push(count);
            parse_times_clone.lock().unwrap().push(parse_elapsed);

            black_box(count)
        });
    });

    report_parse_stats(
        "ferrisetw parser",
        &counts.lock().unwrap(),
        &parse_times.lock().unwrap(),
    );
}

criterion_group!(
    benches,
    bench_etw_rs_static_parser,
    bench_tdh_parser,
    bench_ferrisetw_parser
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
