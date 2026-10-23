//! Live event capture benchmarks for common ETW events
//!
//! This benchmark captures real ETW events once, then benchmarks parsing performance
//! on the same captured data across etw-rs static parser, dynamic parser, and ferrisetw.
//!
//! Events benchmarked:
//! - Microsoft-Windows-Kernel-Process ProcessStart (event ID 1)
//! - Microsoft-Windows-Kernel-Process ThreadStart (event ID 3)
//! - Microsoft-Windows-Kernel-File Create (event ID 12)
//! - Microsoft-Windows-Kernel-Registry CreateKey (event ID 1)
//! - Microsoft-Windows-RPC RpcClientCall (event ID 5)
//!
//! # Requirements
//!
//! Must be run as Administrator for kernel tracing.
//!
//! # Usage
//!
//! ```bash
//! cargo bench --bench live_events
//! ```

#![expect(
    clippy::print_stderr,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_const_for_fn,
    clippy::semicolon_outside_block,
    clippy::undocumented_unsafe_blocks,
    clippy::uninlined_format_args,
    clippy::unnecessary_map_or,
    unreachable_pub,
    reason = "benchmark harness prioritises measurement workflow over strict style rules"
)]

#[path = "bench_util.rs"]
mod bench_util;

use etw::types::{Guid, Sid, SidRef};
use example_providers::kernel::{file, network, process};
use std::hint::black_box;

/// Minimum number of events to capture per event type before benchmarking.
///
/// This is a floor, not a cap. The capture callback keeps appending for as long
/// as the session runs, and the polling loop below only samples every 100ms, so
/// high-rate providers routinely deliver far more than this — which is wanted.
/// All reported figures are per-event averages, so a larger sample just makes
/// them steadier.
const CAPTURE_MINIMUM: usize = 100;

mod registry {
    pub const GUID: etw::Guid = etw::Guid::from_u128(0x70eb4f03_c1de_4f73_a051_33d13d5413bd);
    pub mod keyword {
        pub const CREATE_KEY: u64 = 0x80;
    }
    pub mod event {
        pub const CREATE_KEY: u16 = 1;
    }
}
mod rpc {
    pub const GUID: etw::Guid = etw::Guid::from_u128(0x6ad52b32_d609_4be9_ae07_ce8dae937e39);
    pub mod event {
        pub const RPC_CLIENT_CALL_5: u16 = 5;
    }
}
use etw::{Timestamp, Trace, provider_schema};
use std::{
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};
use windows::Win32::System::Diagnostics::Etw::EVENT_RECORD;

// Define static schemas for benchmarking (provider_schema! also generates
// multi-version types: {Name}Accessors trait and {Name}Parser enum)

// Microsoft-Windows-Kernel-Process: ProcessStart, ThreadStart
provider_schema! {
    guid: etw::Guid::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716),
    events: {
        event {
            id: 1,
            name: "ProcessStart",
            version { 3, fields: {
                ProcessID: u32,
                ProcessSequenceNumber: u64,
                CreateTime: u64,
                ParentProcessID: u32,
                ParentProcessSequenceNumber: u64,
                SessionID: u32,
                Flags: u32,
                ProcessTokenElevationType: u32,
                ProcessTokenIsElevated: u32,
                MandatoryLabel: SidRef,
                ImageName: WideStrRef,
                ImageChecksum: u32,
                TimeDateStamp: u32,
                PackageFullName: WideStrRef,
                PackageRelativeAppId: WideStrRef,
            }}
            version { 4, extends_version: 3, fields: {
                SecurityMitigations: u32,
            }}
        }
        event {
            id: 3,
            name: "ThreadStart",
            version { 1, fields: {
                ProcessID: u32,
                ThreadID: u32,
                StackBase: usize,
                StackLimit: usize,
                UserStackBase: usize,
                UserStackLimit: usize,
                StartAddr: usize,
                Win32StartAddr: usize,
                TebBase: usize,
                SubProcessTag: u32,
            }}
        }
    }
}

// Microsoft-Windows-Kernel-File: FileCreate
provider_schema! {
    guid: etw::Guid::from_u128(0xedd08927_9cc4_4e65_b970_c2560fb5c289),
    events: {
        event {
            id: 12,
            name: "FileCreate",
            version { 1, fields: {
                Irp: usize,
                FileObject: usize,
                IssuingThreadId: u32,
                CreateOptions: u32,
                CreateAttributes: u32,
                ShareAccess: u32,
                FileName: WideStrRef,
            }}
        }
    }
}

// Microsoft-Windows-Kernel-Registry: RegistryCreateKey
provider_schema! {
    guid: etw::Guid::from_u128(0x70eb4f03_c1de_4f73_a051_33d13d5413bd),
    events: {
        event {
            id: 1,
            name: "RegistryCreateKey",
            version { 0, fields: {
                BaseObject: usize,
                KeyObject: usize,
                Status: u32,
                Disposition: u32,
                BaseName: WideStrRef,
                RelativeName: WideStrRef,
            }}
        }
    }
}

// Microsoft-Windows-RPC: RpcClientCall
provider_schema! {
    guid: etw::Guid::from_u128(0x6ad52b32_d609_4be9_ae07_ce8dae937e39),
    events: {
        event {
            id: 5,
            name: "RpcClientCall",
            version { 1, fields: {
                InterfaceUuid: Guid,
                ProcNum: u32,
                Protocol: u32,
                NetworkAddress: WideStrRef,
                Endpoint: WideStrRef,
                Options: WideStrRef,
                AuthenticationLevel: u32,
                AuthenticationService: u32,
                ImpersonationLevel: u32,
            }}
        }
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
    /// Serialize event to binary format for C++ replay.
    ///
    /// Format (little-endian):
    /// - total_size: u32 (size of entire record including this field)
    /// - record_blob_len: u32
    /// - record_blob: [u8; record_blob_len]
    /// - user_data_offset: u64
    /// - user_data_len: u64
    fn serialize(&self) -> Vec<u8> {
        let total_size = 4 + 4 + self.record_blob.len() + 8 + 8;
        let mut buf = Vec::with_capacity(total_size);

        buf.extend_from_slice(&(total_size as u32).to_le_bytes());
        buf.extend_from_slice(&(self.record_blob.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.record_blob);
        buf.extend_from_slice(&(self.user_data_offset as u64).to_le_bytes());
        buf.extend_from_slice(&(self.user_data_len as u64).to_le_bytes());

        buf
    }

    /// Deserialize event from binary format (for testing).
    fn deserialize(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.len() < 4 {
            return None;
        }

        let total_size = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if buf.len() < total_size {
            return None;
        }

        let mut offset = 4;
        let record_blob_len = u32::from_le_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]) as usize;
        offset += 4;

        let record_blob = buf[offset..offset + record_blob_len].to_vec();
        offset += record_blob_len;

        let user_data_offset = u64::from_le_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
            buf[offset + 4],
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
        ]) as usize;
        offset += 8;

        let user_data_len = u64::from_le_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
            buf[offset + 4],
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
        ]) as usize;

        Some((
            Self {
                record_blob,
                user_data_offset,
                user_data_len,
            },
            total_size,
        ))
    }
}

/// Save captured events to binary file for C++ replay.
///
/// Format:
/// - magic: "ETWCAP01" (8 bytes)
/// - event_count: u64
/// - For each event: serialized CapturedEvent (see CapturedEvent::serialize)
fn save_events_to_file(events: &[CapturedEvent], path: &str) -> std::io::Result<()> {
    use std::{fs::File, io::Write};

    let mut file = File::create(path)?;

    // Write magic and count
    file.write_all(b"ETWCAP01")?;
    file.write_all(&(events.len() as u64).to_le_bytes())?;

    // Write each event
    for event in events {
        let serialized = event.serialize();
        file.write_all(&serialized)?;
    }

    Ok(())
}

/// Load captured events from binary file.
fn load_events_from_file(path: &str) -> std::io::Result<Vec<CapturedEvent>> {
    use std::fs;

    let buf = fs::read(path)?;

    // Check magic
    if buf.len() < 8 || &buf[0..8] != b"ETWCAP01" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid magic header",
        ));
    }

    // Read count
    let event_count = u64::from_le_bytes([
        buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
    ]) as usize;

    let mut events = Vec::with_capacity(event_count);
    let mut offset = 16;

    while offset < buf.len() {
        if let Some((event, size)) = CapturedEvent::deserialize(&buf[offset..]) {
            events.push(event);
            offset += size;
        } else {
            break;
        }
    }

    Ok(events)
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
}

/// Parsed Process Start data (shared by all parsers including ferrisetw)
#[derive(Clone)]
#[expect(dead_code, reason = "fields accessed via black_box in the benchmark")]
struct ParsedProcessStart {
    timestamp: i64,
    process_id: u32,
    process_sequence_number: u64,
    create_time: u64,
    parent_process_id: u32,
    parent_process_sequence_number: u64,
    session_id: u32,
    flags: u32,
    process_token_elevation_type: u32,
    process_token_is_elevated: u32,
    mandatory_label: String,
    image_name: String,
    image_checksum: u32,
    time_date_stamp: u32,
    package_full_name: String,
    package_relative_app_id: String,
    security_mitigations: u32,
}

/// Parsed File Create data (shared by all parsers including ferrisetw)
#[derive(Clone)]
#[expect(dead_code, reason = "fields accessed via black_box in the benchmark")]
struct ParsedFileCreate {
    timestamp: i64,
    irp: usize,
    file_object: usize,
    issuing_thread_id: u32,
    create_options: u32,
    create_attributes: u32,
    share_access: u32,
    file_name: String,
}

/// Parsed Thread Start data (shared by all parsers including ferrisetw)
#[derive(Clone)]
#[expect(dead_code, reason = "fields accessed via black_box in the benchmark")]
struct ParsedThreadStart {
    timestamp: i64,
    process_id: u32,
    thread_id: u32,
    stack_base: usize,
    stack_limit: usize,
    user_stack_base: usize,
    user_stack_limit: usize,
    start_addr: usize,
    win32_start_addr: usize,
    teb_base: usize,
    sub_process_tag: u32,
}

/// The subset of Thread Start fields a real consumer tends to want.
///
/// Every other `etw-rs-get` arm reads *all* of an event's properties in
/// declaration order, which is the best case for any lookup that predicts the
/// next index, and not a shape consumers actually have. A thread-creation record
/// generally needs who started the thread and where it started, and ignores the
/// stack bounds entirely.
///
/// The five fields below sit at schema indices 0, 1, 6, 7 and 9, so call
/// positions 2-4 disagree with the identity seed of `ParserCache::learned_hints`.
/// Those three lookups miss on the first event and are learned; every lookup
/// after that hits. The arm therefore measures whether a non-sequential read
/// pattern settles onto the hinted path. Changing this set changes what the
/// benchmark measures, so change it deliberately.
#[derive(Clone)]
#[expect(dead_code, reason = "fields accessed via black_box in the benchmark")]
struct ParsedThreadStartSubset {
    timestamp: i64,
    process_id: u32,
    thread_id: u32,
    start_addr: usize,
    win32_start_addr: usize,
    sub_process_tag: u32,
}

/// Parsed Registry CreateKey data (shared by all parsers including ferrisetw)
#[derive(Clone)]
#[expect(dead_code, reason = "fields accessed via black_box in the benchmark")]
struct ParsedRegistryCreateKey {
    timestamp: i64,
    base_object: usize,
    key_object: usize,
    status: u32,
    disposition: u32,
    base_name: String,
    relative_name: String,
}

/// Parsed RPC Client Call data (shared by all parsers including ferrisetw)
#[derive(Clone)]
#[expect(dead_code, reason = "fields accessed via black_box in the benchmark")]
struct ParsedRpcClientCall {
    timestamp: i64,
    interface_uuid: u128,
    proc_num: u32,
    protocol: u32,
    network_address: String,
    endpoint: String,
    options: String,
    authentication_level: u32,
    authentication_service: u32,
    impersonation_level: u32,
}

/// Convert an etw-rs `Guid` to a `u128`. Thin wrapper kept as the call sites'
/// single conversion point; `Guid::to_u128` is the canonical mapping.
fn guid_to_u128(g: Guid) -> u128 {
    g.to_u128()
}

/// Convert a raw ETW GUID `[u8; 16]` to a `u128`.
/// ETW stores GUIDs with Data1/2/3 in little-endian and Data4 as big-endian bytes,
/// matching the layout that `GUID::from_u128` and `guid_to_u128` use.
fn guid_bytes_to_u128(b: [u8; 16]) -> u128 {
    let data1 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let data2 = u16::from_le_bytes([b[4], b[5]]);
    let data3 = u16::from_le_bytes([b[6], b[7]]);
    let data4 = u64::from_be_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]);
    ((data1 as u128) << 96) | ((data2 as u128) << 80) | ((data3 as u128) << 64) | (data4 as u128)
}

// =============================================================================
// Generic Event Capture Function
// =============================================================================

/// Generic function to capture ETW events for benchmarking.
///
/// This function creates a trace session, enables the specified provider,
/// captures events matching the given event ID (and optionally version) until at
/// least [`CAPTURE_MINIMUM`] have arrived or 120 seconds pass, and returns them.
///
/// # Parameters
///
/// - `session_name`: Unique name for the trace session
/// - `event_description`: Human-readable description for logging (e.g., "Process Start")
/// - `provider_guid`: GUID of the ETW provider to enable
/// - `keyword`: Provider keyword flags to enable
/// - `event_id`: Event ID to capture
/// - `event_version`: Optional event version to filter on (None means any version)
///
/// # Safety
///
/// This function performs unsafe operations to capture EVENT_RECORD structures.
/// The captured events are stored as raw byte blobs and reconstructed later.
fn capture_events(
    session_name: &str,
    event_description: &str,
    provider_guid: Guid,
    keyword: u64,
    event_id: u16,
    event_version: Option<u8>,
) -> Vec<CapturedEvent> {
    eprintln!("\n=== Capturing {event_description} events ===");

    let events = Arc::new(Mutex::new(Vec::with_capacity(100)));
    let events_clone = Arc::clone(&events);

    // Create trace session
    let mut trace = Trace::new(session_name).unwrap();
    trace.enable_provider(provider_guid, keyword).unwrap();

    // Set callback to capture events
    trace.set_event_callback(move |event, _cache| {
        // Filter by provider GUID, event ID, and optionally version
        let matches = event.provider_guid() == provider_guid
            && event.id() == event_id
            && event_version.map_or(true, |v| event.version() == v);

        if !matches {
            return Ok(());
        }

        let user_data = event.user_data();

        // Capture EVENT_RECORD structure + user_data in one blob
        let header_size = size_of::<EVENT_RECORD>();
        let total_size = header_size + user_data.len();
        let mut blob = vec![0u8; total_size];

        // SAFETY: Copy EVENT_RECORD header bytes from the live event pointer.
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
        Ok(())
    });

    // Start processing
    trace.start_processing_thread().unwrap();

    // Wait up to 120 seconds for events
    for _ in 0..1200 {
        std::thread::sleep(Duration::from_millis(100));
        let count = events.lock().unwrap().len();
        if count >= CAPTURE_MINIMUM {
            break;
        }
    }

    trace.stop().unwrap();
    let captured = events.lock().unwrap().clone();

    eprintln!("Captured {} {event_description} events", captured.len());
    eprintln!("=== {event_description} capture complete ===\n");

    captured
}

/// Load events from .bin file, or capture live and save if file doesn't exist.
fn load_or_capture_events(
    filename: &str,
    session_name: &str,
    event_description: &str,
    provider_guid: Guid,
    keyword: u64,
    event_id: u16,
    version: Option<u8>,
) -> Vec<CapturedEvent> {
    // Try to load from file first
    if let Ok(events) = load_events_from_file(filename) {
        eprintln!(
            "Loaded {} {} events from {}",
            events.len(),
            event_description,
            filename
        );
        return events;
    }

    // If file doesn't exist, capture live and save
    eprintln!(
        "File {} not found, capturing live {} events...",
        filename, event_description
    );
    let events = capture_events(
        session_name,
        event_description,
        provider_guid,
        keyword,
        event_id,
        version,
    );

    // Save to file for next time
    if let Err(e) = save_events_to_file(&events, filename) {
        eprintln!("Warning: Failed to save events to {}: {}", filename, e);
    } else {
        eprintln!("Saved {} events to {}", events.len(), filename);
    }

    events
}

/// Capture Process Start events ONCE for reuse across all benchmarks.
fn get_captured_process_events() -> &'static Vec<CapturedEvent> {
    static CAPTURED: OnceLock<Vec<CapturedEvent>> = OnceLock::new();

    CAPTURED.get_or_init(|| {
        load_or_capture_events(
            "captured_process_events.bin",
            "ProcessStartCapture",
            "Process Start",
            process::GUID,
            process::keyword::PROCESS,
            process::event::PROCESS_START,
            Some(4), // v4 only — static parser requires matching version
        )
    })
}

/// Capture File Create events ONCE for reuse across all benchmarks.
fn get_captured_file_events() -> &'static Vec<CapturedEvent> {
    static CAPTURED: OnceLock<Vec<CapturedEvent>> = OnceLock::new();

    CAPTURED.get_or_init(|| {
        load_or_capture_events(
            "captured_file_events.bin",
            "FileCreateCapture",
            "File Create",
            file::GUID,
            file::keyword::CREATE,
            file::event::CREATE,
            None,
        )
    })
}

/// Capture Thread Start events ONCE for reuse across all benchmarks.
fn get_captured_thread_events() -> &'static Vec<CapturedEvent> {
    static CAPTURED: OnceLock<Vec<CapturedEvent>> = OnceLock::new();

    CAPTURED.get_or_init(|| {
        load_or_capture_events(
            "captured_thread_events.bin",
            "ThreadStartCapture",
            "Thread Start",
            process::GUID,
            process::keyword::THREAD,
            process::event::THREAD_START,
            None,
        )
    })
}

/// Capture Registry CreateKey events ONCE for reuse across all benchmarks.
fn get_captured_registry_events() -> &'static Vec<CapturedEvent> {
    static CAPTURED: OnceLock<Vec<CapturedEvent>> = OnceLock::new();

    CAPTURED.get_or_init(|| {
        load_or_capture_events(
            "captured_registry_events.bin",
            "RegistryCreateCapture",
            "Registry CreateKey",
            registry::GUID,
            registry::keyword::CREATE_KEY,
            registry::event::CREATE_KEY,
            None,
        )
    })
}

fn get_captured_rpc_events() -> &'static Vec<CapturedEvent> {
    static CAPTURED: OnceLock<Vec<CapturedEvent>> = OnceLock::new();

    CAPTURED.get_or_init(|| {
        load_or_capture_events(
            "captured_rpc_events.bin",
            "RpcClientCallCapture",
            "RPC Client Call",
            rpc::GUID,
            0xFFFFFFFFFFFFFFFF, // All keywords to catch RPC client calls
            rpc::event::RPC_CLIENT_CALL_5,
            Some(1), // Filter for version 1
        )
    })
}

// ============================================================================
// Process Start Benchmarks
// ============================================================================

fn bench_process_start_dynamic() {
    let events = get_captured_process_events();

    if events.is_empty() {
        eprintln!("WARNING: No Process Start events captured. Skipping benchmark.");
        return;
    }

    // Create and prime the schema cache once before benchmarking
    let mut parser_cache = etw::processing_context::ProcessingContext::new();
    if let Some(first_event) = events.first() {
        let record = first_event.as_event_record();
        let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
        let _ = parser_cache.parser(raw_event); // Prime the cache
    }

    measure("process_start", "etw-rs-get-hinted", events.len(), || {
        for event in events {
            // Reconstruct EVENT_RECORD with valid pointers
            let record = event.as_event_record();
            // SAFETY: record is a valid EVENT_RECORD reconstructed from captured data.
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };

            // Parse using TDH-based dynamic parser
            if let Ok(mut parser) = parser_cache.parser(raw_event) {
                let parsed = ParsedProcessStart {
                    timestamp: record.EventHeader.TimeStamp,
                    process_id: parser.get_hinted("ProcessID", 0).unwrap(),
                    process_sequence_number: parser.get_hinted("ProcessSequenceNumber", 1).unwrap(),
                    create_time: parser.get_hinted::<Timestamp>("CreateTime", 2).unwrap().0 as u64,
                    parent_process_id: parser.get_hinted("ParentProcessID", 3).unwrap(),
                    parent_process_sequence_number: parser
                        .get_hinted("ParentProcessSequenceNumber", 4)
                        .unwrap(),
                    session_id: parser.get_hinted("SessionID", 5).unwrap(),
                    flags: parser.get_hinted("Flags", 6).unwrap(),
                    process_token_elevation_type: parser
                        .get_hinted("ProcessTokenElevationType", 7)
                        .unwrap(),
                    process_token_is_elevated: parser
                        .get_hinted("ProcessTokenIsElevated", 8)
                        .unwrap(),
                    mandatory_label: parser
                        .as_ref_hinted::<SidRef<'_>>("MandatoryLabel", 9)
                        .map(|r| format!("{r}"))
                        .unwrap(),
                    image_name: parser.get_hinted("ImageName", 10).unwrap(),
                    image_checksum: parser.get_hinted("ImageChecksum", 11).unwrap(),
                    time_date_stamp: parser.get_hinted("TimeDateStamp", 12).unwrap(),
                    package_full_name: parser.get_hinted("PackageFullName", 13).unwrap(),
                    package_relative_app_id: parser.get_hinted("PackageRelativeAppId", 14).unwrap(),
                    security_mitigations: parser.get_hinted("SecurityMitigations", 15).unwrap(),
                };

                black_box(&parsed);
            }
        }
    });
}

fn bench_process_start_ferrisetw() {
    let events = get_captured_process_events();

    if events.is_empty() {
        eprintln!("WARNING: No Process Start events captured. Skipping benchmark.");
        return;
    }

    // Create and prime the schema locator once before benchmarking
    let schema_locator = ferrisetw::schema_locator::SchemaLocator::default();
    if let Some(first_event) = events.first() {
        let record = first_event.as_event_record();
        let ferris_record = unsafe { &*(&raw const record).cast::<ferrisetw::EventRecord>() };
        let _ = schema_locator.event_schema(ferris_record); // Prime the cache
    }

    measure("process_start", "ferrisetw", events.len(), || {
        for event in events {
            // Reconstruct EVENT_RECORD with valid pointers
            let record = event.as_event_record();

            // SAFETY: Cast to ferrisetw::EventRecord
            let ferris_record = unsafe { &*(&raw const record).cast::<ferrisetw::EventRecord>() };

            if let Ok(schema) = schema_locator.event_schema(ferris_record) {
                let parser = ferrisetw::parser::Parser::create(ferris_record, &schema);

                // Parse all fields (ferrisetw returns String for strings)
                let parsed = ParsedProcessStart {
                    timestamp: ferris_record.raw_timestamp(),
                    process_id: parser.try_parse("ProcessID").unwrap(),
                    process_sequence_number: parser.try_parse("ProcessSequenceNumber").unwrap(),
                    create_time: parser.try_parse("CreateTime").unwrap(),
                    parent_process_id: parser.try_parse("ParentProcessID").unwrap(),
                    parent_process_sequence_number: parser
                        .try_parse("ParentProcessSequenceNumber")
                        .unwrap(),
                    session_id: parser.try_parse("SessionID").unwrap(),
                    flags: parser.try_parse("Flags").unwrap(),
                    process_token_elevation_type: parser
                        .try_parse("ProcessTokenElevationType")
                        .unwrap(),
                    process_token_is_elevated: parser.try_parse("ProcessTokenIsElevated").unwrap(),
                    mandatory_label: parser.try_parse::<String>("MandatoryLabel").unwrap(),
                    image_name: parser.try_parse::<String>("ImageName").unwrap(),
                    image_checksum: parser.try_parse("ImageChecksum").unwrap(),
                    time_date_stamp: parser.try_parse("TimeDateStamp").unwrap(),
                    package_full_name: parser.try_parse::<String>("PackageFullName").unwrap(),
                    package_relative_app_id: parser
                        .try_parse::<String>("PackageRelativeAppId")
                        .unwrap(),
                    security_mitigations: parser.try_parse("SecurityMitigations").unwrap(),
                };

                black_box(&parsed);
            }
        }
    });
}

fn bench_process_start_get() {
    let events = get_captured_process_events();

    if events.is_empty() {
        eprintln!("WARNING: No Process Start events captured. Skipping benchmark.");
        return;
    }

    // Create and prime the schema cache once before benchmarking
    let mut parser_cache = etw::processing_context::ProcessingContext::new();
    if let Some(first_event) = events.first() {
        let record = first_event.as_event_record();
        let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
        let _ = parser_cache.parser(raw_event); // Prime the cache
    }

    measure("process_start", "etw-rs-get", events.len(), || {
        for event in events {
            let record = event.as_event_record();
            // SAFETY: record is a valid EVENT_RECORD reconstructed from captured data.
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };

            if let Ok(mut parser) = parser_cache.parser(raw_event) {
                let parsed = ParsedProcessStart {
                    timestamp: record.EventHeader.TimeStamp,
                    process_id: parser.get("ProcessID").unwrap(),
                    process_sequence_number: parser.get("ProcessSequenceNumber").unwrap(),
                    create_time: parser.get::<Timestamp>("CreateTime").unwrap().0 as u64,
                    parent_process_id: parser.get("ParentProcessID").unwrap(),
                    parent_process_sequence_number: parser
                        .get("ParentProcessSequenceNumber")
                        .unwrap(),
                    session_id: parser.get("SessionID").unwrap(),
                    flags: parser.get("Flags").unwrap(),
                    process_token_elevation_type: parser.get("ProcessTokenElevationType").unwrap(),
                    process_token_is_elevated: parser.get("ProcessTokenIsElevated").unwrap(),
                    mandatory_label: parser
                        .get::<Sid>("MandatoryLabel")
                        .map(|s| s.to_string())
                        .unwrap(),
                    image_name: parser.get("ImageName").unwrap(),
                    image_checksum: parser.get("ImageChecksum").unwrap(),
                    time_date_stamp: parser.get("TimeDateStamp").unwrap(),
                    package_full_name: parser.get("PackageFullName").unwrap(),
                    package_relative_app_id: parser.get("PackageRelativeAppId").unwrap(),
                    security_mitigations: parser.get("SecurityMitigations").unwrap(),
                };

                black_box(&parsed);
            }
        }
    });
}

fn bench_process_start_static() {
    use ProcessStartAccessors as _;
    let events = get_captured_process_events();

    if events.is_empty() {
        eprintln!("WARNING: No Process Start events captured. Skipping benchmark.");
        return;
    }

    let mut parser_cache = etw::processing_context::ProcessingContext::new();
    if let Some(first_event) = events.first() {
        let record = first_event.as_event_record();
        let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
        let _ = parser_cache.parser(raw_event);
    }

    measure("process_start", "etw-rs-static", events.len(), || {
        for event in events {
            let record = event.as_event_record();
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
            let mut parser = ProcessStartParser::new(raw_event, &mut parser_cache).unwrap();
            let parsed = ParsedProcessStart {
                timestamp: record.EventHeader.TimeStamp,
                process_id: parser.ProcessID().unwrap(),
                process_sequence_number: parser.ProcessSequenceNumber().unwrap(),
                create_time: parser.CreateTime().unwrap(),
                parent_process_id: parser.ParentProcessID().unwrap(),
                parent_process_sequence_number: parser.ParentProcessSequenceNumber().unwrap(),
                session_id: parser.SessionID().unwrap(),
                flags: parser.Flags().unwrap(),
                process_token_elevation_type: parser.ProcessTokenElevationType().unwrap(),
                process_token_is_elevated: parser.ProcessTokenIsElevated().unwrap(),
                mandatory_label: format!("{}", parser.MandatoryLabel().unwrap()),
                image_name: parser.ImageName().unwrap(),
                image_checksum: parser.ImageChecksum().unwrap(),
                time_date_stamp: parser.TimeDateStamp().unwrap(),
                package_full_name: parser.PackageFullName().unwrap(),
                package_relative_app_id: parser.PackageRelativeAppId().unwrap(),
                security_mitigations: parser.SecurityMitigations().unwrap(),
            };

            black_box(&parsed);
        }
    });
}

fn bench_file_create_dynamic() {
    let events = get_captured_file_events();

    if events.is_empty() {
        eprintln!("WARNING: No File Create events captured. Skipping benchmark.");
        return;
    }

    // Create and prime the schema cache once before benchmarking
    let mut parser_cache = etw::processing_context::ProcessingContext::new();
    if let Some(first_event) = events.first() {
        let record = first_event.as_event_record();
        let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
        let _ = parser_cache.parser(raw_event); // Prime the cache
    }

    measure("file_create", "etw-rs-get-hinted", events.len(), || {
        for event in events {
            // Reconstruct EVENT_RECORD with valid pointers
            let record = event.as_event_record();
            // SAFETY: record is a valid EVENT_RECORD reconstructed from captured data.
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };

            // Parse using TDH-based dynamic parser
            if let Ok(mut parser) = parser_cache.parser(raw_event) {
                let parsed = ParsedFileCreate {
                    timestamp: record.EventHeader.TimeStamp,
                    irp: parser.get_hinted("Irp", 0).unwrap(),
                    file_object: parser.get_hinted("FileObject", 1).unwrap(),
                    issuing_thread_id: parser.get_hinted("IssuingThreadId", 2).unwrap(),
                    create_options: parser.get_hinted("CreateOptions", 3).unwrap(),
                    create_attributes: parser.get_hinted("CreateAttributes", 4).unwrap(),
                    share_access: parser.get_hinted("ShareAccess", 5).unwrap(),
                    file_name: parser.get_hinted("FileName", 6).unwrap(),
                };

                black_box(&parsed);
            }
        }
    });
}

fn bench_file_create_ferrisetw() {
    let events = get_captured_file_events();

    if events.is_empty() {
        eprintln!("WARNING: No File Create events captured. Skipping benchmark.");
        return;
    }

    // Create and prime the schema locator once before benchmarking
    let schema_locator = ferrisetw::schema_locator::SchemaLocator::default();
    if let Some(first_event) = events.first() {
        let record = first_event.as_event_record();
        let ferris_record = unsafe { &*(&raw const record).cast::<ferrisetw::EventRecord>() };
        let _ = schema_locator.event_schema(ferris_record); // Prime the cache
    }

    measure("file_create", "ferrisetw", events.len(), || {
        for event in events {
            // Reconstruct EVENT_RECORD with valid pointers
            let record = event.as_event_record();

            // SAFETY: Cast to ferrisetw::EventRecord
            let ferris_record = unsafe { &*(&raw const record).cast::<ferrisetw::EventRecord>() };

            if let Ok(schema) = schema_locator.event_schema(ferris_record) {
                let parser = ferrisetw::parser::Parser::create(ferris_record, &schema);

                let parsed = ParsedFileCreate {
                    timestamp: ferris_record.raw_timestamp(),
                    irp: parser.try_parse::<u64>("Irp").unwrap() as usize,
                    file_object: parser.try_parse::<u64>("FileObject").unwrap() as usize,
                    issuing_thread_id: parser.try_parse("IssuingThreadId").unwrap(),
                    create_options: parser.try_parse("CreateOptions").unwrap(),
                    create_attributes: parser.try_parse("CreateAttributes").unwrap(),
                    share_access: parser.try_parse("ShareAccess").unwrap(),
                    file_name: parser.try_parse::<String>("FileName").unwrap(),
                };

                black_box(&parsed);
            }
        }
    });
}

fn bench_file_create_get() {
    let events = get_captured_file_events();

    if events.is_empty() {
        eprintln!("WARNING: No File Create events captured. Skipping benchmark.");
        return;
    }

    // Create and prime the schema cache once before benchmarking
    let mut parser_cache = etw::processing_context::ProcessingContext::new();
    if let Some(first_event) = events.first() {
        let record = first_event.as_event_record();
        let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
        let _ = parser_cache.parser(raw_event); // Prime the cache
    }

    measure("file_create", "etw-rs-get", events.len(), || {
        for event in events {
            let record = event.as_event_record();
            // SAFETY: record is a valid EVENT_RECORD reconstructed from captured data.
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };

            if let Ok(mut parser) = parser_cache.parser(raw_event) {
                let parsed = ParsedFileCreate {
                    timestamp: record.EventHeader.TimeStamp,
                    irp: parser.get("Irp").unwrap(),
                    file_object: parser.get("FileObject").unwrap(),
                    issuing_thread_id: parser.get("IssuingThreadId").unwrap(),
                    create_options: parser.get("CreateOptions").unwrap(),
                    create_attributes: parser.get("CreateAttributes").unwrap(),
                    share_access: parser.get("ShareAccess").unwrap(),
                    file_name: parser.get("FileName").unwrap(),
                };

                black_box(&parsed);
            }
        }
    });
}

fn bench_file_create_static() {
    use FileCreateAccessors as _;
    let events = get_captured_file_events();

    if events.is_empty() {
        eprintln!("WARNING: No File Create events captured. Skipping benchmark.");
        return;
    }

    let mut parser_cache = etw::processing_context::ProcessingContext::new();
    if let Some(first_event) = events.first() {
        let record = first_event.as_event_record();
        let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
        let _ = parser_cache.parser(raw_event);
    }

    measure("file_create", "etw-rs-static", events.len(), || {
        for event in events {
            let record = event.as_event_record();
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
            let mut parser = FileCreateParser::new(raw_event, &mut parser_cache).unwrap();
            let parsed = ParsedFileCreate {
                timestamp: record.EventHeader.TimeStamp,
                irp: parser.Irp().unwrap(),
                file_object: parser.FileObject().unwrap(),
                issuing_thread_id: parser.IssuingThreadId().unwrap(),
                create_options: parser.CreateOptions().unwrap(),
                create_attributes: parser.CreateAttributes().unwrap(),
                share_access: parser.ShareAccess().unwrap(),
                file_name: parser.FileName().unwrap(),
            };

            black_box(&parsed);
        }
    });
}

// ============================================================================
// Thread Start Benchmarks
// ============================================================================

fn bench_thread_start_dynamic() {
    let events = get_captured_thread_events();

    if events.is_empty() {
        eprintln!("WARNING: No Thread Start events captured. Skipping benchmark.");
        return;
    }

    // Create and prime the schema cache once before benchmarking
    let mut parser_cache = etw::processing_context::ProcessingContext::new();
    if let Some(first_event) = events.first() {
        let record = first_event.as_event_record();
        let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
        let _ = parser_cache.parser(raw_event); // Prime the cache
    }

    measure("thread_start", "etw-rs-get-hinted", events.len(), || {
        for event in events {
            // Reconstruct EVENT_RECORD with valid pointers
            let record = event.as_event_record();
            // SAFETY: record is a valid EVENT_RECORD reconstructed from captured data.
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };

            // Parse using TDH-based dynamic parser
            if let Ok(mut parser) = parser_cache.parser(raw_event) {
                let parsed = ParsedThreadStart {
                    timestamp: record.EventHeader.TimeStamp,
                    process_id: parser.get_hinted("ProcessID", 0).unwrap(),
                    thread_id: parser.get_hinted("ThreadID", 1).unwrap(),
                    stack_base: parser.get_hinted("StackBase", 2).unwrap(),
                    stack_limit: parser.get_hinted("StackLimit", 3).unwrap(),
                    user_stack_base: parser.get_hinted("UserStackBase", 4).unwrap(),
                    user_stack_limit: parser.get_hinted("UserStackLimit", 5).unwrap(),
                    start_addr: parser.get_hinted("StartAddr", 6).unwrap(),
                    win32_start_addr: parser.get_hinted("Win32StartAddr", 7).unwrap(),
                    teb_base: parser.get_hinted("TebBase", 8).unwrap(),
                    sub_process_tag: parser.get_hinted("SubProcessTag", 9).unwrap(),
                };

                black_box(&parsed);
            }
        }
    });
}

fn bench_thread_start_ferrisetw() {
    let events = get_captured_thread_events();

    if events.is_empty() {
        eprintln!("WARNING: No Thread Start events captured. Skipping benchmark.");
        return;
    }

    // Create and prime the schema locator once before benchmarking
    let schema_locator = ferrisetw::schema_locator::SchemaLocator::default();
    if let Some(first_event) = events.first() {
        let record = first_event.as_event_record();
        let ferris_record = unsafe { &*(&raw const record).cast::<ferrisetw::EventRecord>() };
        let _ = schema_locator.event_schema(ferris_record); // Prime the cache
    }

    measure("thread_start", "ferrisetw", events.len(), || {
        for event in events {
            // Reconstruct EVENT_RECORD with valid pointers
            let record = event.as_event_record();

            // SAFETY: Cast to ferrisetw::EventRecord
            let ferris_record = unsafe { &*(&raw const record).cast::<ferrisetw::EventRecord>() };

            if let Ok(schema) = schema_locator.event_schema(ferris_record) {
                let parser = ferrisetw::parser::Parser::create(ferris_record, &schema);

                let parsed = ParsedThreadStart {
                    timestamp: ferris_record.raw_timestamp(),
                    process_id: parser.try_parse("ProcessID").unwrap(),
                    thread_id: parser.try_parse("ThreadID").unwrap(),
                    stack_base: parser.try_parse::<u64>("StackBase").unwrap() as usize,
                    stack_limit: parser.try_parse::<u64>("StackLimit").unwrap() as usize,
                    user_stack_base: parser.try_parse::<u64>("UserStackBase").unwrap() as usize,
                    user_stack_limit: parser.try_parse::<u64>("UserStackLimit").unwrap() as usize,
                    start_addr: parser.try_parse::<u64>("StartAddr").unwrap() as usize,
                    win32_start_addr: parser.try_parse::<u64>("Win32StartAddr").unwrap() as usize,
                    teb_base: parser.try_parse::<u64>("TebBase").unwrap() as usize,
                    sub_process_tag: parser.try_parse("SubProcessTag").unwrap(),
                };

                black_box(&parsed);
            }
        }
    });
}

fn bench_thread_start_get() {
    let events = get_captured_thread_events();

    if events.is_empty() {
        eprintln!("WARNING: No Thread Start events captured. Skipping benchmark.");
        return;
    }

    // Create and prime the schema cache once before benchmarking
    let mut parser_cache = etw::processing_context::ProcessingContext::new();
    if let Some(first_event) = events.first() {
        let record = first_event.as_event_record();
        let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
        let _ = parser_cache.parser(raw_event); // Prime the cache
    }

    measure("thread_start", "etw-rs-get", events.len(), || {
        for event in events {
            let record = event.as_event_record();
            // SAFETY: record is a valid EVENT_RECORD reconstructed from captured data.
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };

            if let Ok(mut parser) = parser_cache.parser(raw_event) {
                let parsed = ParsedThreadStart {
                    timestamp: record.EventHeader.TimeStamp,
                    process_id: parser.get("ProcessID").unwrap(),
                    thread_id: parser.get("ThreadID").unwrap(),
                    stack_base: parser.get("StackBase").unwrap(),
                    stack_limit: parser.get("StackLimit").unwrap(),
                    user_stack_base: parser.get("UserStackBase").unwrap(),
                    user_stack_limit: parser.get("UserStackLimit").unwrap(),
                    start_addr: parser.get("StartAddr").unwrap(),
                    win32_start_addr: parser.get("Win32StartAddr").unwrap(),
                    teb_base: parser.get("TebBase").unwrap(),
                    sub_process_tag: parser.get("SubProcessTag").unwrap(),
                };

                black_box(&parsed);
            }
        }
    });
}

/// Reads a fixed, non-consecutive subset of Thread Start properties.
///
/// Companion to `bench_thread_start_get`, which reads all ten properties in
/// order. The difference between the two arms is the whole point: it isolates
/// how much of `get()`'s cost depends on the caller walking the schema, and so
/// how much of a sequential-access optimisation survives a realistic consumer.
/// See [`ParsedThreadStartSubset`] for why these five properties.
fn bench_thread_start_get_subset() {
    let events = get_captured_thread_events();

    if events.is_empty() {
        eprintln!("WARNING: No Thread Start events captured. Skipping benchmark.");
        return;
    }

    // Create and prime the schema cache once before benchmarking
    let mut parser_cache = etw::processing_context::ProcessingContext::new();
    if let Some(first_event) = events.first() {
        let record = first_event.as_event_record();
        // SAFETY: record is a valid EVENT_RECORD reconstructed from captured data.
        let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
        let _ = parser_cache.parser(raw_event); // Prime the cache
    }

    measure("thread_start", "etw-rs-get-subset", events.len(), || {
        for event in events {
            let record = event.as_event_record();
            // SAFETY: record is a valid EVENT_RECORD reconstructed from captured data.
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };

            if let Ok(mut parser) = parser_cache.parser(raw_event) {
                let parsed = ParsedThreadStartSubset {
                    timestamp: record.EventHeader.TimeStamp,
                    process_id: parser.get("ProcessID").unwrap(),
                    thread_id: parser.get("ThreadID").unwrap(),
                    start_addr: parser.get("StartAddr").unwrap(),
                    win32_start_addr: parser.get("Win32StartAddr").unwrap(),
                    sub_process_tag: parser.get("SubProcessTag").unwrap(),
                };

                black_box(&parsed);
            }
        }
    });
}

fn bench_thread_start_static() {
    use ThreadStartAccessors as _;
    let events = get_captured_thread_events();

    if events.is_empty() {
        eprintln!("WARNING: No Thread Start events captured. Skipping benchmark.");
        return;
    }

    let mut parser_cache = etw::processing_context::ProcessingContext::new();
    if let Some(first_event) = events.first() {
        let record = first_event.as_event_record();
        let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
        let _ = parser_cache.parser(raw_event);
    }

    measure("thread_start", "etw-rs-static", events.len(), || {
        for event in events {
            let record = event.as_event_record();
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
            let mut parser = ThreadStartParser::new(raw_event, &mut parser_cache).unwrap();
            let parsed = ParsedThreadStart {
                timestamp: record.EventHeader.TimeStamp,
                process_id: parser.ProcessID().unwrap(),
                thread_id: parser.ThreadID().unwrap(),
                stack_base: parser.StackBase().unwrap(),
                stack_limit: parser.StackLimit().unwrap(),
                user_stack_base: parser.UserStackBase().unwrap(),
                user_stack_limit: parser.UserStackLimit().unwrap(),
                start_addr: parser.StartAddr().unwrap(),
                win32_start_addr: parser.Win32StartAddr().unwrap(),
                teb_base: parser.TebBase().unwrap(),
                sub_process_tag: parser.SubProcessTag().unwrap(),
            };

            black_box(&parsed);
        }
    });
}

// ============================================================================
// Registry CreateKey Benchmarks
// ============================================================================

fn bench_registry_create_key_dynamic() {
    let events = get_captured_registry_events();

    if events.is_empty() {
        eprintln!("WARNING: No Registry CreateKey events captured. Skipping benchmark.");
        return;
    }

    // Create and prime the schema cache once before benchmarking
    let mut parser_cache = etw::processing_context::ProcessingContext::new();
    if let Some(first_event) = events.first() {
        let record = first_event.as_event_record();
        let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
        let _ = parser_cache.parser(raw_event); // Prime the cache
    }

    measure(
        "registry_create_key",
        "etw-rs-get-hinted",
        events.len(),
        || {
            for event in events {
                // Reconstruct EVENT_RECORD with valid pointers
                let record = event.as_event_record();
                // SAFETY: record is a valid EVENT_RECORD reconstructed from captured data.
                let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };

                // Parse using TDH-based dynamic parser
                if let Ok(mut parser) = parser_cache.parser(raw_event) {
                    let parsed = ParsedRegistryCreateKey {
                        timestamp: record.EventHeader.TimeStamp,
                        base_object: parser.get_hinted("BaseObject", 0).unwrap(),
                        key_object: parser.get_hinted("KeyObject", 1).unwrap(),
                        status: parser.get_hinted("Status", 2).unwrap(),
                        disposition: parser.get_hinted("Disposition", 3).unwrap(),
                        base_name: parser.get_hinted("BaseName", 4).unwrap(),
                        relative_name: parser.get_hinted("RelativeName", 5).unwrap(),
                    };

                    black_box(&parsed);
                }
            }
        },
    );
}

fn bench_registry_create_key_ferrisetw() {
    let events = get_captured_registry_events();

    if events.is_empty() {
        eprintln!("WARNING: No Registry CreateKey events captured. Skipping benchmark.");
        return;
    }

    // Create and prime the schema locator once before benchmarking
    let schema_locator = ferrisetw::schema_locator::SchemaLocator::default();
    if let Some(first_event) = events.first() {
        let record = first_event.as_event_record();
        let ferris_record = unsafe { &*(&raw const record).cast::<ferrisetw::EventRecord>() };
        let _ = schema_locator.event_schema(ferris_record); // Prime the cache
    }

    measure("registry_create_key", "ferrisetw", events.len(), || {
        for event in events {
            // Reconstruct EVENT_RECORD with valid pointers
            let record = event.as_event_record();

            // SAFETY: Cast to ferrisetw::EventRecord
            let ferris_record = unsafe { &*(&raw const record).cast::<ferrisetw::EventRecord>() };

            if let Ok(schema) = schema_locator.event_schema(ferris_record) {
                let parser = ferrisetw::parser::Parser::create(ferris_record, &schema);

                let parsed = ParsedRegistryCreateKey {
                    timestamp: ferris_record.raw_timestamp(),
                    base_object: parser.try_parse::<u64>("BaseObject").unwrap() as usize,
                    key_object: parser.try_parse::<u64>("KeyObject").unwrap() as usize,
                    status: parser.try_parse("Status").unwrap(),
                    disposition: parser.try_parse("Disposition").unwrap(),
                    base_name: parser.try_parse::<String>("BaseName").unwrap(),
                    relative_name: parser.try_parse::<String>("RelativeName").unwrap(),
                };

                black_box(&parsed);
            }
        }
    });
}

fn bench_registry_create_key_get() {
    let events = get_captured_registry_events();

    if events.is_empty() {
        eprintln!("WARNING: No Registry CreateKey events captured. Skipping benchmark.");
        return;
    }

    // Create and prime the schema cache once before benchmarking
    let mut parser_cache = etw::processing_context::ProcessingContext::new();
    if let Some(first_event) = events.first() {
        let record = first_event.as_event_record();
        let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
        let _ = parser_cache.parser(raw_event); // Prime the cache
    }

    measure("registry_create_key", "etw-rs-get", events.len(), || {
        for event in events {
            let record = event.as_event_record();
            // SAFETY: record is a valid EVENT_RECORD reconstructed from captured data.
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };

            if let Ok(mut parser) = parser_cache.parser(raw_event) {
                let parsed = ParsedRegistryCreateKey {
                    timestamp: record.EventHeader.TimeStamp,
                    base_object: parser.get("BaseObject").unwrap(),
                    key_object: parser.get("KeyObject").unwrap(),
                    status: parser.get("Status").unwrap(),
                    disposition: parser.get("Disposition").unwrap(),
                    base_name: parser.get("BaseName").unwrap(),
                    relative_name: parser.get("RelativeName").unwrap(),
                };

                black_box(&parsed);
            }
        }
    });
}

fn bench_registry_create_key_static() {
    use RegistryCreateKeyAccessors as _;
    let events = get_captured_registry_events();

    if events.is_empty() {
        eprintln!("WARNING: No Registry CreateKey events captured. Skipping benchmark.");
        return;
    }

    let mut parser_cache = etw::processing_context::ProcessingContext::new();
    if let Some(first_event) = events.first() {
        let record = first_event.as_event_record();
        let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
        let _ = parser_cache.parser(raw_event);
    }

    measure("registry_create_key", "etw-rs-static", events.len(), || {
        for event in events {
            let record = event.as_event_record();
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
            let mut parser = RegistryCreateKeyParser::new(raw_event, &mut parser_cache).unwrap();
            let parsed = ParsedRegistryCreateKey {
                timestamp: record.EventHeader.TimeStamp,
                base_object: parser.BaseObject().unwrap(),
                key_object: parser.KeyObject().unwrap(),
                status: parser.Status().unwrap(),
                disposition: parser.Disposition().unwrap(),
                base_name: parser.BaseName().unwrap(),
                relative_name: parser.RelativeName().unwrap(),
            };

            black_box(&parsed);
        }
    });
}

// ============================================================================
// RPC Client Call Benchmarks
// ============================================================================

fn bench_rpc_client_call_dynamic() {
    let events = get_captured_rpc_events();

    if events.is_empty() {
        eprintln!("WARNING: No RPC Client Call events captured. Skipping benchmark.");
        return;
    }

    // Create and prime the schema cache once before benchmarking
    let mut parser_cache = etw::processing_context::ProcessingContext::new();
    if let Some(first_event) = events.first() {
        let record = first_event.as_event_record();
        let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
        let _ = parser_cache.parser(raw_event); // Prime the cache
    }

    measure("rpc_client_call", "etw-rs-get-hinted", events.len(), || {
        for event in events {
            // Reconstruct EVENT_RECORD with valid pointers
            let record = event.as_event_record();
            // SAFETY: record is a valid EVENT_RECORD reconstructed from captured data.
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };

            // Parse using TDH-based dynamic parser
            if let Ok(mut parser) = parser_cache.parser(raw_event) {
                let parsed = ParsedRpcClientCall {
                    timestamp: record.EventHeader.TimeStamp,
                    interface_uuid: guid_to_u128(parser.get_hinted("InterfaceUuid", 0).unwrap()),
                    proc_num: parser.get_hinted("ProcNum", 1).unwrap(),
                    protocol: parser.get_hinted("Protocol", 2).unwrap(),
                    network_address: parser.get_hinted("NetworkAddress", 3).unwrap(),
                    endpoint: parser.get_hinted("Endpoint", 4).unwrap(),
                    options: parser.get_hinted("Options", 5).unwrap(),
                    authentication_level: parser.get_hinted("AuthenticationLevel", 6).unwrap(),
                    authentication_service: parser.get_hinted("AuthenticationService", 7).unwrap(),
                    impersonation_level: parser.get_hinted("ImpersonationLevel", 8).unwrap(),
                };

                black_box(&parsed);
            }
        }
    });
}

fn bench_rpc_client_call_ferrisetw() {
    let events = get_captured_rpc_events();

    if events.is_empty() {
        eprintln!("WARNING: No RPC Client Call events captured. Skipping benchmark.");
        return;
    }

    // Create and prime the schema locator once before benchmarking
    let schema_locator = ferrisetw::schema_locator::SchemaLocator::default();
    if let Some(first_event) = events.first() {
        let record = first_event.as_event_record();
        let ferris_record = unsafe { &*(&raw const record).cast::<ferrisetw::EventRecord>() };
        let _ = schema_locator.event_schema(ferris_record); // Prime the cache
    }

    measure("rpc_client_call", "ferrisetw", events.len(), || {
        for event in events {
            // Reconstruct EVENT_RECORD with valid pointers
            let record = event.as_event_record();

            // SAFETY: Cast to ferrisetw::EventRecord
            let ferris_record = unsafe { &*(&raw const record).cast::<ferrisetw::EventRecord>() };

            if let Ok(schema) = schema_locator.event_schema(ferris_record) {
                let parser = ferrisetw::parser::Parser::create(ferris_record, &schema);

                let parsed = ParsedRpcClientCall {
                    timestamp: ferris_record.raw_timestamp(),
                    interface_uuid: guid_bytes_to_u128(
                        parser
                            .try_parse::<Vec<u8>>("InterfaceUuid")
                            .unwrap()
                            .try_into()
                            .unwrap(),
                    ),
                    proc_num: parser.try_parse("ProcNum").unwrap(),
                    protocol: parser.try_parse("Protocol").unwrap(),
                    network_address: parser.try_parse::<String>("NetworkAddress").unwrap(),
                    endpoint: parser.try_parse::<String>("Endpoint").unwrap(),
                    options: parser.try_parse::<String>("Options").unwrap(),
                    authentication_level: parser.try_parse("AuthenticationLevel").unwrap(),
                    authentication_service: parser.try_parse("AuthenticationService").unwrap(),
                    impersonation_level: parser.try_parse("ImpersonationLevel").unwrap(),
                };

                black_box(&parsed);
            }
        }
    });
}

fn bench_rpc_client_call_get() {
    let events = get_captured_rpc_events();

    if events.is_empty() {
        eprintln!("WARNING: No RPC Client Call events captured. Skipping benchmark.");
        return;
    }

    // Create and prime the schema cache once before benchmarking
    let mut parser_cache = etw::processing_context::ProcessingContext::new();
    if let Some(first_event) = events.first() {
        let record = first_event.as_event_record();
        let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
        let _ = parser_cache.parser(raw_event); // Prime the cache
    }

    measure("rpc_client_call", "etw-rs-get", events.len(), || {
        for event in events {
            let record = event.as_event_record();
            // SAFETY: record is a valid EVENT_RECORD reconstructed from captured data.
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };

            if let Ok(mut parser) = parser_cache.parser(raw_event) {
                let parsed = ParsedRpcClientCall {
                    timestamp: record.EventHeader.TimeStamp,
                    interface_uuid: guid_to_u128(parser.get("InterfaceUuid").unwrap()),
                    proc_num: parser.get("ProcNum").unwrap(),
                    protocol: parser.get("Protocol").unwrap(),
                    network_address: parser.get("NetworkAddress").unwrap(),
                    endpoint: parser.get("Endpoint").unwrap(),
                    options: parser.get("Options").unwrap(),
                    authentication_level: parser.get("AuthenticationLevel").unwrap(),
                    authentication_service: parser.get("AuthenticationService").unwrap(),
                    impersonation_level: parser.get("ImpersonationLevel").unwrap(),
                };

                black_box(&parsed);
            }
        }
    });
}

fn bench_rpc_client_call_static() {
    use RpcClientCallAccessors as _;
    let events = get_captured_rpc_events();

    if events.is_empty() {
        eprintln!("WARNING: No RPC Client Call events captured. Skipping benchmark.");
        return;
    }

    let mut parser_cache = etw::processing_context::ProcessingContext::new();
    if let Some(first_event) = events.first() {
        let record = first_event.as_event_record();
        let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
        let _ = parser_cache.parser(raw_event);
    }

    measure("rpc_client_call", "etw-rs-static", events.len(), || {
        for event in events {
            let record = event.as_event_record();
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
            let mut parser = RpcClientCallParser::new(raw_event, &mut parser_cache).unwrap();
            let parsed = ParsedRpcClientCall {
                timestamp: record.EventHeader.TimeStamp,
                interface_uuid: guid_to_u128(parser.InterfaceUuid().unwrap()),
                proc_num: parser.ProcNum().unwrap(),
                protocol: parser.Protocol().unwrap(),
                network_address: parser.NetworkAddress().unwrap(),
                endpoint: parser.Endpoint().unwrap(),
                options: parser.Options().unwrap(),
                authentication_level: parser.AuthenticationLevel().unwrap(),
                authentication_service: parser.AuthenticationService().unwrap(),
                impersonation_level: parser.ImpersonationLevel().unwrap(),
            };

            black_box(&parsed);
        }
    });
}

// ============================================================================
// Pre-flight Consistency Checks
// ============================================================================

/// Parse `events[0]` with all three Process Start implementations and assert every
/// field is identical. Panics with a descriptive message on the first mismatch.
fn preflight_process(events: &[CapturedEvent]) {
    if events.is_empty() {
        return;
    }
    let event = &events[0];

    // Static parser
    let mut sp = ProcessStartV4Parser::from_bytes(event.user_data());
    let s_pid: u32 = sp.ProcessID().unwrap();
    let s_seqnum: u64 = sp.ProcessSequenceNumber().unwrap();
    let s_create: u64 = sp.CreateTime().unwrap();
    let s_parent_pid: u32 = sp.ParentProcessID().unwrap();
    let s_parent_seqnum: u64 = sp.ParentProcessSequenceNumber().unwrap();
    let s_session: u32 = sp.SessionID().unwrap();
    let s_flags: u32 = sp.Flags().unwrap();
    let s_elevation: u32 = sp.ProcessTokenElevationType().unwrap();
    let s_elevated: u32 = sp.ProcessTokenIsElevated().unwrap();
    let s_sid = format!("{}", sp.MandatoryLabel().unwrap());
    let s_image = sp.ImageName().unwrap();
    let s_checksum: u32 = sp.ImageChecksum().unwrap();
    let s_tds: u32 = sp.TimeDateStamp().unwrap();
    let s_pkg_full = sp.PackageFullName().unwrap();
    let s_pkg_rel_app = sp.PackageRelativeAppId().unwrap();
    let s_mitigations: u32 = sp.SecurityMitigations().unwrap();

    // etw-rs get parser
    let record = event.as_event_record();
    let mut parser_cache = etw::processing_context::ProcessingContext::new();
    let raw = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
    let mut gp = parser_cache
        .parser(raw)
        .expect("preflight: get schema failed");
    let g_pid: u32 = gp.get("ProcessID").unwrap();
    let g_seqnum: u64 = gp.get("ProcessSequenceNumber").unwrap();
    let g_create: u64 = gp.get::<Timestamp>("CreateTime").unwrap().0 as u64;
    let g_parent_pid: u32 = gp.get("ParentProcessID").unwrap();
    let g_parent_seqnum: u64 = gp.get("ParentProcessSequenceNumber").unwrap();
    let g_session: u32 = gp.get("SessionID").unwrap();
    let g_flags: u32 = gp.get("Flags").unwrap();
    let g_elevation: u32 = gp.get("ProcessTokenElevationType").unwrap();
    let g_elevated: u32 = gp.get("ProcessTokenIsElevated").unwrap();
    let g_sid: String = gp
        .get::<Sid>("MandatoryLabel")
        .map(|s| s.to_string())
        .unwrap();
    let g_image: String = gp.get("ImageName").unwrap();
    let g_checksum: u32 = gp.get("ImageChecksum").unwrap();
    let g_tds: u32 = gp.get("TimeDateStamp").unwrap();
    let g_pkg_full: String = gp.get("PackageFullName").unwrap();
    let g_pkg_rel_app: String = gp.get("PackageRelativeAppId").unwrap();
    let g_mitigations: u32 = gp.get("SecurityMitigations").unwrap();

    // ferrisetw parser
    let schema_locator = ferrisetw::schema_locator::SchemaLocator::default();
    let ferris_record = unsafe { &*(&raw const record).cast::<ferrisetw::EventRecord>() };
    let schema = schema_locator
        .event_schema(ferris_record)
        .expect("preflight: ferrisetw schema");
    let fp = ferrisetw::parser::Parser::create(ferris_record, &schema);
    let f_pid: u32 = fp.try_parse("ProcessID").unwrap();
    let f_seqnum: u64 = fp.try_parse("ProcessSequenceNumber").unwrap();
    let f_create: u64 = fp.try_parse("CreateTime").unwrap();
    let f_parent_pid: u32 = fp.try_parse("ParentProcessID").unwrap();
    let f_parent_seqnum: u64 = fp.try_parse("ParentProcessSequenceNumber").unwrap();
    let f_session: u32 = fp.try_parse("SessionID").unwrap();
    let f_flags: u32 = fp.try_parse("Flags").unwrap();
    let f_elevation: u32 = fp.try_parse("ProcessTokenElevationType").unwrap();
    let f_elevated: u32 = fp.try_parse("ProcessTokenIsElevated").unwrap();
    let f_sid: String = fp.try_parse::<String>("MandatoryLabel").unwrap();
    let f_image: String = fp.try_parse::<String>("ImageName").unwrap();
    let f_checksum: u32 = fp.try_parse("ImageChecksum").unwrap();
    let f_tds: u32 = fp.try_parse("TimeDateStamp").unwrap();
    let f_pkg_full: String = fp.try_parse::<String>("PackageFullName").unwrap();
    let f_pkg_rel_app: String = fp.try_parse::<String>("PackageRelativeAppId").unwrap();
    let f_mitigations: u32 = fp.try_parse("SecurityMitigations").unwrap();

    // Assert static == get
    assert_eq!(s_pid, g_pid, "process_id: static != get");
    assert_eq!(s_seqnum, g_seqnum, "process_sequence_number: static != get");
    assert_eq!(s_create, g_create, "create_time: static != get");
    assert_eq!(
        s_parent_pid, g_parent_pid,
        "parent_process_id: static != get"
    );
    assert_eq!(
        s_parent_seqnum, g_parent_seqnum,
        "parent_process_sequence_number: static != get"
    );
    assert_eq!(s_session, g_session, "session_id: static != get");
    assert_eq!(s_flags, g_flags, "flags: static != get");
    assert_eq!(
        s_elevation, g_elevation,
        "process_token_elevation_type: static != get"
    );
    assert_eq!(
        s_elevated, g_elevated,
        "process_token_is_elevated: static != get"
    );
    assert_eq!(s_sid, g_sid, "mandatory_label: static != get");
    assert_eq!(s_image, g_image, "image_name: static != get");
    assert_eq!(s_checksum, g_checksum, "image_checksum: static != get");
    assert_eq!(s_tds, g_tds, "time_date_stamp: static != get");
    assert_eq!(s_pkg_full, g_pkg_full, "package_full_name: static != get");
    assert_eq!(
        s_pkg_rel_app, g_pkg_rel_app,
        "package_relative_app_id: static != get"
    );
    assert_eq!(
        s_mitigations, g_mitigations,
        "security_mitigations: static != get"
    );

    // Assert static == ferrisetw
    assert_eq!(s_pid, f_pid, "process_id: static != ferrisetw");
    assert_eq!(
        s_seqnum, f_seqnum,
        "process_sequence_number: static != ferrisetw"
    );
    assert_eq!(s_create, f_create, "create_time: static != ferrisetw");
    assert_eq!(
        s_parent_pid, f_parent_pid,
        "parent_process_id: static != ferrisetw"
    );
    assert_eq!(
        s_parent_seqnum, f_parent_seqnum,
        "parent_process_sequence_number: static != ferrisetw"
    );
    assert_eq!(s_session, f_session, "session_id: static != ferrisetw");
    assert_eq!(s_flags, f_flags, "flags: static != ferrisetw");
    assert_eq!(
        s_elevation, f_elevation,
        "process_token_elevation_type: static != ferrisetw"
    );
    assert_eq!(
        s_elevated, f_elevated,
        "process_token_is_elevated: static != ferrisetw"
    );
    assert_eq!(s_sid, f_sid, "mandatory_label: static != ferrisetw");
    assert_eq!(s_image, f_image, "image_name: static != ferrisetw");
    assert_eq!(
        s_checksum, f_checksum,
        "image_checksum: static != ferrisetw"
    );
    assert_eq!(s_tds, f_tds, "time_date_stamp: static != ferrisetw");
    assert_eq!(
        s_pkg_full, f_pkg_full,
        "package_full_name: static != ferrisetw"
    );
    assert_eq!(
        s_pkg_rel_app, f_pkg_rel_app,
        "package_relative_app_id: static != ferrisetw"
    );
    assert_eq!(
        s_mitigations, f_mitigations,
        "security_mitigations: static != ferrisetw"
    );

    eprintln!("Pre-flight [Process Start]: all parsers agree [OK]");
}

fn preflight_thread(events: &[CapturedEvent]) {
    if events.is_empty() {
        return;
    }
    let event = &events[0];

    // Static parser — all fields are integers
    let sp = ThreadStartV1Parser::from_bytes(event.user_data());
    let s_pid: u32 = sp.ProcessID().unwrap();
    let s_tid: u32 = sp.ThreadID().unwrap();
    let s_stack_base: usize = sp.StackBase().unwrap();
    let s_stack_limit: usize = sp.StackLimit().unwrap();
    let s_user_stack_base: usize = sp.UserStackBase().unwrap();
    let s_user_stack_limit: usize = sp.UserStackLimit().unwrap();
    let s_start_addr: usize = sp.StartAddr().unwrap();
    let s_win32_start_addr: usize = sp.Win32StartAddr().unwrap();
    let s_teb_base: usize = sp.TebBase().unwrap();
    let s_sub_process_tag: u32 = sp.SubProcessTag().unwrap();

    // etw-rs get parser
    let record = event.as_event_record();
    let mut parser_cache = etw::processing_context::ProcessingContext::new();
    let raw = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
    let mut gp = parser_cache
        .parser(raw)
        .expect("preflight: get schema failed");
    let g_pid: u32 = gp.get("ProcessID").unwrap();
    let g_tid: u32 = gp.get("ThreadID").unwrap();
    let g_stack_base: usize = gp.get("StackBase").unwrap();
    let g_stack_limit: usize = gp.get("StackLimit").unwrap();
    let g_user_stack_base: usize = gp.get("UserStackBase").unwrap();
    let g_user_stack_limit: usize = gp.get("UserStackLimit").unwrap();
    let g_start_addr: usize = gp.get("StartAddr").unwrap();
    let g_win32_start_addr: usize = gp.get("Win32StartAddr").unwrap();
    let g_teb_base: usize = gp.get("TebBase").unwrap();
    let g_sub_process_tag: u32 = gp.get("SubProcessTag").unwrap();

    // ferrisetw parser
    let schema_locator = ferrisetw::schema_locator::SchemaLocator::default();
    let ferris_record = unsafe { &*(&raw const record).cast::<ferrisetw::EventRecord>() };
    let schema = schema_locator
        .event_schema(ferris_record)
        .expect("preflight: ferrisetw schema");
    let fp = ferrisetw::parser::Parser::create(ferris_record, &schema);
    let f_pid: u32 = fp.try_parse("ProcessID").unwrap();
    let f_tid: u32 = fp.try_parse("ThreadID").unwrap();
    let f_stack_base = fp.try_parse::<u64>("StackBase").unwrap() as usize;
    let f_stack_limit = fp.try_parse::<u64>("StackLimit").unwrap() as usize;
    let f_user_stack_base = fp.try_parse::<u64>("UserStackBase").unwrap() as usize;
    let f_user_stack_limit = fp.try_parse::<u64>("UserStackLimit").unwrap() as usize;
    let f_start_addr = fp.try_parse::<u64>("StartAddr").unwrap() as usize;
    let f_win32_start_addr = fp.try_parse::<u64>("Win32StartAddr").unwrap() as usize;
    let f_teb_base = fp.try_parse::<u64>("TebBase").unwrap() as usize;
    let f_sub_process_tag: u32 = fp.try_parse("SubProcessTag").unwrap();

    assert_eq!(s_pid, g_pid, "process_id: static != get");
    assert_eq!(s_tid, g_tid, "thread_id: static != get");
    assert_eq!(s_stack_base, g_stack_base, "stack_base: static != get");
    assert_eq!(s_stack_limit, g_stack_limit, "stack_limit: static != get");
    assert_eq!(
        s_user_stack_base, g_user_stack_base,
        "user_stack_base: static != get"
    );
    assert_eq!(
        s_user_stack_limit, g_user_stack_limit,
        "user_stack_limit: static != get"
    );
    assert_eq!(s_start_addr, g_start_addr, "start_addr: static != get");
    assert_eq!(
        s_win32_start_addr, g_win32_start_addr,
        "win32_start_addr: static != get"
    );
    assert_eq!(s_teb_base, g_teb_base, "teb_base: static != get");
    assert_eq!(
        s_sub_process_tag, g_sub_process_tag,
        "sub_process_tag: static != get"
    );

    assert_eq!(s_pid, f_pid, "process_id: static != ferrisetw");
    assert_eq!(s_tid, f_tid, "thread_id: static != ferrisetw");
    assert_eq!(
        s_stack_base, f_stack_base,
        "stack_base: static != ferrisetw"
    );
    assert_eq!(
        s_stack_limit, f_stack_limit,
        "stack_limit: static != ferrisetw"
    );
    assert_eq!(
        s_user_stack_base, f_user_stack_base,
        "user_stack_base: static != ferrisetw"
    );
    assert_eq!(
        s_user_stack_limit, f_user_stack_limit,
        "user_stack_limit: static != ferrisetw"
    );
    assert_eq!(
        s_start_addr, f_start_addr,
        "start_addr: static != ferrisetw"
    );
    assert_eq!(
        s_win32_start_addr, f_win32_start_addr,
        "win32_start_addr: static != ferrisetw"
    );
    assert_eq!(s_teb_base, f_teb_base, "teb_base: static != ferrisetw");
    assert_eq!(
        s_sub_process_tag, f_sub_process_tag,
        "sub_process_tag: static != ferrisetw"
    );

    eprintln!("Pre-flight [Thread Start]: all parsers agree [OK]");
}

fn preflight_file(events: &[CapturedEvent]) {
    if events.is_empty() {
        return;
    }
    let event = &events[0];

    // Static parser
    let mut sp = FileCreateV1Parser::from_bytes(event.user_data());
    let s_irp: usize = sp.Irp().unwrap();
    let s_file_object: usize = sp.FileObject().unwrap();
    let s_tid: u32 = sp.IssuingThreadId().unwrap();
    let s_create_options: u32 = sp.CreateOptions().unwrap();
    let s_create_attributes: u32 = sp.CreateAttributes().unwrap();
    let s_share_access: u32 = sp.ShareAccess().unwrap();
    let s_file_name = sp.FileName().unwrap();

    // etw-rs get parser
    let record = event.as_event_record();
    let mut parser_cache = etw::processing_context::ProcessingContext::new();
    let raw = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
    let mut gp = parser_cache
        .parser(raw)
        .expect("preflight: get schema failed");
    let g_irp: usize = gp.get("Irp").unwrap();
    let g_file_object: usize = gp.get("FileObject").unwrap();
    let g_tid: u32 = gp.get("IssuingThreadId").unwrap();
    let g_create_options: u32 = gp.get("CreateOptions").unwrap();
    let g_create_attributes: u32 = gp.get("CreateAttributes").unwrap();
    let g_share_access: u32 = gp.get("ShareAccess").unwrap();
    let g_file_name: String = gp.get("FileName").unwrap();

    // ferrisetw parser
    let schema_locator = ferrisetw::schema_locator::SchemaLocator::default();
    let ferris_record = unsafe { &*(&raw const record).cast::<ferrisetw::EventRecord>() };
    let schema = schema_locator
        .event_schema(ferris_record)
        .expect("preflight: ferrisetw schema");
    let fp = ferrisetw::parser::Parser::create(ferris_record, &schema);
    let f_irp = fp.try_parse::<u64>("Irp").unwrap() as usize;
    let f_file_object = fp.try_parse::<u64>("FileObject").unwrap() as usize;
    let f_tid: u32 = fp.try_parse("IssuingThreadId").unwrap();
    let f_create_options: u32 = fp.try_parse("CreateOptions").unwrap();
    let f_create_attributes: u32 = fp.try_parse("CreateAttributes").unwrap();
    let f_share_access: u32 = fp.try_parse("ShareAccess").unwrap();
    let f_file_name: String = fp.try_parse::<String>("FileName").unwrap();

    assert_eq!(s_irp, g_irp, "irp: static != get");
    assert_eq!(s_file_object, g_file_object, "file_object: static != get");
    assert_eq!(s_tid, g_tid, "issuing_thread_id: static != get");
    assert_eq!(
        s_create_options, g_create_options,
        "create_options: static != get"
    );
    assert_eq!(
        s_create_attributes, g_create_attributes,
        "create_attributes: static != get"
    );
    assert_eq!(
        s_share_access, g_share_access,
        "share_access: static != get"
    );
    assert_eq!(s_file_name, g_file_name, "file_name: static != get");

    assert_eq!(s_irp, f_irp, "irp: static != ferrisetw");
    assert_eq!(
        s_file_object, f_file_object,
        "file_object: static != ferrisetw"
    );
    assert_eq!(s_tid, f_tid, "issuing_thread_id: static != ferrisetw");
    assert_eq!(
        s_create_options, f_create_options,
        "create_options: static != ferrisetw"
    );
    assert_eq!(
        s_create_attributes, f_create_attributes,
        "create_attributes: static != ferrisetw"
    );
    assert_eq!(
        s_share_access, f_share_access,
        "share_access: static != ferrisetw"
    );
    assert_eq!(s_file_name, f_file_name, "file_name: static != ferrisetw");

    eprintln!("Pre-flight [File Create]: all parsers agree [OK]");
}

fn preflight_registry(events: &[CapturedEvent]) {
    if events.is_empty() {
        return;
    }
    let event = &events[0];

    // Static parser
    let mut sp = RegistryCreateKeyV0Parser::from_bytes(event.user_data());
    let s_base_object: usize = sp.BaseObject().unwrap();
    let s_key_object: usize = sp.KeyObject().unwrap();
    let s_status: u32 = sp.Status().unwrap();
    let s_disposition: u32 = sp.Disposition().unwrap();
    let s_base_name = sp.BaseName().unwrap();
    let s_relative_name = sp.RelativeName().unwrap();

    // etw-rs get parser
    let record = event.as_event_record();
    let mut parser_cache = etw::processing_context::ProcessingContext::new();
    let raw = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
    let mut gp = parser_cache
        .parser(raw)
        .expect("preflight: get schema failed");
    let g_base_object: usize = gp.get("BaseObject").unwrap();
    let g_key_object: usize = gp.get("KeyObject").unwrap();
    let g_status: u32 = gp.get("Status").unwrap();
    let g_disposition: u32 = gp.get("Disposition").unwrap();
    let g_base_name: String = gp.get("BaseName").unwrap();
    let g_relative_name: String = gp.get("RelativeName").unwrap();

    // ferrisetw parser
    let schema_locator = ferrisetw::schema_locator::SchemaLocator::default();
    let ferris_record = unsafe { &*(&raw const record).cast::<ferrisetw::EventRecord>() };
    let schema = schema_locator
        .event_schema(ferris_record)
        .expect("preflight: ferrisetw schema");
    let fp = ferrisetw::parser::Parser::create(ferris_record, &schema);
    let f_base_object = fp.try_parse::<u64>("BaseObject").unwrap() as usize;
    let f_key_object = fp.try_parse::<u64>("KeyObject").unwrap() as usize;
    let f_status: u32 = fp.try_parse("Status").unwrap();
    let f_disposition: u32 = fp.try_parse("Disposition").unwrap();
    let f_base_name: String = fp.try_parse::<String>("BaseName").unwrap();
    let f_relative_name: String = fp.try_parse::<String>("RelativeName").unwrap();

    assert_eq!(s_base_object, g_base_object, "base_object: static != get");
    assert_eq!(s_key_object, g_key_object, "key_object: static != get");
    assert_eq!(s_status, g_status, "status: static != get");
    assert_eq!(s_disposition, g_disposition, "disposition: static != get");
    assert_eq!(s_base_name, g_base_name, "base_name: static != get");
    assert_eq!(
        s_relative_name, g_relative_name,
        "relative_name: static != get"
    );

    assert_eq!(
        s_base_object, f_base_object,
        "base_object: static != ferrisetw"
    );
    assert_eq!(
        s_key_object, f_key_object,
        "key_object: static != ferrisetw"
    );
    assert_eq!(s_status, f_status, "status: static != ferrisetw");
    assert_eq!(
        s_disposition, f_disposition,
        "disposition: static != ferrisetw"
    );
    assert_eq!(s_base_name, f_base_name, "base_name: static != ferrisetw");
    assert_eq!(
        s_relative_name, f_relative_name,
        "relative_name: static != ferrisetw"
    );

    eprintln!("Pre-flight [Registry CreateKey]: all parsers agree [OK]");
}

fn preflight_rpc(events: &[CapturedEvent]) {
    if events.is_empty() {
        return;
    }
    let event = &events[0];

    // Static parser
    let mut sp = RpcClientCallV1Parser::from_bytes(event.user_data());
    let s_uuid = guid_to_u128(sp.InterfaceUuid().unwrap());
    let s_proc_num: u32 = sp.ProcNum().unwrap();
    let s_protocol: u32 = sp.Protocol().unwrap();
    let s_network_address = sp.NetworkAddress().unwrap();
    let s_endpoint = sp.Endpoint().unwrap();
    let s_options = sp.Options().unwrap();
    let s_auth_level: u32 = sp.AuthenticationLevel().unwrap();
    let s_auth_service: u32 = sp.AuthenticationService().unwrap();
    let s_impersonation: u32 = sp.ImpersonationLevel().unwrap();

    // etw-rs get parser
    let record = event.as_event_record();
    let mut parser_cache = etw::processing_context::ProcessingContext::new();
    let raw = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
    let mut gp = parser_cache
        .parser(raw)
        .expect("preflight: get schema failed");
    let g_uuid = guid_to_u128(gp.get("InterfaceUuid").unwrap());
    let g_proc_num: u32 = gp.get("ProcNum").unwrap();
    let g_protocol: u32 = gp.get("Protocol").unwrap();
    let g_network_address: String = gp.get("NetworkAddress").unwrap();
    let g_endpoint: String = gp.get("Endpoint").unwrap();
    let g_options: String = gp.get("Options").unwrap();
    let g_auth_level: u32 = gp.get("AuthenticationLevel").unwrap();
    let g_auth_service: u32 = gp.get("AuthenticationService").unwrap();
    let g_impersonation: u32 = gp.get("ImpersonationLevel").unwrap();

    // ferrisetw parser
    let schema_locator = ferrisetw::schema_locator::SchemaLocator::default();
    let ferris_record = unsafe { &*(&raw const record).cast::<ferrisetw::EventRecord>() };
    let schema = schema_locator
        .event_schema(ferris_record)
        .expect("preflight: ferrisetw schema");
    let fp = ferrisetw::parser::Parser::create(ferris_record, &schema);
    let f_uuid = guid_bytes_to_u128(
        fp.try_parse::<Vec<u8>>("InterfaceUuid")
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let f_proc_num: u32 = fp.try_parse("ProcNum").unwrap();
    let f_protocol: u32 = fp.try_parse("Protocol").unwrap();
    let f_network_address: String = fp.try_parse::<String>("NetworkAddress").unwrap();
    let f_endpoint: String = fp.try_parse::<String>("Endpoint").unwrap();
    let f_options: String = fp.try_parse::<String>("Options").unwrap();
    let f_auth_level: u32 = fp.try_parse("AuthenticationLevel").unwrap();
    let f_auth_service: u32 = fp.try_parse("AuthenticationService").unwrap();
    let f_impersonation: u32 = fp.try_parse("ImpersonationLevel").unwrap();

    // Assert static == get
    assert_eq!(s_uuid, g_uuid, "interface_uuid: static != get (u128)");
    assert_eq!(s_proc_num, g_proc_num, "proc_num: static != get");
    assert_eq!(s_protocol, g_protocol, "protocol: static != get");
    assert_eq!(
        s_network_address, g_network_address,
        "network_address: static != get"
    );
    assert_eq!(s_endpoint, g_endpoint, "endpoint: static != get");
    assert_eq!(s_options, g_options, "options: static != get");
    assert_eq!(
        s_auth_level, g_auth_level,
        "authentication_level: static != get"
    );
    assert_eq!(
        s_auth_service, g_auth_service,
        "authentication_service: static != get"
    );
    assert_eq!(
        s_impersonation, g_impersonation,
        "impersonation_level: static != get"
    );

    // Assert static == ferrisetw (both now u128 via consistent field decomposition)
    assert_eq!(s_uuid, f_uuid, "interface_uuid: static != ferrisetw (u128)");
    assert_eq!(s_proc_num, f_proc_num, "proc_num: static != ferrisetw");
    assert_eq!(s_protocol, f_protocol, "protocol: static != ferrisetw");
    assert_eq!(
        s_network_address, f_network_address,
        "network_address: static != ferrisetw"
    );
    assert_eq!(s_endpoint, f_endpoint, "endpoint: static != ferrisetw");
    assert_eq!(s_options, f_options, "options: static != ferrisetw");
    assert_eq!(
        s_auth_level, f_auth_level,
        "authentication_level: static != ferrisetw"
    );
    assert_eq!(
        s_auth_service, f_auth_service,
        "authentication_service: static != ferrisetw"
    );
    assert_eq!(
        s_impersonation, f_impersonation,
        "impersonation_level: static != ferrisetw"
    );

    eprintln!("Pre-flight [RPC Client Call]: all parsers agree [OK]");
}

/// Run all pre-flight consistency checks before any timed loop starts.
fn run_preflight_checks() {
    preflight_process(get_captured_process_events());
    preflight_thread(get_captured_thread_events());
    preflight_file(get_captured_file_events());
    preflight_registry(get_captured_registry_events());
    preflight_rpc(get_captured_rpc_events());
}

// ═══════════════════════════════════════════════════════════════════════════════
// Mixed-stream benchmark
// ═══════════════════════════════════════════════════════════════════════════════

/// Provider GUIDs, repeated here because dispatch is part of the workload.
const MIXED_PROCESS_PROVIDER: Guid = Guid::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716);
const MIXED_FILE_PROVIDER: Guid = Guid::from_u128(0xedd08927_9cc4_4e65_b970_c2560fb5c289);
const MIXED_REGISTRY_PROVIDER: Guid = Guid::from_u128(0x70eb4f03_c1de_4f73_a051_33d13d5413bd);
const MIXED_RPC_PROVIDER: Guid = Guid::from_u128(0x6ad52b32_d609_4be9_ae07_ce8dae937e39);
const MIXED_NETWORK_PROVIDER: Guid = Guid::from_u128(0x7dd42a49_5329_4832_8dfd_43d979153a88);

/// All six captured event types, interleaved one-per-type in rotation.
///
/// Every other benchmark here replays a single event type in a tight loop, which
/// keeps that type's schema, name table, `ParserCache` and property locations
/// pinned in L1. Real consumers see a stream of *different* events, so those
/// per-schema structures are cold on almost every event. A change that trades
/// instruction count for cache locality therefore measures as a loss on the
/// single-type benches and a win here — so a verdict from those benches alone is
/// only ever a verdict about the warm case.
///
/// Round-robin is deliberately not a realistic *ratio*: a real trace is mostly
/// whichever provider is chattiest. It is a deliberate worst case for schema
/// switching, and therefore an upper bound on interleaving cost — a locality
/// change that cannot pay for itself here will not pay in a real mix. Use this
/// to settle direction, and a captured mixed trace to size the effect.
///
/// Sorting the existing captures by timestamp would not produce an interleave:
/// they were taken sequentially, one provider at a time, so their timestamps
/// form six contiguous blocks.
///
/// Takes `min(len)` from each list so every type is equally represented, and
/// uses each captured event at most once — replaying a short list would warm
/// exactly the caches this benchmark exists to leave cold.
fn get_mixed_stream() -> &'static Vec<&'static CapturedEvent> {
    static MIXED: OnceLock<Vec<&'static CapturedEvent>> = OnceLock::new();

    MIXED.get_or_init(|| {
        let lists: [&'static Vec<CapturedEvent>; 6] = [
            get_captured_process_events(),
            get_captured_thread_events(),
            get_captured_file_events(),
            get_captured_registry_events(),
            get_captured_rpc_events(),
            // The IPv6 network events are the only captured type whose fixed
            // prefix is cut short by a variable-length property, so they are the
            // only ones that exercise per-event property sizing with a cold
            // schema. Without them the mixed row cannot see that cost at all.
            get_captured_network_ipv6_events(),
        ];
        let per_type = lists.iter().map(|l| l.len()).min().unwrap_or(0);
        let mut out = Vec::with_capacity(per_type * lists.len());
        for i in 0..per_type {
            for list in lists {
                out.push(&list[i]);
            }
        }
        eprintln!(
            "Mixed stream: {} events ({} of each of {} types)",
            out.len(),
            per_type,
            lists.len()
        );
        out
    })
}

fn bench_mixed_stream_get() {
    let events = get_mixed_stream();

    if events.is_empty() {
        eprintln!("WARNING: No mixed-stream events captured. Skipping benchmark.");
        return;
    }

    // Prime every schema first, as the single-type benches do, so this measures
    // steady-state interleaving rather than first-sight schema construction.
    let mut parser_cache = etw::processing_context::ProcessingContext::new();
    for event in events.iter().take(6) {
        let record = event.as_event_record();
        // SAFETY: record is a valid EVENT_RECORD reconstructed from captured data.
        let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
        let _ = parser_cache.parser(raw_event);
    }

    measure("mixed_stream", "etw-rs-get", events.len(), || {
        for event in events {
            let record = event.as_event_record();
            // SAFETY: record is a valid EVENT_RECORD reconstructed from captured data.
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };

            // Dispatch on the event's own identity rather than a stored tag:
            // a real consumer has only the record, so this lookup is part of
            // the cost being measured.
            let key = (raw_event.provider_guid(), raw_event.id());
            let timestamp = record.EventHeader.TimeStamp;

            let Ok(mut parser) = parser_cache.parser(raw_event) else {
                continue;
            };

            match key {
                (MIXED_PROCESS_PROVIDER, 1) => {
                    let parsed = ParsedProcessStart {
                        timestamp,
                        process_id: parser.get("ProcessID").unwrap(),
                        process_sequence_number: parser.get("ProcessSequenceNumber").unwrap(),
                        create_time: parser.get::<Timestamp>("CreateTime").unwrap().0 as u64,
                        parent_process_id: parser.get("ParentProcessID").unwrap(),
                        parent_process_sequence_number: parser
                            .get("ParentProcessSequenceNumber")
                            .unwrap(),
                        session_id: parser.get("SessionID").unwrap(),
                        flags: parser.get("Flags").unwrap(),
                        process_token_elevation_type: parser
                            .get("ProcessTokenElevationType")
                            .unwrap(),
                        process_token_is_elevated: parser.get("ProcessTokenIsElevated").unwrap(),
                        mandatory_label: parser
                            .get::<Sid>("MandatoryLabel")
                            .map(|s| s.to_string())
                            .unwrap(),
                        image_name: parser.get("ImageName").unwrap(),
                        image_checksum: parser.get("ImageChecksum").unwrap(),
                        time_date_stamp: parser.get("TimeDateStamp").unwrap(),
                        package_full_name: parser.get("PackageFullName").unwrap(),
                        package_relative_app_id: parser.get("PackageRelativeAppId").unwrap(),
                        security_mitigations: parser.get("SecurityMitigations").unwrap(),
                    };
                    black_box(&parsed);
                }
                (MIXED_PROCESS_PROVIDER, 3) => {
                    let parsed = ParsedThreadStart {
                        timestamp,
                        process_id: parser.get("ProcessID").unwrap(),
                        thread_id: parser.get("ThreadID").unwrap(),
                        stack_base: parser.get("StackBase").unwrap(),
                        stack_limit: parser.get("StackLimit").unwrap(),
                        user_stack_base: parser.get("UserStackBase").unwrap(),
                        user_stack_limit: parser.get("UserStackLimit").unwrap(),
                        start_addr: parser.get("StartAddr").unwrap(),
                        win32_start_addr: parser.get("Win32StartAddr").unwrap(),
                        teb_base: parser.get("TebBase").unwrap(),
                        sub_process_tag: parser.get("SubProcessTag").unwrap(),
                    };
                    black_box(&parsed);
                }
                (MIXED_FILE_PROVIDER, 12) => {
                    let parsed = ParsedFileCreate {
                        timestamp,
                        irp: parser.get("Irp").unwrap(),
                        file_object: parser.get("FileObject").unwrap(),
                        issuing_thread_id: parser.get("IssuingThreadId").unwrap(),
                        create_options: parser.get("CreateOptions").unwrap(),
                        create_attributes: parser.get("CreateAttributes").unwrap(),
                        share_access: parser.get("ShareAccess").unwrap(),
                        file_name: parser.get("FileName").unwrap(),
                    };
                    black_box(&parsed);
                }
                (MIXED_REGISTRY_PROVIDER, 1) => {
                    let parsed = ParsedRegistryCreateKey {
                        timestamp,
                        base_object: parser.get("BaseObject").unwrap(),
                        key_object: parser.get("KeyObject").unwrap(),
                        status: parser.get("Status").unwrap(),
                        disposition: parser.get("Disposition").unwrap(),
                        base_name: parser.get("BaseName").unwrap(),
                        relative_name: parser.get("RelativeName").unwrap(),
                    };
                    black_box(&parsed);
                }
                (MIXED_NETWORK_PROVIDER, 26) => {
                    let parsed = ParsedTcpIpSendV6 {
                        timestamp,
                        pid: parser.get("PID").unwrap(),
                        size: parser.get("size").unwrap(),
                        daddr: parser.get("daddr").unwrap(),
                        saddr: parser.get("saddr").unwrap(),
                        dport: parser.get("dport").unwrap(),
                        sport: parser.get("sport").unwrap(),
                        startime: parser.get("startime").unwrap(),
                        endtime: parser.get("endtime").unwrap(),
                        seqnum: parser.get("seqnum").unwrap(),
                        connid: parser.get("connid").unwrap(),
                    };
                    black_box(&parsed);
                }
                (MIXED_RPC_PROVIDER, 5) => {
                    let parsed = ParsedRpcClientCall {
                        timestamp,
                        interface_uuid: guid_to_u128(parser.get("InterfaceUuid").unwrap()),
                        proc_num: parser.get("ProcNum").unwrap(),
                        protocol: parser.get("Protocol").unwrap(),
                        network_address: parser.get("NetworkAddress").unwrap(),
                        endpoint: parser.get("Endpoint").unwrap(),
                        options: parser.get("Options").unwrap(),
                        authentication_level: parser.get("AuthenticationLevel").unwrap(),
                        authentication_service: parser.get("AuthenticationService").unwrap(),
                        impersonation_level: parser.get("ImpersonationLevel").unwrap(),
                    };
                    black_box(&parsed);
                }
                _ => {}
            }
        }
    });
}

/// Run every arm for this event type, in the order the table lists them.
fn mixed_benches() {
    bench_mixed_stream_get();
}

// ═══════════════════════════════════════════════════════════════════════════════
// IPv6 network benchmark
// ═══════════════════════════════════════════════════════════════════════════════

/// Parsed TcpIp DataSent (IPv6) data.
#[derive(Debug)]
#[expect(dead_code, reason = "fields exist to make the parse observable")]
struct ParsedTcpIpSendV6 {
    timestamp: i64,
    pid: u32,
    size: u32,
    daddr: std::net::Ipv6Addr,
    saddr: std::net::Ipv6Addr,
    dport: u16,
    sport: u16,
    startime: u32,
    endtime: u32,
    seqnum: u32,
    connid: u32,
}

/// Capture TcpIp DataSent (IPv6) events ONCE for reuse across benchmarks.
///
/// The IPv4 variants of these events declare `daddr`/`saddr` as `win:UInt32`,
/// which is fixed-size; the IPv6 variants declare them `win:Binary` with an
/// IPv6 out-type. `Binary` has no fixed size, so `compute_fixed_prefix_info`
/// stops at the first of them — which puts `daddr`, `saddr` and every field
/// after them (`dport`, `sport`, `startime`, `endtime`, `seqnum`, `connid`) on
/// the per-event location path, even though six of those are plain integers.
///
/// This capture exists to measure that: eight of ten fields sized per event
/// solely because two 16-byte addresses are typed as variable-length.
fn get_captured_network_ipv6_events() -> &'static Vec<CapturedEvent> {
    static CAPTURED: OnceLock<Vec<CapturedEvent>> = OnceLock::new();

    CAPTURED.get_or_init(|| {
        load_or_capture_events(
            "captured_network_ipv6_events.bin",
            "NetworkIpv6Capture",
            "TcpIp DataSent IPv6",
            network::GUID,
            network::keyword::IPV6,
            network::event::TCPIP_DATA_SENT_IPV6,
            None,
        )
    })
}

fn bench_network_ipv6_get() {
    let events = get_captured_network_ipv6_events();

    if events.is_empty() {
        eprintln!("WARNING: No IPv6 network events captured. Skipping benchmark.");
        return;
    }

    let mut parser_cache = etw::processing_context::ProcessingContext::new();
    if let Some(first_event) = events.first() {
        let record = first_event.as_event_record();
        // SAFETY: record is a valid EVENT_RECORD reconstructed from captured data.
        let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
        let _ = parser_cache.parser(raw_event); // Prime the cache
    }

    // Dump the first few parses so a change to how IPv6 properties are sized can
    // be diffed against the previous build: moving a property into the fixed
    // prefix must not move where it is read from.
    if std::env::var_os("ETW_BENCH_DUMP_IPV6").is_some() {
        // What does TDH actually report for each property? If daddr/saddr carry a
        // declared length, the fixed prefix already covers them and treating
        // Binary+IPv6 as fixed changes nothing.
        if let Some(first) = events.first() {
            let record = first.as_event_record();
            // SAFETY: record is a valid EVENT_RECORD reconstructed from captured data.
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
            if let Ok(parser) = parser_cache.parser(raw_event) {
                let schema = parser.schema();
                for i in 0..10u32 {
                    if let Some(prop) = schema.property(i) {
                        eprintln!(
                            "SCHEMA [{i}] {:<10} in_type={:<3} out_type={:<3} length={}",
                            schema.property_name(i).unwrap_or("?"),
                            prop.in_type(),
                            prop.out_type(),
                            prop.length()
                        );
                    }
                }
            }
        }
        for event in events.iter().take(3) {
            let record = event.as_event_record();
            // SAFETY: record is a valid EVENT_RECORD reconstructed from captured data.
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
            if let Ok(mut parser) = parser_cache.parser(raw_event) {
                eprintln!(
                    "DUMP pid={:?} size={:?} daddr={:?} saddr={:?} dport={:?} sport={:?}                      startime={:?} endtime={:?} seqnum={:?} connid={:?}",
                    parser.get::<u32>("PID"),
                    parser.get::<u32>("size"),
                    parser.get::<std::net::Ipv6Addr>("daddr"),
                    parser.get::<std::net::Ipv6Addr>("saddr"),
                    parser.get::<u16>("dport"),
                    parser.get::<u16>("sport"),
                    parser.get::<u32>("startime"),
                    parser.get::<u32>("endtime"),
                    parser.get::<u32>("seqnum"),
                    parser.get::<u32>("connid"),
                );
            }
        }
    }

    if std::env::var_os("ETW_BENCH_DUMP_IPV6").is_some() {
        for event in events.iter().take(3) {
            let record = event.as_event_record();
            // SAFETY: record is a valid EVENT_RECORD reconstructed from captured data.
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
            let mut sp = network::KERNEL_NETWORK_TASK_TCPIPDataSent26V0Parser::new(raw_event);
            eprintln!(
                "STATIC pid={:?} size={:?} daddr={:?} dport={:?} sport={:?} seqnum={:?} connid={:?}",
                sp.PID(),
                sp.size(),
                sp.daddr()
                    .map(|d| std::net::Ipv6Addr::from(<[u8; 16]>::try_from(d).unwrap())),
                sp.dport(),
                sp.sport(),
                sp.seqnum(),
                sp.connid(),
            );
        }
    }

    measure("network_ipv6", "etw-rs-get", events.len(), || {
        for event in events {
            let record = event.as_event_record();
            // SAFETY: record is a valid EVENT_RECORD reconstructed from captured data.
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };

            if let Ok(mut parser) = parser_cache.parser(raw_event) {
                let parsed = ParsedTcpIpSendV6 {
                    timestamp: record.EventHeader.TimeStamp,
                    pid: parser.get("PID").unwrap(),
                    size: parser.get("size").unwrap(),
                    daddr: parser.get("daddr").unwrap(),
                    saddr: parser.get("saddr").unwrap(),
                    dport: parser.get("dport").unwrap(),
                    sport: parser.get("sport").unwrap(),
                    startime: parser.get("startime").unwrap(),
                    endtime: parser.get("endtime").unwrap(),
                    seqnum: parser.get("seqnum").unwrap(),
                    connid: parser.get("connid").unwrap(),
                };

                black_box(&parsed);
            }
        }
    });
    measure("network_ipv6", "etw-rs-static", events.len(), || {
        for event in events {
            let record = event.as_event_record();
            // SAFETY: record is a valid EVENT_RECORD reconstructed from captured data.
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };

            let mut parser = network::KERNEL_NETWORK_TASK_TCPIPDataSent26V0Parser::new(raw_event);
            let parsed = ParsedTcpIpSendV6 {
                timestamp: record.EventHeader.TimeStamp,
                pid: parser.PID().unwrap(),
                size: parser.size().unwrap(),
                daddr: std::net::Ipv6Addr::from(
                    <[u8; 16]>::try_from(parser.daddr().unwrap()).unwrap(),
                ),
                saddr: std::net::Ipv6Addr::from(
                    <[u8; 16]>::try_from(parser.saddr().unwrap()).unwrap(),
                ),
                dport: parser.dport().unwrap(),
                sport: parser.sport().unwrap(),
                startime: parser.startime().unwrap(),
                endtime: parser.endtime().unwrap(),
                seqnum: parser.seqnum().unwrap(),
                connid: parser.connid().unwrap(),
            };

            black_box(&parsed);
        }
    });
}

/// Run every arm for this event type, in the order the table lists them.
fn network_ipv6_benches() {
    bench_network_ipv6_get();
}

/// Run every arm for this event type, in the order the table lists them.
fn process_benches() {
    bench_process_start_dynamic();
    bench_process_start_get();
    bench_process_start_static();
    bench_process_start_ferrisetw();
}

/// Run every arm for this event type, in the order the table lists them.
fn thread_benches() {
    bench_thread_start_dynamic();
    bench_thread_start_get();
    bench_thread_start_get_subset();
    bench_thread_start_static();
    bench_thread_start_ferrisetw();
}

/// Run every arm for this event type, in the order the table lists them.
fn file_benches() {
    bench_file_create_dynamic();
    bench_file_create_get();
    bench_file_create_static();
    bench_file_create_ferrisetw();
}

/// Run every arm for this event type, in the order the table lists them.
fn registry_benches() {
    bench_registry_create_key_dynamic();
    bench_registry_create_key_get();
    bench_registry_create_key_static();
    bench_registry_create_key_ferrisetw();
}

/// Run every arm for this event type, in the order the table lists them.
fn rpc_benches() {
    bench_rpc_client_call_dynamic();
    bench_rpc_client_call_get();
    bench_rpc_client_call_static();
    bench_rpc_client_call_ferrisetw();
}

// C++ benchmark build and run integration

/// Per-event medians from the C++ harness, keyed by event group and arm name.
///
/// Empty when the C++ arm was skipped or could not be built, which renders those
/// columns as "-" exactly as an unmeasured Rust arm does.
type CppResults = std::collections::HashMap<(&'static str, String), f64>;

/// Captured event files, paired with the event group each one corresponds to.
///
/// The C++ harness is invoked once per file and does not know the group name, so the
/// mapping lives here and is applied to whatever that invocation reports.
const CPP_BIN_GROUPS: &[(&str, &str)] = &[
    ("captured_process_events.bin", "process_start"),
    ("captured_rpc_events.bin", "rpc_client_call"),
    ("captured_registry_events.bin", "registry_create_key"),
    ("captured_file_events.bin", "file_create"),
    ("captured_thread_events.bin", "thread_start"),
];

/// How many times the whole suite is measured before a table is printed.
///
/// Defaults to three, because a validated table should be what you get without
/// asking for it. Every cell is then measured independently three times and
/// disagreement between passes is reported as that cell's spread.
///
/// This exists because a single pass cannot tell a clean measurement from a
/// contaminated one. A background build once put `rpc_client_call/etw-rs-static` 54%
/// high while every neighbouring cell stayed correct — the burst was narrower than
/// one arm's measurement window, so nothing in a single run's output could have
/// revealed it. Repeating the whole suite catches that by its effect, whatever the
/// cause, which no counter-based check can promise.
///
/// Three is the useful minimum: with two, disagreement tells you something is wrong
/// but not which reading to believe, while with three the per-cell median discards a
/// single disturbed pass on its own.
///
/// `ETW_BENCH_PASSES=1` is the fast path for iteration, where you are looking for a
/// 2x regression and precision is beside the point. `benches/round_robin.py` sets it,
/// since it repeats across binaries itself and would otherwise pay for both.
fn bench_passes() -> usize {
    std::env::var("ETW_BENCH_PASSES")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(3)
}

/// Spread above which a cell is called out as untrustworthy, in percent.
///
/// Run-to-run spread on an idle machine measures about 3% here (ten consecutive runs
/// of `process_start/etw-rs-static` spanned 712.8-754.6ns). 10% is comfortably clear
/// of that while still catching the 54% excursion that prompted this, and is a
/// reporting threshold only — the spread is printed for every cell either way, so a
/// reader can judge a borderline one themselves.
const SPREAD_WARN_PCT: f64 = 10.0;

/// Absolute range below which a cell is never called out, however large its percentage.
///
/// `thread_start/etw-rs-static` measures about 9ns/event, so a sub-2ns wobble on it
/// reads as 20%+ — a figure that describes
/// the denominator rather than the measurement. Flagging them every run would teach
/// the reader to skip the section, which is worse than not having one.
const SPREAD_WARN_MIN_NS: f64 = 2.0;

/// Whether a cell's disagreement between passes is worth reporting.
///
/// Both tests have to pass: large in relative terms, and large enough in absolute
/// terms to be more than arithmetic on a small number.
fn is_unstable(spread_pct: f64, median_ns: f64) -> bool {
    spread_pct > SPREAD_WARN_PCT && range_ns(spread_pct, median_ns) > SPREAD_WARN_MIN_NS
}

/// Recover the absolute range from the spread, which is that range over the median.
fn range_ns(spread_pct: f64, median_ns: f64) -> f64 {
    spread_pct / 100.0 * median_ns
}

/// The event types the tables cover: display label, event group, event count.
fn event_types() -> [(&'static str, &'static str, usize); 6] {
    [
        (
            "Process Start",
            "process_start",
            get_captured_process_events().len(),
        ),
        (
            "RPC Client Call",
            "rpc_client_call",
            get_captured_rpc_events().len(),
        ),
        (
            "Registry CreateKey",
            "registry_create_key",
            get_captured_registry_events().len(),
        ),
        (
            "File Create",
            "file_create",
            get_captured_file_events().len(),
        ),
        (
            "Thread Start",
            "thread_start",
            get_captured_thread_events().len(),
        ),
        // Only the etw-rs-get column is implemented for the mixed stream, so the
        // other parser columns render as "-". The row is here because the
        // single-type rows above all measure the warm case; this one does not.
        ("Mixed Stream", "mixed_stream", get_mixed_stream().len()),
    ]
}

/// Every Rust arm's measurement from one pass, keyed by event group and arm.
type RustPass = std::collections::HashMap<(&'static str, &'static str), Measurement>;

/// Take this pass's measurements, leaving the store empty for the next pass.
fn collect_rust_pass() -> RustPass {
    std::mem::take(
        &mut *recorded()
            .lock()
            .expect("measurement results mutex poisoned"),
    )
}

/// Reduce one cell's passes to a representative reading and a spread.
///
/// The representative is the median *pass*, not an average of them, so the printed
/// min, median and mean all come from the same real measurement rather than being
/// blended across runs that may have happened under different conditions. Spread is
/// the full range over the passes, relative to that representative.
fn aggregate_rust(mut samples: Vec<Measurement>) -> Option<(Measurement, f64)> {
    if samples.is_empty() {
        return None;
    }
    samples.sort_by(|a, b| a.median_ns.total_cmp(&b.median_ns));
    let representative = samples[samples.len() / 2];
    let spread = spread_pct(
        samples[0].median_ns,
        samples[samples.len() - 1].median_ns,
        representative.median_ns,
    );
    Some((representative, spread))
}

/// As [`aggregate_rust`], for the C++ arms, which report only a median.
fn aggregate_cpp(mut medians: Vec<f64>) -> Option<(f64, f64)> {
    if medians.is_empty() {
        return None;
    }
    medians.sort_by(f64::total_cmp);
    let representative = medians[medians.len() / 2];
    let spread = spread_pct(medians[0], medians[medians.len() - 1], representative);
    Some((representative, spread))
}

/// Render a cell's spread, or "-" when a single pass makes it meaningless.
///
/// One pass has a range of zero, and "0.0%" in that column would read as "perfectly
/// reproducible" when what it means is "never checked". Cells get copied out of the
/// table and away from the footer that explains it, so the cell has to be honest on
/// its own.
fn format_spread(passes: usize, spread: f64) -> String {
    if passes > 1 {
        format!("{spread:.1}%")
    } else {
        "-".to_owned()
    }
}

/// Full range across passes as a percentage of the representative reading.
fn spread_pct(lo: f64, hi: f64, representative: f64) -> f64 {
    if representative > 0.0 {
        (hi - lo) / representative * 100.0
    } else {
        0.0
    }
}

/// One row of the combined table: label, event count, Rust arms, C++ arms.
///
/// The two measurement vectors stay separate because the halves carry different
/// statistics — the Rust arms carry min, median and mean, while the C++ harness
/// reports only a median that is comparable with them.
/// Each cell is its representative reading paired with the spread across passes.
type TableRow = (
    &'static str,
    usize,
    Vec<Option<(Measurement, f64)>>,
    Vec<Option<(f64, f64)>>,
);

/// A C++ parser column in the combined table.
struct CppColumn {
    /// Arm name exactly as `cpp_benchmarks.cpp` emits it in its `ETWBENCH` rows.
    id: &'static str,
    /// Column heading used in the markdown summary.
    heading: &'static str,
}

/// C++ columns in table order, following the Rust ones.
///
/// Every arm `cpp_benchmarks.cpp` reports.
const CPP_COLUMNS: &[CppColumn] = &[
    CppColumn {
        id: "krabsetw",
        heading: "krabsetw",
    },
    CppColumn {
        id: "TdhFormatProperty",
        heading: "TdhFormatProperty",
    },
    CppColumn {
        id: "TdhFmtProp (cached)",
        heading: "TdhFormatProperty (cached)",
    },
    CppColumn {
        id: "TdhFmtProp (naive)",
        heading: "TdhFormatProperty (naive)",
    },
    CppColumn {
        id: "TdhGetProperty",
        heading: "TdhGetProperty",
    },
];

#[expect(
    clippy::print_stdout,
    reason = "forwarding C++ benchmark output to stdout"
)]
fn build_and_run_cpp_benchmarks() -> Result<CppResults, String> {
    use std::process::Command;

    // Check cmake is available
    Command::new("cmake")
        .arg("--version")
        .output()
        .map_err(|_| "cmake not found in PATH".to_owned())?;

    let benches_dir = std::path::Path::new("benches");
    let build_dir = benches_dir.join("build");
    let krabsetw_dir = benches_dir.join("krabsetw");

    // Clone krabsetw if not present (header-only library, shallow clone is sufficient)
    if !krabsetw_dir.join("krabs").join("krabs.hpp").exists() {
        eprintln!("\n=== Cloning krabsetw ===");
        let clone = Command::new("git")
            .args([
                "clone",
                "--depth",
                "1",
                "https://github.com/microsoft/krabsetw.git",
                &krabsetw_dir.to_string_lossy(),
            ])
            .output()
            .map_err(|e| format!("git clone krabsetw failed: {e}"))?;

        if !clone.status.success() {
            let stderr = String::from_utf8_lossy(&clone.stderr);
            eprintln!("Warning: failed to clone krabsetw: {stderr}");
            eprintln!("C++ benchmarks will build without krabsetw support");
        }
    }

    eprintln!("\n=== Building C++ benchmarks ===");

    // Configure
    let configure = Command::new("cmake")
        .args(["-B", &build_dir.to_string_lossy(), "-S", "benches"])
        .output()
        .map_err(|e| format!("cmake configure failed: {e}"))?;

    if !configure.status.success() {
        let stderr = String::from_utf8_lossy(&configure.stderr);
        return Err(format!("cmake configure failed:\n{stderr}"));
    }

    // Build
    let build = Command::new("cmake")
        .args([
            "--build",
            &build_dir.to_string_lossy(),
            "--config",
            "Release",
        ])
        .output()
        .map_err(|e| format!("cmake build failed: {e}"))?;

    if !build.status.success() {
        let stderr = String::from_utf8_lossy(&build.stderr);
        return Err(format!("cmake build failed:\n{stderr}"));
    }

    eprintln!("=== C++ build complete ===\n");

    // Find the executable (MSVC puts it in Release/, other generators may not)
    let exe_candidates = [
        build_dir.join("Release").join("cpp_benchmarks.exe"),
        build_dir.join("cpp_benchmarks.exe"),
        build_dir.join("cpp_benchmarks"),
    ];

    let exe_path = exe_candidates
        .iter()
        .find(|p| p.exists())
        .ok_or_else(|| "cpp_benchmarks executable not found after build".to_owned())?;

    let mut results = CppResults::new();

    for &(bin_file, group) in CPP_BIN_GROUPS {
        if !std::path::Path::new(bin_file).exists() {
            eprintln!("Skipping C++ benchmark for {bin_file} (file not found)");
            continue;
        }

        eprintln!("Running C++ benchmark: {bin_file}");
        let run = Command::new(exe_path)
            .arg(bin_file)
            .output()
            .map_err(|e| format!("Failed to run cpp_benchmarks: {e}"))?;

        // Split the machine-readable rows out of the human output, so the table this
        // harness prints is assembled from parsed values rather than from whatever
        // the reader happens to scroll past.
        let stdout = String::from_utf8_lossy(&run.stdout);
        for line in stdout.lines() {
            match parse_cpp_row(line) {
                Some((arm, median_ns)) => {
                    results.insert((group, arm), median_ns);
                }
                None => println!("{line}"),
            }
        }

        // Print stderr (warnings/errors)
        let stderr = String::from_utf8_lossy(&run.stderr);
        if !stderr.is_empty() {
            eprint!("{stderr}");
        }

        if !run.status.success() {
            eprintln!("Warning: cpp_benchmarks exited with {}", run.status);
        }
    }

    Ok(results)
}

/// Parse one `ETWBENCH` row emitted by `cpp_benchmarks.cpp`.
///
/// The format is `ETWBENCH\t<arm>\t<events>\t<median ns/event>`; anything else is
/// human output and is returned as `None` for the caller to forward verbatim.
fn parse_cpp_row(line: &str) -> Option<(String, f64)> {
    let rest = line.strip_prefix("ETWBENCH\t")?;
    let mut fields = rest.split('\t');
    let arm = fields.next()?.trim().to_owned();
    let _events = fields.next()?;
    let median_ns = fields.next()?.trim().parse::<f64>().ok()?;
    Some((arm, median_ns))
}

// =============================================================================
// Result tables
//
// `measure` records one measurement per arm as it runs, for the whole captured
// batch. The cross-parser, per-event comparison that BENCHMARKS.md quotes is
// assembled here from those records.
//
// The reported statistic is the MEDIAN, which is also what cpp_benchmarks.cpp
// prints in its `Median (ns/ev)` column, taken at the same index of the same kind
// of sorted sample series — so it is one statistic computed one way, not two that
// share a name. The C++ headline beside it is an IQR-trimmed mean, which is a
// different figure and is not comparable.
//
// Measured on one thread_start bench, the median, an OLS slope and a trimmed mean
// of the same data came out at 7.64 / 5.70 / 4.26 ns/event — a near-2x spread on a
// single benchmark, so the choice of statistic is not cosmetic. The mean is kept
// beside the median purely as a skew signal: a wide gap means that row is noisy.
//
// The Rust benches build one parsed struct per event and drop it immediately,
// matching cpp_benchmarks.cpp's `DoNotOptimize(parsed)` loop. Keep it that way:
// accumulating results into a live Vec adds allocator and cache work the C++
// side never pays, which silently made the two harnesses incomparable.
//
// One difference remains by design — Rust `String` is UTF-8, so every wide
// property is transcoded, while the C++ structs keep `std::wstring` as-is. That
// is a real cost of the Rust API rather than a harness artefact, so it stays,
// but it means the cross-language rows are close rather than equivalent.
// =============================================================================

/// A parser column in the generated tables.
struct ParserColumn {
    /// Arm id, as passed to `measure` and printed in the tables.
    id: &'static str,
    /// Column heading used in the markdown summary.
    heading: &'static str,
}

/// Parser columns in table order. The first entry is the `vs Baseline` reference,
/// which is taken from the median.
///
/// Every column parses each event's full property set into an owned struct, so
/// the rows are comparable with each other. Keep it that way: a benchmark that
/// reads only some properties, or skips the string conversions, does not belong
/// here as a peer column.
/// The parsers compared, in table order.
///
/// `etw-rs (get)` and `etw-rs (get_hinted)` must differ *only* in how they resolve
/// a property name, so both build their string fields the same way, with
/// `get`/`get_hinted::<String>`. They previously did not: the hinted arms borrowed
/// a `WideStrRef` and called `to_string_lossy`, which is a different API *and*
/// different semantics (lossy rather than strict), so the ratio between the two
/// columns conflated name resolution with string decoding and could not be read
/// as a hinting comparison at all on any event carrying a string.
///
/// Measured in isolation, that string difference is worth under 10ns per field
/// (`String::from_property` 84ns against `WideStrRef` + `to_string_lossy` 82ns on
/// a 58-character path), so it was never the bulk of the gap — but it made the
/// comparison unsound, which is worse than making it wrong by a known amount.
const PARSER_COLUMNS: &[ParserColumn] = &[
    ParserColumn {
        id: "etw-rs-static",
        heading: "etw-rs (static)",
    },
    ParserColumn {
        id: "etw-rs-get-hinted",
        heading: "etw-rs (get_hinted)",
    },
    ParserColumn {
        id: "etw-rs-get",
        heading: "etw-rs (get)",
    },
    ParserColumn {
        id: "ferrisetw",
        heading: "ferrisetw 1.2.0",
    },
];

/// Per-event cost of one parser on one event type, in nanoseconds.
#[expect(
    clippy::struct_field_names,
    reason = "the _ns suffix is the unit, not a repetition of the type name"
)]
#[derive(Clone, Copy)]
struct Measurement {
    mean_ns: f64,
    median_ns: f64,
    /// Fastest observed sample of the reported series.
    ///
    /// Printed beside the median as the sample least contaminated by noise, and
    /// used to choose between the two timing series. The median is the published
    /// figure and the one compared across builds.
    min_ns: f64,
}

// =============================================================================
// Measurement
//
// The Rust arms are timed here rather than by criterion, so that both halves of
// the published table come from one instrument. They did not: the C++ arms have
// always been hand-timed by `benchmark_parser` in cpp_benchmarks.cpp while the
// Rust arms went through criterion, and BENCHMARKS.md prints the two side by side
// as though that were a comparison.
//
// The asymmetry was not theoretical. Criterion's measurement of an arm was
// observed reading 1.57x slow — uniformly, across all 100 of its samples and
// including its own minimum — while a hand-timed loop over the same events, in the
// same process and seconds either side of it, read the true figure. Core clock and
// memory latency were unchanged across the two, measured directly, so the
// divergence was in the measurement rather than in the machine or the parser. The
// state persisted for tens of minutes at a stretch, which is longer than a whole
// run: every pass of a multi-pass run landed inside it and they all agreed with
// each other.
//
// The protocol mirrors `benchmark_parser`: warm up, then time repeated passes over
// the whole captured set and report the median divided by the event count. One
// difference is deliberate, and `SAMPLE_TARGET_NS` explains it.
// =============================================================================

/// Passes over the event set before timing starts, matching the C++ harness.
const WARMUP_PASSES: usize = 10;

/// Timed samples per series, matching the C++ harness's iteration count.
const SAMPLES: usize = 1000;

/// Shortest a single timed sample may be, in nanoseconds.
///
/// The C++ harness times exactly one pass per sample. That is fine for its slower
/// arms and wrong for the fast ones here: `thread_start/etw-rs-static` costs about
/// 5ns/event over 163 events, so one pass is ~815ns, and `Instant` resolves to a
/// 100ns QPC tick. That is a 12% quantum landing on precisely the arms where
/// etw-rs looks best, which would read as a measurement rather than as noise.
///
/// So a sample times however many passes are needed to clear this bound and
/// divides back down. Where one pass already clears it — which is every arm on the
/// larger captures — the two harnesses compute the identical statistic; where it
/// does not, this one is the same statistic better conditioned.
const SAMPLE_TARGET_NS: f64 = 250_000.0;

/// Disagreement between the two timing loops that is worth reporting, in percent.
///
/// Both loops run the same closure over the same events microseconds apart, so they
/// should agree to well within a percent. They are compared at all because the
/// failure this module exists to catch was invisible from inside a single loop:
/// criterion's numbers were self-consistent across a hundred samples and still
/// 1.57x wrong.
const SERIES_DISAGREE_PCT: f64 = 10.0;

/// One timing series reduced to the three statistics the table prints.
#[derive(Clone, Copy)]
struct Series {
    median: f64,
    mean: f64,
    min: f64,
}

/// This pass's measurements, taken by `collect_rust_pass` and refilled by the next.
fn recorded() -> &'static std::sync::Mutex<RustPass> {
    static RECORDED: std::sync::OnceLock<std::sync::Mutex<RustPass>> = std::sync::OnceLock::new();
    RECORDED.get_or_init(|| std::sync::Mutex::new(RustPass::new()))
}

/// Substring an arm's `group/arm` id must contain to be measured, if any.
///
/// Keeps `cargo bench --bench live_events -- thread_start` working, which the
/// no-measurement help text tells the reader to use. Cargo passes `--bench` and may
/// pass other flags of its own, so anything beginning with `-` is skipped and the
/// first bare argument wins.
fn arm_filter() -> Option<&'static str> {
    static FILTER: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    FILTER
        .get_or_init(|| std::env::args().skip(1).find(|a| !a.starts_with('-')))
        .as_deref()
}

/// Settle caches and branch predictors, and report the cost of one pass.
///
/// The cost is what `repeats_for` needs to size a sample, so the warm-up does
/// double duty rather than being timed separately.
#[expect(
    clippy::cast_precision_loss,
    reason = "WARMUP_PASSES is 10, represented exactly by f64"
)]
fn warm_up<F: FnMut()>(mut body: F) -> f64 {
    let start = std::time::Instant::now();
    for _ in 0..WARMUP_PASSES {
        body();
    }
    start.elapsed().as_secs_f64() * 1e9 / WARMUP_PASSES as f64
}

/// How many passes one sample must cover to clear `SAMPLE_TARGET_NS`.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the ratio is clamped to a small positive count before conversion"
)]
fn repeats_for(pass_ns: f64) -> usize {
    if !pass_ns.is_finite() || pass_ns <= 0.0 {
        return 1;
    }
    (SAMPLE_TARGET_NS / pass_ns).ceil().clamp(1.0, 4096.0) as usize
}

/// Time `SAMPLES` samples of `reps` passes each, as per-event nanoseconds.
///
/// Generic rather than taking `&mut dyn FnMut()` so that `measure` can instantiate
/// it twice, once with the closure inlined into this loop and once with it behind a
/// vtable. The two instantiations are different machine code timing identical work,
/// which is what makes the cross-check in `measure` worth anything.
#[expect(
    clippy::cast_precision_loss,
    reason = "repeat and event counts are small integers, represented exactly by f64"
)]
fn time_series<F: FnMut()>(mut body: F, events: usize, reps: usize) -> Vec<f64> {
    let per_sample = (reps * events) as f64;
    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let start = std::time::Instant::now();
        for _ in 0..reps {
            body();
        }
        samples.push(start.elapsed().as_secs_f64() * 1e9 / per_sample);
    }
    samples
}

/// Reduce one series to its median, mean and minimum.
///
/// The median is taken at the same index the C++ harness uses, so the two columns
/// of the published table are the same statistic and not merely the same word. The
/// mean sits beside it only as a skew signal: a wide gap means that row is noisy.
#[expect(
    clippy::cast_precision_loss,
    reason = "SAMPLES is 1000, represented exactly by f64"
)]
fn summarise(mut samples: Vec<f64>) -> Series {
    assert!(!samples.is_empty(), "timed series produced no samples");
    samples.sort_by(f64::total_cmp);
    Series {
        median: samples[samples.len() / 2],
        mean: samples.iter().sum::<f64>() / samples.len() as f64,
        min: samples[0],
    }
}

/// Time one parser against one event type and record it for this pass.
///
/// `body` must do exactly one pass over the whole captured set, building and
/// dropping one parsed struct per event, matching the C++ harness's
/// `DoNotOptimize(parsed)` loop.
///
/// The work is timed twice through different code paths and the faster series is
/// reported. Timing noise on a developer machine is one-sided — contention,
/// throttling and power-state changes only ever make a sample slower — so when two
/// loops over identical work disagree, the faster one is the less contaminated, so
/// the series with the lower minimum is kept. Its median is the reported figure.
#[expect(
    clippy::print_stdout,
    reason = "the RSBENCH row is this harness's machine-readable output"
)]
fn measure(group: &'static str, arm: &'static str, events: usize, mut body: impl FnMut()) {
    assert!(
        events > 0,
        "{group}/{arm}: asked to measure an empty event set"
    );

    if let Some(filter) = arm_filter()
        && !format!("{group}/{arm}").contains(filter)
    {
        return;
    }

    let pass_ns = warm_up(&mut body);
    let reps = repeats_for(pass_ns);

    let direct = summarise(time_series(&mut body, events, reps));
    let dynamic: &mut dyn FnMut() = &mut body;
    let indirect = summarise(time_series(dynamic, events, reps));

    let (best, other) = if direct.min <= indirect.min {
        (direct, indirect)
    } else {
        (indirect, direct)
    };

    let gap = (other.min - best.min) / best.min * 100.0;
    if gap > SERIES_DISAGREE_PCT {
        eprintln!(
            "WARNING: {group}/{arm}: the two timing loops disagree by {gap:.0}% \
             ({:.1} vs {:.1} ns/event). One of them is not measuring the parser; \
             treat this cell as unmeasured.",
            best.min, other.min
        );
    }

    eprintln!(
        "{group}/{arm}: {:.1} ns/event (median of {SAMPLES} samples, {reps} pass(es) each)",
        best.median
    );

    // Machine-readable duplicate of the same median, consumed by
    // `benches/round_robin.py`. On stdout because that is the stream the driver
    // captures, and distinct from the C++ harness's `ETWBENCH` rows so neither
    // parser can pick up the other's output.
    println!("RSBENCH\t{group}\t{arm}\t{events}\t{:.4}", best.median);

    recorded()
        .lock()
        .expect("measurement results mutex poisoned")
        .insert(
            (group, arm),
            Measurement {
                mean_ns: best.mean,
                median_ns: best.median,
                min_ns: best.min,
            },
        );
}

/// Print one per-event table per event type, plus a markdown summary.
#[expect(
    clippy::print_stdout,
    reason = "the result tables are this harness's output"
)]
fn print_tables(rust_passes: &[RustPass], cpp_passes: &[CppResults]) {
    let passes = rust_passes.len().max(cpp_passes.len());
    let mut rows: Vec<TableRow> = Vec::new();
    let mut missing = Vec::new();
    let mut unstable = Vec::new();

    for (label, group, count) in event_types() {
        if count == 0 {
            missing.push(format!("{label} (no events captured)"));
            continue;
        }

        let measured: Vec<Option<(Measurement, f64)>> = PARSER_COLUMNS
            .iter()
            .map(|column| {
                let samples: Vec<Measurement> = rust_passes
                    .iter()
                    .filter_map(|pass| pass.get(&(group, column.id)).copied())
                    .collect();
                let aggregated = aggregate_rust(samples);
                match aggregated {
                    None => missing.push(format!("{label} / {}", column.id)),
                    Some((m, spread)) if is_unstable(spread, m.median_ns) => {
                        unstable.push(format!(
                            "{label} / {} (spread {spread:.0}%, {:.1}ns)",
                            column.id,
                            range_ns(spread, m.median_ns)
                        ));
                    }
                    Some(_) => {}
                }
                aggregated
            })
            .collect();

        let cpp_measured: Vec<Option<(f64, f64)>> = CPP_COLUMNS
            .iter()
            .map(|column| {
                let samples: Vec<f64> = cpp_passes
                    .iter()
                    .filter_map(|pass| pass.get(&(group, column.id.to_owned())).copied())
                    .collect();
                let aggregated = aggregate_cpp(samples);
                if let Some((median_ns, spread)) = aggregated
                    && is_unstable(spread, median_ns)
                {
                    unstable.push(format!(
                        "{label} / {} (spread {spread:.0}%, {:.1}ns)",
                        column.id,
                        range_ns(spread, median_ns)
                    ));
                }
                aggregated
            })
            .collect();

        println!();
        println!("{}", "=".repeat(111));
        println!("{label} - {count} events (per event)");
        println!("{}", "=".repeat(111));
        println!(
            "{:<26}{:>8}{:>14}{:>16}{:>16}{:>10}{:>12}",
            "Parser",
            "Events",
            "Min (ns/ev)",
            "Median (ns/ev)",
            "Mean (ns/ev)",
            "Spread",
            "vs Baseline"
        );
        println!("{}", "-".repeat(111));

        let baseline = measured.first().and_then(|c| c.map(|(m, _)| m.median_ns));
        for (column, cell) in PARSER_COLUMNS.iter().zip(&measured) {
            match *cell {
                Some((m, spread)) => println!(
                    "{:<26}{:>8}{:>14.1}{:>16.1}{:>16.1}{:>10}{:>11.2}x",
                    column.id,
                    count,
                    m.min_ns,
                    m.median_ns,
                    m.mean_ns,
                    format_spread(passes, spread),
                    baseline.map_or(f64::NAN, |b| m.median_ns / b)
                ),
                None => println!(
                    "{:<26}{:>8}{:>14}{:>16}{:>16}{:>10}{:>12}",
                    column.id, count, "-", "-", "-", "-", "-"
                ),
            }
        }

        // The C++ arms report only a median, so min and mean stay empty rather than
        // being filled with a statistic the two harnesses compute differently.
        for (column, cell) in CPP_COLUMNS.iter().zip(&cpp_measured) {
            match *cell {
                Some((median_ns, spread)) => println!(
                    "{:<26}{:>8}{:>14}{:>16.1}{:>16}{:>10}{:>11.2}x",
                    column.id,
                    count,
                    "-",
                    median_ns,
                    "-",
                    format_spread(passes, spread),
                    baseline.map_or(f64::NAN, |b| median_ns / b)
                ),
                None => println!(
                    "{:<26}{:>8}{:>14}{:>16}{:>16}{:>10}{:>12}",
                    column.id, count, "-", "-", "-", "-", "-"
                ),
            }
        }
        println!("{}", "=".repeat(111));

        rows.push((label, count, measured, cpp_measured));
    }

    print_markdown_summary(&rows);

    println!();
    if passes > 1 {
        println!("{passes} passes. Each cell is the median pass, so its min, median and mean all");
        println!("come from one real measurement rather than a blend; Spread is the full range");
        println!("across passes relative to that reading. A single disturbed pass is discarded by");
        println!("the median but still shows up in Spread.");
    } else {
        println!("Single pass (ETW_BENCH_PASSES=1): Spread is undefined and every cell is one");
        println!("unvalidated measurement. The default is three passes; one cannot distinguish a");
        println!(
            "clean reading from one disturbed by load, and does not try to. Fine for spotting"
        );
        println!("a 2x regression, not for anything you intend to publish.");
    }
    println!();
    println!("Every column is a median from this run: the Rust arms from `measure`, the C++");
    println!("arms from cpp_benchmarks.cpp, which is why it runs first. Median because it is the");
    println!("only statistic both harnesses compute the same way - the C++ trimmed mean is not");
    println!("comparable, and the C++ arms report no min or mean here for the same reason.");
    println!("These benches build one struct per event and");
    println!("drop it, as the C++ loop does; the remaining difference is that Rust transcodes");
    println!("wide properties to UTF-8 while the C++ structs keep UTF-16.");

    if !unstable.is_empty() {
        println!();
        println!(
            "Unstable - passes disagree by over {SPREAD_WARN_PCT:.0}% and {SPREAD_WARN_MIN_NS:.0}ns ({}):",
            unstable.len()
        );
        for entry in &unstable {
            println!("  - {entry}");
        }
        println!();
        println!("These cells disagreed between passes by more than run-to-run noise on an idle");
        println!("machine accounts for, so something perturbed at least one of them. Do not");
        println!("publish them; re-run on a quiet machine.");
    }

    if !missing.is_empty() {
        println!();
        println!("Not measured in this run ({}):", missing.len());
        for entry in &missing {
            println!("  - {entry}");
        }
    }

    // Nothing at all measured almost always means the filter matched no benchmark,
    // and the reason is unobvious enough to be worth spelling out: `cargo bench live`
    // looks like it selects this binary but does not. Saying so here turns a table of
    // dashes into an instruction.
    let measured_anything = rows.iter().any(|(_, _, rust, cpp)| {
        rust.iter().any(Option::is_some) || cpp.iter().any(Option::is_some)
    });
    if !measured_anything {
        println!();
        println!("No benchmark in this binary produced a measurement.");
        println!();
        println!("The usual cause is an arm filter that matched nothing. Cargo treats a bare");
        println!("argument as a *filter* passed to every bench target, not as a target selector:");
        println!(
            "`cargo bench live` matches no id here (they read `process_start/etw-rs-static`)."
        );
        println!("To run this binary:");
        println!();
        println!("    cargo bench --bench live_events                 # everything");
        println!("    cargo bench --bench live_events -- thread_start # one group");
    }
}

/// Print the same results as a markdown table, the source BENCHMARKS.md's table is
/// assembled from.
#[expect(
    clippy::print_stdout,
    reason = "the result tables are this harness's output"
)]
fn print_markdown_summary(rows: &[TableRow]) {
    use std::fmt::Write as _;

    if rows.is_empty() {
        return;
    }

    println!();
    println!("Markdown summary — median ns/event, for BENCHMARKS.md:");
    println!();

    let mut header = String::from("| Event Type |");
    let mut divider = String::from("|--|");
    for column in PARSER_COLUMNS {
        let _ = write!(header, " {} |", column.heading);
        divider.push_str("--|");
    }
    for column in CPP_COLUMNS {
        let _ = write!(header, " {} |", column.heading);
        divider.push_str("--|");
    }
    println!("{header}");
    println!("{divider}");

    for &(label, count, ref measured, ref cpp_measured) in rows {
        let mut line = format!("| **{label}** ({count} events) |");
        for cell in measured {
            match *cell {
                Some((m, _)) => {
                    let _ = write!(line, " {:.0}ns |", m.median_ns);
                }
                None => line.push_str(" — |"),
            }
        }
        for cell in cpp_measured {
            match *cell {
                Some((median_ns, _)) => {
                    let _ = write!(line, " {median_ns:.0}ns |");
                }
                None => line.push_str(" — |"),
            }
        }
        println!("{line}");
    }
}

fn main() {
    bench_util::pin_to_performance_cores();

    // Pre-flight: parse one event from each type with all three implementations
    // and assert field-level equality before entering any timed loop.
    run_preflight_checks();

    let passes = bench_passes();
    let mut rust_passes: Vec<RustPass> = Vec::new();
    let mut cpp_passes: Vec<CppResults> = Vec::new();

    for pass in 1..=passes {
        if passes > 1 {
            eprintln!("\n=== pass {pass} of {passes} ===");
        }

        // Events are captured live on the first run and saved to .bin files. Subsequent
        // runs load from disk, so every pass parses byte-identical data.
        process_benches();
        rpc_benches();
        mixed_benches();
        network_ipv6_benches();
        registry_benches();
        file_benches();
        thread_benches();

        rust_passes.push(collect_rust_pass());
        cpp_passes.push(run_cpp_benchmarks());
    }

    // Aggregate every pass into one table.
    print_tables(&rust_passes, &cpp_passes);
}

/// Build and run the C++ arm, or return nothing if it is skipped or unavailable.
///
/// The C++ arm runs before the tables, not after, so its results can go into them.
/// BENCHMARKS.md quotes Rust and C++ side by side, and for six months those halves came
/// from separate runs assembled by hand — which is how a Rust column measured under one
/// set of conditions ended up published beside a C++ column measured under another. One
/// run, one table, or the comparison is not a comparison.
///
/// It costs about a minute per invocation and is irrelevant when re-running one Rust
/// bench to compare two Rust builds, so `ETW_BENCH_SKIP_CPP=1` drops it for the
/// round-robin driver (`benches/round_robin.py`). The C++ columns then
/// render as "-", the same as any other arm this run did not measure.
fn run_cpp_benchmarks() -> CppResults {
    if std::env::var_os("ETW_BENCH_SKIP_CPP").is_some() {
        eprintln!("\nC++ benchmarks skipped: ETW_BENCH_SKIP_CPP set");
        CppResults::new()
    } else {
        build_and_run_cpp_benchmarks().unwrap_or_else(|e| {
            eprintln!("\nC++ benchmarks skipped: {e}");
            CppResults::new()
        })
    }
}
