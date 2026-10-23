//! Comparison benchmarks for etw-rs parsing performance
//!
//! These benchmarks measure:
//! - Schema cache hit vs direct TDH API calls
//! - get() vs get_hinted() for shallow and deep fields
//! - Multi-field access patterns
//!
//! # Usage
//!
//! ```bash
//! cargo bench --bench comparison
//! ```
//!
//! All benchmarks use mock events with schemas from TDH and do NOT require
//! administrator privileges.

#![expect(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::unwrap_used,
    missing_docs,
    clippy::missing_const_for_fn,
    clippy::semicolon_outside_block,
    // Benchmark code has pervasive unsafe for EVENT_RECORD construction.
    clippy::undocumented_unsafe_blocks,
    clippy::as_ptr_cast_mut,
    clippy::option_if_let_else,
    reason = "benchmark harness prioritises measurement workflow over strict style rules"
)]

use criterion::{Criterion, criterion_group};
use etw::{Error::Win32Error, event_schema};
use std::hint::black_box as bb;
use windows::{
    Win32::{
        Foundation::ERROR_INSUFFICIENT_BUFFER,
        System::Diagnostics::Etw::{
            EVENT_HEADER_FLAG_64_BIT_HEADER, EVENT_RECORD, TRACE_EVENT_INFO, TdhGetEventInformation,
        },
    },
    core::GUID,
};

// =============================================================================
// Mock Event Helpers
// =============================================================================

/// Mock event holder that owns both the data and EVENT_RECORD
/// This allows RawEvent to safely borrow from the record
struct MockEvent {
    #[expect(dead_code, reason = "kept alive for the EVENT_RECORD.UserData pointer")]
    data: Vec<u8>,
    record: EVENT_RECORD,
}

impl MockEvent {
    fn new(data: Vec<u8>, provider_guid: GUID, event_id: u16, version: u8) -> Self {
        let mut record: EVENT_RECORD = unsafe { std::mem::zeroed() };
        record.EventHeader.ProviderId = provider_guid;
        record.EventHeader.EventDescriptor.Id = event_id;
        record.EventHeader.EventDescriptor.Version = version;
        record.UserData = data.as_ptr() as *mut _;
        record.UserDataLength = data.len() as u16;

        Self { data, record }
    }

    fn as_raw_event(&self) -> &etw::event::RawEvent {
        unsafe { etw::event::RawEvent::from_ptr((&raw const self.record).cast()) }
    }
}

// =============================================================================
// Captured Event Storage
// =============================================================================

/// A captured ETW event with its data stored for benchmarking.
/// We only store what's needed - not the full EVENT_RECORD (which has raw pointers).
#[derive(Clone)]
struct CapturedEvent {
    /// Provider GUID
    provider_guid: windows::core::GUID,
    /// Event ID
    event_id: u16,
    /// Opcode
    opcode: u8,
    /// Version
    version: u8,
    /// Flags
    flags: u16,
    /// Owned copy of the user data
    user_data: Vec<u8>,
    /// Cached schema buffer (TRACE_EVENT_INFO)
    schema_buffer: Vec<u8>,
}

impl CapturedEvent {
    /// Reconstruct an EVENT_RECORD for use with our parser.
    /// The returned record borrows from self.
    fn to_event_record(&self) -> EVENT_RECORD {
        let mut record: EVENT_RECORD = unsafe { std::mem::zeroed() };
        record.EventHeader.ProviderId = self.provider_guid;
        record.EventHeader.EventDescriptor.Id = self.event_id;
        record.EventHeader.EventDescriptor.Opcode = self.opcode;
        record.EventHeader.EventDescriptor.Version = self.version;
        record.EventHeader.Flags = self.flags;
        record.UserData = self.user_data.as_ptr() as *mut _;
        record.UserDataLength = self.user_data.len() as u16;
        record
    }

    fn schema(&self) -> &TRACE_EVENT_INFO {
        unsafe { &*self.schema_buffer.as_ptr().cast::<TRACE_EVENT_INFO>() }
    }

    fn property_count(&self) -> u32 {
        self.schema().TopLevelPropertyCount
    }
}

// =============================================================================
// Mock Event Creation (no admin required)
// =============================================================================

/// Create mock DNS events for benchmarking.
///
/// Uses TdhGetEventInformation to get real schemas, then constructs
/// realistic user data. No admin privileges required.
fn capture_dns_events(count: usize) -> Option<Vec<CapturedEvent>> {
    // Microsoft-Windows-DNS-Client provider
    // Event 3008 is a common DNS query event
    let provider_guid = windows::core::GUID {
        data1: 0x1C95126E,
        data2: 0x7EEA,
        data3: 0x49A9,
        data4: [0xA3, 0xFE, 0xA3, 0x78, 0xB0, 0x3D, 0xDB, 0x4D],
    };

    // Create mock event to get schema from TDH
    let mut record: EVENT_RECORD = unsafe { std::mem::zeroed() };
    record.EventHeader.ProviderId = provider_guid;
    record.EventHeader.EventDescriptor.Id = 3008; // DNS query event
    record.EventHeader.EventDescriptor.Version = 0;
    record.EventHeader.Flags = EVENT_HEADER_FLAG_64_BIT_HEADER as u16;

    // Get schema from TDH
    let schema_buffer = match get_schema_buffer(&record) {
        Ok(buf) => buf,
        Err(e) => {
            eprintln!("Failed to get DNS event schema: {e:?}");
            return None;
        }
    };

    // Construct realistic user data for DNS query event
    // Event 3008 typically has: QueryName (string), QueryType (u32), etc.
    let mut user_data = Vec::new();

    // QueryName - null-terminated UTF-16 string "example.com"
    let query_name = "example.com";
    for c in query_name.encode_utf16() {
        user_data.extend_from_slice(&c.to_le_bytes());
    }
    user_data.extend_from_slice(&[0, 0]); // null terminator

    // QueryType - u32 (1 = A record)
    user_data.extend_from_slice(&1u32.to_le_bytes());

    // QueryOptions - u64
    user_data.extend_from_slice(&0u64.to_le_bytes());

    // ServerList - empty string
    user_data.extend_from_slice(&[0, 0]);

    // Pad to ensure enough data
    while user_data.len() < 128 {
        user_data.push(0);
    }

    let event = CapturedEvent {
        provider_guid,
        event_id: 3008,
        opcode: 0,
        version: 0,
        flags: EVENT_HEADER_FLAG_64_BIT_HEADER as u16,
        user_data,
        schema_buffer,
    };

    Some(vec![event; count])
}

/// Create mock ProcessStart events for benchmarking.
///
/// ProcessStart events (v4) have the following fields:
/// - ProcessID (u32, index 0)
/// - ProcessSequenceNumber (u64, index 1)
/// - CreateTime (u64, index 2)
/// - ParentProcessID (u32, index 3)
/// - ParentProcessSequenceNumber (u64, index 4)
/// - SessionID (u32, index 5)
/// - Flags (u32, index 6)
/// - ProcessTokenElevationType (u32, index 7)
/// - ProcessTokenIsElevated (u32, index 8)
/// - MandatoryLabel (SidRef, index 9)
/// - ImageName (WideStrRef, index 10)
/// - ImageChecksum (u32, index 11)
/// - TimeDateStamp (u32, index 12)
/// - PackageFullName (WideStrRef, index 13)
/// - PackageRelativeAppId (WideStrRef, index 14)
/// - SecurityMitigations (u32, index 15)
fn capture_process_events(count: usize) -> Option<Vec<CapturedEvent>> {
    // Microsoft-Windows-Kernel-Process provider
    let provider_guid = windows::core::GUID {
        data1: 0x22FB2CD6,
        data2: 0x0E7B,
        data3: 0x422B,
        data4: [0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16],
    };

    // Create mock event to get schema from TDH
    let mut record: EVENT_RECORD = unsafe { std::mem::zeroed() };
    record.EventHeader.ProviderId = provider_guid;
    record.EventHeader.EventDescriptor.Id = 1; // ProcessStart
    record.EventHeader.EventDescriptor.Version = 4;
    record.EventHeader.Flags = EVENT_HEADER_FLAG_64_BIT_HEADER as u16;

    // Get schema from TDH
    let schema_buffer = match get_schema_buffer(&record) {
        Ok(buf) => buf,
        Err(e) => {
            eprintln!("Failed to get ProcessStart schema: {e:?}");
            return None;
        }
    };

    // Construct realistic user data for ProcessStart event (version 4).
    // Layout matches the actual v4 schema from Microsoft-Windows-Kernel-Process.
    let mut user_data = Vec::new();

    // ProcessID - u32 (index 0)
    user_data.extend_from_slice(&1234u32.to_le_bytes());
    // ProcessSequenceNumber - u64 (index 1)
    user_data.extend_from_slice(&1u64.to_le_bytes());
    // CreateTime - u64 (index 2)
    user_data.extend_from_slice(&0u64.to_le_bytes());
    // ParentProcessID - u32 (index 3)
    user_data.extend_from_slice(&5678u32.to_le_bytes());
    // ParentProcessSequenceNumber - u64 (index 4)
    user_data.extend_from_slice(&0x1234_5678_9ABC_DEF0u64.to_le_bytes());
    // SessionID - u32 (index 5)
    user_data.extend_from_slice(&1u32.to_le_bytes());
    // Flags - u32 (index 6)
    user_data.extend_from_slice(&0u32.to_le_bytes());
    // ProcessTokenElevationType - u32 (index 7)
    user_data.extend_from_slice(&1u32.to_le_bytes()); // TokenElevationTypeDefault
    // ProcessTokenIsElevated - u32 (index 8)
    user_data.extend_from_slice(&0u32.to_le_bytes());

    // MandatoryLabel - SidRef (index 9) — S-1-16-8192 (Medium Integrity Label)
    // revision(1) + subauth_count(1) + authority(6) + subauth(4)
    let sid = [1u8, 1, 0, 0, 0, 0, 0, 16, 0, 32, 0, 0]; // S-1-16-8192
    user_data.extend_from_slice(&sid);

    // ImageName - null-terminated UTF-16 string (index 10)
    let image_name = "C:\\Windows\\System32\\cmd.exe";
    for c in image_name.encode_utf16() {
        user_data.extend_from_slice(&c.to_le_bytes());
    }
    user_data.extend_from_slice(&[0, 0]);

    // ImageChecksum - u32 (index 11)
    user_data.extend_from_slice(&0u32.to_le_bytes());
    // TimeDateStamp - u32 (index 12)
    user_data.extend_from_slice(&0u32.to_le_bytes());

    // PackageFullName - empty WideStrRef (index 13)
    user_data.extend_from_slice(&[0, 0]);
    // PackageRelativeAppId - empty WideStrRef (index 14)
    user_data.extend_from_slice(&[0, 0]);

    // SecurityMitigations - u32 (index 15)
    user_data.extend_from_slice(&0u32.to_le_bytes());

    let event = CapturedEvent {
        provider_guid,
        event_id: 1,
        opcode: 1, // Start opcode
        version: 4,
        flags: EVENT_HEADER_FLAG_64_BIT_HEADER as u16,
        user_data,
        schema_buffer,
    };

    Some(vec![event; count])
}

/// Get raw TRACE_EVENT_INFO buffer for an event.
fn get_schema_buffer(event: &EVENT_RECORD) -> etw::Result<Vec<u8>> {
    let mut buffer_size = 0u32;

    // First call to get required size
    let status = unsafe { TdhGetEventInformation(event, None, None, &raw mut buffer_size) };

    if status != ERROR_INSUFFICIENT_BUFFER.0 {
        return Err(Win32Error(status));
    }

    // Allocate and retrieve
    let mut buffer = vec![0u8; buffer_size as usize];
    let status = unsafe {
        TdhGetEventInformation(
            event,
            None,
            Some(buffer.as_mut_ptr().cast::<TRACE_EVENT_INFO>()),
            &raw mut buffer_size,
        )
    };

    if status != 0 {
        return Err(Win32Error(status));
    }

    Ok(buffer)
}

// =============================================================================
// TdhFormatProperty Wrapper
// =============================================================================

use windows::{
    Win32::System::Diagnostics::Etw::{
        EVENT_PROPERTY_INFO, PROPERTY_DATA_DESCRIPTOR, PropertyParamLength, TdhFormatProperty,
        TdhGetProperty, TdhGetPropertySize,
    },
    core::PWSTR,
};

/// Parse a property using TdhFormatProperty (Windows API).
///
/// This follows the pattern from Microsoft's documentation:
/// https://learn.microsoft.com/en-us/windows/win32/etw/using-tdhformatproperty-to-consume-event-data
///
/// The key insight is that TdhFormatProperty returns the number of bytes consumed,
/// so we iterate properties in order and track the current position in the buffer.
fn parse_property_with_tdh(
    info: &TRACE_EVENT_INFO,
    user_data: &[u8],
    property_index: usize,
    pointer_size: u8,
) -> Option<String> {
    if property_index >= info.TopLevelPropertyCount as usize {
        return None;
    }

    // Track current position in user data - we must iterate from the start
    let mut data_offset = 0usize;
    let mut output_buffer: Vec<u16> = vec![0; 256];

    // Iterate through properties up to and including the target
    for i in 0..=property_index {
        let prop = unsafe {
            let props_ptr =
                std::ptr::addr_of!(info.EventPropertyInfoArray).cast::<EVENT_PROPERTY_INFO>();
            &*props_ptr.add(i)
        };

        let in_type = unsafe { prop.Anonymous1.nonStructType.InType };
        let out_type = unsafe { prop.Anonymous1.nonStructType.OutType };

        // Get property length - use declared length or let TdhFormatProperty figure it out
        let prop_length = unsafe {
            if (prop.Flags.0 & PropertyParamLength.0) != 0 {
                // Length is in another property - for simplicity, use 0 to let TDH calculate
                0u16
            } else {
                prop.Anonymous3.length
            }
        };

        let remaining_data = &user_data[data_offset..];
        if remaining_data.is_empty() {
            return None;
        }

        // Call TdhFormatProperty
        loop {
            let mut buffer_size = (output_buffer.len() * 2) as u32;
            let mut consumed = 0u16;

            let status = unsafe {
                TdhFormatProperty(
                    std::ptr::from_ref(info).cast_mut(),
                    None,
                    pointer_size as u32,
                    in_type,
                    out_type,
                    prop_length,
                    remaining_data,
                    &raw mut buffer_size,
                    Some(PWSTR(output_buffer.as_mut_ptr())),
                    &raw mut consumed,
                )
            };

            if status == ERROR_INSUFFICIENT_BUFFER.0 && output_buffer.len() < 8192 {
                output_buffer.resize((buffer_size / 2 + 1) as usize, 0);
                continue;
            }

            if status != 0 {
                // TdhFormatProperty failed - can't continue
                return None;
            }

            // Advance data pointer by consumed bytes
            data_offset += consumed as usize;

            // If this is the property we want, return it
            if i == property_index {
                let len = output_buffer
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(output_buffer.len());
                return String::from_utf16(&output_buffer[..len]).ok();
            }

            break;
        }
    }

    None
}

/// Parse a property using TdhFormatProperty, returning raw UTF-16.
///
/// This is for fair comparison with etw-rs WideString (no UTF-16→UTF-8 conversion).
fn parse_property_with_tdh_utf16(
    info: &TRACE_EVENT_INFO,
    user_data: &[u8],
    property_index: usize,
    pointer_size: u8,
) -> Option<Vec<u16>> {
    if property_index >= info.TopLevelPropertyCount as usize {
        return None;
    }

    let mut data_offset = 0usize;
    let mut output_buffer: Vec<u16> = vec![0; 256];

    for i in 0..=property_index {
        let prop = unsafe {
            let props_ptr =
                std::ptr::addr_of!(info.EventPropertyInfoArray).cast::<EVENT_PROPERTY_INFO>();
            &*props_ptr.add(i)
        };

        let in_type = unsafe { prop.Anonymous1.nonStructType.InType };
        let out_type = unsafe { prop.Anonymous1.nonStructType.OutType };

        let prop_length = unsafe {
            if (prop.Flags.0 & PropertyParamLength.0) != 0 {
                0u16
            } else {
                prop.Anonymous3.length
            }
        };

        let remaining_data = &user_data[data_offset..];
        if remaining_data.is_empty() {
            return None;
        }

        loop {
            let mut buffer_size = (output_buffer.len() * 2) as u32;
            let mut consumed = 0u16;

            let status = unsafe {
                TdhFormatProperty(
                    std::ptr::from_ref(info).cast_mut(),
                    None,
                    pointer_size as u32,
                    in_type,
                    out_type,
                    prop_length,
                    remaining_data,
                    &raw mut buffer_size,
                    Some(PWSTR(output_buffer.as_mut_ptr())),
                    &raw mut consumed,
                )
            };

            if status == ERROR_INSUFFICIENT_BUFFER.0 && output_buffer.len() < 8192 {
                output_buffer.resize((buffer_size / 2 + 1) as usize, 0);
                continue;
            }

            if status != 0 {
                return None;
            }

            data_offset += consumed as usize;

            if i == property_index {
                let len = output_buffer
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(output_buffer.len());
                return Some(output_buffer[..len].to_vec());
            }

            break;
        }
    }

    None
}

/// Parse a property using TdhFormatProperty with CACHED schema, returning raw UTF-16.
fn parse_property_tdh_cached_utf16(
    schema_buffer: &[u8],
    event: &EVENT_RECORD,
    property_index: usize,
) -> Option<Vec<u16>> {
    let info = unsafe { &*schema_buffer.as_ptr().cast::<TRACE_EVENT_INFO>() };

    let pointer_size = 8u8; // 64-bit only

    let user_data = if event.UserDataLength > 0 && !event.UserData.is_null() {
        unsafe {
            std::slice::from_raw_parts(event.UserData as *const u8, event.UserDataLength as usize)
        }
    } else {
        return None;
    };

    parse_property_with_tdh_utf16(info, user_data, property_index, pointer_size)
}

/// Find property index by name in TRACE_EVENT_INFO.
///
/// This is the name lookup cost that TdhFormatProperty doesn't include.
fn find_property_index(info: &TRACE_EVENT_INFO, property_name: &str) -> Option<usize> {
    for i in 0..info.TopLevelPropertyCount as usize {
        let prop = unsafe {
            let props_ptr =
                std::ptr::addr_of!(info.EventPropertyInfoArray).cast::<EVENT_PROPERTY_INFO>();
            &*props_ptr.add(i)
        };

        // Get property name from the schema buffer
        let name_offset = prop.NameOffset as usize;
        if name_offset == 0 {
            continue;
        }

        // Property name is a wide string at NameOffset from start of TRACE_EVENT_INFO
        let info_ptr = std::ptr::from_ref(info).cast::<u8>();
        let name_ptr = unsafe { info_ptr.add(name_offset).cast::<u16>() };

        // Read the wide string
        let mut len = 0;
        while unsafe { *name_ptr.add(len) } != 0 && len < 256 {
            len += 1;
        }
        let name_slice = unsafe { std::slice::from_raw_parts(name_ptr, len) };
        if let Ok(name) = String::from_utf16(name_slice)
            && name == property_name
        {
            return Some(i);
        }
    }
    None
}

/// Parse a property using TdhFormatProperty - FULLY EQUIVALENT to get().
///
/// This function takes ONLY what get() has access to:
/// - EVENT_RECORD (the raw event)
/// - property_name (the field name to retrieve)
///
/// It must:
/// 1. Call TdhGetEventInformation to get the schema (like our schema cache does)
/// 2. Find the property index by searching property names
/// 3. Iterate through properties using TdhFormatProperty
/// 4. Return the parsed string
///
/// This is the fair apples-to-apples comparison with get().
fn parse_property_tdh_equivalent(event: &EVENT_RECORD, property_name: &str) -> Option<String> {
    // Step 1: Get schema from TDH (equivalent to schema cache lookup)
    let schema_buffer = get_schema_buffer(event).ok()?;
    let info = unsafe { &*schema_buffer.as_ptr().cast::<TRACE_EVENT_INFO>() };

    // Step 2: Find property index by name (equivalent to get()'s name lookup)
    let property_index = find_property_index(info, property_name)?;

    // Step 3: Get pointer size from event flags
    let pointer_size = 8u8; // 64-bit only

    // Step 4: Get user data
    let user_data = if event.UserDataLength > 0 && !event.UserData.is_null() {
        unsafe {
            std::slice::from_raw_parts(event.UserData as *const u8, event.UserDataLength as usize)
        }
    } else {
        return None;
    };

    // Step 5: Parse using TdhFormatProperty (equivalent to FromProperty parsing)
    parse_property_with_tdh(info, user_data, property_index, pointer_size)
}

/// Parse a property using TdhFormatProperty with CACHED schema.
///
/// This is equivalent to get() when the schema is already cached.
/// Takes:
/// - Pre-cached schema buffer
/// - EVENT_RECORD (for user data)
/// - property_name
fn parse_property_tdh_cached(
    schema_buffer: &[u8],
    event: &EVENT_RECORD,
    property_name: &str,
) -> Option<String> {
    let info = unsafe { &*schema_buffer.as_ptr().cast::<TRACE_EVENT_INFO>() };

    // Find property index by name
    let property_index = find_property_index(info, property_name)?;

    // Get pointer size from event flags
    let pointer_size = 8u8; // 64-bit only

    // Get user data
    let user_data = if event.UserDataLength > 0 && !event.UserData.is_null() {
        unsafe {
            std::slice::from_raw_parts(event.UserData as *const u8, event.UserDataLength as usize)
        }
    } else {
        return None;
    };

    // Parse using TdhFormatProperty
    parse_property_with_tdh(info, user_data, property_index, pointer_size)
}

/// Parse a property using TdhGetProperty (Windows API).
///
/// TdhGetProperty allows random access by property name, but is less efficient
/// than sequential iteration because it must scan properties each time.
fn parse_property_with_tdh_get(event: &EVENT_RECORD, property_name: &str) -> Option<String> {
    // Convert property name to wide string
    let wide_name: Vec<u16> = property_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // Set up property descriptor
    let pdd = PROPERTY_DATA_DESCRIPTOR {
        PropertyName: wide_name.as_ptr() as usize as u64,
        ArrayIndex: u32::MAX, // ULONG_MAX means not an array element
        Reserved: 0,
    };

    // First, get the size needed
    let mut size = 0u32;
    let status =
        unsafe { TdhGetPropertySize(event, None, std::slice::from_ref(&pdd), &raw mut size) };

    if status != 0 || size == 0 {
        return None;
    }

    // Allocate buffer and get property
    let mut buffer = vec![0u8; size as usize];
    let status = unsafe { TdhGetProperty(event, None, std::slice::from_ref(&pdd), &mut buffer) };

    if status != 0 {
        return None;
    }

    // Try to interpret as wide string (most common case)
    // This is a simplification - real code would check the property type
    if buffer.len() >= 2 {
        let wide: Vec<u16> = buffer
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let len = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
        return String::from_utf16(&wide[..len]).ok();
    }

    None
}

/// Parse a property using TdhGetProperty, returning raw UTF-16.
///
/// This is for fair comparison with etw-rs WideString (no UTF-16→UTF-8 conversion).
fn parse_property_with_tdh_get_utf16(
    event: &EVENT_RECORD,
    property_name: &str,
) -> Option<Vec<u16>> {
    let wide_name: Vec<u16> = property_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let pdd = PROPERTY_DATA_DESCRIPTOR {
        PropertyName: wide_name.as_ptr() as usize as u64,
        ArrayIndex: u32::MAX,
        Reserved: 0,
    };

    let mut size = 0u32;
    let status =
        unsafe { TdhGetPropertySize(event, None, std::slice::from_ref(&pdd), &raw mut size) };

    if status != 0 || size == 0 {
        return None;
    }

    let mut buffer = vec![0u8; size as usize];
    let status = unsafe { TdhGetProperty(event, None, std::slice::from_ref(&pdd), &mut buffer) };

    if status != 0 {
        return None;
    }

    if buffer.len() >= 2 {
        let wide: Vec<u16> = buffer
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let len = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
        return Some(wide[..len].to_vec());
    }

    None
}

// =============================================================================
// Benchmarks
// =============================================================================

/// Benchmark get() vs TDH APIs for shallow fields (index 0).
///
/// EQUIVALENT COMPARISONS - both sides have the same information:
/// 1. CACHED: Schema already retrieved, only need property name
/// 2. UNCACHED: Must retrieve schema first, then parse by name
fn bench_shallow_fields(c: &mut Criterion) {
    let events = match capture_dns_events(50) {
        Some(e) if !e.is_empty() => e,
        _ => {
            eprintln!("Skipping shallow_fields benchmark: no events captured");
            return;
        }
    };

    // Use first event for consistent benchmarking
    let event = &events[0];
    let record = event.to_event_record();

    // Get first field name (we need this for both sides)
    let first_field = {
        let schema_buffer = get_schema_buffer(&record).unwrap();
        let info = unsafe { &*schema_buffer.as_ptr().cast::<TRACE_EVENT_INFO>() };
        // Get first property name
        if info.TopLevelPropertyCount > 0 {
            let prop = unsafe {
                let props_ptr =
                    std::ptr::addr_of!(info.EventPropertyInfoArray).cast::<EVENT_PROPERTY_INFO>();
                &*props_ptr
            };
            let name_offset = prop.NameOffset as usize;
            if name_offset > 0 {
                let info_ptr = std::ptr::from_ref(info).cast::<u8>();
                let name_ptr = unsafe { info_ptr.add(name_offset).cast::<u16>() };
                let mut len = 0;
                while unsafe { *name_ptr.add(len) } != 0 && len < 256 {
                    len += 1;
                }
                let name_slice = unsafe { std::slice::from_raw_parts(name_ptr, len) };
                String::from_utf16(name_slice).unwrap_or_else(|_| "Field0".to_owned())
            } else {
                "Field0".to_owned()
            }
        } else {
            "Field0".to_owned()
        }
    };

    println!("\n=== Shallow Field Benchmarks (index 0) ===");
    println!("Field: '{first_field}'");

    let field_index = 0usize;

    // Validate all parsing methods produce the same result
    {
        // etw-rs with fresh cache
        let mut parser_cache = etw::processing_context::ProcessingContext::new();
        let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
        let mut parser = parser_cache.parser(raw_event).unwrap();
        let etw_rs_get: Result<String, _> = parser.get(&first_field);
        let etw_rs_hinted: Result<etw::WideString, _> =
            parser.get_hinted(&first_field, field_index as u32);

        // TdhFormatProperty equivalent (full path)
        let tdh_format_equiv = parse_property_tdh_equivalent(&record, &first_field);

        // TdhGetProperty
        let tdh_get_result = parse_property_with_tdh_get(&record, &first_field);

        println!("Validation (all should match):");
        println!(
            "  etw-rs get():           {:?}",
            etw_rs_get
                .as_ref()
                .map(|s| s.chars().take(40).collect::<String>())
        );
        println!(
            "  etw-rs get_hinted():    {:?}",
            etw_rs_hinted
                .as_ref()
                .ok()
                .and_then(|ws| ws.decode_utf16().ok())
                .map(|s| s.chars().take(40).collect::<String>())
        );
        println!(
            "  TdhFormatProperty:      {:?}",
            tdh_format_equiv
                .as_ref()
                .map(|s| s.chars().take(40).collect::<String>())
        );
        println!(
            "  TdhGetProperty:         {:?}",
            tdh_get_result
                .as_ref()
                .map(|s| s.chars().take(40).collect::<String>())
        );
    }

    // ==========================================================================
    // EQUIVALENT COMPARISON - CACHED SCHEMA
    // Both sides: have cached schema, given property name, must parse
    // Compares all 4 methods: get(), get_hinted(), TdhFormatProperty, TdhGetProperty
    // ==========================================================================
    {
        let mut group = c.benchmark_group("shallow_cached");

        // Pre-populate etw-rs cache
        let mut parser_cache = etw::processing_context::ProcessingContext::new();
        {
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
            let _ = parser_cache.get_or_lookup(raw_event);
        }

        // Pre-cache TDH schema buffer
        let tdh_schema_buffer = event.schema_buffer.clone();

        // etw-rs get(): cached schema + name lookup + parsing → String
        group.bench_function("etw_rs_get", |b| {
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
            let mut parser = parser_cache.parser(raw_event).unwrap();
            b.iter(|| {
                let result: Result<String, _> = parser.get(&first_field);
                bb(result.ok())
            });
        });

        // etw-rs get_hinted(): cached schema + UTF-16 name + index hint → WideString
        group.bench_function("etw_rs_get_hinted", |b| {
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
            let mut parser = parser_cache.parser(raw_event).unwrap();
            b.iter(|| {
                let result: Result<etw::WideString, _> =
                    parser.get_hinted(&first_field, field_index as u32);
                bb(result.ok())
            });
        });

        // TdhFormatProperty: cached schema + name lookup + parsing → String
        group.bench_function("tdh_format_property", |b| {
            b.iter(|| {
                let result = parse_property_tdh_cached(&tdh_schema_buffer, &record, &first_field);
                bb(result)
            });
        });

        // TdhGetProperty: does its own schema lookup internally each time → String
        group.bench_function("tdh_get_property", |b| {
            b.iter(|| {
                let result = parse_property_with_tdh_get(&record, &first_field);
                bb(result)
            });
        });

        group.finish();
    }

    // ==========================================================================
    // EQUIVALENT COMPARISON - UNCACHED (COLD PATH)
    // Both sides: must retrieve schema, given property name, must parse
    // Compares all 4 methods: get(), get_hinted(), TdhFormatProperty, TdhGetProperty
    // ==========================================================================
    {
        let mut group = c.benchmark_group("shallow_uncached");

        // etw-rs get(): fresh schema lookup + name lookup + parsing → String
        group.bench_function("etw_rs_get", |b| {
            b.iter(|| {
                // Create fresh cache each time to force TDH lookup
                let mut parser_cache = etw::processing_context::ProcessingContext::new();
                let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
                let mut parser = parser_cache.parser(raw_event).unwrap();
                let result: Result<String, _> = parser.get(&first_field);
                bb(result.ok())
            });
        });

        // etw-rs get_hinted(): fresh schema lookup + UTF-16 name + index hint → WideString
        group.bench_function("etw_rs_get_hinted", |b| {
            b.iter(|| {
                let mut parser_cache = etw::processing_context::ProcessingContext::new();
                let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
                let mut parser = parser_cache.parser(raw_event).unwrap();
                let result: Result<etw::WideString, _> =
                    parser.get_hinted(&first_field, field_index as u32);
                bb(result.ok())
            });
        });

        // TdhFormatProperty: fresh TdhGetEventInformation + name lookup + parsing → String
        group.bench_function("tdh_format_property", |b| {
            b.iter(|| {
                let result = parse_property_tdh_equivalent(&record, &first_field);
                bb(result)
            });
        });

        // TdhGetProperty: does its own schema lookup internally → String
        group.bench_function("tdh_get_property", |b| {
            b.iter(|| {
                let result = parse_property_with_tdh_get(&record, &first_field);
                bb(result)
            });
        });

        group.finish();
    }
}

/// Benchmark get() vs TDH APIs for deep fields using ProcessStart events.
///
/// ProcessStart events have string fields at various depths:
/// - ImageName (typically around index 4-5)
/// - CommandLine (typically the last field, index ~7)
///
/// This tests parsing performance for fields that require iterating through
/// multiple prior fields to reach.
///
/// EQUIVALENT COMPARISONS - both sides have the same information:
/// 1. CACHED: Schema already retrieved, only need property name
/// 2. UNCACHED: Must retrieve schema first, then parse by name
fn bench_deep_fields(c: &mut Criterion) {
    let events = match capture_process_events(10) {
        Some(e) if !e.is_empty() => e,
        _ => {
            eprintln!("Skipping deep_fields benchmark: no ProcessStart events captured");
            return;
        }
    };

    let event = &events[0];
    let record = event.to_event_record();

    let field_count = event.property_count();

    // Find the CommandLine field index (it's the deepest string field)
    let schema_buffer = get_schema_buffer(&record).unwrap();
    let info = unsafe { &*schema_buffer.as_ptr().cast::<TRACE_EVENT_INFO>() };

    let mut deep_field: Option<(usize, String)> = None;

    // Search for "CommandLine" field specifically, or fall back to last string field
    for i in 0..field_count as usize {
        let prop = unsafe {
            let props_ptr =
                std::ptr::addr_of!(info.EventPropertyInfoArray).cast::<EVENT_PROPERTY_INFO>();
            &*props_ptr.add(i)
        };

        let name_offset = prop.NameOffset as usize;
        if name_offset == 0 {
            continue;
        }

        let info_ptr = std::ptr::from_ref(info).cast::<u8>();
        let name_ptr = unsafe { info_ptr.add(name_offset).cast::<u16>() };
        let mut len = 0;
        while unsafe { *name_ptr.add(len) } != 0 && len < 256 {
            len += 1;
        }
        let name_slice = unsafe { std::slice::from_raw_parts(name_ptr, len) };
        if let Ok(name) = String::from_utf16(name_slice) {
            if name == "CommandLine" {
                deep_field = Some((i, name));
                break;
            }
            // Keep track of last string field as fallback
            let in_type = unsafe { prop.Anonymous1.nonStructType.InType };
            if in_type == 1 || in_type == 2 {
                deep_field = Some((i, name));
            }
        }
    }

    let Some((deep_index, deep_field_name)) = deep_field else {
        eprintln!("Skipping deep_fields benchmark: no string field found");
        return;
    };

    println!("\n=== Deep Field Benchmarks (index {deep_index}) ===");
    println!("Field: '{deep_field_name}' (of {field_count} fields)");

    // Validate all parsing methods produce the same result
    {
        let mut parser_cache = etw::processing_context::ProcessingContext::new();
        let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
        let mut parser = parser_cache.parser(raw_event).unwrap();
        let etw_rs_get: Result<String, _> = parser.get(&deep_field_name);
        let etw_rs_hinted: Result<etw::WideString, _> =
            parser.get_hinted(&deep_field_name, deep_index as u32);

        let tdh_format_equiv = parse_property_tdh_equivalent(&record, &deep_field_name);
        let tdh_get_result = parse_property_with_tdh_get(&record, &deep_field_name);

        println!("Validation (all should match):");
        println!(
            "  etw-rs get():           {:?}",
            etw_rs_get
                .as_ref()
                .map(|s| s.chars().take(40).collect::<String>())
        );
        println!(
            "  etw-rs get_hinted():    {:?}",
            etw_rs_hinted
                .as_ref()
                .ok()
                .and_then(|ws| ws.decode_utf16().ok())
                .map(|s| s.chars().take(40).collect::<String>())
        );
        println!(
            "  TdhFormatProperty:      {:?}",
            tdh_format_equiv
                .as_ref()
                .map(|s| s.chars().take(40).collect::<String>())
        );
        println!(
            "  TdhGetProperty:         {:?}",
            tdh_get_result
                .as_ref()
                .map(|s| s.chars().take(40).collect::<String>())
        );
    }

    // ==========================================================================
    // EQUIVALENT COMPARISON - CACHED SCHEMA
    // Compares all 4 methods: get(), get_hinted(), TdhFormatProperty, TdhGetProperty
    // ==========================================================================
    {
        let mut group = c.benchmark_group("deep_cached");

        // Pre-populate etw-rs cache
        let mut parser_cache = etw::processing_context::ProcessingContext::new();
        {
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
            let _ = parser_cache.get_or_lookup(raw_event);
        }

        // Pre-cache TDH schema buffer
        let tdh_schema_buffer = event.schema_buffer.clone();

        // etw-rs get(): cached schema + name lookup + parsing → String
        group.bench_function("etw_rs_get", |b| {
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
            let mut parser = parser_cache.parser(raw_event).unwrap();
            b.iter(|| {
                let result: Result<String, _> = parser.get(&deep_field_name);
                bb(result.ok())
            });
        });

        // etw-rs get_hinted(): cached schema + UTF-16 name + index hint → WideString
        group.bench_function("etw_rs_get_hinted", |b| {
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
            let mut parser = parser_cache.parser(raw_event).unwrap();
            b.iter(|| {
                let result: Result<etw::WideString, _> =
                    parser.get_hinted(&deep_field_name, deep_index as u32);
                bb(result.ok())
            });
        });

        // TdhFormatProperty: cached schema + name lookup + parsing → String
        group.bench_function("tdh_format_property", |b| {
            b.iter(|| {
                let result =
                    parse_property_tdh_cached(&tdh_schema_buffer, &record, &deep_field_name);
                bb(result)
            });
        });

        // TdhGetProperty: does its own schema lookup internally each time → String
        group.bench_function("tdh_get_property", |b| {
            b.iter(|| {
                let result = parse_property_with_tdh_get(&record, &deep_field_name);
                bb(result)
            });
        });

        group.finish();
    }

    // ==========================================================================
    // EQUIVALENT COMPARISON - UNCACHED (COLD PATH)
    // Compares all 4 methods: get(), get_hinted(), TdhFormatProperty, TdhGetProperty
    // ==========================================================================
    {
        let mut group = c.benchmark_group("deep_uncached");

        // etw-rs get(): fresh schema lookup + name lookup + parsing → String
        group.bench_function("etw_rs_get", |b| {
            b.iter(|| {
                let mut parser_cache = etw::processing_context::ProcessingContext::new();
                let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
                let mut parser = parser_cache.parser(raw_event).unwrap();
                let result: Result<String, _> = parser.get(&deep_field_name);
                bb(result.ok())
            });
        });

        // etw-rs get_hinted(): fresh schema lookup + UTF-16 name + index hint → WideString
        group.bench_function("etw_rs_get_hinted", |b| {
            b.iter(|| {
                let mut parser_cache = etw::processing_context::ProcessingContext::new();
                let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
                let mut parser = parser_cache.parser(raw_event).unwrap();
                let result: Result<etw::WideString, _> =
                    parser.get_hinted(&deep_field_name, deep_index as u32);
                bb(result.ok())
            });
        });

        // TdhFormatProperty: fresh TdhGetEventInformation + name lookup + parsing → String
        group.bench_function("tdh_format_property", |b| {
            b.iter(|| {
                let result = parse_property_tdh_equivalent(&record, &deep_field_name);
                bb(result)
            });
        });

        // TdhGetProperty: does its own schema lookup internally → String
        group.bench_function("tdh_get_property", |b| {
            b.iter(|| {
                let result = parse_property_with_tdh_get(&record, &deep_field_name);
                bb(result)
            });
        });

        group.finish();
    }
}

/// Benchmark TdhGetEventInformation vs our schema cache.
///
/// This is a full comparison of schema retrieval:
/// - TdhGetEventInformation (Windows API)
/// - etw-rs ProcessingContext (our implementation)
fn bench_schema_comparison(c: &mut Criterion) {
    let events = match capture_dns_events(10) {
        Some(e) if !e.is_empty() => e,
        _ => {
            eprintln!("Skipping schema comparison benchmark: no events captured");
            return;
        }
    };

    let event = &events[0];
    let record = event.to_event_record();

    println!("\n=== Schema Retrieval Comparison ===");
    println!("Schema buffer size: {} bytes", event.schema_buffer.len());
    println!("Property count: {}", event.property_count());

    // ==========================================================================
    // CACHED SCHEMA RETRIEVAL
    // ==========================================================================
    {
        let mut group = c.benchmark_group("schema_cached");

        // Pre-populate etw-rs cache
        let mut parser_cache = etw::processing_context::ProcessingContext::new();
        {
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
            let _ = parser_cache.get_or_lookup(raw_event);
        }

        // etw-rs: cache hit (HashMap lookup + Arc clone)
        group.bench_function("etw_rs_cache_hit", |b| {
            b.iter(|| {
                let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
                let schema = parser_cache.get_or_lookup(raw_event).unwrap();
                bb(schema.property_count())
            });
        });

        // TdhGetEventInformation: repeated calls (may be cached by TDH internally)
        group.bench_function("tdh_get_event_info", |b| {
            b.iter(|| {
                let schema_buffer = get_schema_buffer(&record).unwrap();
                bb(schema_buffer.len())
            });
        });

        group.finish();
    }

    // ==========================================================================
    // UNCACHED SCHEMA RETRIEVAL (COLD PATH)
    // ==========================================================================
    {
        let mut group = c.benchmark_group("schema_uncached");

        // etw-rs: cache miss (must call TdhGetEventInformation + cache insert)
        group.bench_function("etw_rs_cache_miss", |b| {
            b.iter(|| {
                let mut parser_cache = etw::processing_context::ProcessingContext::new();
                let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
                let schema = parser_cache.get_or_lookup(raw_event).unwrap();
                bb(schema.property_count())
            });
        });

        // TdhGetEventInformation: single call
        group.bench_function("tdh_get_event_info", |b| {
            b.iter(|| {
                let schema_buffer = get_schema_buffer(&record).unwrap();
                bb(schema_buffer.len())
            });
        });

        group.finish();
    }

    // ==========================================================================
    // PARSER CREATION COST
    // ==========================================================================
    {
        let mut group = c.benchmark_group("parser_creation");

        let mut parser_cache = etw::processing_context::ProcessingContext::new();
        {
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
            let _ = parser_cache.get_or_lookup(raw_event);
        }

        // etw-rs: parser creation from cached schema
        group.bench_function("etw_rs_parser_create", |b| {
            b.iter(|| {
                let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
                let mut parser = parser_cache.parser(raw_event).unwrap();
                // Just validate parser was created (try a get on non-existent field)
                let _: Result<u32, _> = parser.get("__nonexistent__");
                bb(true)
            });
        });

        group.finish();
    }

    // ==========================================================================
    // TDH CACHING DIAGNOSTIC
    // ==========================================================================
    println!("\n=== TDH Internal Caching Diagnostic ===");
    {
        use std::time::Instant;

        if let Some(fresh_event) = events.last() {
            let fresh_record = fresh_event.to_event_record();

            // Measure first call
            let start = Instant::now();
            let _ = get_schema_buffer(&fresh_record);
            let first_call = start.elapsed();

            // Measure subsequent calls (average of 10)
            let start = Instant::now();
            for _ in 0..10 {
                let _ = get_schema_buffer(&fresh_record);
            }
            let subsequent_avg = start.elapsed() / 10;

            println!("  First TdhGetEventInformation call: {first_call:?}");
            println!("  Subsequent calls (avg of 10):      {subsequent_avg:?}");
            #[expect(clippy::cast_precision_loss, reason = "f64 for timing ratio display")]
            let ratio = first_call.as_nanos() as f64 / subsequent_avg.as_nanos() as f64;
            println!("  Ratio (first/subsequent):          {ratio:.2}x");

            if first_call > subsequent_avg * 2 {
                println!("  -> TDH appears to cache internally (first call significantly slower)");
            } else {
                println!("  -> TDH does not appear to cache (consistent timing)");
            }
        }
    }
    println!("=======================================\n");
}

/// Benchmark zero-copy string access vs allocating access.
///
/// This compares:
/// - `get::<String>()`: Allocates, converts UTF-16→UTF-8
/// - `get_wide()`: Zero-copy, returns WideStrRef referencing buffer
/// - `get_wide().decode_utf16()`: Zero-copy access + deferred conversion
fn bench_zero_copy_strings(c: &mut Criterion) {
    // Try DNS events first, fall back to process events
    let events = capture_dns_events(50)
        .filter(|e| !e.is_empty())
        .or_else(|| {
            eprintln!("DNS events unavailable, using process events for zero_copy benchmark");
            capture_process_events(10)
        });

    let events = match events {
        Some(e) if !e.is_empty() => e,
        _ => {
            eprintln!("Skipping zero_copy_strings benchmark: no events captured");
            return;
        }
    };

    let event = &events[0];
    let record = event.to_event_record();

    // Find a Unicode string field for testing
    let schema_buffer = get_schema_buffer(&record).unwrap();
    let info = unsafe { &*schema_buffer.as_ptr().cast::<TRACE_EVENT_INFO>() };

    let mut string_field: Option<(usize, String)> = None;
    for i in 0..info.TopLevelPropertyCount as usize {
        let prop = unsafe {
            let props_ptr =
                std::ptr::addr_of!(info.EventPropertyInfoArray).cast::<EVENT_PROPERTY_INFO>();
            &*props_ptr.add(i)
        };

        let in_type = unsafe { prop.Anonymous1.nonStructType.InType };
        let name_offset = prop.NameOffset as usize;

        if name_offset > 0 && in_type == 1 {
            // InType 1 = UnicodeString
            let info_ptr = std::ptr::from_ref(info).cast::<u8>();
            let name_ptr = unsafe { info_ptr.add(name_offset).cast::<u16>() };
            let mut len = 0;
            while unsafe { *name_ptr.add(len) } != 0 && len < 256 {
                len += 1;
            }
            let name_slice = unsafe { std::slice::from_raw_parts(name_ptr, len) };
            if let Ok(name) = String::from_utf16(name_slice) {
                string_field = Some((i, name));
                break;
            }
        }
    }

    let Some((field_index, field_name)) = string_field else {
        eprintln!("Skipping zero_copy_strings benchmark: no Unicode string field found");
        return;
    };

    println!("\n=== Zero-Copy String Benchmarks ===");
    println!("Field: '{field_name}' at index {field_index}");

    let mut parser_cache = etw::processing_context::ProcessingContext::new();
    {
        let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
        let _ = parser_cache.get_or_lookup(raw_event);
    }

    // Validate all methods produce the same string
    {
        let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
        let mut parser = parser_cache.parser(raw_event).unwrap();

        let allocating: String = parser.get(&field_name).unwrap_or_else(|_| String::new());
        let zero_copy_str: String = parser
            .as_ref::<etw::WideStrRef>(&field_name)
            .ok()
            .map(|ws| ws.to_string_lossy())
            .unwrap_or_default();
        let wide_len = parser
            .as_ref::<etw::WideStrRef>(&field_name)
            .ok()
            .and_then(|ws| ws.as_wide_slice())
            .map_or(0, <[u16]>::len);

        println!("Validation:");
        println!(
            "  get::<String>():        {:?}",
            allocating.chars().take(40).collect::<String>()
        );
        println!(
            "  get_wide().decode_utf16(): {:?}",
            zero_copy_str.chars().take(40).collect::<String>()
        );
        println!("  get_wide() (raw len):   {wide_len} u16 units");
    }

    // ==========================================================================
    // ZERO-COPY VS ALLOCATING STRING ACCESS
    // ==========================================================================
    {
        let mut group = c.benchmark_group("string_access");

        // get::<String>() - allocates and converts
        group.bench_function("get_string_allocating", |b| {
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
            let mut parser = parser_cache.parser(raw_event).unwrap();
            b.iter(|| {
                let result: Result<String, _> = parser.get(&field_name);
                bb(result.ok())
            });
        });

        // get_wide() - zero-copy, no allocation (measure via is_empty check)
        group.bench_function("get_wide_zero_copy", |b| {
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
            let mut parser = parser_cache.parser(raw_event).unwrap();
            b.iter(|| {
                let result = parser.as_ref::<etw::WideStrRef>(&field_name);
                // Use a non-allocating check to verify we got the data
                bb(result.map_or(true, |ws| ws.is_empty()))
            });
        });

        // get_wide().to_string_lossy() - zero-copy access + deferred conversion
        group.bench_function("get_wide_then_convert", |b| {
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
            let mut parser = parser_cache.parser(raw_event).unwrap();
            b.iter(|| {
                let result = parser
                    .as_ref::<etw::WideStrRef>(&field_name)
                    .map(|ws| ws.to_string_lossy());
                bb(result.ok())
            });
        });

        group.finish();
    }

    // ==========================================================================
    // ZERO-COPY STRING OPERATIONS (without conversion)
    // These benchmarks show operations you can do on WideStrRef without allocation
    // ==========================================================================
    {
        let mut group = c.benchmark_group("zero_copy_operations");

        // Compare with ASCII (common use case: checking if field matches a known value)
        group.bench_function("wide_eq_ascii", |b| {
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
            let mut parser = parser_cache.parser(raw_event).unwrap();
            b.iter(|| {
                if let Ok(ws) = parser.as_ref::<etw::WideStrRef>(&field_name) {
                    bb(ws.eq_ascii("example.com"))
                } else {
                    bb(false)
                }
            });
        });

        // Check if string starts with a prefix (e.g., filtering by domain)
        group.bench_function("wide_starts_with_ascii", |b| {
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
            let mut parser = parser_cache.parser(raw_event).unwrap();
            b.iter(|| {
                if let Ok(ws) = parser.as_ref::<etw::WideStrRef>(&field_name) {
                    bb(ws.starts_with_ascii("test"))
                } else {
                    bb(false)
                }
            });
        });

        // Check if string contains a substring
        group.bench_function("wide_contains_ascii", |b| {
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
            let mut parser = parser_cache.parser(raw_event).unwrap();
            b.iter(|| {
                if let Ok(ws) = parser.as_ref::<etw::WideStrRef>(&field_name) {
                    bb(ws.contains_ascii(".local"))
                } else {
                    bb(false)
                }
            });
        });

        // For comparison: same check but converting to String first (the slow way)
        group.bench_function("string_contains_via_allocation", |b| {
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
            let mut parser = parser_cache.parser(raw_event).unwrap();
            b.iter(|| {
                let result: Result<String, _> = parser.get(&field_name);
                if let Ok(s) = result {
                    bb(s.contains(".local"))
                } else {
                    bb(false)
                }
            });
        });

        group.finish();
    }
}

/// Comprehensive benchmark for different property types.
///
/// Tests all 5 methods (get, get_hinted, get_at, TdhFormatProperty, TdhGetProperty)
/// for each data type. Where TDH returns a formatted string but the target type is
/// not a string, the conversion cost is included in the comparison.
///
/// Types tested:
/// - u32 (ProcessID) - integer
/// - u64 (DirectoryTableBase) - large integer
/// - SID (UserSID) - security identifier
/// - WideString (ImageName) - Unicode string
fn bench_property_types(c: &mut Criterion) {
    // Use ProcessStart events - they have multiple field types
    let events = match capture_process_events(10) {
        Some(e) if !e.is_empty() => e,
        _ => {
            eprintln!("Skipping property_types benchmark: no ProcessStart events captured");
            return;
        }
    };

    let event = &events[0];
    let record = event.to_event_record();

    // Pre-populate caches
    let mut parser_cache = etw::processing_context::ProcessingContext::new();
    {
        let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
        let _ = parser_cache.get_or_lookup(raw_event);
    }
    let tdh_schema_buffer = event.schema_buffer.clone();

    // Property locations in ProcessStart v4 event.
    let u32_field = "ProcessID";
    let u32_index = 0usize;
    let u64_field = "ParentProcessSequenceNumber";
    let u64_index = 4usize;
    let sid_field = "MandatoryLabel";
    let sid_index = 9usize;
    let string_field = "ImageName";
    let string_index = 10usize;

    println!("\n=== Property Type Benchmarks (All 5 Methods) ===");
    println!("u32 field: '{u32_field}' at index {u32_index}");
    println!("u64 field: '{u64_field}' at index {u64_index}");
    println!("SID field: '{sid_field}' at index {sid_index}");
    println!("String field: '{string_field}' at index {string_index}");

    // ==========================================================================
    // TYPE: u32 (ProcessID)
    // etw-rs returns u32 directly, TDH returns formatted string that must be parsed
    // ==========================================================================
    {
        let mut group = c.benchmark_group("type_u32");

        // Validate
        {
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
            let mut parser = parser_cache.parser(raw_event).unwrap();
            let etw_get: Result<u32, _> = parser.get(u32_field);
            let tdh_str = parse_property_tdh_cached(&tdh_schema_buffer, &record, u32_field);
            let tdh_get = parse_property_with_tdh_get(&record, u32_field);
            println!("\nu32 validation:");
            println!("  etw-rs get():       {etw_get:?}");
            println!("  TdhFormatProperty:  {tdh_str:?} (as string)");
            println!("  TdhGetProperty:     {tdh_get:?} (as string)");
        }

        // etw-rs get() → u32 directly
        group.bench_function("etw_rs_get", |b| {
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
            let mut parser = parser_cache.parser(raw_event).unwrap();
            b.iter(|| {
                let result: Result<u32, _> = parser.get(u32_field);
                bb(result.ok())
            });
        });

        // etw-rs get_hinted() → u32 directly
        group.bench_function("etw_rs_get_hinted", |b| {
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
            let mut parser = parser_cache.parser(raw_event).unwrap();
            b.iter(|| {
                let result: Result<u32, _> = parser.get_hinted(u32_field, u32_index as u32);
                bb(result.ok())
            });
        });

        // TdhFormatProperty → String → parse to u32 (fair comparison)
        group.bench_function("tdh_format_property", |b| {
            b.iter(|| {
                let result = parse_property_tdh_cached(&tdh_schema_buffer, &record, u32_field)
                    .and_then(|s| s.parse::<u32>().ok());
                bb(result)
            });
        });

        // TdhGetProperty → String → parse to u32 (fair comparison)
        group.bench_function("tdh_get_property", |b| {
            b.iter(|| {
                let result = parse_property_with_tdh_get(&record, u32_field)
                    .and_then(|s| s.parse::<u32>().ok());
                bb(result)
            });
        });

        group.finish();
    }

    // ==========================================================================
    // TYPE: u64 (ParentProcessSequenceNumber)
    // etw-rs returns u64 directly, TDH returns formatted string
    // ==========================================================================
    {
        let mut group = c.benchmark_group("type_u64");

        // Validate
        {
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
            let mut parser = parser_cache.parser(raw_event).unwrap();
            let etw_get: Result<u64, _> = parser.get(u64_field);
            let tdh_str = parse_property_tdh_cached(&tdh_schema_buffer, &record, u64_field);
            println!("\nu64 validation:");
            println!("  etw-rs get():       {etw_get:?}");
            println!("  TdhFormatProperty:  {tdh_str:?} (as string)");
        }

        // etw-rs get() → u64 directly
        group.bench_function("etw_rs_get", |b| {
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
            let mut parser = parser_cache.parser(raw_event).unwrap();
            b.iter(|| {
                let result: Result<u64, _> = parser.get(u64_field);
                bb(result.ok())
            });
        });

        // etw-rs get_hinted() → u64 directly
        group.bench_function("etw_rs_get_hinted", |b| {
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
            let mut parser = parser_cache.parser(raw_event).unwrap();
            b.iter(|| {
                let result: Result<u64, _> = parser.get_hinted(u64_field, u64_index as u32);
                bb(result.ok())
            });
        });

        // TdhFormatProperty → String → parse to u64 (fair comparison)
        // Note: TDH formats u64 as hex string (0x...) so we parse both formats
        group.bench_function("tdh_format_property", |b| {
            b.iter(|| {
                let result = parse_property_tdh_cached(&tdh_schema_buffer, &record, u64_field)
                    .and_then(|s| {
                        // Try decimal first, then hex
                        s.parse::<u64>().ok().or_else(|| {
                            s.strip_prefix("0x")
                                .or_else(|| s.strip_prefix("0X"))
                                .and_then(|hex| u64::from_str_radix(hex, 16).ok())
                        })
                    });
                bb(result)
            });
        });

        // TdhGetProperty → String → parse to u64 (fair comparison)
        group.bench_function("tdh_get_property", |b| {
            b.iter(|| {
                let result = parse_property_with_tdh_get(&record, u64_field).and_then(|s| {
                    s.parse::<u64>().ok().or_else(|| {
                        s.strip_prefix("0x")
                            .or_else(|| s.strip_prefix("0X"))
                            .and_then(|hex| u64::from_str_radix(hex, 16).ok())
                    })
                });
                bb(result)
            });
        });

        group.finish();
    }

    // ==========================================================================
    // TYPE: SID (UserSID)
    // etw-rs returns Sid directly, TDH returns SDDL string (S-1-5-18)
    // ==========================================================================
    {
        let mut group = c.benchmark_group("type_sid");

        // Validate
        {
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
            let mut parser = parser_cache.parser(raw_event).unwrap();
            let etw_get: Result<etw::Sid, _> = parser.get(sid_field);
            let tdh_str = parse_property_tdh_cached(&tdh_schema_buffer, &record, sid_field);
            println!("\nSID validation:");
            println!(
                "  etw-rs get():       {:?}",
                etw_get.as_ref().map(std::string::ToString::to_string)
            );
            println!("  TdhFormatProperty:  {tdh_str:?} (SDDL string)");
        }

        // etw-rs get() → Sid directly (binary representation)
        group.bench_function("etw_rs_get", |b| {
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
            let mut parser = parser_cache.parser(raw_event).unwrap();
            b.iter(|| {
                let result: Result<etw::Sid, _> = parser.get(sid_field);
                bb(result.ok())
            });
        });

        // etw-rs get_hinted() → Sid directly
        group.bench_function("etw_rs_get_hinted", |b| {
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
            let mut parser = parser_cache.parser(raw_event).unwrap();
            b.iter(|| {
                let result: Result<etw::Sid, _> = parser.get_hinted(sid_field, sid_index as u32);
                bb(result.ok())
            });
        });

        // TdhFormatProperty → SDDL String (no further conversion - users often want SDDL)
        group.bench_function("tdh_format_property", |b| {
            b.iter(|| {
                let result = parse_property_tdh_cached(&tdh_schema_buffer, &record, sid_field);
                bb(result)
            });
        });

        // TdhGetProperty → SDDL String
        group.bench_function("tdh_get_property", |b| {
            b.iter(|| {
                let result = parse_property_with_tdh_get(&record, sid_field);
                bb(result)
            });
        });

        group.finish();
    }

    // ==========================================================================
    // TYPE: WideString (ImageName)
    // Both etw-rs and TDH return UTF-16 strings
    // ==========================================================================
    {
        let mut group = c.benchmark_group("type_widestring");

        // Validate
        {
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
            let mut parser = parser_cache.parser(raw_event).unwrap();
            let etw_get: Result<String, _> = parser.get(string_field);
            let tdh_str = parse_property_tdh_cached(&tdh_schema_buffer, &record, string_field);
            println!("\nWideString validation:");
            println!(
                "  etw-rs get():       {:?}",
                etw_get
                    .as_ref()
                    .map(|s| s.chars().take(40).collect::<String>())
            );
            println!(
                "  TdhFormatProperty:  {:?}",
                tdh_str
                    .as_ref()
                    .map(|s| s.chars().take(40).collect::<String>())
            );
        }

        // etw-rs get() → String (UTF-16 → UTF-8 conversion)
        group.bench_function("etw_rs_get", |b| {
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
            let mut parser = parser_cache.parser(raw_event).unwrap();
            b.iter(|| {
                let result: Result<String, _> = parser.get(string_field);
                bb(result.ok())
            });
        });

        // etw-rs get_hinted() → WideString (no conversion, native UTF-16)
        group.bench_function("etw_rs_get_hinted", |b| {
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
            let mut parser = parser_cache.parser(raw_event).unwrap();
            b.iter(|| {
                let result: Result<etw::WideString, _> =
                    parser.get_hinted(string_field, string_index as u32);
                bb(result.ok())
            });
        });

        // TdhFormatProperty → UTF-16 → UTF-8 String
        group.bench_function("tdh_format_property", |b| {
            b.iter(|| {
                let result = parse_property_tdh_cached(&tdh_schema_buffer, &record, string_field);
                bb(result)
            });
        });

        // TdhGetProperty → UTF-16 → UTF-8 String
        group.bench_function("tdh_get_property", |b| {
            b.iter(|| {
                let result = parse_property_with_tdh_get(&record, string_field);
                bb(result)
            });
        });

        // Fair UTF-16 comparison: TdhFormatProperty → Vec<u16> (no conversion)
        // Compares apples-to-apples with get_hinted/get_at returning WideString
        group.bench_function("tdh_format_utf16", |b| {
            b.iter(|| {
                let result =
                    parse_property_tdh_cached_utf16(&tdh_schema_buffer, &record, string_index);
                bb(result)
            });
        });

        // Fair UTF-16 comparison: TdhGetProperty → Vec<u16> (no conversion)
        group.bench_function("tdh_get_utf16", |b| {
            b.iter(|| {
                let result = parse_property_with_tdh_get_utf16(&record, string_field);
                bb(result)
            });
        });

        group.finish();
    }
}

/// Benchmark index-based access vs name-based access.
///
/// This compares the three access methods:
/// - get(name): Name lookup + parsing
/// - get_hinted(name, index): Verified index + parsing
fn bench_index_access(c: &mut Criterion) {
    let events = match capture_dns_events(50) {
        Some(e) if !e.is_empty() => e,
        _ => {
            eprintln!("Skipping index_access benchmark: no events captured");
            return;
        }
    };

    let event = &events[0];
    let record = event.to_event_record();

    // Get field info
    let schema_buffer = get_schema_buffer(&record).unwrap();
    let info = unsafe { &*schema_buffer.as_ptr().cast::<TRACE_EVENT_INFO>() };

    // Find first string field for meaningful comparison
    let mut target_field: Option<(usize, String)> = None;
    for i in 0..info.TopLevelPropertyCount as usize {
        let prop = unsafe {
            let props_ptr =
                std::ptr::addr_of!(info.EventPropertyInfoArray).cast::<EVENT_PROPERTY_INFO>();
            &*props_ptr.add(i)
        };

        let in_type = unsafe { prop.Anonymous1.nonStructType.InType };
        let name_offset = prop.NameOffset as usize;

        if name_offset > 0 && (in_type == 1 || in_type == 2) {
            let info_ptr = std::ptr::from_ref(info).cast::<u8>();
            let name_ptr = unsafe { info_ptr.add(name_offset).cast::<u16>() };
            let mut len = 0;
            while unsafe { *name_ptr.add(len) } != 0 && len < 256 {
                len += 1;
            }
            let name_slice = unsafe { std::slice::from_raw_parts(name_ptr, len) };
            if let Ok(name) = String::from_utf16(name_slice) {
                target_field = Some((i, name));
                break;
            }
        }
    }

    let Some((field_index, field_name)) = target_field else {
        eprintln!("Skipping index_access benchmark: no string field found");
        return;
    };

    println!("\n=== Index-Based Access Benchmarks ===");
    println!("Field: '{field_name}' at index {field_index}");

    // Convert field name to UTF-16 for get_hinted (performance API)

    let mut parser_cache = etw::processing_context::ProcessingContext::new();
    {
        let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
        let _ = parser_cache.get_or_lookup(raw_event);
    }

    // Pre-cache TDH schema buffer for comparison
    let tdh_schema_buffer = event.schema_buffer.clone();

    // Validate all methods produce same result
    {
        let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
        let mut parser = parser_cache.parser(raw_event).unwrap();

        let by_name: Result<String, _> = parser.get(&field_name);
        let by_hint: Result<etw::WideString, _> =
            parser.get_hinted(&field_name, field_index as u32);

        println!("Validation (all should match):");
        println!(
            "  get(name):            {:?}",
            by_name
                .as_ref()
                .map(|s| s.chars().take(30).collect::<String>())
        );
        println!(
            "  get_hinted(utf16, i): {:?}",
            by_hint
                .as_ref()
                .ok()
                .and_then(|ws| ws.decode_utf16().ok())
                .map(|s| s.chars().take(30).collect::<String>())
        );
    }

    // ==========================================================================
    // INDEX-BASED ACCESS COMPARISON
    // Compares etw-rs access methods: get(), get_hinted()
    // (See shallow_cached/deep_cached for full TDH comparison)
    // ==========================================================================
    {
        let mut group = c.benchmark_group("index_based_access");

        // get() - convenience API, by name, returns String
        group.bench_function("etw_rs_get", |b| {
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
            let mut parser = parser_cache.parser(raw_event).unwrap();
            b.iter(|| {
                let result: Result<String, _> = parser.get(&field_name);
                bb(result.ok())
            });
        });

        // get_hinted() - performance API, by UTF-16 name + index, returns WideString
        group.bench_function("etw_rs_get_hinted", |b| {
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
            let mut parser = parser_cache.parser(raw_event).unwrap();
            b.iter(|| {
                let result: Result<etw::WideString, _> =
                    parser.get_hinted(&field_name, field_index as u32);
                bb(result.ok())
            });
        });

        // TdhFormatProperty - for comparison (cached schema, by index)
        group.bench_function("tdh_format_property", |b| {
            let info = unsafe { &*tdh_schema_buffer.as_ptr().cast::<TRACE_EVENT_INFO>() };
            let pointer_size = 8u8; // 64-bit only
            let user_data = unsafe {
                std::slice::from_raw_parts(
                    record.UserData as *const u8,
                    record.UserDataLength as usize,
                )
            };
            b.iter(|| {
                let result = parse_property_with_tdh(info, user_data, field_index, pointer_size);
                bb(result)
            });
        });

        // TdhGetProperty - for comparison (does own schema lookup)
        group.bench_function("tdh_get_property", |b| {
            b.iter(|| {
                let result = parse_property_with_tdh_get(&record, &field_name);
                bb(result)
            });
        });

        group.finish();
    }
}

/// Benchmark multiple field access patterns.
fn bench_multi_field_access(c: &mut Criterion) {
    let events = match capture_dns_events(50) {
        Some(e) if !e.is_empty() => e,
        _ => {
            eprintln!("Skipping multi_field benchmark: no events captured");
            return;
        }
    };

    let mut group = c.benchmark_group("multi_field_access");

    let event = &events[0];
    let record = event.to_event_record();

    let mut parser_cache = etw::processing_context::ProcessingContext::new();
    {
        let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
        let _ = parser_cache.get_or_lookup(raw_event);
    }

    // Get all field names
    let field_names: Vec<String> = {
        let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
        let schema = parser_cache.get_or_lookup(raw_event).unwrap();
        schema.properties().filter_map(|p| p.name()).collect()
    };

    if field_names.len() < 2 {
        eprintln!("Skipping multi_field benchmark: need at least 2 fields");
        return;
    }

    let num_fields = field_names.len().min(5);

    // Pre-cache TDH schema buffer for TDH benchmarks
    let tdh_schema_buffer = event.schema_buffer.clone();

    println!("\n=== Multi-Field Access Benchmarks ===");
    println!("Accessing {num_fields} fields sequentially");
    println!("Compares: get(), get_hinted(), get_at(), TdhFormatProperty, TdhGetProperty");

    // Sequential access with get()
    group.bench_function("sequential_get", |b| {
        let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
        let mut parser = parser_cache.parser(raw_event).unwrap();
        b.iter(|| {
            let mut results = Vec::with_capacity(num_fields);
            for name in field_names.iter().take(num_fields) {
                let r: Result<String, _> = parser.get(name.as_str());
                results.push(r.ok());
            }
            bb(results)
        });
    });

    // Sequential access with get_hinted() using field names
    group.bench_function("sequential_get_hinted", |b| {
        let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
        let mut parser = parser_cache.parser(raw_event).unwrap();
        b.iter(|| {
            let mut results = Vec::with_capacity(num_fields);
            for (i, name) in field_names.iter().take(num_fields).enumerate() {
                let r: Result<etw::WideString, _> = parser.get_hinted(name.as_str(), i as u32);
                results.push(r.ok());
            }
            bb(results)
        });
    });

    // Sequential access with properties() iterator - zero-copy WideStrRef
    group.bench_function("sequential_iter_zero_copy", |b| {
        let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
        let mut parser = parser_cache.parser(raw_event).unwrap();
        b.iter(|| {
            let mut results = Vec::with_capacity(num_fields);
            for prop in parser.properties().unwrap().take(num_fields) {
                // Zero-copy: just borrow the UTF-16 data
                let r = prop.as_wide_str().ok();
                results.push(r.map(|s| s.len()));
            }
            bb(results)
        });
    });

    // Sequential access with properties() iterator - allocating WideString
    group.bench_function("sequential_iter_allocating", |b| {
        let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
        let mut parser = parser_cache.parser(raw_event).unwrap();
        b.iter(|| {
            let mut results = Vec::with_capacity(num_fields);
            for prop in parser.properties().unwrap().take(num_fields) {
                // Allocating: create owned WideString
                let r = prop.to_wide_string().ok();
                results.push(r);
            }
            bb(results)
        });
    });

    // Random order access with get()
    group.bench_function("random_order_get", |b| {
        let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
        let mut parser = parser_cache.parser(raw_event).unwrap();
        b.iter(|| {
            let mut results = Vec::with_capacity(num_fields);
            // Access in reverse order (worst case for sequential parsing)
            for name in field_names.iter().take(num_fields).rev() {
                let r: Result<String, _> = parser.get(name.as_str());
                results.push(r.ok());
            }
            bb(results)
        });
    });

    // Random order access with get_hinted() using field names
    group.bench_function("random_order_get_hinted", |b| {
        let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
        let mut parser = parser_cache.parser(raw_event).unwrap();
        b.iter(|| {
            let mut results = Vec::with_capacity(num_fields);
            // Access in reverse order with hints
            for (i, name) in field_names.iter().take(num_fields).enumerate().rev() {
                let r: Result<etw::WideString, _> = parser.get_hinted(name.as_str(), i as u32);
                results.push(r.ok());
            }
            bb(results)
        });
    });

    // TdhFormatProperty sequential: O(n) - single pass through all properties
    group.bench_function("sequential_tdh_format_property", |b| {
        b.iter(|| {
            let info = unsafe { &*tdh_schema_buffer.as_ptr().cast::<TRACE_EVENT_INFO>() };
            let pointer_size = 8u8; // 64-bit only
            let user_data = unsafe {
                std::slice::from_raw_parts(
                    record.UserData as *const u8,
                    record.UserDataLength as usize,
                )
            };

            let mut results = Vec::with_capacity(num_fields);
            let mut data_offset = 0usize;
            let mut output_buffer: Vec<u16> = vec![0; 256];

            // Single pass through properties 0..num_fields
            for i in 0..num_fields {
                let prop = unsafe {
                    let props_ptr = std::ptr::addr_of!(info.EventPropertyInfoArray)
                        .cast::<EVENT_PROPERTY_INFO>();
                    &*props_ptr.add(i)
                };

                let in_type = unsafe { prop.Anonymous1.nonStructType.InType };
                let out_type = unsafe { prop.Anonymous1.nonStructType.OutType };
                let prop_length = unsafe {
                    if (prop.Flags.0 & PropertyParamLength.0) != 0 {
                        0u16
                    } else {
                        prop.Anonymous3.length
                    }
                };

                let remaining_data = &user_data[data_offset..];
                if remaining_data.is_empty() {
                    break;
                }

                loop {
                    let mut buffer_size = (output_buffer.len() * 2) as u32;
                    let mut consumed = 0u16;

                    let status = unsafe {
                        TdhFormatProperty(
                            std::ptr::from_ref(info).cast_mut(),
                            None,
                            pointer_size as u32,
                            in_type,
                            out_type,
                            prop_length,
                            remaining_data,
                            &raw mut buffer_size,
                            Some(PWSTR(output_buffer.as_mut_ptr())),
                            &raw mut consumed,
                        )
                    };

                    if status == ERROR_INSUFFICIENT_BUFFER.0 && output_buffer.len() < 8192 {
                        output_buffer.resize((buffer_size / 2 + 1) as usize, 0);
                        continue;
                    }

                    if status != 0 {
                        results.push(None);
                        break;
                    }

                    data_offset += consumed as usize;
                    let len = output_buffer
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(output_buffer.len());
                    results.push(String::from_utf16(&output_buffer[..len]).ok());
                    break;
                }
            }
            bb(results)
        });
    });

    // TdhGetProperty: O(k×n) - rescans from beginning for each property
    group.bench_function("sequential_tdh_get_property", |b| {
        b.iter(|| {
            let mut results = Vec::with_capacity(num_fields);
            for name in field_names.iter().take(num_fields) {
                let result = parse_property_with_tdh_get(&record, name);
                results.push(result);
            }
            bb(results)
        });
    });

    group.finish();
}

// =============================================================================
// Multi-Property TdhGetProperty Scaling Benchmark
// =============================================================================

/// Benchmark demonstrating O(n²) vs O(n) scaling when reading multiple properties.
///
/// This benchmark shows why Microsoft recommends against TdhGetProperty:
/// - TdhGetProperty: Each call rescans from the beginning → O(k×n) for k properties
/// - TdhFormatProperty: Sequential iteration → O(n) total
/// - etw-rs: Caches locations → O(n) first pass, O(1) subsequent
///
/// Uses ProcessStart events which have 16 properties including multiple strings.
fn bench_multi_property_scaling(c: &mut Criterion) {
    let events = match capture_process_events(10) {
        Some(e) if !e.is_empty() => e,
        _ => {
            eprintln!("Skipping multi_property_scaling benchmark: no ProcessStart events captured");
            return;
        }
    };

    let event = &events[0];
    let record = event.to_event_record();

    // Get all property names and find string properties at various depths
    let schema_buffer = get_schema_buffer(&record).unwrap();
    let info = unsafe { &*schema_buffer.as_ptr().cast::<TRACE_EVENT_INFO>() };

    let mut all_props: Vec<(usize, String, u16)> = Vec::new(); // (index, name, in_type)
    for i in 0..info.TopLevelPropertyCount as usize {
        let prop = unsafe {
            let props_ptr =
                std::ptr::addr_of!(info.EventPropertyInfoArray).cast::<EVENT_PROPERTY_INFO>();
            &*props_ptr.add(i)
        };

        let in_type = unsafe { prop.Anonymous1.nonStructType.InType };
        let name_offset = prop.NameOffset as usize;

        if name_offset > 0 {
            let info_ptr = std::ptr::from_ref(info).cast::<u8>();
            let name_ptr = unsafe { info_ptr.add(name_offset).cast::<u16>() };
            let mut len = 0;
            while unsafe { *name_ptr.add(len) } != 0 && len < 256 {
                len += 1;
            }
            let name_slice = unsafe { std::slice::from_raw_parts(name_ptr, len) };
            if let Ok(name) = String::from_utf16(name_slice) {
                all_props.push((i, name, in_type));
            }
        }
    }

    // Select properties at different depths for testing
    // We want: early (index ~2), middle (index ~7), late (index ~12), last (index ~15)
    let test_indices: Vec<usize> = {
        let total = all_props.len();
        if total < 4 {
            (0..total).collect()
        } else {
            vec![1, total / 3, 2 * total / 3, total - 1]
        }
    };

    let test_props: Vec<(usize, String)> = test_indices
        .iter()
        .filter_map(|&i| all_props.get(i).map(|(idx, name, _)| (*idx, name.clone())))
        .collect();
    if test_props.len() < 2 {
        eprintln!("Skipping multi_property_scaling benchmark: need at least 2 properties");
        return;
    }

    println!("\n=== Multi-Property Scaling Benchmark ===");
    println!(
        "Testing {} properties at indices: {:?}",
        test_props.len(),
        test_props.iter().map(|(i, _)| i).collect::<Vec<_>>()
    );
    for (idx, name) in &test_props {
        println!("  [{idx}] {name}");
    }

    let mut parser_cache = etw::processing_context::ProcessingContext::new();
    {
        let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
        let _ = parser_cache.get_or_lookup(raw_event);
    }

    let tdh_schema_buffer = event.schema_buffer.clone();

    // Validate all methods work
    {
        let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
        let mut parser = parser_cache.parser(raw_event).unwrap();

        println!("\nValidation (reading {} properties):", test_props.len());
        for (idx, name) in &test_props {
            let etw_result: Result<String, _> = parser.get(name.as_str());
            let tdh_get_result = parse_property_with_tdh_get(&record, name);
            println!(
                "  [{}] {}: etw-rs={}, tdh_get={}",
                idx,
                name,
                etw_result.as_ref().map_or(0, std::string::String::len),
                tdh_get_result.as_ref().map_or(0, std::string::String::len)
            );
        }
    }

    // ==========================================================================
    // MULTI-PROPERTY ACCESS - Shows O(n²) vs O(n) scaling
    // ==========================================================================
    {
        let mut group = c.benchmark_group("multi_property_scaling");

        let prop_names: Vec<String> = test_props.iter().map(|(_, n)| n.clone()).collect();
        let prop_indices: Vec<usize> = test_props.iter().map(|(i, _)| *i).collect();

        // TdhGetProperty: O(k×n) - rescans from beginning for each property
        // This is what Microsoft warns against!
        group.bench_function("tdh_get_property_repeated", |b| {
            b.iter(|| {
                let mut results = Vec::with_capacity(prop_names.len());
                for name in &prop_names {
                    // Each call rescans properties 0..target_index
                    let result = parse_property_with_tdh_get(&record, name);
                    results.push(result);
                }
                bb(results)
            });
        });

        // TdhFormatProperty sequential: O(n) - single pass through all properties
        // This is the MSDN-recommended pattern: iterate once, collect results along the way
        group.bench_function("tdh_format_sequential", |b| {
            let max_idx = *prop_indices.iter().max().unwrap_or(&0);
            let prop_set: std::collections::HashSet<usize> = prop_indices.iter().copied().collect();

            b.iter(|| {
                let info = unsafe { &*tdh_schema_buffer.as_ptr().cast::<TRACE_EVENT_INFO>() };
                let pointer_size = 8u8; // 64-bit only
                let user_data = unsafe {
                    std::slice::from_raw_parts(
                        record.UserData as *const u8,
                        record.UserDataLength as usize,
                    )
                };

                let mut results: std::collections::HashMap<usize, Option<String>> =
                    std::collections::HashMap::new();
                let mut data_offset = 0usize;
                let mut output_buffer: Vec<u16> = vec![0; 256];

                // Single pass through properties 0..=max_idx
                for i in 0..=max_idx {
                    let prop = unsafe {
                        let props_ptr = std::ptr::addr_of!(info.EventPropertyInfoArray)
                            .cast::<EVENT_PROPERTY_INFO>();
                        &*props_ptr.add(i)
                    };

                    let in_type = unsafe { prop.Anonymous1.nonStructType.InType };
                    let out_type = unsafe { prop.Anonymous1.nonStructType.OutType };
                    let prop_length = unsafe {
                        if (prop.Flags.0 & PropertyParamLength.0) != 0 {
                            0u16
                        } else {
                            prop.Anonymous3.length
                        }
                    };

                    let remaining_data = &user_data[data_offset..];
                    if remaining_data.is_empty() {
                        break;
                    }

                    loop {
                        let mut buffer_size = (output_buffer.len() * 2) as u32;
                        let mut consumed = 0u16;

                        let status = unsafe {
                            TdhFormatProperty(
                                std::ptr::from_ref(info).cast_mut(),
                                None,
                                pointer_size as u32,
                                in_type,
                                out_type,
                                prop_length,
                                remaining_data,
                                &raw mut buffer_size,
                                Some(PWSTR(output_buffer.as_mut_ptr())),
                                &raw mut consumed,
                            )
                        };

                        if status == ERROR_INSUFFICIENT_BUFFER.0 && output_buffer.len() < 8192 {
                            output_buffer.resize((buffer_size / 2 + 1) as usize, 0);
                            continue;
                        }

                        if status != 0 {
                            break;
                        }

                        data_offset += consumed as usize;

                        // Collect result if this is a property we want
                        if prop_set.contains(&i) {
                            let len = output_buffer
                                .iter()
                                .position(|&c| c == 0)
                                .unwrap_or(output_buffer.len());
                            results.insert(i, String::from_utf16(&output_buffer[..len]).ok());
                        }

                        break;
                    }
                }

                // Return results in the requested order
                let final_results: Vec<Option<String>> = prop_indices
                    .iter()
                    .map(|idx| results.get(idx).cloned().flatten())
                    .collect();
                bb(final_results)
            });
        });

        // etw-rs get(): O(n) first property, subsequent benefit from offset cache
        group.bench_function("etw_rs_get_multiple", |b| {
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
            let mut parser = parser_cache.parser(raw_event).unwrap();
            b.iter(|| {
                let mut results = Vec::with_capacity(prop_names.len());
                for name in &prop_names {
                    let result: Result<String, _> = parser.get(name.as_str());
                    results.push(result.ok());
                }
                bb(results)
            });
        });

        group.finish();
    }

    // ==========================================================================
    // SCALING TEST - Increasing number of properties
    // Shows how performance degrades with TdhGetProperty as you read more props
    // ==========================================================================
    {
        let mut group = c.benchmark_group("property_count_scaling");

        let all_names: Vec<String> = all_props.iter().map(|(_, n, _)| n.clone()).collect();
        // Test with 1, 2, 4, 8 properties (or max available)
        for count in [1, 2, 4, 8] {
            if count > all_names.len() {
                break;
            }

            let names_subset: Vec<&String> = all_names.iter().take(count).collect();

            // TdhGetProperty with N properties
            group.bench_function(format!("tdh_get_property_{count}"), |b| {
                b.iter(|| {
                    let mut results = Vec::with_capacity(count);
                    for name in &names_subset {
                        let result = parse_property_with_tdh_get(&record, name);
                        results.push(result);
                    }
                    bb(results)
                });
            });

            // etw-rs with N properties
            group.bench_function(format!("etw_rs_get_{count}"), |b| {
                let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
                let mut parser = parser_cache.parser(raw_event).unwrap();
                b.iter(|| {
                    let mut results = Vec::with_capacity(count);
                    for name in &names_subset {
                        let result: Result<String, _> = parser.get(name.as_str());
                        results.push(result.ok());
                    }
                    bb(results)
                });
            });
        }

        group.finish();
    }
}

// =============================================================================
// Static Schema Parsing Benchmarks
// =============================================================================

// Define static schemas for kernel file events.

// FileCreate event (ID 12, Version 1) - Version used in benchmarks
event_schema! {
    guid: etw::Guid::from_u128(0xedd08927_9cc4_4e65_b970_c2560fb5c289),
    name: "FileCreate",
    id: 12,
    version: 1,
    fields: {
        Irp: usize,
        FileObject: usize,
        IssuingThreadId: u32,
        CreateOptions: u32,
        CreateAttributes: u32,
        ShareAccess: u32,
        FileName: WideStrRef,
    }
}

// Multi-variable field schema for testing parser caching benefit
// Realistic event with mixed fixed and variable fields
event_schema! {
    name: "TestMultiVar",
    id: 99,
    version: 1,
    fields: {
        Field1: u32,
        Field2: u64,
        Field3: u64,
        Field4: u32,
        String1: WideStrRef,
        String2: WideStrRef,
        Field5: u32,
        Field6: u32,
        String3: WideStrRef,
    }
}

/// Create mock event data with multiple variable-length fields for caching tests.
/// Layout: u32, u64, u64, u32, WideString, WideString, u32, u32, WideString
fn create_multi_variable_mock_event() -> MockEvent {
    let mut data = Vec::new();

    // Fixed fields (20 bytes total)
    data.extend_from_slice(&1234u32.to_le_bytes()); // Field1
    data.extend_from_slice(&5678u64.to_le_bytes()); // Field2
    data.extend_from_slice(&9012u64.to_le_bytes()); // Field3
    data.extend_from_slice(&3456u32.to_le_bytes()); // Field4

    // First variable string
    let str1 = "First string with some content";
    for ch in str1.encode_utf16() {
        data.extend_from_slice(&ch.to_le_bytes());
    }
    data.extend_from_slice(&0u16.to_le_bytes()); // null terminator

    // Second variable string
    let str2 = "Second string also with content";
    for ch in str2.encode_utf16() {
        data.extend_from_slice(&ch.to_le_bytes());
    }
    data.extend_from_slice(&0u16.to_le_bytes()); // null terminator

    // Fixed fields after variable strings (8 bytes total)
    data.extend_from_slice(&7890u32.to_le_bytes()); // Field5
    data.extend_from_slice(&1122u32.to_le_bytes()); // Field6

    // Third variable string
    let str3 = "Third string completes the set";
    for ch in str3.encode_utf16() {
        data.extend_from_slice(&ch.to_le_bytes());
    }
    data.extend_from_slice(&0u16.to_le_bytes()); // null terminator

    MockEvent::new(
        data,
        GUID::from_u128(0xedd08927_9cc4_4e65_b970_c2560fb5c289),
        99,
        1,
    )
}

/// Create mock FileCreate event data for static schema benchmarking.
fn create_static_schema_mock_event() -> MockEvent {
    let mut data = Vec::new();

    // Fixed fields (32 bytes)
    data.extend_from_slice(&0x1234567890ABCDEFu64.to_le_bytes()); // Irp (usize/u64)
    data.extend_from_slice(&0xFEDCBA0987654321u64.to_le_bytes()); // FileObject (usize/u64)
    data.extend_from_slice(&1234u32.to_le_bytes()); // IssuingThreadId
    data.extend_from_slice(&0x00000040u32.to_le_bytes()); // CreateOptions
    data.extend_from_slice(&0x00000080u32.to_le_bytes()); // CreateAttributes
    data.extend_from_slice(&0x00000007u32.to_le_bytes()); // ShareAccess

    // Variable-length FileName (UTF-16 null-terminated)
    let filename = "C:\\Windows\\System32\\notepad.exe";
    for ch in filename.encode_utf16() {
        data.extend_from_slice(&ch.to_le_bytes());
    }
    data.extend_from_slice(&0u16.to_le_bytes()); // null terminator

    MockEvent::new(
        data,
        GUID::from_u128(0xedd08927_9cc4_4e65_b970_c2560fb5c289),
        12,
        1,
    )
}

/// Benchmark: Static schema sequential parser - 5 fixed fields with caching.
fn bench_static_schema_sequential(c: &mut Criterion) {
    let mock = create_static_schema_mock_event();

    c.bench_function("static_schema_sequential_5_fields", |b| {
        b.iter(|| {
            // Create sequential parser (caches offsets for variable fields)
            let parser = FileCreateV1Parser::new(mock.as_raw_event());

            // Access 5 fixed fields sequentially
            let irp = parser.Irp().unwrap();
            let file_obj = parser.FileObject().unwrap();
            let thread_id = parser.IssuingThreadId().unwrap();
            let options = parser.CreateOptions().unwrap();
            let attrs = parser.CreateAttributes().unwrap();

            bb((irp, file_obj, thread_id, options, attrs))
        });
    });
}

/// Benchmark: Static parser - variable field access (can cache offset).
fn bench_static_parser_variable(c: &mut Criterion) {
    let mock = create_static_schema_mock_event();

    c.bench_function("static_parser_variable_field", |b| {
        b.iter(|| {
            // Access FileName variable field using parser
            let mut parser = FileCreateV1Parser::new(mock.as_raw_event());
            let filename = parser.FileName().unwrap();
            bb(filename)
        });
    });
}

/// Benchmark: Static parser - 3 different variable fields (caches offsets).
fn bench_static_parser_multi_variable(c: &mut Criterion) {
    let mock = create_multi_variable_mock_event();

    c.bench_function("static_parser_3_variable_fields", |b| {
        b.iter(|| {
            // Access 3 different variable fields using parser
            // Parser caches each offset after first access
            let mut parser = TestMultiVarV1Parser::new(mock.as_raw_event());
            let s1 = parser.String1().unwrap();
            let s2 = parser.String2().unwrap();
            let s3 = parser.String3().unwrap();
            bb((s1, s2, s3))
        });
    });
}

// =============================================================================
// Additional benchmarks for etw-rs (get) method
// =============================================================================

/// Benchmark: etw-rs (get) single integer field.
fn bench_get_single_field(c: &mut Criterion) {
    let events = match capture_process_events(10) {
        Some(e) if !e.is_empty() => e,
        _ => {
            eprintln!("Skipping get_single_field benchmark: no events captured");
            return;
        }
    };

    let event = &events[0];
    let record = event.to_event_record();
    let mut parser_cache = etw::processing_context::ProcessingContext::new();

    c.bench_function("etw_rs_get_single_u32", |b| {
        b.iter(|| {
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
            let mut parser = parser_cache.parser(bb(raw_event)).unwrap();
            let pid: u32 = parser.get("ProcessID").unwrap();
            bb(pid)
        });
    });
}

/// Benchmark: etw-rs (get) 5 fixed fields sequentially.
fn bench_get_five_fields(c: &mut Criterion) {
    let events = match capture_process_events(10) {
        Some(e) if !e.is_empty() => e,
        _ => {
            eprintln!("Skipping get_5_fields benchmark: no events captured");
            return;
        }
    };

    let event = &events[0];
    let record = event.to_event_record();
    let mut parser_cache = etw::processing_context::ProcessingContext::new();

    c.bench_function("etw_rs_get_5_fields", |b| {
        b.iter(|| {
            let raw_event = unsafe { etw::RawEvent::from_ptr((&raw const record).cast()) };
            let mut parser = parser_cache.parser(bb(raw_event)).unwrap();
            // Get first available field to keep benchmark consistent
            let _: Result<u32, _> = parser.get("ProcessID");
            let _: Result<u32, _> = parser.get("SessionID");
            let _: Result<String, _> = parser.get("ImageName");
            // Repeat two more times to get 5 field accesses
            let _: Result<u32, _> = parser.get("ProcessID");
            let result: Result<u32, _> = parser.get("SessionID");
            bb(result.ok())
        });
    });
}

// Note: TdhGetProperty for 5 fields can be estimated from existing 4-field benchmark:
// 4 fields = 2830ns, so 5 fields ≈ 3538ns (2830 × 5/4)

// =============================================================================
// Main
// =============================================================================

criterion_group!(
    benches,
    bench_shallow_fields,
    bench_deep_fields,
    bench_schema_comparison,
    bench_zero_copy_strings,
    bench_property_types,
    bench_index_access,
    bench_multi_field_access,
    bench_multi_property_scaling,
    bench_static_schema_sequential,
    bench_static_parser_variable,
    bench_static_parser_multi_variable,
    bench_get_single_field,
    bench_get_five_fields,
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
