//! Integration test for ETW field type parsing
//!
//! This test verifies that TDH field types can be observed from real ETW providers.
//! Unit tests in `parser.rs` provide complete coverage for FromProperty implementations.
//!
//! # TDH Type Coverage (Kernel Providers)
//!
//! | TdhInType          | Rust Type   | Provider Event                              |
//! |--------------------|-------------|---------------------------------------------|
//! | UnicodeString      | String      | Kernel-Process: ProcessStart.ImageName      |
//! | AnsiString         | String      | Kernel-Process: ProcessStop.ImageName       |
//! | UInt8              | u8          | Kernel-Process: CpuBasePriorityChange       |
//! | UInt16             | u16         | Kernel-Network: TCP events (dport/sport)    |
//! | UInt32             | u32         | Kernel-Process: ProcessStart.ProcessID      |
//! | UInt64             | u64         | Kernel-Process: ProcessStop.CommitCharge    |
//! | Pointer            | usize       | Kernel-Process: ThreadStart.StackBase       |
//! | FileTime           | Timestamp   | Kernel-Process: ProcessStart.CreateTime     |
//! | SID                | Sid         | Kernel-Process: ProcessStart_V3 (v3 only)   |
//! | GUID               | GUID        | Kernel-Process: JobStart.ContainerID        |
//! | Binary             | Vec<u8>     | Kernel-Network: IPv6 events (daddr/saddr)   |
//!
//! Types NOT in Kernel providers (tested via unit tests only):
//! - Int8, Int16, Int32, Int64, Float, Double, Boolean
//! - SystemTime, HexInt32, HexInt64, CountedString, CountedAnsiString

#![cfg(not(miri))]
// Win32 API calls are not supported under Miri.
// Tests use println for output and unwrap/expect for cleaner test code
#![expect(
    clippy::print_stdout,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::clone_on_ref_ptr,
    clippy::str_to_string,
    clippy::semicolon_outside_block,
    clippy::undocumented_unsafe_blocks,
    reason = "test binary: printing aids diagnosis and panics are the failure mode"
)]

#[path = "common/mod.rs"]
mod common;

use etw::{AnsiString, Sid, TdhInType, Timestamp, Trace, processing_context::in_type_name};
use example_providers::kernel::{network, process};
use std::{
    collections::HashMap,
    process::Command,
    sync::{Arc, Mutex},
    time::Duration,
};

/// Types expected from Kernel-Process + Kernel-Network providers
const EXPECTED_TYPES: &[&str] = &[
    "UnicodeString", // ProcessStart.ImageName
    "AnsiString",    // ProcessStop.ImageName
    "UInt8",         // CpuBasePriorityChange.OldPriority
    "UInt16",        // Kernel-Network: TCP dport/sport
    "UInt32",        // ProcessStart.ProcessID
    "UInt64",        // ProcessStop.CommitCharge
    "Pointer",       // ThreadStart.StackBase
    "FileTime",      // ProcessStart.CreateTime
    "SID",           // ProcessStart_V3.MandatoryLabel
    "GUID",          // JobStart.ContainerID
    "Binary",        // Kernel-Network: IPv6 daddr/saddr
];

#[test]
fn test_field_type_coverage() {
    let mut trace = Trace::new("etw-rs_Test_FieldTypes").expect("Failed to create trace session");

    let Some(()) = common::skip_or_panic("trace.start", trace.start()) else {
        return;
    };

    let Some(()) = common::skip_or_panic(
        "Failed to enable Kernel-Process provider",
        trace.enable_provider(process::GUID, etw::ALL_KEYWORDS),
    ) else {
        return;
    };

    trace
        .enable_provider(network::GUID, etw::ALL_KEYWORDS)
        .expect("Failed to enable Kernel-Network provider");

    // Map from type name to (property_name, sample_value)
    let type_samples = Arc::new(Mutex::new(HashMap::<String, (String, String)>::new()));
    let type_samples_clone = type_samples.clone();

    trace.set_event_callback(move |event, context| {
        let mut parser = context.parser(event)?;

        let mut samples = type_samples_clone.lock().unwrap();

        // Collect property info first to avoid borrow conflict
        let props: Vec<_> = parser
            .schema()
            .properties()
            .filter_map(|prop| {
                let type_name = in_type_name(prop.in_type());
                if samples.contains_key(type_name) {
                    return None;
                }
                let prop_name = prop.name()?;
                Some((
                    type_name.to_string(),
                    prop_name,
                    TdhInType::from_raw(prop.in_type()),
                ))
            })
            .collect();

        // Now parse values
        for (type_name, prop_name, in_type) in props {
            let value_str = match in_type {
                TdhInType::UnicodeString => parser
                    .get::<std::ffi::OsString>(prop_name.as_str())
                    .map_or_else(|e| format!("ERR: {e}"), |v| format!("{v:?}")),
                TdhInType::AnsiString => parser.get::<AnsiString>(prop_name.as_str()).map_or_else(
                    |e| format!("ERR: {e}"),
                    |v| format!("{:?}", v.to_string_lossy()),
                ),
                TdhInType::UInt8 => parser
                    .get::<u8>(prop_name.as_str())
                    .map_or_else(|e| format!("ERR: {e}"), |v| format!("{v}")),
                TdhInType::UInt16 => parser
                    .get::<u16>(prop_name.as_str())
                    .map_or_else(|e| format!("ERR: {e}"), |v| format!("{v}")),
                TdhInType::UInt32 => parser
                    .get::<u32>(prop_name.as_str())
                    .map_or_else(|e| format!("ERR: {e}"), |v| format!("{v}")),
                TdhInType::UInt64 => parser
                    .get::<u64>(prop_name.as_str())
                    .map_or_else(|e| format!("ERR: {e}"), |v| format!("{v}")),
                TdhInType::Pointer => parser
                    .get::<usize>(prop_name.as_str())
                    .map_or_else(|e| format!("ERR: {e}"), |v| format!("0x{v:x}")),
                TdhInType::FileTime => parser.get::<Timestamp>(prop_name.as_str()).map_or_else(
                    |e| format!("ERR: {e}"),
                    |v| format!("Timestamp({})", v.raw()),
                ),
                TdhInType::Sid => parser
                    .get::<Sid>(prop_name.as_str())
                    .map_or_else(|e| format!("ERR: {e}"), |v| v.to_string()),
                TdhInType::Guid => parser
                    .get::<etw::Guid>(prop_name.as_str())
                    .map_or_else(|e| format!("ERR: {e}"), |v| format!("{v:?}")),
                TdhInType::Binary => parser.get::<Vec<u8>>(prop_name.as_str()).map_or_else(
                    |e| format!("ERR: {e}"),
                    |v| {
                        if v.len() <= 16 {
                            format!("{v:02x?}")
                        } else {
                            format!("{:02x?}... ({} bytes)", &v[..16], v.len())
                        }
                    },
                ),
                _ => "(skipped)".to_string(),
            };

            samples.insert(type_name, (prop_name, value_str));
        }

        Ok(())
    });

    trace
        .start_processing_thread()
        .expect("Failed to start processing");

    // Trigger 1: Process spawn + exit → UnicodeString, AnsiString, UInt32, UInt64, FileTime,
    // Pointer, SID
    let child = Command::new("cmd.exe").args(["/c", "ver"]).spawn().unwrap();
    let _ = child.wait_with_output();

    // Trigger 2: Thread priority change → UInt8
    use windows::Win32::System::Threading::{
        GetCurrentThread, SetThreadPriority, THREAD_PRIORITY_ABOVE_NORMAL, THREAD_PRIORITY_NORMAL,
    };
    unsafe {
        let thread = GetCurrentThread();
        SetThreadPriority(thread, THREAD_PRIORITY_ABOVE_NORMAL).ok();
        SetThreadPriority(thread, THREAD_PRIORITY_NORMAL).ok();
    }

    // Trigger 3: Job creation → GUID
    use windows::Win32::System::JobObjects::CreateJobObjectW;
    unsafe {
        let job = CreateJobObjectW(None, None);
        if let Ok(handle) = job {
            windows::Win32::Foundation::CloseHandle(handle).ok();
        }
    }

    // Trigger 4: local IPv4 TCP connection → UInt16 (ports)
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener};
    let v4_listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
    let v4_addr = v4_listener.local_addr().unwrap();
    let _ = std::net::TcpStream::connect_timeout(&v4_addr, Duration::from_secs(2));
    drop(v4_listener);

    // Trigger 5: local IPv6 TCP connection → Binary (IPv6 addresses)
    // If IPv6 loopback is unavailable, skip the Binary expectation.
    let mut expected_types = EXPECTED_TYPES.to_vec();
    let v6_addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0));
    if let Ok(v6_listener) = TcpListener::bind(v6_addr) {
        let listener_addr = v6_listener.local_addr().unwrap();
        let _ = std::net::TcpStream::connect_timeout(&listener_addr, Duration::from_secs(2));
        drop(v6_listener);
    } else {
        expected_types.retain(|type_name| *type_name != "Binary");
        println!("IPv6 loopback unavailable; skipping Binary type expectation");
    }

    std::thread::sleep(Duration::from_millis(500));
    trace.stop().expect("Failed to stop session");

    // Report types with sample values
    let samples = type_samples.lock().unwrap();
    println!("\nTypes parsed ({}):", samples.len());

    let mut sorted_types: Vec<_> = samples.keys().cloned().collect();
    sorted_types.sort();
    for type_name in &sorted_types {
        if let Some((prop_name, value)) = samples.get(type_name) {
            println!("  {type_name:15} <- {prop_name:20} = {value}");
        }
    }

    // Verify expected types
    let mut missing = Vec::new();
    for expected in &expected_types {
        if !samples.contains_key(*expected) {
            missing.push(*expected);
        }
    }

    assert!(
        missing.is_empty(),
        "Missing types: {missing:?}\nObserved: {sorted_types:?}"
    );

    // Check for parse errors
    let errors: Vec<_> = samples
        .iter()
        .filter(|(_, (_, v))| v.starts_with("ERR:"))
        .map(|(t, (p, v))| format!("{t}.{p}: {v}"))
        .collect();

    assert!(
        errors.is_empty(),
        "Parse errors:\n  {}",
        errors.join("\n  ")
    );

    println!(
        "\nAll {} expected types parsed successfully!",
        expected_types.len()
    );
}
