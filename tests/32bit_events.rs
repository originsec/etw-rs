//! Integration tests for 32-bit event parsing.
//!
//! User-mode providers emit events in the process's bitness. Running workloads
//! from 32-bit PowerShell produces 32-bit events that our parser must handle.
//!
//! Two test cases:
//! 1. **DNS-Client** — events with no Pointer/SizeT fields, verifying basic 32-bit event parsing
//!    works.
//! 2. **DotNETRuntime** — GCSampledObjectAllocationHigh (event 20) has `Address: Pointer` and
//!    `TypeID: Pointer` fields that must be parsed as 4-byte values from a 32-bit CLR process.
//!
//! Requirements:
//! - Requires Performance Log Users group membership (or Administrator) for ETW session creation
//! - 32-bit PowerShell must exist at `C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`

#![cfg(not(miri))]
// Win32 API calls are not supported under Miri.
// Tests use println for output and unwrap/expect for cleaner test code
#![expect(
    clippy::print_stdout,
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test binary: printing aids diagnosis and panics are the failure mode"
)]

#[path = "common/mod.rs"]
mod common;

use etw::Trace;
use example_providers::user::{dns_client, dotnet_runtime};
use std::{
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::Duration,
};

/// Path to 32-bit PowerShell on 64-bit Windows.
const POWERSHELL_X86: &str = r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe";

/// Launch 32-bit PowerShell with the given command and wait for it to finish.
fn run_powershell_x86(command: &str) {
    println!("Launching 32-bit PowerShell: {command}");
    match Command::new(POWERSHELL_X86)
        .args(["-NoProfile", "-Command", command])
        .output()
    {
        Ok(output) => {
            println!(
                "PowerShell x86 exited with status={}, stdout={} bytes",
                output.status,
                output.stdout.len()
            );
        }
        Err(e) => {
            println!("WARNING: Failed to launch 32-bit PowerShell: {e}");
        }
    }
}

// ---------------------------------------------------------------------------
// Test 1: 32-bit DNS-Client events (no Pointer/SizeT fields)
// ---------------------------------------------------------------------------

#[test]
fn test_parse_32bit_dns_events() {
    assert!(
        std::path::Path::new(POWERSHELL_X86).exists(),
        "32-bit PowerShell not found at {POWERSHELL_X86}"
    );

    let mut trace = Trace::new("etw-rs_Test_32bit_DNS").expect("Failed to create trace session");

    let Some(()) = common::skip_or_panic("trace.start", trace.start()) else {
        return;
    };

    // Enable DNS-Client with all keywords to capture event 3008 (query completed)
    trace
        .enable_provider(dns_client::GUID, 0xFFFF_FFFF_FFFF_FFFF)
        .expect("Failed to enable DNS-Client provider");

    let parsed_count = Arc::new(AtomicU32::new(0));
    let got_32bit = Arc::new(AtomicBool::new(false));
    let parse_errors = Arc::new(AtomicU32::new(0));
    let printed_once = Arc::new(AtomicBool::new(false));

    let parsed_clone = Arc::clone(&parsed_count);
    let got_32bit_clone = Arc::clone(&got_32bit);
    let errors_clone = Arc::clone(&parse_errors);
    let printed_once_clone = Arc::clone(&printed_once);

    trace.set_event_callback(move |event, context| {
        if event.provider_guid() != dns_client::GUID {
            return Ok(());
        }

        let flags = event.as_raw().EventHeader.Flags;
        let is_32bit = (flags
            & windows::Win32::System::Diagnostics::Etw::EVENT_HEADER_FLAG_32_BIT_HEADER as u16)
            != 0;

        if is_32bit {
            got_32bit_clone.store(true, Ordering::Relaxed);
        }

        // Try to parse — this is what we're testing
        match context.parser(event) {
            Ok(mut parser) => {
                // Event 3008 has QueryName (UnicodeString) and QueryStatus (UInt32)
                if event.id() == dns_client::event::EVENT_3008 {
                    let name = parser.get::<std::ffi::OsString>("QueryName")?;
                    let name = name.display();
                    let status: u32 = parser.get("QueryStatus")?;
                    if printed_once_clone
                        .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                        .is_ok()
                    {
                        println!(
                            "Parsed DNS event 3008: name={name} status={status} is_32bit={is_32bit}"
                        );
                    }
                }
                parsed_clone.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                println!(
                    "Parse error for event_id={} is_32bit={is_32bit}: {e}",
                    event.id()
                );
                errors_clone.fetch_add(1, Ordering::Relaxed);
            }
        }

        Ok(())
    });

    trace
        .start_processing_thread()
        .expect("Failed to start processing");

    // Trigger DNS from 32-bit PowerShell — produces 32-bit DNS-Client events
    run_powershell_x86("Resolve-DnsName example.com");

    // Wait for events to arrive
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(100));
        if got_32bit.load(Ordering::Relaxed) && parsed_count.load(Ordering::Relaxed) > 0 {
            break;
        }
    }

    trace.stop().expect("Failed to stop session");

    let total_parsed = parsed_count.load(Ordering::Relaxed);
    let total_errors = parse_errors.load(Ordering::Relaxed);
    let saw_32bit = got_32bit.load(Ordering::Relaxed);

    println!("Results: parsed={total_parsed} errors={total_errors} saw_32bit={saw_32bit}");

    assert!(
        saw_32bit,
        "Expected to see 32-bit events from SysWOW64 PowerShell"
    );
    assert_eq!(
        total_errors, 0,
        "Parser should handle 32-bit events without errors"
    );
    assert!(
        total_parsed > 0,
        "Should have parsed at least one DNS-Client event"
    );
}

// ---------------------------------------------------------------------------
// Test 2: 32-bit .NET Runtime events with Pointer fields
// ---------------------------------------------------------------------------

/// A GC sampled allocation event captured from a 32-bit CLR process.
/// Event 20 (GCSampledObjectAllocationHigh) has Pointer-typed fields.
#[derive(Debug)]
struct GcSampledAlloc {
    address: usize,
    type_id: usize,
    is_32bit: bool,
}

#[test]
fn test_parse_32bit_pointer_fields() {
    assert!(
        std::path::Path::new(POWERSHELL_X86).exists(),
        "32-bit PowerShell not found at {POWERSHELL_X86}"
    );

    let mut trace =
        Trace::new("etw-rs_Test_32bit_Pointer").expect("Failed to create trace session");

    let Some(()) = common::skip_or_panic("trace.start", trace.start()) else {
        return;
    };

    // GCSampledObjectAllocationHigh (event 20) requires keyword 0x200000.
    // This event has Address: Pointer and TypeID: Pointer fields.
    trace
        .enable_provider(
            dotnet_runtime::GUID,
            dotnet_runtime::keyword::GCKEYWORD | 0x20_0000,
        )
        .expect("Failed to enable DotNETRuntime provider");

    let captured = Arc::new(Mutex::new(Vec::<GcSampledAlloc>::new()));
    let got_32bit = Arc::new(AtomicBool::new(false));
    let parse_errors = Arc::new(AtomicU32::new(0));
    let printed_once = Arc::new(AtomicBool::new(false));

    let captured_clone = Arc::clone(&captured);
    let got_32bit_clone = Arc::clone(&got_32bit);
    let errors_clone = Arc::clone(&parse_errors);
    let printed_once_clone = Arc::clone(&printed_once);

    trace.set_event_callback(move |event, context| {
        if event.provider_guid() != dotnet_runtime::GUID {
            return Ok(());
        }

        let flags = event.as_raw().EventHeader.Flags;
        let is_32bit = (flags
            & windows::Win32::System::Diagnostics::Etw::EVENT_HEADER_FLAG_32_BIT_HEADER as u16)
            != 0;

        if is_32bit {
            got_32bit_clone.store(true, Ordering::Relaxed);
        }

        // GCSampledObjectAllocationHigh (event 20) has Pointer fields
        if event.id() != 20 {
            return Ok(());
        }

        match context.parser(event) {
            Ok(mut parser) => {
                let address: usize = parser.get("Address")?;
                let type_id: usize = parser.get("TypeID")?;
                let _count: u32 = parser.get("ObjectCountForTypeSample")?;
                let _size: u64 = parser.get("TotalSizeForTypeSample")?;
                let _instance_id: u16 = parser.get("ClrInstanceID")?;

                if is_32bit {
                    // 32-bit pointer must fit in 32-bit range
                    assert!(
                        u32::try_from(type_id).is_ok(),
                        "TypeID from 32-bit process should fit in 32 bits, got 0x{type_id:X}"
                    );
                    assert!(
                        u32::try_from(address).is_ok(),
                        "Address from 32-bit process should fit in 32 bits, got 0x{address:X}"
                    );
                }

                if printed_once_clone
                    .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    println!(
                        "GCSampledObjectAllocationHigh: Address=0x{address:X} TypeID=0x{type_id:X} is_32bit={is_32bit}"
                    );
                }

                captured_clone.lock().unwrap().push(GcSampledAlloc {
                    address,
                    type_id,
                    is_32bit,
                });
            }
            Err(e) => {
                println!(
                    "Parse error for event_id={} version={} is_32bit={is_32bit}: {e}",
                    event.id(),
                    event.version()
                );
                errors_clone.fetch_add(1, Ordering::Relaxed);
            }
        }

        Ok(())
    });

    // Low-volume provider: GCAllocationTick events only fire from the 32-bit
    // PowerShell invocation below. Use the startup timeout so ProcessTrace
    // has time to settle before we issue the trigger.
    // (Tuned for slow CI startup.)
    trace
        .set_processing_thread_startup_timeout(500)
        .start_processing_thread()
        .expect("Failed to start processing");

    // Force allocations in 32-bit .NET CLR to trigger GCAllocationTick events.
    // GCAllocationTick fires every ~100KB of allocations. We allocate many large
    // byte arrays to reliably exceed that threshold multiple times.
    run_powershell_x86(
        "for ($j = 0; $j -lt 50; $j++) { \
             $a = New-Object 'byte[]' 1MB; \
             [GC]::Collect(); \
         }",
    );

    // Wait for events
    for _ in 0..100 {
        std::thread::sleep(Duration::from_millis(100));
        let events = captured.lock().unwrap();
        if events.iter().any(|e| e.is_32bit) {
            break;
        }
    }

    trace.stop().expect("Failed to stop session");

    let events = captured.lock().unwrap();
    let total_errors = parse_errors.load(Ordering::Relaxed);
    let saw_32bit = got_32bit.load(Ordering::Relaxed);

    let events_32bit: Vec<_> = events.iter().filter(|e| e.is_32bit).collect();

    println!(
        "Results: total_events={} 32bit_events={} errors={total_errors} saw_32bit={saw_32bit}",
        events.len(),
        events_32bit.len()
    );

    assert!(saw_32bit, "Expected to see 32-bit events from 32-bit CLR");
    assert_eq!(
        total_errors, 0,
        "Parser should handle 32-bit Pointer fields without errors"
    );
    assert!(
        !events_32bit.is_empty(),
        "Should have parsed at least one GCSampledObjectAllocationHigh with Pointer fields from 32-bit CLR"
    );

    // Verify the pointer values look reasonable (non-zero, fits in 32-bit)
    for e in &events_32bit {
        assert_ne!(e.type_id, 0, "TypeID should not be zero");
        assert!(
            u32::try_from(e.type_id).is_ok(),
            "TypeID from 32-bit process must fit in 32 bits: 0x{:X}",
            e.type_id
        );
        assert_ne!(e.address, 0, "Address should not be zero");
        assert!(
            u32::try_from(e.address).is_ok(),
            "Address from 32-bit process must fit in 32 bits: 0x{:X}",
            e.address
        );
    }
}
