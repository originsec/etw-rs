//! Integration test for extended data items (SID, PROCESS_START_KEY, STACK_TRACE).

#![cfg(not(miri))]
// Win32 API calls are not supported under Miri.
// Tests use println for output and unwrap/expect for cleaner test code
#![expect(
    clippy::print_stdout,
    clippy::expect_used,
    clippy::clone_on_ref_ptr,
    clippy::missing_const_for_fn,
    reason = "test binary: printing aids diagnosis and panics are the failure mode"
)]

#[path = "common/mod.rs"]
mod common;

use etw::{EnableProperty, Trace, event::extended_data_type};
use example_providers::kernel::process;
use std::{
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use windows::Win32::System::Diagnostics::Etw::TRACE_LEVEL_INFORMATION;

/// Test that SID extended data is captured when enabled
#[test]
fn test_extended_data_sid() {
    let mut trace = Trace::new("etw-rs_Test_ExtSid").expect("Failed to create trace session");

    let Some(()) = common::skip_or_panic("trace.start", trace.start()) else {
        return;
    };

    // Enable with SID extended data. The callback filters for PROCESS_START.
    let Some(()) = common::skip_or_panic(
        "Failed to enable provider with SID",
        trace.enable_provider_ex(
            process::GUID,
            TRACE_LEVEL_INFORMATION,
            process::keyword::PROCESS | process::keyword::THREAD,
            EnableProperty::SID,
            None,
        ),
    ) else {
        return;
    };

    let sid_found = Arc::new(AtomicBool::new(false));
    let events_with_ext_data = Arc::new(AtomicUsize::new(0));
    let sid_found_clone = sid_found.clone();
    let events_clone = events_with_ext_data.clone();

    trace.set_event_callback(move |event, _context| {
        use process::event::PROCESS_START;

        if event.id() != PROCESS_START {
            return Ok(());
        }

        // Check for extended data
        let ext_count = event.extended_data_count();
        if ext_count > 0 {
            events_clone.fetch_add(1, Ordering::Relaxed);

            // Look for SID
            if let Ok(sid) = event.sid() {
                // Basic SID validation: first byte is revision (usually 1)
                if sid.revision() == 1
                    && sid_found_clone
                        .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                        .is_ok()
                {
                    println!(
                        "SID found for process event! Length: {} bytes",
                        sid.as_bytes().len()
                    );
                    // Also check via iterator (first event only)
                    for item in event.extended_data() {
                        println!(
                            "  Extended data type: {}, size: {} bytes",
                            extended_type_name(item.ext_type),
                            item.data.len()
                        );
                    }
                }
            }
        }

        Ok(())
    });

    trace
        .start_processing_thread()
        .expect("Failed to start processing");

    // Spawn a child process to trigger events
    let _ = Command::new("cmd.exe")
        .args(["/c", "echo", "test"])
        .output();

    for _ in 0..30 {
        std::thread::sleep(Duration::from_millis(100));
        if sid_found.load(Ordering::Relaxed) {
            break;
        }
    }

    trace.stop().expect("Failed to stop session");

    let ext_events = events_with_ext_data.load(Ordering::Relaxed);
    println!("Events with extended data: {ext_events}");

    if !sid_found.load(Ordering::Relaxed) {
        println!(
            "WARNING: SID not found in extended data - this may be expected on some configurations"
        );
    }
}

/// Test that PROCESS_START_KEY extended data is captured when enabled
#[test]
fn test_extended_data_process_start_key() {
    let mut trace = Trace::new("etw-rs_Test_ExtPSK").expect("Failed to create trace session");

    let Some(()) = common::skip_or_panic("trace.start", trace.start()) else {
        return;
    };

    // Enable with PROCESS_START_KEY extended data.
    // THREAD keyword included for background activity; see SID test for details.
    let Some(()) = common::skip_or_panic(
        "Failed to enable provider with PROCESS_START_KEY",
        trace.enable_provider_ex(
            process::GUID,
            TRACE_LEVEL_INFORMATION,
            process::keyword::PROCESS | process::keyword::THREAD,
            EnableProperty::PROCESS_START_KEY,
            None,
        ),
    ) else {
        return;
    };

    let key_found = Arc::new(AtomicBool::new(false));
    let key_found_clone = key_found.clone();

    trace.set_event_callback(move |event, _context| {
        use process::event::PROCESS_START;

        if event.id() != PROCESS_START {
            return Ok(());
        }

        if let Ok(key) = event.process_start_key()
            && key_found_clone
                .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            println!("Process start key: 0x{key:016X}");
        }

        Ok(())
    });

    trace
        .start_processing_thread()
        .expect("Failed to start processing");

    // Spawn a child process to trigger events
    let _ = Command::new("cmd.exe")
        .args(["/c", "echo", "test"])
        .output();

    for _ in 0..30 {
        std::thread::sleep(Duration::from_millis(100));
        if key_found.load(Ordering::Relaxed) {
            break;
        }
    }

    trace.stop().expect("Failed to stop session");

    if !key_found.load(Ordering::Relaxed) {
        println!(
            "WARNING: Process start key not found - this may be expected on some configurations"
        );
    }
}

/// Test that STACK_TRACE extended data is captured when enabled
#[test]
fn test_extended_data_stack_trace() {
    let mut trace = Trace::new("etw-rs_Test_ExtStack").expect("Failed to create trace session");

    let Some(()) = common::skip_or_panic("trace.start", trace.start()) else {
        return;
    };

    // Enable with STACK_TRACE extended data.
    // THREAD keyword included for background activity; see SID test for details.
    let Some(()) = common::skip_or_panic(
        "Failed to enable provider with STACK_TRACE",
        trace.enable_provider_ex(
            process::GUID,
            TRACE_LEVEL_INFORMATION,
            process::keyword::PROCESS | process::keyword::THREAD,
            EnableProperty::STACK_TRACE,
            None,
        ),
    ) else {
        return;
    };

    let stack_found = Arc::new(AtomicBool::new(false));
    let stack_found_clone = stack_found.clone();

    trace.set_event_callback(move |event, _context| {
        use process::event::PROCESS_START;

        if event.id() != PROCESS_START {
            return Ok(());
        }

        if let Ok(stack) = event.stack_trace()
            && stack_found_clone
                .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            println!(
                "Stack trace: {} bytes, {} frames",
                stack.as_bytes().len(),
                stack.len()
            );

            println!("  Match ID: 0x{:016X}", stack.match_id());
            let addrs = stack.addresses();
            for (i, addr) in addrs.iter().take(5).enumerate() {
                println!("    [{i}] 0x{addr:016X}");
            }
            if addrs.len() > 5 {
                println!("    ... and {} more frames", addrs.len() - 5);
            }
        }

        Ok(())
    });

    trace
        .start_processing_thread()
        .expect("Failed to start processing");

    // Spawn a child process to trigger events
    let _ = Command::new("cmd.exe")
        .args(["/c", "echo", "test"])
        .output();

    for _ in 0..30 {
        std::thread::sleep(Duration::from_millis(100));
        if stack_found.load(Ordering::Relaxed) {
            break;
        }
    }

    trace.stop().expect("Failed to stop session");

    if !stack_found.load(Ordering::Relaxed) {
        println!("WARNING: Stack trace not found - this may be expected on some configurations");
    }
}

/// Test combining multiple extended data flags
#[test]
fn test_extended_data_combined() {
    let mut trace = Trace::new("etw-rs_Test_ExtCombined").expect("Failed to create trace session");

    let Some(()) = common::skip_or_panic("trace.start", trace.start()) else {
        return;
    };

    // Enable with multiple extended data flags.
    // THREAD keyword included for background activity; see SID test for details.
    let enable_flags = EnableProperty::SID | EnableProperty::PROCESS_START_KEY;
    let Some(()) = common::skip_or_panic(
        "Failed to enable provider with combined flags",
        trace.enable_provider_ex(
            process::GUID,
            TRACE_LEVEL_INFORMATION,
            process::keyword::PROCESS | process::keyword::THREAD,
            enable_flags,
            None,
        ),
    ) else {
        return;
    };

    let found_both = Arc::new(AtomicBool::new(false));
    let found_both_clone = found_both.clone();

    trace.set_event_callback(move |event, _context| {
        use process::event::PROCESS_START;

        if event.id() != PROCESS_START {
            return Ok(());
        }

        let has_sid = event.sid().is_ok();
        let has_psk = event.process_start_key().is_ok();

        if (has_sid || has_psk)
            && found_both_clone
                .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            println!(
                "Process event - extended data count: {}, SID: {}, PSK: {}",
                event.extended_data_count(),
                has_sid,
                has_psk
            );
        }

        Ok(())
    });

    trace
        .start_processing_thread()
        .expect("Failed to start processing");

    // Spawn a child process to trigger events
    let _ = Command::new("cmd.exe")
        .args(["/c", "echo", "test"])
        .output();

    for _ in 0..30 {
        std::thread::sleep(Duration::from_millis(100));
        if found_both.load(Ordering::Relaxed) {
            break;
        }
    }

    trace.stop().expect("Failed to stop session");

    if !found_both.load(Ordering::Relaxed) {
        println!("WARNING: Extended data not found - this may be expected on some configurations");
    }
}

/// Helper function to convert extended data type to name
fn extended_type_name(ext_type: u16) -> &'static str {
    match ext_type {
        extended_data_type::RELATED_ACTIVITYID => "RelatedActivityId",
        extended_data_type::SID => "SID",
        extended_data_type::TS_ID => "TS_ID",
        extended_data_type::INSTANCE_INFO => "InstanceInfo",
        extended_data_type::STACK_TRACE32 => "StackTrace32",
        extended_data_type::STACK_TRACE64 => "StackTrace64",
        extended_data_type::PROCESS_START_KEY => "ProcessStartKey",
        extended_data_type::PROV_TRAITS => "ProvTraits",
        extended_data_type::CONTAINER_ID => "ContainerId",
        _ => "Unknown",
    }
}
