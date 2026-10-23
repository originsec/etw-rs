//! Integration test for Trace virtual memory allocation events.

#![cfg(not(miri))]
// Win32 API calls are not supported under Miri.
// Tests use println for output and unwrap/expect for cleaner test code
#![expect(
    clippy::print_stdout,
    clippy::expect_used,
    clippy::clone_on_ref_ptr,
    clippy::option_if_let_else,
    reason = "test binary: printing aids diagnosis and panics are the failure mode"
)]

#[path = "common/mod.rs"]
mod common;

use etw::{
    Trace,
    system_logger::masks::{PERF_NO_SYSCONFIG, PERF_VIRTUAL_ALLOC},
};
use example_providers::classic::kernel_trace::page_fault;
use serial_test::serial;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

#[test]
#[serial(system_logger)]
fn test_system_virtual_alloc_events() {
    let mut trace = Trace::new("etw-rs_Test_VAlloc").expect("Failed to create trace session");

    trace.set_events(&[PERF_VIRTUAL_ALLOC, PERF_NO_SYSCONFIG]);

    let Some(()) = common::skip_or_panic("trace.start", trace.start()) else {
        return;
    };

    let event_captured = Arc::new(AtomicBool::new(false));
    let event_captured_clone = event_captured.clone();

    trace.set_event_callback(move |event, context| {
        // VirtualAlloc events come through the PAGE_FAULT GUID
        if event.provider_guid() != page_fault::GUID {
            return Ok(());
        }

        let op = match event.opcode() {
            page_fault::opcode::VIRTUAL_ALLOC => "VirtualAlloc",
            page_fault::opcode::VIRTUAL_FREE => "VirtualFree",
            _ => return Ok(()),
        };

        // Try to get process ID from the event
        let pid = if let Ok(mut parser) = context.parser(event) {
            parser.get::<u32>("ProcessId").unwrap_or(0)
        } else {
            0
        };

        if event_captured_clone
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            println!("{op} event captured (PID: {pid})");
        }
        Ok(())
    });

    trace
        .start_processing_thread()
        .expect("Failed to start processing");

    // Trigger VirtualAlloc events by allocating memory
    // Vec allocations go through VirtualAlloc for large sizes
    let _large_alloc: Vec<u8> = vec![0u8; 1024 * 1024]; // 1MB allocation

    // Also spawn a process which will do VirtualAlloc internally
    let _ = std::process::Command::new("cmd.exe")
        .args(["/c", "echo", "test"])
        .output();

    for _ in 0..30 {
        std::thread::sleep(Duration::from_millis(100));
        if event_captured.load(Ordering::Relaxed) {
            break;
        }
    }

    trace.stop().expect("Failed to stop session");

    if !event_captured.load(Ordering::Relaxed) {
        println!("WARNING: No VirtualAlloc events captured");
    }
}
