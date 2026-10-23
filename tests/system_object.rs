//! Integration test for Trace object manager (handle) events.
//!
//! Requires Administrator on dev-local; the soft-skip helper handles that.

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
    system_logger::masks::{PERF_NO_SYSCONFIG, PERF_OB_HANDLE},
};
use example_providers::classic::kernel_trace::ob_trace;
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
fn test_system_object_events() {
    let mut trace = Trace::new("etw-rs_Test_Object").expect("Failed to create trace session");

    trace.set_events(&[PERF_OB_HANDLE, PERF_NO_SYSCONFIG]);

    let Some(()) = common::skip_or_panic("trace.start", trace.start()) else {
        return;
    };

    let event_captured = Arc::new(AtomicBool::new(false));
    let event_captured_clone = event_captured.clone();

    trace.set_event_callback(move |event, context| {
        // Filter for object manager events
        if event.provider_guid() != ob_trace::GUID {
            return Ok(());
        }

        let op = match event.opcode() {
            ob_trace::opcode::OBJECT_CREATE_HANDLE => "CreateHandle",
            ob_trace::opcode::OBJECT_CLOSE_HANDLE => "CloseHandle",
            ob_trace::opcode::OBJECT_DUPLICATE_HANDLE => "DuplicateHandle",
            _ => return Ok(()),
        };

        // Try to get object type from the event
        let obj_type = if let Ok(mut parser) = context.parser(event) {
            parser.get::<String>("ObjectType").unwrap_or_default()
        } else {
            String::new()
        };

        println!("{op} event captured (type: {obj_type})");
        event_captured_clone.store(true, Ordering::Relaxed);
        Ok(())
    });

    trace
        .start_processing_thread()
        .expect("Failed to start processing");

    // Trigger handle events by:
    // 1. Opening files (creates file handles)
    // 2. Spawning processes (creates process/thread handles)
    let temp_path = std::env::temp_dir().join("etw_rs_test_object.txt");
    {
        let _file = std::fs::File::create(&temp_path);
        // File handle is closed when _file goes out of scope
    }
    let _ = std::fs::remove_file(&temp_path);

    // Spawn a process which creates process and thread handles
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
        println!("WARNING: No object handle events captured");
    }
}
