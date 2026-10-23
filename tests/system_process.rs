//! Integration tests for MOF/classic System Logger Process events
//!
//! These tests assert correct *parser* behaviour against known values derived
//! from a child process we control. The MOF Process_V3 layout is:
//!
//! ```text
//! [0] UniqueProcessKey  Pointer  (8 bytes on x64, 4 on x86)
//! [1] ProcessId         UINT32
//! [2] ParentId          UINT32   ← tests u32 after a pointer-sized field
//! [3] SessionId         UINT32
//! [4] ExitStatus        LONG     ← only meaningful on End
//! [5] DirectoryTableBase Pointer
//! [6] Flags             UINT32
//! [7] UserSID           WBEMSID
//! [8] ImageFileName     AnsiStr  ← tests ANSI string parsing
//! [9] CommandLine       WideStr  ← tests Unicode string parsing (Win Vista+)
//! ```

#![cfg(not(miri))]
// Win32 API calls are not supported under Miri.
// Tests use println for output and unwrap/expect for cleaner test code
#![expect(
    clippy::print_stdout,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::clone_on_ref_ptr,
    reason = "test binary: printing aids diagnosis and panics are the failure mode"
)]

#[path = "common/mod.rs"]
mod common;

use etw::{
    AnsiStrRef, Trace,
    system_logger::masks::{PERF_NO_SYSCONFIG, PERF_PROCESS},
};
use example_providers::classic::kernel_trace::process as classic_process;
use serial_test::serial;
use std::{
    process::Command,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use windows::Win32::Globalization::CP_ACP;

struct StartData {
    pid: u32,
    parent_id: u32,
    image_name: String,
}

struct EndData {
    pid: u32,
    exit_status: i32,
}

#[test]
#[serial(system_logger)]
fn test_system_process_parses_u32_ansistr_and_pointer_fields() {
    let mut trace = Trace::new("etw-rs_Test_Process").expect("Failed to create trace session");

    trace.set_events(&[PERF_PROCESS, PERF_NO_SYSCONFIG]);
    let Some(()) = common::skip_or_panic("trace.start", trace.start()) else {
        return;
    };

    let starts: Arc<Mutex<Vec<StartData>>> = Arc::new(Mutex::new(Vec::new()));
    let ends: Arc<Mutex<Vec<EndData>>> = Arc::new(Mutex::new(Vec::new()));
    let starts_cb = starts.clone();
    let ends_cb = ends.clone();

    trace.set_event_callback(move |event, context| {
        if event.provider_guid() != classic_process::GUID {
            return Ok(());
        }
        match event.opcode() {
            classic_process::opcode::START => {
                if let Ok(mut p) = context.parser(event) {
                    let pid: u32 = p.get("ProcessId").unwrap_or(0);
                    let parent_id: u32 = p.get("ParentId").unwrap_or(0);
                    let image_name = p
                        .as_ref::<AnsiStrRef<'_>>("ImageFileName")
                        .and_then(|a| a.decode(CP_ACP))
                        .unwrap_or_default();
                    starts_cb.lock().unwrap().push(StartData {
                        pid,
                        parent_id,
                        image_name,
                    });
                }
            }
            classic_process::opcode::END => {
                if let Ok(mut p) = context.parser(event) {
                    let pid: u32 = p.get("ProcessId").unwrap_or(0);
                    let exit_status: i32 = p.get("ExitStatus").unwrap_or(-1);
                    ends_cb.lock().unwrap().push(EndData { pid, exit_status });
                }
            }
            _ => {}
        }
        Ok(())
    });

    trace
        .start_processing_thread()
        .expect("Failed to start processing");

    let own_pid = std::process::id();

    let mut child = Command::new("cmd.exe")
        .args(["/c", "exit", "0"])
        .spawn()
        .expect("Failed to spawn cmd.exe");
    let child_pid = child.id();
    let _ = child.wait();

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
        if ends.lock().unwrap().iter().any(|e| e.pid == child_pid) {
            break;
        }
    }

    trace.stop().expect("Failed to stop session");

    // --- Start event assertions ---

    let starts = starts.lock().unwrap();
    let start = starts
        .iter()
        .find(|s| s.pid == child_pid)
        .unwrap_or_else(|| panic!("no Process Start event for PID {child_pid}"));

    // u32 at position [1] (after an 8-byte Pointer on x64).
    assert_eq!(start.pid, child_pid, "Start.ProcessId mismatch");

    // u32 at position [2]: tests that the parser advanced pointer-width bytes
    // for UniqueProcessKey before reading ProcessId and ParentId.
    assert_eq!(
        start.parent_id, own_pid,
        "Start.ParentId should be our own PID {own_pid}"
    );

    // ANSI string after several pointer/u32 fields.
    assert!(
        start.image_name.to_lowercase().ends_with("cmd.exe"),
        "Start.ImageFileName {:?} does not end with 'cmd.exe'",
        start.image_name
    );

    println!(
        "Process Start: PID={} ParentId={} ImageFileName={:?}",
        start.pid, start.parent_id, start.image_name
    );

    // --- End event assertions ---

    let ends = ends.lock().unwrap();
    let end = ends
        .iter()
        .find(|e| e.pid == child_pid)
        .unwrap_or_else(|| panic!("no Process End event for PID {child_pid}"));

    assert_eq!(end.pid, child_pid, "End.ProcessId mismatch");

    // i32 exit status: `cmd /c exit 0` exits with STATUS_SUCCESS (0).
    assert_eq!(
        end.exit_status, 0,
        "End.ExitStatus should be 0 for 'cmd /c exit 0'"
    );

    println!(
        "Process End: PID={} ExitStatus={}",
        end.pid, end.exit_status
    );
}
