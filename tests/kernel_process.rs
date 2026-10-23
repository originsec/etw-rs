//! Integration tests for Microsoft-Windows-Kernel-Process provider
//!
//! These tests assert correct *parser* behaviour against known values derived
//! from a child process we control. Each field is chosen to exercise a
//! distinct aspect of the parser:
//!
//! - `ProcessID` (u32 at position 0) — exact PID match via `child.id()`
//! - `ParentProcessID` (u32 after a u64) — verifies u64 advances position correctly
//! - `CreateTime` (FileTime → `Timestamp`) — same value must appear in both Start and Stop
//! - `ExitCode` (u32 in Stop) — exact match: we spawn with `exit 0`
//! - `ImageName` in Start (WideStrRef) — full NT path ending with `cmd.exe`
//! - `ImageName` in Stop (AnsiStrRef) — base name ending with `cmd.exe`

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

use etw::{Timestamp, Trace};
use example_providers::kernel::process;
use std::{
    process::Command,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

struct StartFields {
    pid: u32,
    parent_pid: u32,
    create_time: Timestamp,
    image_name: String,
}

struct StopFields {
    pid: u32,
    create_time: Timestamp,
    exit_time: Timestamp,
    exit_code: u32,
    image_name: String,
}

#[test]
fn test_kernel_process_parses_u32_filetime_and_strings() {
    let mut trace =
        Trace::new("etw-rs_Test_KernelProcess").expect("Failed to create trace session");

    let Some(()) = common::skip_or_panic(
        "trace.enable_provider",
        trace.enable_provider(process::GUID, process::keyword::PROCESS),
    ) else {
        return;
    };

    // Collect parsed fields for Start and Stop events. We store all events and
    // filter by PID at assertion time to avoid races with other processes.
    let starts: Arc<Mutex<Vec<StartFields>>> = Arc::new(Mutex::new(Vec::new()));
    let stops: Arc<Mutex<Vec<StopFields>>> = Arc::new(Mutex::new(Vec::new()));
    let starts_cb = starts.clone();
    let stops_cb = stops.clone();

    trace.set_event_callback(move |event, context| {
        use process::event::{PROCESS_START, PROCESS_STOP};
        match event.id() {
            PROCESS_START => {
                let mut p = context.parser(event)?;
                starts_cb.lock().unwrap().push(StartFields {
                    pid: p.get("ProcessID")?,
                    parent_pid: p.get("ParentProcessID")?,
                    create_time: p.get("CreateTime")?,
                    image_name: p.get("ImageName")?,
                });
            }
            PROCESS_STOP => {
                let mut p = context.parser(event)?;
                stops_cb.lock().unwrap().push(StopFields {
                    pid: p.get("ProcessID")?,
                    create_time: p.get("CreateTime")?,
                    exit_time: p.get("ExitTime")?,
                    exit_code: p.get("ExitCode")?,
                    image_name: p.get("ImageName")?,
                });
            }
            _ => {}
        }
        Ok(())
    });

    trace
        .start_processing_thread()
        .expect("Failed to start processing");

    let own_pid = std::process::id();

    // Spawn a child with a known command and exit code. Record its PID before
    // waiting so we have ground truth for every field assertion below.
    let mut child = Command::new("cmd.exe")
        .args(["/c", "exit", "0"])
        .spawn()
        .expect("Failed to spawn cmd.exe");
    let child_pid = child.id();
    let _ = child.wait();

    // Poll until the ProcessStop for the child arrives or the deadline passes.
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
        if stops.lock().unwrap().iter().any(|s| s.pid == child_pid) {
            break;
        }
    }

    trace.stop().expect("Failed to stop session");

    // --- ProcessStart assertions ---

    let starts = starts.lock().unwrap();
    let start = starts
        .iter()
        .find(|s| s.pid == child_pid)
        .unwrap_or_else(|| panic!("no ProcessStart event for PID {child_pid}"));

    // u32 at position 0: exact PID match.
    assert_eq!(start.pid, child_pid, "ProcessStart.ProcessID mismatch");

    // u32 after intervening fields: verifies the parser advances correctly.
    assert_eq!(
        start.parent_pid, own_pid,
        "ProcessStart.ParentProcessID should be our own PID {own_pid}"
    );

    // FileTime field: set at process creation; raw value must be non-zero.
    assert_ne!(
        start.create_time.raw(),
        0,
        "ProcessStart.CreateTime should be non-zero"
    );

    // WideStrRef (Unicode string): full NT device path ending with the binary name.
    assert!(
        start.image_name.to_lowercase().ends_with("cmd.exe"),
        "ProcessStart.ImageName {:?} does not end with 'cmd.exe'",
        start.image_name
    );

    println!(
        "ProcessStart: PID={} ParentPID={} CreateTime={} ImageName={:?}",
        start.pid,
        start.parent_pid,
        start.create_time.raw(),
        start.image_name
    );

    // --- ProcessStop assertions ---

    let stops = stops.lock().unwrap();
    let stop = stops
        .iter()
        .find(|s| s.pid == child_pid)
        .unwrap_or_else(|| panic!("no ProcessStop event for PID {child_pid}"));

    // u32 at position 0.
    assert_eq!(stop.pid, child_pid, "ProcessStop.ProcessID mismatch");

    // CreateTime in Stop must equal CreateTime in Start (same process object).
    // Cross-event FileTime equality catches misaligned reads in either event.
    assert_eq!(
        stop.create_time.raw(),
        start.create_time.raw(),
        "ProcessStop.CreateTime ({}) != ProcessStart.CreateTime ({})",
        stop.create_time.raw(),
        start.create_time.raw(),
    );

    // ExitTime must be >= CreateTime (process cannot exit before it starts).
    assert!(
        stop.exit_time.raw() >= stop.create_time.raw(),
        "ProcessStop.ExitTime ({}) < CreateTime ({})",
        stop.exit_time.raw(),
        stop.create_time.raw(),
    );

    // u32 exit code: we spawned `cmd /c exit 0`, so this must be 0.
    assert_eq!(
        stop.exit_code, 0,
        "ProcessStop.ExitCode should be 0 for 'cmd /c exit 0'"
    );

    // AnsiStrRef (ANSI string): Stop event uses a different string type than Start.
    assert!(
        stop.image_name.to_lowercase().ends_with("cmd.exe"),
        "ProcessStop.ImageName {:?} does not end with 'cmd.exe'",
        stop.image_name
    );

    println!(
        "ProcessStop: PID={} CreateTime={} ExitTime={} ExitCode={} ImageName={:?}",
        stop.pid,
        stop.create_time.raw(),
        stop.exit_time.raw(),
        stop.exit_code,
        stop.image_name
    );
}
