//! Integration tests for Microsoft-Windows-Kernel-File provider
//!
//! These tests assert correct *parser* behaviour against known values derived
//! from file operations we perform ourselves. The `NameCreate` event layout is:
//!
//! ```text
//! [0] FileKey   Pointer       (8 bytes on x64, 4 on x86)
//! [1] FileName  UnicodeString ← WideStrRef; tests wide-string after a pointer
//! ```
//!
//! Creating a file at a uniquely named path and filtering on that name gives
//! us ground truth: the FileName field must decode to the exact path we used.

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

use etw::Trace;
use example_providers::kernel::file;
use std::{
    fs,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

struct NameCreateData {
    file_key: usize,
    file_name: String,
}

#[test]
fn test_kernel_file_parses_pointer_and_widestr_fields() {
    // Unique name so we can identify our own NameCreate among system-wide noise.
    let unique_name = format!("etw_rs_parser_{}.tmp", std::process::id());
    let temp_path = std::env::temp_dir().join(&unique_name);
    let unique_name_lc = unique_name.to_lowercase();
    let unique_name_lc_cb = unique_name_lc.clone();

    let mut trace = Trace::new("etw-rs_Test_KernelFile").expect("Failed to create trace session");

    let Some(()) = common::skip_or_panic("trace.start", trace.start()) else {
        return;
    };

    let Some(()) = common::skip_or_panic(
        "Failed to enable Kernel-File provider",
        trace.enable_provider(file::GUID, file::keyword::FILENAME),
    ) else {
        return;
    };

    // Only store NameCreate events whose FileName ends with our unique name.
    let captures: Arc<Mutex<Vec<NameCreateData>>> = Arc::new(Mutex::new(Vec::new()));
    let captures_cb = captures.clone();

    trace.set_event_callback(move |event, context| {
        if event.id() != file::event::NAME_CREATE {
            return Ok(());
        }
        let mut p = context.parser(event)?;
        let file_key: usize = p.get("FileKey")?;
        let file_name: String = p.get("FileName")?;
        if file_name.to_lowercase().ends_with(&unique_name_lc_cb) {
            captures_cb.lock().unwrap().push(NameCreateData {
                file_key,
                file_name,
            });
        }
        Ok(())
    });

    trace
        .start_processing_thread()
        .expect("Failed to start processing");

    // Create the file — this is the operation that triggers NameCreate.
    fs::write(&temp_path, b"").expect("Failed to create temp file");

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
        if !captures.lock().unwrap().is_empty() {
            break;
        }
    }

    let _ = fs::remove_file(&temp_path);
    trace.stop().expect("Failed to stop session");

    let captures = captures.lock().unwrap();
    assert!(
        !captures.is_empty(),
        "no NameCreate event for {unique_name:?} — FILENAME keyword not delivering events"
    );
    let ev = &captures[0];

    // Pointer field [0]: kernel file object address, must be non-zero.
    assert_ne!(
        ev.file_key, 0,
        "NameCreate.FileKey should be a non-zero kernel pointer"
    );

    // WideStrRef field [1], positioned after the pointer: must end with our filename.
    // ETW delivers the full NT device path, e.g.:
    //   \Device\HarddiskVolumeN\Users\...\Temp\etw_rs_parser_PID.tmp
    assert!(
        ev.file_name.to_lowercase().ends_with(&unique_name_lc),
        "NameCreate.FileName {:?} does not end with {unique_name:?}",
        ev.file_name
    );

    println!(
        "NameCreate: FileKey=0x{:x} FileName={:?}",
        ev.file_key, ev.file_name
    );
}
