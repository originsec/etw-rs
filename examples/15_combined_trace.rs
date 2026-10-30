#![expect(
    clippy::print_stdout,
    reason = "example output is the point of the example"
)]

//! Combined Process Provider example.
//!
//! Modern providers can also be combined with the `EnableFlags` and `PERFINFO_GROUPMASK` system
//! logger enablement methods.
//!
//! # Requirements
//!
//! Must be run as Administrator for kernel tracing.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example 15_combined_trace
//! ```

use etw::{Sid, Trace, system_logger::masks::PERF_NO_SYSCONFIG};
use example_providers::{classic::process as system_process, kernel::process as kernel_process};
use std::{ffi::OsString, thread::sleep, time::Duration};

fn main() -> etw::Result<()> {
    println!("System Logger + Manifest Provider Example");
    println!("═════════════════════════════════════════");

    let mut trace = Trace::new("combined_trace")?;

    // Enable system logger event groups.
    // - PERF_PROCESS: Process start/end events
    // - PERF_NO_SYSCONFIG: Suppress some system configuration events at startup
    // Enable Microsoft-Windows-Kernel-Process provider.
    trace
        .set_events(&[system_process::PERF_PROCESS, PERF_NO_SYSCONFIG])
        .enable_provider(kernel_process::GUID, kernel_process::keyword::PROCESS)?;

    trace.set_event_callback(|event, context| {
        if event.provider_guid() == system_process::CLASS_GUID
            && event.opcode() == system_process::opcode::START
        {
            let mut parser = context.parser(event)?;
            let pid: u32 = parser.get("ProcessId")?;
            // Only the classic event includes the command line and user SID
            let sid: Sid = parser.get("UserSID")?;
            let cmdline: OsString = parser.get("CommandLine")?;
            println!(
                "[+] SystemLogger   pid:{pid} sid:{sid} {}",
                cmdline.display()
            );
        }

        if event.provider_guid() == kernel_process::GUID
            && event.id() == kernel_process::event::PROCESS_START
        {
            let mut parser = context.parser(event)?;
            let pid: u32 = parser.get("ProcessID")?;
            let image_name: OsString = parser.get("ImageName")?;
            // Only the modern event includes the sequence number and integrity
            // Note: EVENT_HEADER_EXT_TYPE_SID logs the creator thread's SID
            let sequence: u64 = parser.get("ProcessSequenceNumber")?;
            let integrity: Sid = parser.get("MandatoryLabel")?;
            println!(
                "[+] Kernel-Process pid:{pid} sequence:{sequence} integrity:{integrity} {}",
                image_name.display()
            );
        }

        Ok(())
    });

    println!("Listening for process events for 10 seconds...");
    trace.start_processing_thread()?;
    sleep(Duration::from_secs(10));

    Ok(())
}
