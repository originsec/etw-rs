#![expect(
    clippy::print_stdout,
    reason = "example output is the point of the example"
)]

//! Process System Provider example.
//!
//! This example demonstrates using the System Providers.
//! These are a convenience *enablement-only* method for system logger events in addition to the
//! `EnableFlags` and `PERFINFO_GROUPMASK` methods.
//!
//! # Important
//!
//! System providers require [`SYSTEM_LOGGER_MODE`](etw::session::SYSTEM_LOGGER_MODE) to be set.
//!
//! # Requirements
//!
//! Must be run as Administrator for kernel tracing.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example 14_system_providers
//! ```

use etw::{SidRef, Trace, WideStrRef, session::SYSTEM_LOGGER_MODE};
use example_providers::{classic::process as system_process, kernel::process as kernel_process};
use std::{thread::sleep, time::Duration};
use windows::Win32::System::Diagnostics::Etw::{
    SYSTEM_PROCESS_KW_GENERAL, SystemProcessProviderGuid,
};

fn main() -> etw::Result<()> {
    println!("Process System Provider Example");
    println!("═══════════════════════════════");

    let mut trace = Trace::new("system_providers")?;
    trace.set_log_file_mode(SYSTEM_LOGGER_MODE).start()?;

    // https://learn.microsoft.com/en-us/windows/win32/etw/system-providers
    // Enable the Process System Provider with the GENERAL keyword
    // This is the same pattern as modern (manifest) providers.
    trace.enable_provider(
        etw::Guid::from_u128(SystemProcessProviderGuid.to_u128()),
        SYSTEM_PROCESS_KW_GENERAL,
    )?;
    println!("Enabled system logger process provider.");

    // System providers can be mixed with non-system providers.
    // Let's also enable the modern Microsoft-Windows-Kernel-Process provider
    trace.enable_provider(kernel_process::GUID, kernel_process::keyword::PROCESS)?;
    println!("Enabled Microsoft-Windows-Kernel-Process provider.");

    trace.set_event_callback(|event, context| {
        // Important:
        // Even though we enable using the modern System Provider keywords approach,
        // the generated events are still the legacy system trace events.
        // https://learn.microsoft.com/en-us/windows/win32/etw/msnt-systemtrace
        if event.provider_guid() == system_process::CLASS_GUID
            && event.opcode() == system_process::opcode::START
        {
            let mut parser = context.parser(event)?;
            let pid: u32 = parser.get("ProcessId")?;
            let cmdline: String = parser
                .as_ref::<WideStrRef>("CommandLine")?
                .to_string_lossy();
            println!("[+] System Logger  pid:{pid} {cmdline}");
        }

        if event.provider_guid() == kernel_process::GUID
            && event.id() == kernel_process::event::PROCESS_START
        {
            let mut parser = context.parser(event)?;

            let pid: u32 = parser.get("ProcessID")?;
            let sequence: u64 = parser.get("ProcessSequenceNumber")?;
            let integrity: String = parser.as_ref::<SidRef>("MandatoryLabel")?.to_string();
            let image_name: String = parser.as_ref::<WideStrRef>("ImageName")?.to_string_lossy();
            println!(
                "[+] Kernel-Process pid:{pid} sequence:{sequence} integrity:{integrity} {image_name}"
            );
        }

        Ok(())
    });

    println!("Listening for process events for 10 seconds...");
    trace.start_processing_thread()?;
    sleep(Duration::from_secs(10));

    Ok(())
}
