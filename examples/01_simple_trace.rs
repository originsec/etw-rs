#![expect(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "example output is the point of the example"
)]

//! Example demonstrating the simple dynamic schema parser API.
//!
//! This example monitors process creation and termination using the
//! Microsoft-Windows-Kernel-Process provider.
//!
//! # Requirements
//!
//! Must be run as Administrator for kernel tracing.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example 01_simple_trace
//! ```

use etw::{Error::Win32Error, Trace};
use example_providers::kernel::{
    process,
    process::{event::PROCESS_START, keyword::PROCESS},
};
use std::{thread::sleep, time::Duration};
use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;

fn main() -> etw::Result<()> {
    println!("Simple Realtime Trace Example - Process Start/Stop Events");

    // Configure a realtime trace session with default settings
    let mut trace = Trace::new("simple_trace")?;

    // Enable Kernel-Process provider for process start/stop events.
    // Win32 note: EnableTraceEx2(EVENT_CONTROL_CODE_ENABLE_PROVIDER) is called immediately.
    // This means StartTrace is called implicitly if start() hasn't been called yet.
    //
    // `Win32Error` carries the raw code, so the classic first-run failure — not
    // running elevated — matches the windows-sys constant directly.
    match trace.enable_provider(process::GUID, PROCESS) {
        Ok(()) => println!("Enabled Microsoft-Windows-Kernel-Process provider."),
        Err(Win32Error(ERROR_ACCESS_DENIED)) => {
            eprintln!("Access denied: kernel tracing needs Administrator privileges.");
            std::process::exit(1);
        }
        Err(e) => return Err(e),
    }

    // Configure a callback to log event details
    trace.set_event_callback(move |event, context| {
        // Using the TDH schema allows safe parsing of events using the registered schema
        let mut parser = context.parser(event)?;

        // We then get fields by type and name
        let pid: u32 = parser.get("ProcessID")?;
        let image_name: String = parser.get("ImageName")?;

        match event.id() {
            PROCESS_START => {
                let parent_id: u32 = parser.get("ParentProcessID")?;
                println!("[+] Process started: {image_name} (PID: {pid}, Parent: {parent_id})");
            }

            _ => {
                // Or just use `format_event` to generically output the event name and all
                // properties
                println!("[-] {}", parser.format_event()?);
            }
        }

        Ok(())
    });

    // Start processing events on a dedicated worker thread
    println!("Listening for process events for 10 seconds...");
    trace.start_processing_thread()?;
    sleep(Duration::from_secs(10));

    // The trace will gracefully stop when it goes out of scope
    Ok(())
}
