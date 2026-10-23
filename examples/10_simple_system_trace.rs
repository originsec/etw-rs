#![expect(
    clippy::print_stdout,
    reason = "example output is the point of the example"
)]

//! Process monitoring example using system logger EnableFlags mode.
//!
//! This example demonstrates monitoring process creation and termination
//! using the simpler `set_enable_flags()` API with `EVENT_TRACE_FLAG_*` constants.
//!
//! This is the system logger equivalent of `01_simple_trace.rs`, showing
//! how to use the legacy system providers instead of modern ETW providers.
//!
//! # Requirements
//!
//! Must be run as Administrator for kernel tracing.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example 10_simple_system_trace
//! ```

use etw::Trace;
use example_providers::classic::kernel_trace::{
    enable_flags, event_trace_event,
    process::{
        self,
        opcode::{END, START},
    },
    system_config,
};
use std::{thread::sleep, time::Duration};

fn main() -> etw::Result<()> {
    println!("Simple System Trace Example - Process Start/Stop Events");

    let mut trace = Trace::new("simple_system_trace")?;

    // Enable process events using the EnableFlags API
    // This implicitly sets the SYSTEM_LOGGER_MODE flag.
    trace.set_enable_flags(enable_flags::PROCESS).start()?;

    // Configure a callback to log event details
    trace.set_event_callback(move |event, context| {
        // Filter events by "provider GUID".
        // For classic (MOF) events this field contains the class guid.
        match event.provider_guid() {
            process::GUID => {
                // System logger events use opcode instead of event ID
                match event.opcode() {
                    START => {
                        // Using the TDH schema allows safe parsing of registered events —
                        // including classic events. We cache the schema lookup for performance.
                        let mut parser = context.parser(event)?;
                        let image_name: String = parser.get("ImageFileName")?;
                        let process_id: u32 = parser.get("ProcessId")?;
                        let parent_id: u32 = parser.get("ParentId")?;
                        println!(
                            "[+] Process started: {image_name} (PID: {process_id}, Parent: {parent_id})"
                        );
                    }
                    END => {
                        let mut parser = context.parser(event)?;
                        let image_name: String = parser.get("ImageFileName")?;
                        let process_id: u32 = parser.get("ProcessId")?;
                        let exit_code: i32 = parser.get("ExitStatus")?;
                        println!(
                            "[-] Process stopped: {image_name} (PID: {process_id}, Exit: {exit_code})"
                        );
                    }
                    // DC_START (3), DC_END (4), DEFUNCT (39), or other opcodes
                    _ => {}
                }
            }
            event_trace_event::GUID | system_config::GUID => {
                // EventTrace header/control events and system configuration events
                // are implicitly enabled - silently ignore
            }
            _ => {
                println!(
                    "[?] Unexpected event - provider:{:?} opcode:{}",
                    event.provider_guid(),
                    event.opcode()
                );
            }
        }

        Ok(())
    });

    // Start processing events on a dedicated worker thread
    println!("Listening for process events for 10 seconds...\n");
    trace.start_processing_thread()?;
    sleep(Duration::from_secs(10));

    // The trace will gracefully stop when it goes out of scope.
    Ok(())
}
