#![expect(
    clippy::print_stdout,
    reason = "example output is the point of the example"
)]

//! System logger trace example with stack walking.
//!
//! This example demonstrates:
//! - Enabling system logger event groups via `PERFINFO_GROUPMASK`
//! - Configuring stack walking for specific events
//! - Processing classic (MOF) events using class guids
//!
//! # Requirements
//!
//! Must be run as Administrator for kernel tracing.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example 11_typical_system_trace
//! ```

use etw::{Trace, stack_walk::StackWalkData, system_logger::masks::PERF_NO_SYSCONFIG};
use example_providers::classic::{image, process, stack_walk};
use std::{thread::sleep, time::Duration};

fn main() -> etw::Result<()> {
    println!("System Trace Example - Kernel Events with Stack Tracing");
    println!();

    let mut trace = Trace::new("typical_system_trace")?;

    // Enable system logger event groups.
    // These semi-documented group masks are a superset of the basic enable_flags.
    // - PERF_PROCESS: Process start/end events
    // - PERF_LOADER: Image (DLL/EXE) load/unload events
    // - PERF_NO_SYSCONFIG: Suppress some system configuration events at startup
    // Enable stack walking for process start events only
    trace
        .set_events(&[process::PERF_PROCESS, image::PERF_LOADER, PERF_NO_SYSCONFIG])
        .set_stack_walking(&[process::hook_id::START])?
        .start()?;

    trace.set_event_callback(move |event, context| {
        // Classic events use class GUIDs to identify the event source
        match event.provider_guid() {
            process::CLASS_GUID if event.opcode() == process::opcode::START => {
                let mut parser = context.parser(event)?;
                let image_name: String = parser.get("ImageFileName")?;
                let pid = event.process_id();
                let new_pid: u32 = parser.get("ProcessId")?;
                let timestamp = event.timestamp();
                println!("[+] {timestamp} pid:{pid} CreateProcess({image_name})={new_pid}");
            }

            stack_walk::CLASS_GUID if event.opcode() == stack_walk::opcode::STACK => {
                let timestamp = event.timestamp();

                // For system loggers stack walks are always emitted in a separate event - or even
                // two. The kernel and user mode portions may arrive in different
                // events. The UserData of the StackWalk event contains the
                // timestamp, pid and tid of the original event. Because they are
                // emitted on the same thread, ETW guarantees that they will always arrive in order.

                // The schema is not very ergonomic for stack walks however.
                // It defines individually named stack entries rather than an array.
                // Plus the Version 2 schema also only defines 32 entries.
                // Version 1 defined 192 entries - which is the maximum stack depth that ETW will
                // emit. So V2 does not define an entry for every possible index
                // meaning that the stack may appear to be truncated if you parse using the schema.

                // ETW also has a "feature" where trailing 0s are dropped from the end of the
                // UserData. And this impacts how final field(s) need to be parsed.
                // A null-terminated string might not be null-terminated.
                // 4-byte booleans might only be 1-byte, and integers might be missing entirely.
                // So the length of the stack walk is dependent on UserDataLength.
                // But schema-based parsing will always return 0 for trailing entries, meaning that
                // you need to parse and check each entry to find the end.
                if let Ok(mut parser) = context.parser(event) {
                    let _process_id: u32 = parser.get("StackProcess")?;
                    let _thread_id: u32 = parser.get("StackThread")?;
                    let _timestamp: u64 = parser.get("EventTimeStamp")?;
                    let _stack_1: u64 = parser.get("Stack1")?;
                    let _stack_2: u64 = parser.get("Stack2")?;
                    // ...
                    let _stack_32: u64 = parser.get("Stack32")?;
                    // ... further entries are not accessible via the TDH schema.
                }

                // Instead we provide a custom parser
                let stack_parser = StackWalkData::from_event(event)?;
                let pid = stack_parser.process_id();
                let event_timestamp = stack_parser.event_timestamp();
                // Which accesses the stack walk as a slice.
                let len = stack_parser.addresses().len();
                println!(
                    "[*] {timestamp} pid:{pid} Stack Walk timestamp:{event_timestamp} length:{len}"
                );
            }

            image::CLASS_GUID if event.opcode() == image::opcode::LOAD => {
                let mut parser = context.parser(event)?;
                let file_name: String = parser.get("FileName")?;
                // Verbosity: only print ntdll loads for this demo as we just want to show event
                // timing.
                if !file_name.to_lowercase().ends_with("\\ntdll.dll") {
                    return Ok(());
                }

                let pid = event.process_id();
                let timestamp = event.timestamp();
                println!("[*] {timestamp} pid:{pid} Image loaded: {file_name}\n");
            }

            // Ignore other events - especially EVENT_TRACE_GUID header events
            _ => {}
        }

        Ok(())
    });

    println!("Listening for kernel events for 10 seconds...\n");
    trace.start_processing_thread()?;
    sleep(Duration::from_secs(10));

    Ok(())
}
