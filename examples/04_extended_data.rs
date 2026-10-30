#![expect(
    clippy::print_stdout,
    reason = "example output is the point of the example"
)]

//! ETW data example demonstrating access to fields, properties and extended data items.
//!
//! # Requirements
//!
//! Must be run as Administrator for kernel tracing.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example 04_extended_data
//! ```

use etw::{EnableProperty, Trace, WideStrRef};
use example_providers::{kernel, kernel::process::event::PROCESS_START};
use std::{
    ffi::OsString, os::windows::ffi::OsStringExt, process::Command, thread::sleep, time::Duration,
};
use windows::Win32::{
    Foundation::{HMODULE, MAX_PATH},
    System::{
        Diagnostics::Etw::TRACE_LEVEL_INFORMATION,
        Memory::{MEMORY_BASIC_INFORMATION, VirtualQuery},
        ProcessStatus::GetModuleBaseNameW,
        Threading::GetCurrentProcess,
    },
};

fn main() -> etw::Result<()> {
    println!("Extended Data Example\n");
    println!("This example demonstrates capturing extended event data:");
    println!("  - SID (Security Identifier): User identity for the event logger");
    println!("  - Process Start Key: Locally unique process identifier for logger");
    println!("  - Stack Trace: stack walk at logging time");

    let mut trace = Trace::new("extended_data")?;
    trace.set_exclude_kernel_stack(true).start()?;

    let property_flags =
        EnableProperty::SID | EnableProperty::PROCESS_START_KEY | EnableProperty::STACK_TRACE;
    trace.enable_provider_ex(
        kernel::process::GUID,
        TRACE_LEVEL_INFORMATION,
        kernel::process::keyword::PROCESS,
        property_flags,
        None,
    )?;
    println!("Enabled Microsoft-Windows-Kernel-Process provider.\n");

    trace.set_event_callback(move |event, context| {
        // Scope processing to just our process
        if event.process_id() != std::process::id() {
            return Ok(());
        }

        // ProcessStart is logged by the creating process, but ProcessStop by the exiting child,
        // so only ProcessStart carries our PID.
        assert_eq!(PROCESS_START, event.id());

        // Fields have accessors
        let process_id = event.process_id();

        // Properties (UserData) have parameterised parsers
        let mut parser = context.parser(event)?;
        let image_name: OsString = parser.get("ImageName")?;

        // We can also just grab a reference for faster filtering prior to copying data from the
        // event
        let _image_name_ref: WideStrRef = parser.as_ref("ImageName")?;

        // Extended data items (ExtendedData) have parsers
        let psk = event.process_start_key()?;
        let sid = event.sid()?;
        let stack = event.stack_trace()?;

        let stack_summary = resolve_modules(&stack.addresses());
        println!("Process: {}", image_name.display());
        println!("  PSK: 0x{psk:016X} (PID:{process_id})");
        println!("  SID: {sid}");
        println!("  Stack walk -");
        println!("    MatchId: {}", stack.match_id());
        println!("    Addresses: {:x?}", stack.addresses());
        println!("    Summary: {stack_summary}");

        Ok(())
    });

    trace.start_processing_thread()?;

    // Trigger an event
    let _ = Command::new("cmd.exe")
        .args(["/c", "echo", "test process"])
        .output();

    sleep(Duration::from_secs(2));
    trace.stop()?;

    Ok(())
}

/// Resolve addresses to module names, returning a pipe-delimited string (deduplicated).
fn resolve_modules(addresses: &[u64]) -> String {
    // SAFETY: GetCurrentProcess returns a pseudo-handle that doesn't need to be closed.
    let process = unsafe { GetCurrentProcess() };
    let mut result = Vec::new();
    let mut last: Option<String> = None;

    let mut mbi = MEMORY_BASIC_INFORMATION::default();
    let mut name_buf = [0u16; MAX_PATH as usize];
    for &addr in addresses {
        // Get the allocation base (aka module base aka HMODULE) for this address
        // SAFETY: VirtualQuery writes to mbi.
        let size = unsafe {
            VirtualQuery(
                Some(addr as *const _),
                &raw mut mbi,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        let name = if size == 0 {
            format!("0x{addr:x}")
        } else {
            let base = HMODULE(mbi.AllocationBase.cast());
            // SAFETY: GetModuleBaseNameW writes to name_buf.
            let len = unsafe { GetModuleBaseNameW(process, Some(base), &mut name_buf) } as usize;
            if len == 0 {
                format!("0x{addr:x}")
            } else {
                OsString::from_wide(&name_buf[..len])
                    .to_string_lossy()
                    .to_lowercase()
            }
        };

        // Deduplicate consecutive entries
        if last.as_ref() != Some(&name) {
            result.push(name.clone());
            last = Some(name);
        }
    }

    result.join("|")
}
