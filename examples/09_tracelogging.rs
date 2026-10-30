#![expect(
    clippy::print_stdout,
    reason = "example output is the point of the example"
)]

//! Example demonstrating collection of TraceLogging (self-describing) events.
//!
//! This example consumes the kernel `KernelProcess` TraceLogging provider — which
//! is distinct from the manifest `Microsoft-Windows-Kernel-Process` provider — and
//! decodes its `ProcessStarted` event.
//!
//! Most ETW providers register an XML manifest that describes their events.
//! TraceLogging providers instead carry each event's schema *inline with the event*,
//! in an `EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL` extended-data item (see
//! [`RawEvent::tracelogging_metadata`]).
//!
//! Decoding explicitly uses `context.tracelogging_parser(event)`, the TraceLogging
//! counterpart to `context.parser(event)`. A TraceLogging event is typically
//! identified by its EventName but uniqueness of this value is by convention only.
//! So the TraceLogging cache is keyed by each event's metadata blob in its entirety.
//!
//! # Requirements
//!
//! Must be run as Administrator for kernel TraceLogging tracing.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example 09_tracelogging
//! ```

use etw::{ALL_KEYWORDS, Guid, Trace};
use std::{ffi::OsString, process::Command, thread::sleep, time::Duration};
use windows::Win32::System::Diagnostics::Etw::TRACE_LEVEL_VERBOSE;

/// The kernel `KernelProcess` TraceLogging provider. Note this is *not* the
/// manifest `Microsoft-Windows-Kernel-Process` (`22fb2cd6-...`).
const KERNEL_PROCESS_TL_GUID: Guid = Guid::from_u128(0x2839ff94_8f12_4e1b_82e3_af7af77a450f);

fn main() -> etw::Result<()> {
    println!("TraceLogging Collection Example - KernelProcess ProcessStarted");

    let mut trace = Trace::new("etw-rs_tracelogging_example")?;

    trace.enable_provider_ex(
        KERNEL_PROCESS_TL_GUID,
        TRACE_LEVEL_VERBOSE,
        ALL_KEYWORDS,
        0,
        None,
    )?;
    println!("Enabled the KernelProcess TraceLogging provider.");

    trace.set_event_callback(move |event, context| {
        // The callback will also receive other ETW session bookkeeping events.
        if event.provider_guid() != KERNEL_PROCESS_TL_GUID {
            return Ok(());
        }

        // We know that this is a TraceLogging provider - so we explicitly use that
        // constructor.
        // Runtime detection is possible but would cost us unnecessary work on each event.
        let mut parser = context.tracelogging_parser(event)?;

        // The event name lives in the inline metadata. TraceLogging events have no
        // usable EventDescriptor.Id — it is 0 — so the name is the identity. Usually.
        // Some pathological providers might reuse a name.
        let Some(name) = parser.schema().event_name() else {
            return Ok(());
        };
        if name != "ProcessStarted" {
            return Ok(());
        }

        // Both strings are UTF-16 (counted), so they are read as `OsString`.
        let image: OsString = parser.get("ImageFileName")?;
        let parent_pid: u32 = parser.get("ParentPid")?;
        let command_line: OsString = parser.get("CommandLine")?;
        println!(
            "[+] {name}: image={} parent_pid={parent_pid} command_line={}",
            image.display(),
            command_line.display()
        );
        Ok(())
    });

    trace.start_processing_thread()?;
    println!("Collecting ProcessStarted events for 5 seconds...");

    // Guarantee at least one event by spawning a short-lived child.
    if let Ok(mut child) = Command::new("cmd.exe").args(["/c", "ver"]).spawn() {
        let _ = child.wait();
    }

    sleep(Duration::from_secs(5));

    // The trace stops gracefully when it goes out of scope.
    Ok(())
}
