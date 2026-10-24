#![expect(
    clippy::print_stdout,
    reason = "example output is the point of the example"
)]

//! Example demonstrating collection of TraceLogging (self-describing) events.
//!
//! Most ETW providers ship a separate XML manifest that describes their events.
//! TraceLogging providers instead carry each event's schema — its name and field
//! layout — *inline with the event*, in an `EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL`
//! extended-data item (see [`RawEvent::tracelogging_metadata`]).
//!
//! This example consumes the kernel `KernelProcess` TraceLogging provider — which
//! is distinct from the classic manifest `Microsoft-Windows-Kernel-Process` — and
//! decodes its `ProcessStarted` event. That event fires on every process
//! creation, so spawning a child process guarantees some traffic to show.
//!
//! Decoding uses `context.tracelogging_parser(event)`, the TraceLogging
//! counterpart to `context.parser(event)`. Which one to call is the caller's to
//! state — a provider is manifest-based or self-describing as a fixed property,
//! known when you enable it — so neither path spends anything working it out per
//! event. The TraceLogging cache is keyed by each event's metadata blob rather
//! than by Event Id/Version, because a self-describing event's Id is 0.
//!
//! # Requirements
//!
//! Must be run as Administrator for ETW session creation.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example 09_tracelogging
//! ```

use etw::{ALL_KEYWORDS, Guid, Trace};
use std::{process::Command, thread::sleep, time::Duration};
use windows::Win32::System::Diagnostics::Etw::TRACE_LEVEL_VERBOSE;

/// The kernel `KernelProcess` TraceLogging provider. Note this is *not* the
/// classic manifest `Microsoft-Windows-Kernel-Process` (`22fb2cd6-...`).
const KERNEL_PROCESS_GUID: Guid = Guid::from_u128(0x2839ff94_8f12_4e1b_82e3_af7af77a450f);

fn main() -> etw::Result<()> {
    println!("TraceLogging Collection Example - KernelProcess ProcessStarted");

    let mut trace = Trace::new("etw-rs_tracelogging_example")?;

    // Enable at verbose level; ProcessStarted is a level-5 event.
    trace.enable_provider_ex(
        KERNEL_PROCESS_GUID,
        TRACE_LEVEL_VERBOSE,
        ALL_KEYWORDS,
        0,
        None,
    )?;
    println!("Enabled the KernelProcess TraceLogging provider.");

    trace.set_event_callback(move |event, context| {
        // `tracelogging_parser` rather than `parser`: we know KernelProcess is a
        // TraceLogging provider because we chose to enable it, so the regime is
        // stated rather than detected. It returns `NotPresent` for anything that
        // is not self-describing — ETW also delivers session bookkeeping such as
        // the `EventTrace` header — so skip those rather than fail the callback.
        let Ok(mut parser) = context.tracelogging_parser(event) else {
            return Ok(());
        };

        // The event name lives in the inline metadata. TraceLogging events have no
        // usable EventDescriptor.Id — it is 0 — so the name is the identity.
        let name = parser.schema().event_name().unwrap_or_default();
        if name != "ProcessStarted" {
            return Ok(());
        }

        let image: String = parser.get("ImageFileName").unwrap_or_default();
        let parent_pid: u32 = parser.get("ParentPid").unwrap_or(0);
        let command_line: String = parser.get("CommandLine").unwrap_or_default();
        println!("[+] {name}: image={image} parent_pid={parent_pid} command_line={command_line:?}");
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
