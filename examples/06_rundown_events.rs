#![expect(
    clippy::print_stdout,
    reason = "example output is the point of the example"
)]

//! Rundown events example.
//!
//! This example demonstrates rundown events that capture system state.
//!
//! Rundown events are not true real-time tracing events. Instead they describe the state
//! of the system - either at the start or end of a trace.
//!
//! Usually these are just extra events in the provider. For example,
//! Microsoft-Windows-Kernel-Process has ProcessRundown events as well as ProcessStart events.
//!
//! ...but the rundown events often cannot be enabled by keyword alone.
//! The trace sometimes needs to be sent EVENT_CONTROL_CODE_CAPTURE_STATE.
//! This is what capture_state() does.
//!
//! capture_state() can be called before or after start_processing_thread():
//!
//! - **Before**: Events buffer in ETW kernel buffers until ProcessTrace drains them. Risk: on
//!   systems with many processes, the buffer may overflow before ProcessTrace starts consuming. Use
//!   larger buffers or call start_processing_thread() first.
//!
//! - **After**: ProcessTrace is already running, so rundown events flow to the callback
//!   immediately. Events can still be lost if the callback falls behind, but there is no backlog
//!   waiting for the consumer — this is the safer approach.
//!
//! Some providers don't follow this pattern and instead split this functionality
//! into a separate provider. For example, Microsoft-Windows-DotNETRuntime and
//! Microsoft-Windows-DotNETRuntimeRundown.
//!
//! # Requirements
//!
//! Must be run as Administrator for kernel tracing.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example 06_rundown_events
//! ```
//!
//! Based on krabsetw's user_trace_007_rundown.cpp.

use etw::Trace;
use example_providers::{
    kernel,
    kernel::process::{
        event::{PROCESS_RUNDOWN, PROCESS_START},
        keyword::PROCESS,
    },
    user,
    user::{
        dotnet_runtime::{event::LOADER_ASSEMBLY_LOAD, keyword::LOADER_KEYWORD},
        dotnet_runtime_rundown::{
            event::LOADER_ASSEMBLY_DC_START,
            keyword::{LOADER_RUNDOWN_KEYWORD, START_RUNDOWN_KEYWORD},
        },
    },
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering::Relaxed},
};

/// Separate counters for rundown (snapshot) vs real-time events.
#[derive(Default)]
struct Stats {
    // Rundown events — system state snapshots from capture_state()
    process_rundown: AtomicUsize,
    assembly_rundown: AtomicUsize,
    // Real-time events — activity that occurs while tracing
    process_start: AtomicUsize,
    assembly_load: AtomicUsize,
}

impl Stats {
    fn rundown_total(&self) -> usize {
        self.process_rundown.load(Relaxed) + self.assembly_rundown.load(Relaxed)
    }

    /// Wait for rundown events to settle, then print and reset rundown counters only.
    fn print_rundown_and_reset(&self, label: &str) {
        std::thread::sleep(std::time::Duration::from_secs(3));
        let mut last = self.rundown_total();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            std::thread::sleep(std::time::Duration::from_millis(500));
            let now = self.rundown_total();
            if now == last || std::time::Instant::now() >= deadline {
                break;
            }
            last = now;
        }

        println!("\n{label}:");
        println!(
            "  Process rundown events:    {}",
            self.process_rundown.swap(0, Relaxed)
        );
        println!(
            "  Assembly rundown events:   {}",
            self.assembly_rundown.swap(0, Relaxed)
        );
    }

    /// Print real-time event totals (accumulated across the entire run).
    fn print_realtime(&self) {
        println!("\nReal-time events (accumulated):");
        println!(
            "  Process start events:      {}",
            self.process_start.load(Relaxed)
        );
        println!(
            "  Assembly load events:      {}",
            self.assembly_load.load(Relaxed)
        );
    }
}

fn main() -> etw::Result<()> {
    println!("Rundown Events Example");
    println!("══════════════════════");

    let mut trace = Trace::new("rundown_events")?;
    trace.start()?;

    let stats = Arc::new(Stats::default());
    let stats_cb = Arc::clone(&stats);

    // Process provider — demonstrates single-provider rundown via CAPTURE_STATE
    trace.enable_provider(kernel::process::GUID, PROCESS)?;

    // .NET Runtime providers — demonstrates split-provider rundown pattern.
    // Some providers use a separate *Rundown provider instead of CAPTURE_STATE.

    // Real-time assembly load events
    trace.enable_provider(user::dotnet_runtime::GUID, LOADER_KEYWORD)?;

    // Assembly rundown events (loaded assemblies).
    // Use StartRundownKeyword / EndRundownKeyword to control whether the state
    // is enumerated at the start or end of the trace.
    trace.enable_provider(
        user::dotnet_runtime_rundown::GUID,
        LOADER_RUNDOWN_KEYWORD | START_RUNDOWN_KEYWORD,
    )?;

    // Approach 1: capture_state BEFORE start_processing_thread
    //
    // Rundown events are buffered in ETW kernel buffers until ProcessTrace
    // starts draining. This works, but risks buffer overflow on systems with
    // many processes/modules before the consumer thread is running.
    trace.capture_state(kernel::process::GUID)?;

    // Set callback and start processing
    trace.set_event_callback(move |event, _context| {
        match event.provider_guid() {
            kernel::process::GUID => match event.id() {
                PROCESS_RUNDOWN => {
                    stats_cb.process_rundown.fetch_add(1, Relaxed);
                }
                PROCESS_START => {
                    stats_cb.process_start.fetch_add(1, Relaxed);
                }
                _ => {}
            },
            user::dotnet_runtime::GUID if event.id() == LOADER_ASSEMBLY_LOAD => {
                stats_cb.assembly_load.fetch_add(1, Relaxed);
            }
            user::dotnet_runtime_rundown::GUID if event.id() == LOADER_ASSEMBLY_DC_START => {
                stats_cb.assembly_rundown.fetch_add(1, Relaxed);
            }
            _ => {}
        }

        Ok(())
    });

    trace.start_processing_thread()?;
    stats.print_rundown_and_reset("1. capture_state BEFORE processing (buffered)");

    // Approach 2: capture_state AFTER start_processing_thread
    //
    // ProcessTrace is already draining, so rundown events flow to the callback
    // immediately — this is the safer approach.
    //
    // Only Kernel-Process is asked to capture state, so this round reports no assembly
    // rundown events: the .NET rundown provider enumerates once, when it is enabled.
    trace.capture_state(kernel::process::GUID)?;
    stats.print_rundown_and_reset("2. capture_state AFTER processing (immediate)");

    stats.print_realtime();

    trace.stop()?;

    Ok(())
}
