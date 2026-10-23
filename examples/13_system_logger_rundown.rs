#![expect(
    clippy::print_stdout,
    reason = "example output is the point of the example"
)]

//! System logger rundown example.
//!
//! Demonstrates three rundown behaviours:
//!
//! 1. **Automatic DC_START**: The kernel emits process/thread/image DC_START events at session
//!    start (no explicit action needed).
//!
//! 2. **Explicit file rundown**: `send_file_rundown_code()` triggers FileRundown (opcode 36) events
//!    enumerating open file objects.
//!
//! 3. **Automatic DC_END**: The kernel emits process/thread/image DC_END events when the session
//!    stops.
//!
//! # Requirements
//!
//! Must be run as Administrator for kernel tracing.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example 13_system_logger_rundown
//! ```
//!
//! Based on krabsetw's kernel_trace_003_rundown.cpp.

use etw::{
    Trace,
    system_logger::masks::{PERF_FILENAME, PERF_LOADER, PERF_PROC_THREAD},
};
use example_providers::classic::{
    event_trace_event, file_io, image, process, system_config, thread,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering::Relaxed},
};

fn main() -> etw::Result<()> {
    println!("System Logger Rundown Events Example");
    println!("════════════════════════════════════");

    let mut trace = Trace::new("system_logger_rundown")?;
    trace.set_events(&[PERF_PROC_THREAD, PERF_LOADER, PERF_FILENAME]);
    trace.start()?;

    let stats = Arc::new(RundownStats::default());

    // Our callback just counts the various event types to demonstrate receipt.
    trace.set_event_callback({
        let stats = Arc::clone(&stats);
        move |event, context| handle_event(event, context, &stats)
    });

    // Start processing — ProcessTrace must be running before send_file_rundown_code()
    // to avoid event loss from buffer pressure.
    trace.start_processing_thread()?;

    // DC_START events are automatically emitted at session start for each enabled provider.
    stats.print_and_reset("1. DC_START events at session start");

    // FILE_RUNDOWN events can be triggered for a running trace.
    // In practice, this means that you can *sometimes* receive a *partial* list of file objects
    // created before your trace started. The file object state is tracked globally by
    // fileinfo.sys, but only while at least one system logger has `PERF_FILENAME`, `PERF_FILE_IO`
    // or `PERF_FILE_IO_INIT` enabled. Otherwise this will error with `ERROR_DEV_NOT_EXIST`.
    trace.send_file_rundown_code()?;
    stats.print_and_reset("2. Explicit filename rundown after trigger");

    // DC_END events are automatically emitted at session stop for each enabled provider.
    // FILE_RUNDOWN events are also emitted, if enabled.
    trace.stop()?;
    stats.print_and_reset("3. DC_END events at session stop");

    Ok(())
}

/// Counters for all rundown-related event types.
#[derive(Default)]
struct RundownStats {
    process_dc_start: AtomicUsize,
    process_dc_end: AtomicUsize,
    thread_dc_start: AtomicUsize,
    thread_dc_end: AtomicUsize,
    image_dc_start: AtomicUsize,
    image_dc_end: AtomicUsize,
    file_rundown: AtomicUsize,
    hwconfig: AtomicUsize,
    event_trace: AtomicUsize,
}

impl RundownStats {
    fn total(&self) -> usize {
        self.process_dc_start.load(Relaxed)
            + self.process_dc_end.load(Relaxed)
            + self.thread_dc_start.load(Relaxed)
            + self.thread_dc_end.load(Relaxed)
            + self.image_dc_start.load(Relaxed)
            + self.image_dc_end.load(Relaxed)
            + self.file_rundown.load(Relaxed)
            + self.hwconfig.load(Relaxed)
            + self.event_trace.load(Relaxed)
    }

    fn print_and_reset(&self, label: &str) {
        println!("\n{label}:");

        // We need to pause a moment to allow the object enumeration to complete
        std::thread::sleep(std::time::Duration::from_secs(3));

        // Wait until no new events arrive for 1.5s, or 60s timeout.
        let mut last = self.total();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            std::thread::sleep(std::time::Duration::from_millis(1500));
            let now = self.total();
            if now == last || std::time::Instant::now() >= deadline {
                break;
            }
            last = now;
        }

        println!("  Trace   Config:    {}", self.event_trace.swap(0, Relaxed));
        println!("  System  Config:    {}", self.hwconfig.swap(0, Relaxed));
        println!(
            "  Process DC_START:  {}",
            self.process_dc_start.swap(0, Relaxed)
        );
        println!(
            "  Process DC_END:    {}",
            self.process_dc_end.swap(0, Relaxed)
        );
        println!(
            "  Thread  DC_START:  {}",
            self.thread_dc_start.swap(0, Relaxed)
        );
        println!(
            "  Thread  DC_END:    {}",
            self.thread_dc_end.swap(0, Relaxed)
        );
        println!(
            "  Image   DC_START:  {}",
            self.image_dc_start.swap(0, Relaxed)
        );
        println!(
            "  Image   DC_END:    {}",
            self.image_dc_end.swap(0, Relaxed)
        );
        println!(
            "  File    Rundown:   {}",
            self.file_rundown.swap(0, Relaxed)
        );
    }
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "signature must match set_event_callback's FnMut requirement"
)]
fn handle_event(
    event: &etw::RawEvent,
    _context: &mut etw::processing_context::ProcessingContext,
    stats: &RundownStats,
) -> etw::Result<()> {
    let provider = event.provider_guid();
    match provider {
        // The Process, Thread and Image providers have Data Collection Start and End events.
        process::CLASS_GUID => match event.opcode() {
            process::opcode::DC_START => {
                stats.process_dc_start.fetch_add(1, Relaxed);
            }
            process::opcode::DC_END => {
                stats.process_dc_end.fetch_add(1, Relaxed);
            }
            _ => {}
        },
        thread::CLASS_GUID => match event.opcode() {
            thread::opcode::DC_START => {
                stats.thread_dc_start.fetch_add(1, Relaxed);
            }
            thread::opcode::DC_END => {
                stats.thread_dc_end.fetch_add(1, Relaxed);
            }
            _ => {}
        },
        image::CLASS_GUID => match event.opcode() {
            image::opcode::DC_START => {
                stats.image_dc_start.fetch_add(1, Relaxed);
            }
            image::opcode::DC_END => {
                stats.image_dc_end.fetch_add(1, Relaxed);
            }
            _ => {}
        },
        file_io::CLASS_GUID if event.opcode() == file_io::opcode::FILE_RUNDOWN => {
            stats.file_rundown.fetch_add(1, Relaxed);
        }
        system_config::CLASS_GUID => {
            stats.hwconfig.fetch_add(1, Relaxed);
        }
        event_trace_event::CLASS_GUID => {
            stats.event_trace.fetch_add(1, Relaxed);
        }
        _ => {}
    }
    Ok(())
}
