#![expect(
    clippy::print_stdout,
    reason = "example output is the point of the example"
)]

//! Multiple provider monitoring example.
//!
//! This example demonstrates consuming events from multiple ETW providers
//! simultaneously in a single trace session, routing each event to a handler that
//! constructs the generated static parser it needs.
//!
//! # Requirements
//!
//! Must be run as Administrator for kernel tracing.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example 03_typical_trace
//! ```

use etw::{
    RawEvent, Trace,
    processing_context::ProcessingContext,
    session::{NO_PER_PROCESSOR_BUFFERING, SECURE_MODE},
};
use example_providers::kernel::{
    etw_subsystem::{
        self, LostEventAccessors, LostSystemEventAccessors, LostTraceLoggingEventAccessors,
        LostWPPEventAccessors,
    },
    file::{self, NameCreateAccessors, NameDeleteAccessors},
    process::{self, ProcessStartAccessors, ProcessStopAccessors},
};
use std::{
    sync::mpsc,
    thread::{available_parallelism, sleep},
    time::Duration,
};
use windows::Win32::System::Threading::{INFINITE, THREAD_PRIORITY_ABOVE_NORMAL};

fn main() -> anyhow::Result<()> {
    println!("Typical Realtime Trace Example - Process, File and EventTracing Events");

    // Validates every provider_schema! schema against the Windows TDH registry.
    // Registered at link time — adding a new provider automatically includes it here.
    // Note: if you don't call this explicitly, then Trace::new will invoke it.
    etw::validate_all_schemas()?;

    // Create real-time trace session and then customise settings
    let mut trace = Trace::new("typical_trace")?;

    // ETW defaults are good, but sometimes explicit scaling with CPU count helps with peak loads.
    let processor_count = available_parallelism().map_or(2, |n| n.get() as u32);
    let min_buffers = processor_count * 2;
    let max_buffers = processor_count * 4;

    // The maximum ETW single event size is 64 KB, though most events cannot be this large in
    // practice. Using buffers smaller than this may result in dropped events for some
    // providers.
    let buffer_size = 64;

    trace
        // EVENT_TRACE_REAL_TIME_MODE and EVENT_TRACE_INDEPENDENT_SESSION_MODE are
        // always set by etw-rs for `Trace` and cannot be overridden.
        // EVENT_TRACE_xxx_ON_HYBRID_SHUTDOWN will be set by the OS if not set.
        .set_log_file_mode(SECURE_MODE | NO_PER_PROCESSOR_BUFFERING)
        .set_buffer_configuration(buffer_size, min_buffers, max_buffers, 0)
        .start()?;

    // Enable Kernel-Process provider for process start/stop events.
    trace.enable_provider(process::GUID, process::keyword::PROCESS)?;

    // Enable Kernel-File provider for file name create/delete events.
    trace.enable_provider(file::GUID, file::keyword::FILENAME)?;

    // Enable Kernel-EventTracing provider for lost event notifications.
    trace.enable_provider(etw_subsystem::GUID, etw_subsystem::keyword::LOST_EVENT)?;

    // Route events to per-event handler functions. Each handler constructs its
    // `{Name}Parser`, which resolves the event version once; the parser then reads
    // fields through the superset accessor trait, falling back to the dynamic
    // parser for versions newer than the declared schema.
    // See: example_providers::kernel::{process, file, etw_subsystem} for the schema definitions.
    trace.set_event_callback(
        move |event, context| match (event.provider_guid(), event.id()) {
            (process::GUID, process::event::PROCESS_START) => handle_process_start(event, context),
            (process::GUID, process::event::PROCESS_STOP) => handle_process_stop(event, context),
            (file::GUID, file::event::NAME_CREATE) => handle_name_create(event, context),
            (file::GUID, file::event::NAME_DELETE) => handle_name_delete(event, context),
            (etw_subsystem::GUID, etw_subsystem::event::LOST_EVENT) => {
                handle_lost_event(event, context)
            }
            (etw_subsystem::GUID, etw_subsystem::event::LOST_TRACE_LOGGING_EVENT) => {
                handle_lost_trace_logging_event(event, context)
            }
            (etw_subsystem::GUID, etw_subsystem::event::LOST_WPP_EVENT) => {
                handle_lost_wpp_event(event, context)
            }
            (etw_subsystem::GUID, etw_subsystem::event::LOST_SYSTEM_EVENT) => {
                handle_lost_system_event(event, context)
            }
            (guid, id) => {
                debug_assert!(false, "unexpected event: guid={guid:?} id={id}");
                Ok(())
            }
        },
    );

    // After `start`, the trace session state reflects the set properties plus OS defaults.
    // The providers and processing thread properties can still be updated later.
    println!("Trace session: {trace:#?}");

    // Set up Ctrl+C handler
    let (tx, ctrl_c) = mpsc::channel();
    ctrlc::set_handler(move || {
        println!("\nCtrl+C received, stopping...");
        let _ = tx.send(());
    })?;

    println!("Listening for events... Press Ctrl+C to stop.\n");
    sleep(Duration::from_secs(2));

    // etw-rs sets sane defaults — but allows everything to be overridden.
    trace
        .set_processing_thread_description("typical_trace processing thread")
        .set_processing_thread_priority(THREAD_PRIORITY_ABOVE_NORMAL.0)
        .set_processing_thread_shutdown_timeout(INFINITE)
        .start_processing_thread()?;

    // Wait until Ctrl+C
    ctrl_c.recv().ok();

    trace.stop()?;
    println!("════════════════════════════════════════════════════════════");
    println!("Trace session stopped.");

    let stats = trace.statistics();
    println!("Statistics: {stats}");

    Ok(())
}

// ---------------------------------------------------------------------------
// Per-event handlers. Each takes the raw event and processing context and
// constructs its own parser.
// ---------------------------------------------------------------------------

fn handle_process_start(event: &RawEvent, context: &mut ProcessingContext) -> etw::Result<()> {
    let mut parser = process::ProcessStartParser::new(event, context)?;
    let pid = parser.ProcessID()?;
    let image = parser.ImageName()?;
    println!("[PROCESS] Started: {} (PID: {pid})", image.display());
    Ok(())
}

fn handle_process_stop(event: &RawEvent, context: &mut ProcessingContext) -> etw::Result<()> {
    let mut parser = process::ProcessStopParser::new(event, context)?;
    let pid = parser.ProcessID()?;
    let exit_code = parser.ExitCode()?;
    let image = parser.ImageName()?;
    println!("[PROCESS] Stopped: {image} (PID: {pid}, Exit: {exit_code})");
    Ok(())
}

fn handle_name_create(event: &RawEvent, context: &mut ProcessingContext) -> etw::Result<()> {
    let mut parser = file::NameCreateParser::new(event, context)?;
    let filename = parser.FileName()?;
    println!("[FILE]    Create: {}", filename.display());
    Ok(())
}

fn handle_name_delete(event: &RawEvent, context: &mut ProcessingContext) -> etw::Result<()> {
    let mut parser = file::NameDeleteParser::new(event, context)?;
    let filename = parser.FileName()?;
    println!("[FILE]    Delete: {}", filename.display());
    Ok(())
}

fn handle_lost_event(event: &RawEvent, context: &mut ProcessingContext) -> etw::Result<()> {
    let mut parser = etw_subsystem::LostEventParser::new(event, context)?;
    let provider = parser.ProviderId()?;
    let id = parser.EventId()?;
    let session = parser.SessionName()?;
    println!(
        "[LOST] ETW event lost - Provider:{provider} Id:{id} Session:{}",
        session.display()
    );
    Ok(())
}

fn handle_lost_trace_logging_event(
    event: &RawEvent,
    context: &mut ProcessingContext,
) -> etw::Result<()> {
    let mut parser = etw_subsystem::LostTraceLoggingEventParser::new(event, context)?;
    let provider = parser.ProviderId()?;
    // EventName is an ANSI string whose out-type is Utf8 (`@ out(Utf8)` in its schema),
    // so the `String` conversion decodes it as UTF-8 rather than the active code page.
    let name = parser.EventName()?;
    let session = parser.SessionName()?;
    println!(
        "[LOST] TraceLogging event lost - Provider:{provider} Name:{name} Session:{}",
        session.display()
    );
    Ok(())
}

fn handle_lost_wpp_event(event: &RawEvent, context: &mut ProcessingContext) -> etw::Result<()> {
    let mut parser = etw_subsystem::LostWPPEventParser::new(event, context)?;
    let provider = parser.MessageGuid()?;
    let id = parser.MessageNumber()?;
    let session = parser.SessionName()?;
    println!(
        "[LOST] WPP event lost - Provider:{provider} Id:{id} Session:{}",
        session.display()
    );
    Ok(())
}

fn handle_lost_system_event(event: &RawEvent, context: &mut ProcessingContext) -> etw::Result<()> {
    let mut parser = etw_subsystem::LostSystemEventParser::new(event, context)?;
    let hook_id = parser.HookId()?;
    let session = parser.SessionName()?;
    println!(
        "[LOST] System event lost - Id:{hook_id:#x} Session:{}",
        session.display()
    );
    Ok(())
}
