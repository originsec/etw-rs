#![expect(
    clippy::print_stdout,
    reason = "example output is the point of the example"
)]

//! Delayed stack walk event example.
//!
//! This example demonstrates monitoring TCP connection events with stack walks.
//! Because much of the networking stack runs at `DISPATCH_LEVEL`, the kernel cannot
//! access the user-mode stack at event time. Instead, a DPC is queued that emits
//! the user-mode frames in a subsequent stack walk event.
//!
//! This example handles events from two providers:
//! 1. `Microsoft-Windows-TCPIP` - TCP connection events
//! 2. `Microsoft-Windows-Kernel-EventTracing` - Delayed stack walk events with user-mode frames
//!
//! The `match_id` field correlates delayed stack walks with their original events.
//!
//! # Requirements
//!
//! Must be run as Administrator for kernel tracing.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example 05_delayed_stack_walks
//! ```

use etw::{EnableProperty, EventIdFilter, ProviderFilter, Trace};
use example_providers::{
    kernel,
    kernel::{
        etw_subsystem::event::STACK_TRACE,
        tcpip::{event::TCP_REQUEST_CONNECT, keyword::CONNECT_PATH},
    },
};
use std::{
    ffi::OsString,
    net::{SocketAddr, TcpStream},
    os::windows::ffi::OsStringExt,
    thread::sleep,
    time::Duration,
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
    println!("TCP/IP Connection Stack Trace Example");
    println!("======================================\n");
    println!("This example demonstrates delayed stack walks:");
    println!("  - TCP connect events arrive first (without user-mode stack)");
    println!("  - Stack walk events arrive later with the user-mode frames");
    println!("  - Events are correlated using match_id\n");

    let mut trace = Trace::new("delayed_stack_walks")?;
    trace.start()?;

    // Enable TCP connect events with stack tracing and stack walk filtering.
    // The ProviderFilter combines both event ID filtering (which events are
    // delivered) and stack walk filtering (which events get stack traces).
    trace.enable_provider_ex(
        kernel::tcpip::GUID,
        TRACE_LEVEL_INFORMATION,
        CONNECT_PATH,
        EnableProperty::STACK_TRACE,
        Some(
            ProviderFilter::new()
                .event_ids(EventIdFilter::include(&[TCP_REQUEST_CONNECT]))
                .stack_walk(EventIdFilter::include(&[TCP_REQUEST_CONNECT])),
        ),
    )?;
    println!("[+] Enabled TCP connect() events");

    trace.set_event_callback(move |event, context| {
        match event.provider_guid() {
            kernel::tcpip::GUID => handle_tcpip_event(event, context),
            // This provider was not explicitly enabled, but events still arrive for it.
            // This is one example of where an approach that abstracted to a callback function
            // per enabled provider isn't ideal.
            kernel::etw_subsystem::GUID => handle_stack_walk_event(event),
            _ => unreachable!(),
        }
    });

    trace.start_processing_thread()?;

    // Trigger a TCP connection event
    let addr = SocketAddr::from(([1, 1, 1, 1], 80)); // Cloudflare
    match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
        Ok(_stream) => {
            println!("[*] Connected to {addr}\n");
        }
        Err(e) => {
            println!("[!] Failed to connect to {addr}: {e}\n");
        }
    }

    sleep(Duration::from_secs(2));
    Ok(())
}

fn handle_tcpip_event(
    event: &etw::RawEvent,
    context: &mut etw::processing_context::ProcessingContext,
) -> etw::Result<()> {
    // only process events from our process
    let pid = event.process_id();
    if pid != std::process::id() {
        return Ok(());
    }

    let mut parser = context.parser(event)?;
    let remote: SocketAddr = parser.get("RemoteAddress")?;
    let stack = event.stack_trace()?;
    let match_id = stack.match_id();
    let km_frames = stack
        .addresses()
        .iter()
        .filter(|a| **a >= 0xFFFF_8000_0000_0000_u64)
        .count();
    let um_frames = stack
        .addresses()
        .iter()
        .filter(|a| **a <= 0x7FFF_FFFF_FFFF_u64)
        .count();
    // In this scenario, we are only expecting kernel frames - not user-mode ones.
    assert_eq!(um_frames, 0);
    assert_eq!(km_frames, stack.len());

    let timestamp = event.timestamp();
    println!(
        "{timestamp} pid:{pid} TCP connect({remote}) event - match_id:{match_id:#x} km_frames:{km_frames} um_frames:{um_frames}"
    );

    Ok(())
}

fn handle_stack_walk_event(event: &etw::RawEvent) -> etw::Result<()> {
    assert_eq!(event.id(), STACK_TRACE);

    // only process events from our process
    let pid = event.process_id();
    if pid != std::process::id() {
        return Ok(());
    }

    let timestamp = event.timestamp();
    let stack = event.stack_trace()?;
    let match_id = stack.match_id();
    let summary = resolve_modules(&stack.addresses());

    println!(
        "{timestamp} pid:{pid} Deferred StackWalk event      - match_id:{match_id:#x} {summary}"
    );

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
        // SAFETY: VirtualQuery writes to mbi, which is valid and properly sized.
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
            // SAFETY: GetModuleBaseNameW writes to name_buf which is properly sized.
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
