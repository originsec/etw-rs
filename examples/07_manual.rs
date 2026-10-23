#![expect(
    clippy::print_stdout,
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "example output is the point of the example; unwraps keep the raw parsing readable"
)]

//! Manual ETW example demonstrating low-level API usage.
//!
//! This example shows how to:
//! 1. Manually set V2Options flags like ExcludeKernelStack
//! 2. Manually call EnableTraceEx2 with ENABLE_TRACE_PARAMETERS
//! 3. Manually parse event UserData without TDH schema lookup
//!
//! Compare with 04_extended_data.rs which uses the higher-level etw-rs APIs.
//!
//! # Requirements
//!
//! Must be run as Administrator for kernel tracing.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example 07_manual
//! ```

use etw::{Error::Win32Error, Trace, event::extended_data_type};
use example_providers::{kernel, kernel::process::event::PROCESS_START};
use std::{
    ffi::OsString, os::windows::ffi::OsStringExt, process::Command, thread::sleep, time::Duration,
};
use windows::Win32::{
    Foundation::{HLOCAL, HMODULE, LocalFree, MAX_PATH},
    Security::{Authorization::ConvertSidToStringSidW, GetLengthSid, IsValidSid, PSID},
    System::{
        Diagnostics::Etw::{
            CONTROLTRACE_HANDLE, ENABLE_TRACE_PARAMETERS, ENABLE_TRACE_PARAMETERS_VERSION_2,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_ENABLE_PROPERTY_PROCESS_START_KEY,
            EVENT_ENABLE_PROPERTY_STACK_TRACE, EnableTraceEx2, TRACE_LEVEL_INFORMATION,
        },
        Memory::{MEMORY_BASIC_INFORMATION, VirtualQuery},
        ProcessStatus::GetModuleBaseNameW,
        Threading::GetCurrentProcess,
    },
};

fn main() -> etw::Result<()> {
    println!("Manual ETW Example\n");
    println!("This example demonstrates low-level ETW API usage:");
    println!("  - Manual ExcludeKernelStack flag setting");
    println!("  - Manual EnableTraceEx2 calls");
    println!("  - Manual event data parsing without TDH\n");

    let mut trace = Trace::new("manual_example")?;

    // We can access the underlying EVENT_TRACE_PROPERTIES_V2 to set any fields
    // that don't have helpers.
    //
    // =========================================================================
    // Example: Manually set ExcludeKernelStack
    // =========================================================================
    // ```
    // typedef struct _EVENT_TRACE_PROPERTIES_V2 {
    // ...
    //   union {
    //     struct {
    //         ULONG Wow : 1; // Logger was started by a WOW64 process (output only).
    //         ULONG QpcDeltaTracking : 1; // QPC delta tracking events are enabled.
    //         ULONG LargeMdlPages : 1; // Buffers allocated via large MDL pages.
    //         ULONG ExcludeKernelStack : 1; // Exclude kernel stack from stack walk.
    //     } DUMMYSTRUCTNAME;
    //     ULONG64 V2Options;
    //   } DUMMYUNIONNAME3;
    // } EVENT_TRACE_PROPERTIES_V2, *PEVENT_TRACE_PROPERTIES_V2;
    // ```
    //
    // In C++ this would simply be -
    // `properties.ExcludeKernelStack = TRUE;`
    //
    // Rust dislikes bitfields, so windows-rs doesn't define them.
    //
    const EXCLUDE_KERNEL_STACK_BIT: u32 = 1 << 3;
    // SAFETY: Accessing the raw properties structure
    unsafe {
        let properties = trace.properties_mut();
        properties.Anonymous3.Anonymous._bitfield |= EXCLUDE_KERNEL_STACK_BIT;
    };
    println!("Set ExcludeKernelStack flag manually");

    trace.start()?;

    // We can also access the underlying session ID (the `CONTROLTRACE_HANDLE` value) directly.
    //
    // =========================================================================
    // Example: Call EnableTraceEx2 directly
    // =========================================================================
    let enable_params = ENABLE_TRACE_PARAMETERS {
        Version: ENABLE_TRACE_PARAMETERS_VERSION_2,
        EnableProperty: EVENT_ENABLE_PROPERTY_PROCESS_START_KEY | EVENT_ENABLE_PROPERTY_STACK_TRACE,
        ControlFlags: 0,
        SourceId: windows::core::GUID::zeroed(),
        EnableFilterDesc: std::ptr::null_mut(),
        FilterDescCount: 0,
    };

    // Raw FFI wants the consumer's own `windows` GUID; convert via u128.
    let process_guid = windows::core::GUID::from_u128(kernel::process::GUID.to_u128());
    // SAFETY: EnableTraceEx2 is a Win32 API. Session handle is valid after start().
    let status = unsafe {
        EnableTraceEx2(
            CONTROLTRACE_HANDLE {
                Value: trace.session_id().expect("session started"),
            },
            &raw const process_guid,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
            TRACE_LEVEL_INFORMATION as u8,
            kernel::process::keyword::PROCESS,
            0, // MatchAllKeyword
            0, // Timeout
            Some(&raw const enable_params),
        )
    };

    if status.is_err() {
        return Err(Win32Error(status.0));
    }
    println!("Enabled provider manually via EnableTraceEx2\n");

    // =========================================================================
    // Example: Parse event data without TDH
    // =========================================================================
    trace.set_event_callback(move |event, _context| {
        // Filter to processes created by our process only
        if event.process_id() != std::process::id() || event.id() != PROCESS_START {
            return Ok(());
        }

        // Parsing events without the runtime schema is faster, but less maintainable.
        // It also lacks the field name and type correctness checks.
        //
        // =====================================================================
        // Example: Parse UserData (event payload) without TDH
        // =====================================================================
        // Use the information from the instrumentation manifest -
        //
        // <provider name="Microsoft-Windows-Kernel-Process" ...
        // ...
        // <events>
        //   <event value="1" symbol="ProcessStart" version="4" task="ProcessStart"
        //          opcode="win:Start" level="win:Informational"
        //          keywords="WINEVENT_KEYWORD_PROCESS" template="ProcessStartArgs_V4" />
        // ...
        // </events>
        // <templates>
        //   <template tid="ProcessStartArgs_V4">
        //     <data name="ProcessID" inType="win:UInt32" />
        //     <data name="ProcessSequenceNumber" inType="win:UInt64" />
        //     <data name="CreateTime" inType="win:FILETIME" />
        //     <data name="ParentProcessID" inType="win:UInt32" />
        //     <data name="ParentProcessSequenceNumber" inType="win:UInt64" />
        //     <data name="SessionID" inType="win:UInt32" />
        //     <data name="Flags" inType="win:UInt32" />
        //     <data name="ProcessTokenElevationType" inType="win:UInt32" />
        //     <data name="ProcessTokenIsElevated" inType="win:UInt32" />
        //     <data name="MandatoryLabel" inType="win:SID" />
        //     <data name="ImageName" inType="win:UnicodeString" />
        //     <data name="ImageChecksum" inType="win:UInt32" />
        //     <data name="TimeDateStamp" inType="win:UInt32" />
        //     <data name="PackageFullName" inType="win:UnicodeString" />
        //     <data name="PackageRelativeAppId" inType="win:UnicodeString" />
        //     <data name="SecurityMitigations" inType="win:UInt32" />
        //   </template>
        // ...
        if event.version() != 4 {
            println!("ProcessStart version {} not implemented", event.version());
            return Ok(());
        }

        let user_data = event.user_data();
        if user_data.len() < 56 {
            println!("Event data too short: {} bytes", user_data.len());
            return Ok(());
        }

        let pid = u32::from_le_bytes(*user_data.first_chunk::<4>().unwrap());
        let session_id = u32::from_le_bytes(*user_data[32..].first_chunk::<4>().unwrap());

        // Parse SID - this is the last fixed offset field.
        // SID is variable length, use GetLengthSid to determine size.
        let sid_offset = 48;
        let sid_bytes = &user_data[sid_offset..];
        #[expect(
            clippy::as_ptr_cast_mut,
            reason = "PSID requires *mut but the Win32 API only reads through it"
        )]
        let psid = PSID(sid_bytes.as_ptr() as *mut _);

        // SAFETY: psid points to at least 8 bytes (minimum SID header)
        let (sid_str, sid_len) = unsafe {
            if IsValidSid(psid).as_bool() {
                let sid_len = GetLengthSid(psid) as usize;
                if user_data.len() < sid_offset + sid_len {
                    ("<truncated>".to_owned(), 8)
                } else {
                    let mut string_sid = windows::core::PWSTR::null();
                    let sid_str = if ConvertSidToStringSidW(psid, &raw mut string_sid).is_ok() {
                        let s = string_sid.to_string().unwrap_or_default();
                        let _ = LocalFree(Some(HLOCAL(string_sid.0.cast())));
                        s
                    } else {
                        "<error>".to_owned()
                    };
                    (sid_str, sid_len)
                }
            } else {
                ("<invalid>".to_owned(), 8)
            }
        };

        // ImageName follows the variable length SID
        let image_name_offset = sid_offset + sid_len;
        let image_name = if image_name_offset < user_data.len() {
            parse_wide_string(&user_data[image_name_offset..])
        } else {
            "<unknown>".to_owned()
        };

        println!("Process: {image_name}");
        println!("  PID: {pid}");
        println!("  Session: {session_id}");
        println!("  MandatoryLabel: {sid_str}");

        // =====================================================================
        // Example: Parse ExtendedData
        // =====================================================================
        println!("  Extended data items: {}", event.extended_data_count());
        for item in event.extended_data() {
            match item.ext_type {
                extended_data_type::PROCESS_START_KEY => {
                    if item.data.len() >= 8 {
                        let psk = u64::from_le_bytes(item.data[..8].try_into().unwrap_or([0; 8]));
                        println!("    ProcessStartKey: 0x{psk:016X}");
                    }
                }
                extended_data_type::STACK_TRACE64 => {
                    // Stack trace: 8-byte match_id followed by 8-byte addresses
                    if item.data.len() >= 16 {
                        let match_id =
                            u64::from_le_bytes(item.data[..8].try_into().unwrap_or([0; 8]));
                        let addr_count = (item.data.len() - 8) / 8;

                        // Parse addresses manually
                        let addresses: Vec<u64> = item.data[8..]
                            .as_chunks::<8>()
                            .0
                            .iter()
                            .map(|c| u64::from_le_bytes(*c))
                            .collect();

                        let stack_summary = resolve_modules(&addresses);
                        println!(
                            "    StackTrace64: match_id=0x{match_id:X}, {addr_count} frames, {stack_summary}"
                        );
                    }
                }
                _ => {
                    println!("    Type {}: {} bytes", item.ext_type, item.data.len());
                }
            }
        }

        println!();
        Ok(())
    });

    trace.start_processing_thread()?;

    // The `PROCESSTRACE_HANDLE` is also accessible; `Some` while processing.
    let _ = trace.raw_process_trace_handle();

    // Trigger an event
    println!("Spawning test process...\n");
    let _ = Command::new("cmd.exe")
        .args(["/c", "echo", "test process"])
        .output();

    sleep(Duration::from_secs(2));
    trace.stop()?;

    println!("\nTrace session stopped.");
    Ok(())
}

/// Parse a null-terminated wide (UTF-16LE) string from a byte slice
fn parse_wide_string(data: &[u8]) -> String {
    // Convert bytes to u16 pairs
    let u16_iter = data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c));

    // Take until null terminator
    let chars: Vec<u16> = u16_iter.take_while(|&c| c != 0).collect();

    OsString::from_wide(&chars).to_string_lossy().into_owned()
}

/// Resolve addresses to module names, returning a pipe-delimited string (deduplicated).
fn resolve_modules(addresses: &[u64]) -> String {
    // SAFETY: GetCurrentProcess returns a pseudo-handle that is always valid.
    let process = unsafe { GetCurrentProcess() };
    let mut result = Vec::new();
    let mut last: Option<String> = None;

    let mut mbi = MEMORY_BASIC_INFORMATION::default();
    let mut name_buf = [0u16; MAX_PATH as usize];
    for &addr in addresses {
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
