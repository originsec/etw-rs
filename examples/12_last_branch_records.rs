#![expect(
    clippy::print_stdout,
    clippy::unwrap_used,
    reason = "example output is the point of the example; unwraps keep the raw parsing readable"
)]

//! Last Branch Record (LBR) tracing example.
//!
//! This example demonstrates capturing Last Branch Records with CPU sampling events.
//! LBR provides a hardware-assisted call stack alternative, recording recent branches.
//!
//! # Requirements
//!
//! - Must be run as Administrator for kernel tracing
//! - Windows 10 19H1 / Server 2019 or later
//! - Additional CPU requirements based on desired LBR feature set
//!
//! # Usage
//!
//! ```bash
//! cargo run --example 12_last_branch_records
//! ```
//!
//! # Notes
//!
//! LBR events are attached to CPU sampling (SAMPLE_PROFILE) events.
//! When LBR data is present, the event comes from the LBR GUID
//! (`99134383-5248-43FC-834B-529454E75DF3`), containing branch history.

use etw::{
    Trace,
    stack_walk::LbrData,
    system_logger::{
        self, CALLSTACK_ENABLE, EXCLUDE_KERNEL,
        masks::{PERF_NO_SYSCONFIG, PERF_PROFILE},
    },
};
use example_providers::classic::{lbr, perf_info};
use std::{thread::sleep, time::Duration};

fn main() -> etw::Result<()> {
    println!("Last Branch Record (LBR) Tracing Example");
    println!();
    println!("Requirements:");
    println!("  - Administrator privileges");
    println!("  - Windows 10 19H1+ / Server 2019+");
    println!("  - Intel Pentium+ or AMD Zen4+ CPU");
    println!("  - CPL filtering: Intel Broadwell+ or AMD Zen4+");
    println!("  - Call Stack mode: Intel Haswell+");
    println!("  - Hyper-V supports LBR, but only for non-hybrid CPUs");
    println!();

    // Enable SeSystemProfilePrivilege (required for CPU profiling)
    println!("Enabling SeSystemProfilePrivilege...");
    system_logger::profiling::enable_profile_privilege()?;
    // Set the system-wide profile sampling interval (1 second = 10,000,000 * 100ns)
    println!("Setting profile interval to 1 second...");
    system_logger::profiling::set_profile_interval(10_000_000)?;

    // Create a system logger session with (sampled) profile events enabled
    let mut trace = Trace::new("last_branch_records")?;
    trace
        .set_events(&[PERF_PROFILE, PERF_NO_SYSCONFIG])
        .start()?;

    trace.enable_lbr(
        EXCLUDE_KERNEL | CALLSTACK_ENABLE,
        &[perf_info::hook_id::SAMPLED_PROFILE],
    )?;

    trace.set_event_callback(move |event, context| {
        match event.provider_guid() {
            perf_info::CLASS_GUID if event.opcode() == perf_info::opcode::SAMPLED_PROFILE => {
                // There is no schema registered for this event!

                // The MOF definition is documented however -
                // https://learn.microsoft.com/en-us/windows/win32/etw/sampledprofile
                //
                // [EventType{46}, EventTypeName{"SampleProfile"}]
                // class SampledProfile : PerfInfo
                // {
                //   uint32 InstructionPointer;
                //   uint32 ThreadId;
                //   uint32 Count;
                // };
                //
                // Note: the process id and thread id in the event header are untrustworthy.
                // This is a performance optimisation for high volume system provider events.
                // So always sanity check values in new data sources.
                let user_data = event.user_data();
                let ip = u64::from_le_bytes(*user_data.first_chunk::<8>().unwrap());
                let tid = u32::from_le_bytes(*user_data[8..].first_chunk::<4>().unwrap());
                println!("\n[SAMPLE] TID: {tid}, IP: 0x{ip:016X}");
            }

            lbr::CLASS_GUID if event.opcode() == lbr::opcode::RECORD => {
                // There is a *partial* schema for this event.
                let mut parser = context.parser(event)?;
                let _timestamp: u64 = parser.get("TimeStamp")?;
                let _pid: u32 = parser.get("ProcessId")?;
                let _tid: u32 = parser.get("ThreadId")?;
                let _options: u32 = parser.get("Options")?;
                // let entries: ???  = parser.get("Entries")?;
                // The last property `Entries` is `TDH_INTYPE_NULL` in the schema - which is
                // invalid.

                // Instead we provide a custom parser
                let lbr = LbrData::from_event(event)?;
                println!(
                    "    LBR: {} branches (PID: {}, TID: {}, flags: 0x{:08X})",
                    lbr.num_branches(),
                    lbr.process_id(),
                    lbr.thread_id(),
                    lbr.filter_flags()
                );

                // Print first few branch entries
                let branches = lbr.branches();
                for (i, branch) in branches.iter().enumerate().take(3) {
                    println!("      [{i}] 0x{:016X} -> 0x{:016X}", branch.from, branch.to);
                }
                if branches.len() > 3 {
                    println!("      ... ({} more branches)", branches.len() - 3);
                }
            }

            // Other events (including EVENT_TRACE_GUID) - ignore
            _ => {}
        }

        Ok(())
    });

    trace.start_processing_thread()?;
    println!();
    println!("Listening for CPU samples with LBR for 5 seconds...");
    println!();
    sleep(Duration::from_secs(5));
    Ok(())
}
