//! Benchmark utilities shared across all bench harnesses.

// This file is included via `#[path]` into private modules, so `pub` items
// trigger `unreachable_pub`. Suppressing since `pub(crate)` then triggers
// `redundant_pub_crate`.
//
// Must stay an `allow`: the lint fires in some of the 5 bench binaries that
// include this file but not all of them, so an `expect` would report itself
// unfulfilled for whichever binary happens not to trigger it.
#![allow(
    unreachable_pub,
    reason = "included via #[path] into private bench modules"
)]

/// One logical processor, as reported by `GetSystemCpuSetInformation`.
#[derive(Clone, Copy)]
struct CpuSetEntry {
    /// Processor group the core belongs to.
    group: u16,
    /// Index of the core within its processor group.
    logical_index: u8,
    /// Intel Thread Director class; higher is faster.
    efficiency_class: u8,
}

/// Pin this process to the performance cores of a hybrid CPU.
///
/// First opts the process out of execution-speed power throttling (see
/// [`disable_power_throttling`]), then enumerates CPU sets via
/// `GetSystemCpuSetInformation`, selects the highest `EfficiencyClass`, and confines
/// the process to those cores using a hard affinity mask. Both halves are needed: a
/// throttled process is slow even on a performance core. On non-hybrid machines, where
/// every core shares one class, only the throttling opt-out applies.
///
/// A hard mask is deliberate. This previously called `SetProcessDefaultCpuSets`,
/// which is only a scheduling *hint*: the kernel may ignore it, and the old code
/// printed a reassuring "pinned to N P-cores" either way, so a benchmark that had
/// been scheduled elsewhere still reported its figures as if pinned.
///
/// Measured on an Intel Core Ultra 7 268V, `process_start/etw-rs-static` launched
/// from background tooling: 723ns/event with the old hint, roughly 650 with a hard
/// mask, and about 287 once [`disable_power_throttling`] is applied as well. The
/// mask is the smaller half of that; do not remove either.
///
/// # Panics
///
/// Panics if the CPU set topology cannot be read, if the performance cores span
/// more than one processor group, or if the process cannot be confined to them
/// and then observed running there. Figures measured off the performance cores
/// are not comparable with anything, so failing loudly beats reporting them.
#[expect(
    clippy::print_stderr,
    reason = "Benchmark utility, stderr output is intentional"
)]
pub fn pin_to_performance_cores() {
    use std::thread;
    use windows::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentProcessorNumber, GetProcessAffinityMask,
        SetProcessAffinityMask,
    };

    // Choosing the right core is only half of it, and the smaller half: a throttled
    // process is slow wherever it runs. Lift that first.
    disable_power_throttling();

    let entries = query_cpu_sets();
    let Some(max_class) = entries.iter().map(|e| e.efficiency_class).max() else {
        panic!(
            "CPU pinning: GetSystemCpuSetInformation reported no CPU sets, so the cores \
             this benchmark runs on cannot be confirmed. Refusing to report timings."
        )
    };
    let perf: Vec<CpuSetEntry> = entries
        .iter()
        .copied()
        .filter(|e| e.efficiency_class == max_class)
        .collect();

    // Every core in one class means there is nothing to choose between.
    if perf.len() == entries.len() {
        eprintln!(
            "CPU pinning: all {} cores are EfficiencyClass {max_class} (non-hybrid), no pinning needed",
            entries.len()
        );
        return;
    }

    // `SetProcessAffinityMask` addresses a single processor group. Machines large
    // enough to split performance cores across groups need `SetThreadGroupAffinity`
    // instead; rather than silently pinning to part of the set, stop.
    let group = perf[0].group;
    assert!(
        perf.iter().all(|e| e.group == group),
        "CPU pinning: performance cores span multiple processor groups, which \
         SetProcessAffinityMask cannot express. Refusing to report timings."
    );

    let mask: usize = perf
        .iter()
        .fold(0, |acc, e| acc | 1usize << e.logical_index);

    // SAFETY: `GetCurrentProcess` returns a pseudo-handle that is always valid, and
    // `mask` only has bits set for logical processor indices the kernel just reported.
    unsafe { SetProcessAffinityMask(GetCurrentProcess(), mask) }.unwrap_or_else(|e| {
        panic!(
            "CPU pinning: SetProcessAffinityMask({mask:#x}) failed: {e}. \
             Refusing to report timings."
        )
    });

    // Read the mask back rather than trusting the setter, then confirm this thread
    // has actually been migrated onto it.
    let mut applied: usize = 0;
    let mut system: usize = 0;
    // SAFETY: both pointers reference live `usize` locals for the duration of the call.
    unsafe { GetProcessAffinityMask(GetCurrentProcess(), &raw mut applied, &raw mut system) }
        .unwrap_or_else(|e| {
            panic!("CPU pinning: GetProcessAffinityMask failed: {e}. Refusing to report timings.")
        });
    assert_eq!(
        applied, mask,
        "CPU pinning: affinity mask read back incorrectly. Refusing to report timings."
    );

    // Affinity takes effect on reschedule, so yield before giving up. 8 attempts is
    // far more than the single reschedule this needs; it exists only so a momentarily
    // busy machine does not fail the check spuriously.
    let mut current = u32::MAX;
    for _ in 0..8 {
        // SAFETY: no preconditions; returns the processor this thread is running on.
        current = unsafe { GetCurrentProcessorNumber() };
        if mask & (1usize << current) != 0 {
            eprintln!(
                "CPU pinning: confined to {} P-cores (EfficiencyClass {max_class}) of {} via \
                 affinity mask {mask:#x}, running on CPU {current}",
                perf.len(),
                entries.len()
            );
            return;
        }
        thread::yield_now();
    }

    panic!(
        "CPU pinning: affinity mask {mask:#x} was applied but this thread is still on \
         CPU {current}, outside the performance set. Refusing to report timings."
    );
}

/// Opt this process out of Windows execution-speed power throttling.
///
/// A benchmark launched from background tooling starts with `ControlMask == 0`, i.e.
/// the system decides whether to throttle it, and measurably does. Opting out is worth
/// more than the core pinning above: an ABBA-paired comparison of two builds differing
/// only in this call measured **-55.04% +/- 0.46%** over 12 pairs on
/// `process_start/etw-rs-static` (`benches/round_robin.py`).
///
/// The mechanism behind that is *not* established. Sampling the benchmark process from
/// outside put its effective clock at 3215MHz throttled against 4064MHz not, which is
/// only 1.26x and cannot by itself explain a 2.19x change in wall time — the throttled
/// run also retires the same work in roughly 1.7x the cycles. That external sampling is
/// confounded by criterion's parallel analysis phase, so treat both figures as
/// indicative. What is solid is the effect and its sign; do not repeat a tidier
/// explanation than the measurements support.
///
/// Raising the process priority class lifts it too, but that is a blunt instrument that
/// changes how the benchmark competes with every other process on the machine.
///
/// # Panics
///
/// Panics if the opt-out is rejected, which leaves the process liable to throttling.
/// Throttled figures are not comparable with anything, so failing loudly beats
/// reporting them.
#[expect(
    clippy::expect_used,
    reason = "the size of a local struct is a compile-time constant that fits in u32"
)]
fn disable_power_throttling() {
    use std::mem::size_of;
    use windows::Win32::System::Threading::{
        GetCurrentProcess, PROCESS_POWER_THROTTLING_CURRENT_VERSION,
        PROCESS_POWER_THROTTLING_EXECUTION_SPEED, PROCESS_POWER_THROTTLING_STATE,
        ProcessPowerThrottling, SetProcessInformation,
    };

    // `ControlMask` selects which policy is being set and `StateMask` is the value.
    // EXECUTION_SPEED with a zero state means "always run at full speed"; leaving
    // `ControlMask` zero instead would hand the decision back to the system.
    let state = PROCESS_POWER_THROTTLING_STATE {
        Version: PROCESS_POWER_THROTTLING_CURRENT_VERSION,
        ControlMask: PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
        StateMask: 0,
    };

    // SAFETY: `GetCurrentProcess` returns an always-valid pseudo-handle. `state` is a
    // live, correctly versioned `PROCESS_POWER_THROTTLING_STATE`, and the size passed
    // is that of the same type, as `ProcessPowerThrottling` requires.
    unsafe {
        SetProcessInformation(
            GetCurrentProcess(),
            ProcessPowerThrottling,
            (&raw const state).cast(),
            u32::try_from(size_of::<PROCESS_POWER_THROTTLING_STATE>())
                .expect("PROCESS_POWER_THROTTLING_STATE is 12 bytes"),
        )
    }
    .unwrap_or_else(|e| {
        panic!(
            "CPU pinning: could not opt out of EcoQoS power throttling: {e}. Timings \
             taken under a clock cap are not comparable. Refusing to report timings."
        )
    });
}

/// Read the logical processors and their efficiency classes from the kernel.
///
/// Returns an empty vector when the topology is unavailable; callers treat that
/// as fatal rather than benchmarking on unknown cores.
fn query_cpu_sets() -> Vec<CpuSetEntry> {
    use std::mem::size_of;
    use windows::Win32::System::SystemInformation::{
        CPU_SET_INFORMATION_TYPE, GetSystemCpuSetInformation, SYSTEM_CPU_SET_INFORMATION,
    };

    // Query required buffer size
    let mut length = 0u32;
    // SAFETY: First call with None/0 to query the required buffer size.
    // `length` is a valid pointer to a u32.
    // Expected to return FALSE with ERROR_INSUFFICIENT_BUFFER; we only need `length`.
    let _ = unsafe { GetSystemCpuSetInformation(None, 0, &raw mut length, None, None) };
    if length == 0 {
        return Vec::new();
    }

    // Allocate buffer and fill with CPU set information.
    // Entries are variable-sized (keyed by the `Size` field), so we use a raw
    // byte buffer and walk it manually.
    //
    // Use Vec<u64> (8-byte aligned) because SYSTEM_CPU_SET_INFORMATION contains
    // u64 fields and requires 8-byte alignment. Vec<u8> would only guarantee
    // 1-byte alignment, making the cast below unsound.
    let byte_len = length as usize;
    let mut buffer = vec![0u64; byte_len.div_ceil(size_of::<u64>())];
    // SAFETY: buffer is correctly sized per the previous query (`byte_len` bytes).
    // Vec<u64> guarantees 8-byte alignment as required by SYSTEM_CPU_SET_INFORMATION.
    // `length` receives the actual bytes written.
    let ok = unsafe {
        GetSystemCpuSetInformation(
            Some(buffer.as_mut_ptr().cast::<SYSTEM_CPU_SET_INFORMATION>()),
            length,
            &raw mut length,
            None,
            None,
        )
    };
    if !ok.as_bool() {
        return Vec::new();
    }

    let mut entries = Vec::new();
    let mut offset = 0usize;
    while offset < length as usize {
        // SAFETY: offset is within the buffer bounds, which the size check below
        // maintains on each step. The base pointer is 8-byte aligned (Vec<u64>) and
        // the kernel places each SYSTEM_CPU_SET_INFORMATION entry at a naturally
        // aligned offset within the buffer, so the cast is sound.
        let info = unsafe {
            &*buffer
                .as_ptr()
                .cast::<u8>()
                .add(offset)
                .cast::<SYSTEM_CPU_SET_INFORMATION>()
        };
        let size = info.Size as usize;
        if size == 0 || offset + size > length as usize {
            break;
        }

        if info.Type == CPU_SET_INFORMATION_TYPE(0) {
            // SAFETY: Type check above guarantees the CpuSet union variant is active.
            let cpu_set = unsafe { &info.Anonymous.CpuSet };
            entries.push(CpuSetEntry {
                group: cpu_set.Group,
                logical_index: cpu_set.LogicalProcessorIndex,
                efficiency_class: cpu_set.EfficiencyClass,
            });
        }
        offset += size;
    }

    entries
}
