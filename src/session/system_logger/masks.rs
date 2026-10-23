//! PERFINFO group mask constants and utilities for system logger sessions.
//!
//! The `PERF_*` constants control which kernel event groups are enabled when
//! system logger mode is active on a [`Trace`](crate::Trace) session. They map to the
//! `PERFINFO_GROUPMASK` mechanism used by `StartTraceW` with system logger mode.
//!
//! Each constant encodes both its mask array index (bits 31–29) and value
//! (bits 28–0). Use [`add_group_mask()`] to apply them correctly.
//!
//! # References
//!
//! - [KrabsETW perfinfo_groupmask.hpp](https://github.com/microsoft/krabsetw/blob/master/krabs/krabs/perfinfo_groupmask.hpp)
//! - [Geoff Chappell, PERFINFO_GROUPMASK](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntwmi/perfinfo_groupmask.htm)

// ═══════════════════════════════════════════════════════════════════════════════
// Masks[0] — Classic EVENT_TRACE_FLAG_* values
// ═══════════════════════════════════════════════════════════════════════════════

pub const PERF_PROCESS: u32 = 0x0000_0001;
pub const PERF_THREAD: u32 = 0x0000_0002;
pub const PERF_PROC_THREAD: u32 = 0x0000_0003;
pub const PERF_LOADER: u32 = 0x0000_0004;
pub const PERF_PROCESS_COUNTERS: u32 = 0x0000_0008;
pub const PERF_DISK_IO: u32 = 0x0000_0300;
pub const PERF_FILENAME: u32 = 0x0000_0200;
pub const PERF_DISK_IO_INIT: u32 = 0x0000_0400;
pub const PERF_ALL_FAULTS: u32 = 0x0000_1000;
pub const PERF_HARD_FAULTS: u32 = 0x0000_2000;
pub const PERF_VAMAP: u32 = 0x0000_8000;
pub const PERF_NETWORK: u32 = 0x0001_0000;
pub const PERF_REGISTRY: u32 = 0x0002_0000;
pub const PERF_DBGPRINT: u32 = 0x0004_0000;
pub const PERF_JOB: u32 = 0x0008_0000;
pub const PERF_ALPC: u32 = 0x0010_0000;
pub const PERF_SPLIT_IO: u32 = 0x0020_0000;
pub const PERF_DEBUG_EVENTS: u32 = 0x0040_0000;
pub const PERF_FILE_IO: u32 = 0x0200_0000;
pub const PERF_FILE_IO_INIT: u32 = 0x0400_0000;
pub const PERF_NO_SYSCONFIG: u32 = 0x1000_0000;

// ═══════════════════════════════════════════════════════════════════════════════
// Masks[1] — Extended group mask events
// ═══════════════════════════════════════════════════════════════════════════════

pub const PERF_MEMORY: u32 = 0x2000_0001;
pub const PERF_PROFILE: u32 = 0x2000_0002;
pub const PERF_CONTEXT_SWITCH: u32 = 0x2000_0004;
pub const PERF_FOOTPRINT: u32 = 0x2000_0008;
pub const PERF_DRIVERS: u32 = 0x2000_0010;
pub const PERF_REFSET: u32 = 0x2000_0020;
pub const PERF_POOL: u32 = 0x2000_0040;
// Intentional combination — enables both PERF_POOL (bit 0x40) and PERF_MEMORY (bit 0x01) in
// Masks[1].
pub const PERF_POOLTRACE: u32 = 0x2000_0041;
pub const PERF_DPC: u32 = 0x2000_0080;
pub const PERF_COMPACT_CSWITCH: u32 = 0x2000_0100;
pub const PERF_DISPATCHER: u32 = 0x2000_0200;
pub const PERF_PMC_PROFILE: u32 = 0x2000_0400;
// Intentional combination — enables both PERF_PMC_PROFILE (bit 0x400) and PERF_PROFILE (bit 0x002)
// in Masks[1].
pub const PERF_PROFILING: u32 = 0x2000_0402;
pub const PERF_PROCESS_INSWAP: u32 = 0x2000_0800;
pub const PERF_AFFINITY: u32 = 0x2000_1000;
pub const PERF_PRIORITY: u32 = 0x2000_2000;
pub const PERF_INTERRUPT: u32 = 0x2000_4000;
pub const PERF_VIRTUAL_ALLOC: u32 = 0x2000_8000;
pub const PERF_SPINLOCK: u32 = 0x2001_0000;
pub const PERF_SYNC_OBJECTS: u32 = 0x2002_0000;
pub const PERF_DPC_QUEUE: u32 = 0x2004_0000;
pub const PERF_MEMINFO: u32 = 0x2008_0000;
pub const PERF_CONTMEM_GEN: u32 = 0x2010_0000;
pub const PERF_SPINLOCK_CNTRS: u32 = 0x2020_0000;
// Intentional combination — enables both PERF_SPINLOCK_CNTRS (bit 0x0020_0000) and
// PERF_SPINLOCK (bit 0x0001_0000) in Masks[1].
pub const PERF_SPININSTR: u32 = 0x2021_0000;
// Intentional alias — both names map to the same bit in krabsetw's perfinfo_groupmask.hpp
pub const PERF_SESSION: u32 = 0x2040_0000;
pub const PERF_PFSECTION: u32 = 0x2040_0000;
pub const PERF_MEMINFO_WS: u32 = 0x2080_0000;
pub const PERF_KERNEL_QUEUE: u32 = 0x2100_0000;
pub const PERF_INTERRUPT_STEER: u32 = 0x2200_0000;
pub const PERF_SHOULD_YIELD: u32 = 0x2400_0000;
pub const PERF_WS: u32 = 0x2800_0000;

// ═══════════════════════════════════════════════════════════════════════════════
// Masks[2] — Additional extended events
// ═══════════════════════════════════════════════════════════════════════════════

pub const PERF_ANTI_STARVATION: u32 = 0x4000_0001;
pub const PERF_PROCESS_FREEZE: u32 = 0x4000_0002;
pub const PERF_PFN_LIST: u32 = 0x4000_0004;
pub const PERF_WS_DETAIL: u32 = 0x4000_0008;
pub const PERF_WS_ENTRY: u32 = 0x4000_0010;
pub const PERF_HEAP: u32 = 0x4000_0020;
pub const PERF_SYSCALL: u32 = 0x4000_0040;
pub const PERF_UMS: u32 = 0x4000_0080;
pub const PERF_BACKTRACE: u32 = 0x4000_0100;
pub const PERF_VULCAN: u32 = 0x4000_0200;
pub const PERF_OBJECTS: u32 = 0x4000_0400;
pub const PERF_EVENTS: u32 = 0x4000_0800;
pub const PERF_FULLTRACE: u32 = 0x4000_1000;
pub const PERF_DFSS: u32 = 0x4000_2000;
pub const PERF_PREFETCH: u32 = 0x4000_4000;
pub const PERF_PROCESSOR_IDLE: u32 = 0x4000_8000;
pub const PERF_CPU_CONFIG: u32 = 0x4001_0000;
pub const PERF_TIMER: u32 = 0x4002_0000;
pub const PERF_CLOCK_INTERRUPT: u32 = 0x4004_0000;
pub const PERF_LOAD_BALANCER: u32 = 0x4008_0000;
pub const PERF_CLOCK_TIMER: u32 = 0x4010_0000;
pub const PERF_IDLE_SELECTION: u32 = 0x4020_0000;
pub const PERF_IPI: u32 = 0x4040_0000;
pub const PERF_IO_TIMER: u32 = 0x4080_0000;
pub const PERF_REG_HIVE: u32 = 0x4100_0000;
pub const PERF_REG_NOTIF: u32 = 0x4200_0000;
pub const PERF_PPM_EXIT_LATENCY: u32 = 0x4400_0000;
pub const PERF_WORKER_THREAD: u32 = 0x4800_0000;

// Masks[3] — no kernel events are defined for this index (0x6xxx range unused)

// ═══════════════════════════════════════════════════════════════════════════════
// Masks[4] — Object and power events
// ═══════════════════════════════════════════════════════════════════════════════

pub const PERF_OPTICAL_IO: u32 = 0x8000_0001;
pub const PERF_OPTICAL_IO_INIT: u32 = 0x8000_0002;
pub const PERF_DLL_INFO: u32 = 0x8000_0008;
pub const PERF_DLL_FLUSH_WS: u32 = 0x8000_0010;
pub const PERF_OB_HANDLE: u32 = 0x8000_0040;
pub const PERF_OB_OBJECT: u32 = 0x8000_0080;
pub const PERF_WAKE_DROP: u32 = 0x8000_0200;
pub const PERF_WAKE_EVENT: u32 = 0x8000_0400;
pub const PERF_DEBUGGER: u32 = 0x8000_0800;
pub const PERF_PROC_ATTACH: u32 = 0x8000_1000;
pub const PERF_WAKE_COUNTER: u32 = 0x8000_2000;
pub const PERF_POWER: u32 = 0x8000_8000;
pub const PERF_SOFT_TRIM: u32 = 0x8001_0000;
pub const PERF_CC: u32 = 0x8002_0000;
pub const PERF_FLT_IO_INIT: u32 = 0x8008_0000;
pub const PERF_FLT_IO: u32 = 0x8010_0000;
pub const PERF_FLT_FASTIO: u32 = 0x8020_0000;
pub const PERF_FLT_IO_FAILURE: u32 = 0x8040_0000;
pub const PERF_HV_PROFILE: u32 = 0x8080_0000;
pub const PERF_WDF_DPC: u32 = 0x8100_0000;
pub const PERF_WDF_INTERRUPT: u32 = 0x8200_0000;
pub const PERF_CACHE_FLUSH: u32 = 0x8400_0000;

// ═══════════════════════════════════════════════════════════════════════════════
// Masks[5] — Hibernation events
// ═══════════════════════════════════════════════════════════════════════════════

pub const PERF_HIBER_RUNDOWN: u32 = 0xA000_0001;

// ═══════════════════════════════════════════════════════════════════════════════
// Masks[6] — System configuration events
// ═══════════════════════════════════════════════════════════════════════════════

pub const PERF_SYSCFG_SYSTEM: u32 = 0xC000_0001;
pub const PERF_SYSCFG_GRAPHICS: u32 = 0xC000_0002;
pub const PERF_SYSCFG_STORAGE: u32 = 0xC000_0004;
pub const PERF_SYSCFG_NETWORK: u32 = 0xC000_0008;
pub const PERF_SYSCFG_SERVICES: u32 = 0xC000_0010;
pub const PERF_SYSCFG_PNP: u32 = 0xC000_0020;
pub const PERF_SYSCFG_OPTICAL: u32 = 0xC000_0040;
pub const PERF_SYSCFG_ALL: u32 = 0xDFFF_FFFF;

// ═══════════════════════════════════════════════════════════════════════════════
// Masks[7] — Control mask
// ═══════════════════════════════════════════════════════════════════════════════

pub const PERF_CLUSTER_OFF: u32 = 0xE000_0001;
pub const PERF_MEMORY_CONTROL: u32 = 0xE000_0002;

// ═══════════════════════════════════════════════════════════════════════════════
// Mask index constants
// ═══════════════════════════════════════════════════════════════════════════════

/// Bitmask to extract the group index from a `PERF_*` constant (top 3 bits).
pub const PERF_MASK_INDEX: u32 = 0xE000_0000;

/// Bitmask to extract the group value from a `PERF_*` constant (lower 29 bits).
pub const PERF_MASK_GROUP: u32 = !PERF_MASK_INDEX;

/// Number of group mask slots in `PERFINFO_GROUPMASK`.
pub const PERF_NUM_MASKS: usize = 8;

// ═══════════════════════════════════════════════════════════════════════════════
// Extension Item Types
// ═══════════════════════════════════════════════════════════════════════════════

// Source:
// https://github.com/microsoft/perfview/blob/a3829cda183fbdb0069a88a32f182aba6f32cbf8/src/TraceEvent/ETWKernelControl.cs#L328-L335

/// Extension type for `PERFINFO_GROUPMASK` (8 u32 values).
pub const ETW_EXT_ENABLE_FLAGS: u16 = 1;

/// Extension type for process ID filter.
pub const ETW_EXT_PIDS: u16 = 2;

/// Extension type for stack walk event filter.
pub const ETW_EXT_STACKWALK_FILTER: u16 = 3;

/// Extension type for pool tag filter.
pub const ETW_EXT_POOLTAG_FILTER: u16 = 4;

/// Extension type for stack caching configuration.
pub const ETW_EXT_STACK_CACHING: u16 = 5;

// ═══════════════════════════════════════════════════════════════════════════════
// Filter Limits
// ═══════════════════════════════════════════════════════════════════════════════

/// Maximum number of hook IDs for stack walk filtering.
///
/// Value determined experimentally; no public header definition known.
pub const ETW_MAX_STACKWALK_FILTER: usize = 256;

/// Maximum number of pool tags for filtering.
///
/// See <https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntetw/event_trace_information_class.htm>.
pub const ETW_MAX_POOLTAG_FILTER: usize = 4;

/// Maximum number of object type tags for filtering.
///
/// See <https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntetw/event_trace_information_class.htm>.
pub const ETW_MAX_OBJECT_TYPE_FILTER: usize = 4;

/// LBR event opcode (`evntrace.h` `TRACE_LBR_EVENT_OPCODE`).
pub const TRACE_LBR_EVENT_OPCODE: u8 = 0x20;

/// Maximum number of events that can trigger LBR collection (`evntrace.h`
/// `TRACE_LBR_MAXIMUM_EVENTS`).
pub const TRACE_LBR_MAXIMUM_EVENTS: usize = 4;

/// Maximum number of events for PMC (Performance Monitoring Counter) profiling.
///
/// See <https://github.com/winsiderss/systeminformer/blob/e4e28c91d4c2dfffcb3b8b1b8b537b213ef6c029/phnt/include/ntexapi.h#L3265-L3268>.
pub const ETW_MAX_PMC_EVENTS: usize = 4;

// ═══════════════════════════════════════════════════════════════════════════════
// Helper Functions
// ═══════════════════════════════════════════════════════════════════════════════

/// Extracts the group mask array index from a `PERF_*` constant.
///
/// The index is encoded in the top 3 bits (bits 29–31).
///
/// # Example
///
/// ```
/// use etw::system_logger::masks::{PERF_CONTEXT_SWITCH, perf_mask_index};
///
/// // PERF_CONTEXT_SWITCH = 0x2000_0004 -> index 1
/// assert_eq!(perf_mask_index(PERF_CONTEXT_SWITCH), 1);
/// ```
#[inline]
#[must_use]
pub const fn perf_mask_index(flag: u32) -> usize {
    ((flag & PERF_MASK_INDEX) >> 29) as usize
}

/// Extracts the group mask value from a `PERF_*` constant.
///
/// The value is the lower 29 bits.
///
/// # Example
///
/// ```
/// use etw::system_logger::masks::{PERF_CONTEXT_SWITCH, perf_mask_value};
///
/// // PERF_CONTEXT_SWITCH = 0x2000_0004 -> value 0x0000_0004
/// assert_eq!(perf_mask_value(PERF_CONTEXT_SWITCH), 0x0000_0004);
/// ```
#[inline]
#[must_use]
pub const fn perf_mask_value(flag: u32) -> u32 {
    flag & PERF_MASK_GROUP
}

/// Adds a `PERF_*` flag to a group mask array.
///
/// This function extracts the index and value from the flag and ORs
/// the value into the appropriate slot in the masks array.
///
/// # Example
///
/// ```
/// use etw::system_logger::masks::{
///     PERF_CONTEXT_SWITCH, PERF_PROCESS, PERF_THREAD, add_group_mask,
/// };
///
/// let mut masks = [0u32; 8];
/// add_group_mask(&mut masks, PERF_PROCESS);
/// add_group_mask(&mut masks, PERF_THREAD);
/// add_group_mask(&mut masks, PERF_CONTEXT_SWITCH);
///
/// assert_eq!(masks[0], 0x0000_0003); // PROCESS | THREAD
/// assert_eq!(masks[1], 0x0000_0004); // CONTEXT_SWITCH
/// ```
#[inline]
pub const fn add_group_mask(masks: &mut [u32; 8], flag: u32) {
    let index = perf_mask_index(flag);
    let value = perf_mask_value(flag);
    masks[index] |= value;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Class GUID → PERF_* Mask Mapping
// ═══════════════════════════════════════════════════════════════════════════════

/// Look up the `PERF_*` group masks that enable events for a kernel event class GUID.
///
/// Returns a slice of `(name, value)` pairs. Most classes map to a single mask,
/// but some (e.g., PERFINFO) map to multiple masks that each enable different
/// event subsets within the same class.
///
/// Returns an empty slice if the GUID is not a known kernel event class.
#[must_use]
pub const fn guid_to_perf_masks(guid: &crate::Guid) -> &'static [(&'static str, u32)] {
    // Indexed by group ID for the common 1:1 cases, with multi-mask entries
    // for groups that host events from multiple PERF_* categories.
    match guid.to_u128() {
        // 0x01 IO — disk I/O events
        0x3d6fa8d4_fe05_11d0_9dda_00c04fd7ba7c => &[
            ("PERF_DISK_IO", PERF_DISK_IO),
            ("PERF_DISK_IO_INIT", PERF_DISK_IO_INIT),
            ("PERF_FILENAME", PERF_FILENAME),
        ],
        // 0x02 MEMORY — page faults, memory, virtual alloc
        0x3d6fa8d3_fe05_11d0_9dda_00c04fd7ba7c => &[
            ("PERF_ALL_FAULTS", PERF_ALL_FAULTS),
            ("PERF_HARD_FAULTS", PERF_HARD_FAULTS),
            ("PERF_MEMORY", PERF_MEMORY),
            ("PERF_VIRTUAL_ALLOC", PERF_VIRTUAL_ALLOC),
        ],
        // 0x03 PROCESS
        0x3d6fa8d0_fe05_11d0_9dda_00c04fd7ba7c => &[("PERF_PROCESS", PERF_PROCESS)],
        // 0x04 FILE — file I/O events
        0x90cbdc39_4a3e_11d1_84f4_0000f80464e3 => &[
            ("PERF_FILE_IO", PERF_FILE_IO),
            ("PERF_FILE_IO_INIT", PERF_FILE_IO_INIT),
            ("PERF_FILENAME", PERF_FILENAME),
        ],
        // 0x05 THREAD — thread lifecycle, context switches, scheduling
        0x3d6fa8d1_fe05_11d0_9dda_00c04fd7ba7c => &[
            ("PERF_THREAD", PERF_THREAD),
            ("PERF_CONTEXT_SWITCH", PERF_CONTEXT_SWITCH),
            ("PERF_COMPACT_CSWITCH", PERF_COMPACT_CSWITCH),
            ("PERF_DISPATCHER", PERF_DISPATCHER),
            ("PERF_PRIORITY", PERF_PRIORITY),
            ("PERF_AFFINITY", PERF_AFFINITY),
            ("PERF_SPINLOCK", PERF_SPINLOCK),
            ("PERF_ANTI_STARVATION", PERF_ANTI_STARVATION),
            ("PERF_KERNEL_QUEUE", PERF_KERNEL_QUEUE),
            ("PERF_LOAD_BALANCER", PERF_LOAD_BALANCER),
            ("PERF_WORKER_THREAD", PERF_WORKER_THREAD),
            ("PERF_DFSS", PERF_DFSS),
        ],
        // 0x06 TCPIP | 0x08 UDPIP — both enabled by the same network mask
        0x9a280ac0_c8e0_11d1_84e2_00c04fb998a2 | 0xbf3a50c5_a9c9_4988_a005_2df0b7c80f80 => {
            &[("PERF_NETWORK", PERF_NETWORK)]
        }
        // 0x07 JOB
        0x3282fc76_feed_498e_8aa7_e70f459d430e => &[("PERF_JOB", PERF_JOB)],
        // 0x09 REGISTRY
        0xae53722e_c863_11d2_8659_00c04fa321a1 => &[("PERF_REGISTRY", PERF_REGISTRY)],
        // 0x0A DBGPRINT
        0x13976d09_a327_438c_950b_7f03192815c7 => &[("PERF_DBGPRINT", PERF_DBGPRINT)],
        // 0x0E POOL
        0x0268a8b6_74fd_4302_9dd0_6e8f1795c0cf => &[("PERF_POOL", PERF_POOL)],
        // 0x0F PERFINFO — profile, DPC, ISR, syscall, timers, spinlocks
        0xce1dbfb4_137e_4da6_87b0_3f59aa102cbc => &[
            ("PERF_PROFILE", PERF_PROFILE),
            ("PERF_PMC_PROFILE", PERF_PMC_PROFILE),
            ("PERF_DPC", PERF_DPC),
            ("PERF_INTERRUPT", PERF_INTERRUPT),
            ("PERF_SYSCALL", PERF_SYSCALL),
            ("PERF_DPC_QUEUE", PERF_DPC_QUEUE),
            ("PERF_SPINLOCK", PERF_SPINLOCK),
            ("PERF_TIMER", PERF_TIMER),
            ("PERF_CLOCK_INTERRUPT", PERF_CLOCK_INTERRUPT),
            ("PERF_CLOCK_TIMER", PERF_CLOCK_TIMER),
            ("PERF_IPI", PERF_IPI),
            ("PERF_IO_TIMER", PERF_IO_TIMER),
            ("PERF_INTERRUPT_STEER", PERF_INTERRUPT_STEER),
            ("PERF_SHOULD_YIELD", PERF_SHOULD_YIELD),
            ("PERF_WDF_DPC", PERF_WDF_DPC),
            ("PERF_WDF_INTERRUPT", PERF_WDF_INTERRUPT),
            ("PERF_CACHE_FLUSH", PERF_CACHE_FLUSH),
        ],
        // 0x10 HEAP
        0x222962ab_6180_4b88_a825_346b75f2a24a => &[("PERF_HEAP", PERF_HEAP)],
        // 0x11 OBJECT
        0x89497f50_effe_4440_8cf2_ce6b1cdcaca7 => &[("PERF_OB_HANDLE", PERF_OB_HANDLE)],
        // 0x12 POWER — power state transitions, idle selection
        0xe43445e0_0903_48c3_b878_ff0fccebdd04 => &[
            ("PERF_POWER", PERF_POWER),
            ("PERF_PROCESSOR_IDLE", PERF_PROCESSOR_IDLE),
            ("PERF_IDLE_SELECTION", PERF_IDLE_SELECTION),
            ("PERF_PPM_EXIT_LATENCY", PERF_PPM_EXIT_LATENCY),
        ],
        // 0x19 UMS — user-mode scheduling
        0x9aec974b_5b8e_4118_9b92_3186d8002ce5 => &[("PERF_UMS", PERF_UMS)],
        // 0x14 IMAGE
        0x2cb15d1d_5fc1_11d2_abe1_00a0c911f518 => &[("PERF_LOADER", PERF_LOADER)],
        // 0x16 CC (cache controller)
        0x7687a439_f752_45b8_b741_321aec0f8df9 => &[("PERF_CC", PERF_CC)],
        // 0x1A ALPC
        0x45d8cccd_539f_4b72_a8b7_5c683142609a => &[("PERF_ALPC", PERF_ALPC)],
        // 0x1B SPLITIO
        0xd837ca92_12b9_44a5_ad6a_3a65b3578aa8 => &[("PERF_SPLIT_IO", PERF_SPLIT_IO)],
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_extraction() {
        // Masks[0] flags
        assert_eq!(perf_mask_index(PERF_PROCESS), 0);
        assert_eq!(perf_mask_value(PERF_PROCESS), 0x0000_0001);

        // Masks[1] flags
        assert_eq!(perf_mask_index(PERF_CONTEXT_SWITCH), 1);
        assert_eq!(perf_mask_value(PERF_CONTEXT_SWITCH), 0x0000_0004);

        // Masks[2] flags
        assert_eq!(perf_mask_index(PERF_SYSCALL), 2);
        assert_eq!(perf_mask_value(PERF_SYSCALL), 0x0000_0040);

        // Masks[4] flags
        assert_eq!(perf_mask_index(PERF_OB_HANDLE), 4);
        assert_eq!(perf_mask_value(PERF_OB_HANDLE), 0x0000_0040);

        // Masks[5] flags
        assert_eq!(perf_mask_index(PERF_HIBER_RUNDOWN), 5);
        assert_eq!(perf_mask_value(PERF_HIBER_RUNDOWN), 0x0000_0001);

        // Masks[6] flags
        assert_eq!(perf_mask_index(PERF_SYSCFG_SYSTEM), 6);
        assert_eq!(perf_mask_value(PERF_SYSCFG_SYSTEM), 0x0000_0001);

        // Masks[7] flags
        assert_eq!(perf_mask_index(PERF_CLUSTER_OFF), 7);
        assert_eq!(perf_mask_value(PERF_CLUSTER_OFF), 0x0000_0001);
    }

    #[test]
    fn test_add_group_mask() {
        let mut masks = [0u32; 8];

        add_group_mask(&mut masks, PERF_PROCESS);
        add_group_mask(&mut masks, PERF_THREAD);
        add_group_mask(&mut masks, PERF_DISK_IO);

        assert_eq!(masks[0], 0x0000_0303); // PROCESS | THREAD | DISK_IO
        assert_eq!(masks[1], 0);
        assert_eq!(masks[2], 0);
    }

    #[test]
    fn test_proc_thread_combined() {
        // Verify PERF_PROC_THREAD equals PERF_PROCESS | PERF_THREAD
        assert_eq!(PERF_PROC_THREAD, PERF_PROCESS | PERF_THREAD);
    }

    #[test]
    fn test_guid_to_perf_masks_process() {
        let process_guid = crate::Guid::from_u128(0x3d6fa8d0_fe05_11d0_9dda_00c04fd7ba7c);
        let masks = guid_to_perf_masks(&process_guid);
        assert_eq!(masks.len(), 1);
        assert_eq!(masks[0], ("PERF_PROCESS", PERF_PROCESS));
    }

    #[test]
    fn test_guid_to_perf_masks_thread_has_many() {
        let thread_guid = crate::Guid::from_u128(0x3d6fa8d1_fe05_11d0_9dda_00c04fd7ba7c);
        let masks = guid_to_perf_masks(&thread_guid);
        assert!(masks.len() > 1, "THREAD group should map to multiple masks");
        let names: Vec<&str> = masks.iter().map(|&(n, _)| n).collect();
        assert!(names.contains(&"PERF_THREAD"));
        assert!(names.contains(&"PERF_CONTEXT_SWITCH"));
    }

    #[test]
    fn test_guid_to_perf_masks_perfinfo_has_many() {
        let perfinfo_guid = crate::Guid::from_u128(0xce1dbfb4_137e_4da6_87b0_3f59aa102cbc);
        let masks = guid_to_perf_masks(&perfinfo_guid);
        assert!(masks.len() > 5, "PERFINFO maps to many masks");
        let names: Vec<&str> = masks.iter().map(|&(n, _)| n).collect();
        assert!(names.contains(&"PERF_PROFILE"));
        assert!(names.contains(&"PERF_DPC"));
        assert!(names.contains(&"PERF_SYSCALL"));
    }

    #[test]
    fn test_guid_to_perf_masks_io_and_file() {
        // IO disk
        let io_guid = crate::Guid::from_u128(0x3d6fa8d4_fe05_11d0_9dda_00c04fd7ba7c);
        let io_masks = guid_to_perf_masks(&io_guid);
        let io_names: Vec<&str> = io_masks.iter().map(|&(n, _)| n).collect();
        assert!(io_names.contains(&"PERF_DISK_IO"));

        // FILE
        let file_guid = crate::Guid::from_u128(0x90cbdc39_4a3e_11d1_84f4_0000f80464e3);
        let file_masks = guid_to_perf_masks(&file_guid);
        let file_names: Vec<&str> = file_masks.iter().map(|&(n, _)| n).collect();
        assert!(file_names.contains(&"PERF_FILE_IO"));

        // MEMORY
        let mem_guid = crate::Guid::from_u128(0x3d6fa8d3_fe05_11d0_9dda_00c04fd7ba7c);
        let mem_masks = guid_to_perf_masks(&mem_guid);
        let mem_names: Vec<&str> = mem_masks.iter().map(|&(n, _)| n).collect();
        assert!(mem_names.contains(&"PERF_MEMORY"));
    }

    #[test]
    fn test_guid_to_perf_masks_single_entry_guids() {
        let cases: &[(u128, &str)] = &[
            (0x9a280ac0_c8e0_11d1_84e2_00c04fb998a2, "PERF_NETWORK"), // TCPIP
            (0xbf3a50c5_a9c9_4988_a005_2df0b7c80f80, "PERF_NETWORK"), // UDPIP
            (0x3282fc76_feed_498e_8aa7_e70f459d430e, "PERF_JOB"),     // JOB
            (0xae53722e_c863_11d2_8659_00c04fa321a1, "PERF_REGISTRY"), // REGISTRY
            (0x13976d09_a327_438c_950b_7f03192815c7, "PERF_DBGPRINT"), // DBGPRINT
            (0x0268a8b6_74fd_4302_9dd0_6e8f1795c0cf, "PERF_POOL"),    // POOL
            (0x222962ab_6180_4b88_a825_346b75f2a24a, "PERF_HEAP"),    // HEAP
            (0x89497f50_effe_4440_8cf2_ce6b1cdcaca7, "PERF_OB_HANDLE"), // OBJECT
            (0x9aec974b_5b8e_4118_9b92_3186d8002ce5, "PERF_UMS"),     // UMS
            (0x2cb15d1d_5fc1_11d2_abe1_00a0c911f518, "PERF_LOADER"),  // IMAGE
            (0x7687a439_f752_45b8_b741_321aec0f8df9, "PERF_CC"),      // CC
            (0x45d8cccd_539f_4b72_a8b7_5c683142609a, "PERF_ALPC"),    // ALPC
            (0xd837ca92_12b9_44a5_ad6a_3a65b3578aa8, "PERF_SPLIT_IO"), // SPLITIO
        ];
        for &(guid_val, expected_name) in cases {
            let guid = crate::Guid::from_u128(guid_val);
            let masks = guid_to_perf_masks(&guid);
            assert!(!masks.is_empty(), "guid 0x{guid_val:032X} returned empty");
            let names: Vec<&str> = masks.iter().map(|&(n, _)| n).collect();
            assert!(
                names.contains(&expected_name),
                "guid 0x{guid_val:032X} should map to {expected_name}, got {names:?}"
            );
        }
    }

    #[test]
    fn test_guid_to_perf_masks_power() {
        let power_guid = crate::Guid::from_u128(0xe43445e0_0903_48c3_b878_ff0fccebdd04);
        let masks = guid_to_perf_masks(&power_guid);
        let names: Vec<&str> = masks.iter().map(|&(n, _)| n).collect();
        assert!(names.contains(&"PERF_POWER"));
        assert!(names.contains(&"PERF_PROCESSOR_IDLE"));
    }

    #[test]
    fn test_guid_to_perf_masks_unknown() {
        let unknown = crate::Guid::from_u128(0xdeadbeef_dead_beef_dead_beefdeadbeef);
        assert!(guid_to_perf_masks(&unknown).is_empty());
    }
}
