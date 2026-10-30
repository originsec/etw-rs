//! Integration tests for system logger rundown.
//!
//! ## `test_system_logger_dc_rundown`
//!
//! Verifies automatic DC_START and DC_END kernel rundown using
//! `PERF_PROC_THREAD + PERF_LOADER`.
//!
//! ## `test_system_logger_file_rundown_and_filename_parsing`
//!
//! Single PERF_FILENAME session:
//! - Open `PROBE_COUNT` distinct files → assert `≥ PROBE_COUNT` real-time `FILE_CREATE` events
//!   arrive while fileinfo.sys is tracking.
//! - Call `send_file_rundown_code()` → assert `≥ PROBE_COUNT` `FILE_RUNDOWN` events arrive from the
//!   explicit trigger.
//! - Parse `FileName` (`WideStrRef` after a `Pointer`) from those rundown events and assert every
//!   probe name is present.
//!
//! # Requirements
//!
//! Administrator (kernel system trace).

#![cfg(not(miri))]
// Win32 API calls are not supported under Miri.
#![expect(
    clippy::print_stdout,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::clone_on_ref_ptr,
    reason = "test binary: printing aids diagnosis and panics are the failure mode"
)]

#[path = "common/mod.rs"]
mod common;

use etw::{
    Trace,
    system_logger::masks::{PERF_FILENAME, PERF_LOADER, PERF_PROC_THREAD},
};
use example_providers::classic::{file_io, image, process, thread};
use serial_test::serial;
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering::Relaxed},
    },
    thread::sleep,
    time::{Duration, Instant},
};
use windows::Win32::Foundation::{NTSTATUS, STATUS_ACCESS_DENIED, STATUS_INFO_LENGTH_MISMATCH};

// Source: <https://ntdoc.m417z.com/system_information_class>.
// SystemBasicProcessInformation (251) is the modern, compact form: each entry
// is a fixed-size header `{ NextEntryOffset, UniqueProcessId, Inherited,
// SequenceNumber, ImageName }`. Available since Windows 11 26100.4770.
// SystemFullProcessInformation (148) is the legacy fallback: same shape as
// SYSTEM_PROCESS_INFORMATION plus a trailing SYSTEM_PROCESS_INFORMATION_EXTENSION
// whose last 8 bytes are `ProcessSequenceNumber`.
const SYSTEM_BASIC_PROCESS_INFORMATION: u32 = 251;
const SYSTEM_FULL_PROCESS_INFORMATION: u32 = 148;

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQuerySystemInformation(
        system_information_class: u32,
        system_information: *mut std::ffi::c_void,
        system_information_length: u32,
        return_length: *mut u32,
    ) -> NTSTATUS;
}

/// Number of distinct probe files opened per trace to create a deterministic
/// floor for both real-time and rundown event counts.
const PROBE_COUNT: usize = 50;

/// Call `NtQuerySystemInformation` for the given class, growing the buffer
/// until the call returns something other than `STATUS_INFO_LENGTH_MISMATCH`.
/// Returns the populated buffer (truncated to `return_length`) on success,
/// or the failure NTSTATUS otherwise.
fn query_system_information(class: u32) -> Result<Vec<u8>, NTSTATUS> {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let mut returned: u32 = 0;
        // SAFETY: We pass a properly-sized, owned mutable buffer; ntdll
        // writes `returned` bytes into it and reports its size via `returned`.
        let status = unsafe {
            NtQuerySystemInformation(
                class,
                buf.as_mut_ptr().cast(),
                u32::try_from(buf.len()).unwrap(),
                &raw mut returned,
            )
        };
        if status == STATUS_INFO_LENGTH_MISMATCH {
            // `returned` is the required size on this error; grow generously
            // because process state may have churned by the retry.
            let needed = (returned as usize).max(buf.len() * 2);
            buf.resize(needed + 16 * 1024, 0);
            continue;
        }
        if !status.is_ok() {
            return Err(status);
        }
        buf.truncate(returned as usize);
        return Ok(buf);
    }
}

/// Snapshot the set of live `(PID -> ProcessStartKey)` pairs via a single
/// `NtQuerySystemInformation` syscall.
///
/// Prefers `SystemBasicProcessInformation` (Win11 26100.4770+) which yields a
/// compact `(NextEntryOffset, PID, ParentPID, SequenceNumber, ImageName)`
/// record per process. Falls back to `SystemFullProcessInformation` whose
/// `SYSTEM_PROCESS_INFORMATION_EXTENSION` ends with `ProcessSequenceNumber`
/// — we read PID at the well-known offset 0x50 and pull the PSK from the
/// last 8 bytes of each entry.
///
/// PSK uniquely identifies a process for the lifetime of the boot — unlike
/// PID, the kernel never reuses it. Pairing PID with PSK gives the overlap
/// below an identity key that's robust against PID reuse inside the
/// snapshot window.
fn snapshot_live_psks() -> Result<HashMap<u32, u64>, NTSTATUS> {
    if let Ok(buf) = query_system_information(SYSTEM_BASIC_PROCESS_INFORMATION) {
        return Ok(parse_basic_process_information(&buf));
    }
    let buf = query_system_information(SYSTEM_FULL_PROCESS_INFORMATION)?;
    Ok(parse_full_process_information(&buf))
}

/// Walk a `SystemBasicProcessInformation` reply.
///
/// Each entry layout on 64-bit Windows:
/// ```text
///   0:  u32  NextEntryOffset             (next = ptr + offset, 0 = end)
///   4:  u32  _padding
///   8:  u64  UniqueProcessId             (HANDLE; PID in low 32 bits)
///  16:  u64  InheritedFromUniqueProcessId
///  24:  u64  SequenceNumber              ← PSK
///  32:  ...  UNICODE_STRING ImageName
/// ```
fn parse_basic_process_information(buf: &[u8]) -> HashMap<u32, u64> {
    let mut out = HashMap::new();
    let mut offset = 0usize;
    loop {
        if offset + 32 > buf.len() {
            break;
        }
        let next = u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap()) as usize;
        let pid = u64::from_le_bytes(buf[offset + 8..offset + 16].try_into().unwrap()) as u32;
        let psk = u64::from_le_bytes(buf[offset + 24..offset + 32].try_into().unwrap());
        if pid != 0 {
            out.insert(pid, psk);
        }
        if next == 0 {
            break;
        }
        offset += next;
    }
    out
}

/// Walk a `SystemFullProcessInformation` reply.
///
/// `SYSTEM_PROCESS_INFORMATION` has the well-known layout with
/// `UniqueProcessId` at offset 0x50 (80) on 64-bit Windows. The trailing
/// `SYSTEM_PROCESS_INFORMATION_EXTENSION` ends with `ULONGLONG
/// ProcessSequenceNumber` — so the PSK is the last 8 bytes of each entry,
/// whose end is given by `NextEntryOffset` (or the buffer end for the final
/// entry).
fn parse_full_process_information(buf: &[u8]) -> HashMap<u32, u64> {
    let mut out = HashMap::new();
    let mut offset = 0usize;
    loop {
        if offset + 88 > buf.len() {
            break;
        }
        let next = u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap()) as usize;
        let entry_end = if next == 0 { buf.len() } else { offset + next };
        if entry_end < offset + 88 || entry_end > buf.len() {
            break;
        }
        let pid = u64::from_le_bytes(buf[offset + 80..offset + 88].try_into().unwrap()) as u32;
        let psk = u64::from_le_bytes(buf[entry_end - 8..entry_end].try_into().unwrap());
        if pid != 0 {
            out.insert(pid, psk);
        }
        if next == 0 {
            break;
        }
        offset += next;
    }
    out
}

#[test]
#[serial(system_logger)]
fn test_system_logger_dc_rundown() {
    // Snapshot {PID -> ProcessStartKey} right before the trace starts. The
    // post-drain snapshot below uses the same shape; their intersection on
    // (PID, PSK) pairs identifies processes definitively alive throughout
    // the startup window (PSK is unique per kernel object — no reuse).
    // This first query runs before the trace opens, so it is also the
    // elevation gate: NtQuerySystemInformation returns STATUS_ACCESS_DENIED
    // for this class on a non-elevated caller, in which case the whole test
    // (which needs a kernel system-logger session anyway) skips.
    let snapshot_pre_start = match snapshot_live_psks() {
        Ok(m) => m,
        Err(status) if status == STATUS_ACCESS_DENIED => {
            println!(
                "Skipping: NtQuerySystemInformation returned STATUS_ACCESS_DENIED — \
                 requires Administrator."
            );
            return;
        }
        Err(status) => panic!("NtQuerySystemInformation(SystemFullProcessInformation): {status:?}"),
    };

    let mut trace = Trace::new("etw-rs_Test_DcRundown").expect("session creation");
    let _ = trace
        .set_buffer_size(64)
        .set_minimum_buffers(4)
        .set_maximum_buffers(64);
    trace.set_events(&[PERF_PROC_THREAD, PERF_LOADER]);
    let Some(()) = common::skip_or_panic("trace.start", trace.start()) else {
        return;
    };

    let process_dc_start_pids: Arc<Mutex<HashSet<u32>>> = Arc::new(Mutex::new(HashSet::new()));
    let process_dc_end_pids: Arc<Mutex<HashSet<u32>>> = Arc::new(Mutex::new(HashSet::new()));
    let thread_dc_start = Arc::new(AtomicUsize::new(0));
    let image_dc_start = Arc::new(AtomicUsize::new(0));

    let process_dc_start_cb = process_dc_start_pids.clone();
    let process_dc_end_cb = process_dc_end_pids.clone();
    let thread_dc_start_cb = thread_dc_start.clone();
    let image_dc_start_cb = image_dc_start.clone();

    trace.set_event_callback(move |event, ctx| {
        match event.provider_guid() {
            g if g == process::CLASS_GUID => match event.opcode() {
                process::opcode::DC_START => {
                    if let Ok(mut p) = ctx.parser(event)
                        && let Ok(pid) = p.get::<u32>("ProcessId")
                    {
                        process_dc_start_cb.lock().unwrap().insert(pid);
                    }
                }
                process::opcode::DC_END => {
                    if let Ok(mut p) = ctx.parser(event)
                        && let Ok(pid) = p.get::<u32>("ProcessId")
                    {
                        process_dc_end_cb.lock().unwrap().insert(pid);
                    }
                }
                _ => {}
            },
            g if g == thread::CLASS_GUID && event.opcode() == thread::opcode::DC_START => {
                thread_dc_start_cb.fetch_add(1, Relaxed);
            }
            g if g == image::CLASS_GUID && event.opcode() == image::opcode::DC_START => {
                image_dc_start_cb.fetch_add(1, Relaxed);
            }
            _ => {}
        }
        Ok(())
    });

    trace
        .start_processing_thread()
        .expect("start_processing_thread");

    // DC_START rundown is asynchronous: the kernel iterates every live
    // process/thread/image after enabling the session and dispatches one event
    // per object. On busy hosts (or right after another test exercised the
    // system logger) this can take well over 500ms to drain. Poll until the
    // PID set plateaus.
    let mut prev = 0;
    let mut stable_ticks = 0;
    let mut ticks_taken = 0;
    for _ in 0..80 {
        sleep(Duration::from_millis(100));
        ticks_taken += 1;
        let now = process_dc_start_pids.lock().unwrap().len();
        if now == prev && now > 0 {
            stable_ticks += 1;
            if stable_ticks >= 10 {
                break;
            }
        } else {
            stable_ticks = 0;
            prev = now;
        }
    }
    println!("DC_START drain settled after {ticks_taken}00ms");

    // Snapshot {PID -> PSK} right after DC_START has drained. Intersecting on
    // (PID, PSK) pairs gives processes definitively alive throughout the
    // startup window; the kernel MUST have included these in DC_START.
    let snapshot_post_drain =
        snapshot_live_psks().expect("NtQuerySystemInformation after DC_START drain");
    let dc_start_pids = process_dc_start_pids.lock().unwrap().clone();
    let threads = thread_dc_start.load(Relaxed);
    let images = image_dc_start.load(Relaxed);
    println!(
        "before-stop: process DC_START PIDs={} thread DC_START={threads} image DC_START={images}",
        dc_start_pids.len()
    );

    // Snapshot once more right before stop, then stop and let the DC_END
    // rundown drain. Processes alive in both snapshots straddling stop()
    // are guaranteed to appear in DC_END.
    let snapshot_pre_stop = snapshot_live_psks().expect("NtQuerySystemInformation before stop");
    trace.stop().expect("stop");
    sleep(Duration::from_secs(1));
    let snapshot_post_stop = snapshot_live_psks().expect("NtQuerySystemInformation after stop");

    let dc_end_pids = process_dc_end_pids.lock().unwrap().clone();
    println!("after-stop: process DC_END PIDs={}", dc_end_pids.len());

    // Overlap on (PID, PSK) pairs: a PID present in both snapshots whose PSK
    // matches identifies the *same* process at both times. If a process
    // exited and got the same PID reassigned, its PSK would differ and it
    // would be (correctly) excluded from the overlap.
    let overlap_psks_start: HashSet<u64> = snapshot_pre_start
        .iter()
        .filter(|(pid, psk)| snapshot_post_drain.get(pid) == Some(psk))
        .map(|(_, psk)| *psk)
        .collect();
    // For reporting, map missing PSK → PID (PID is the same in both snapshots
    // for any overlap PSK by definition).
    let missed_at_start: Vec<(u64, u32)> = overlap_psks_start
        .iter()
        .filter_map(|psk| {
            let pid = *snapshot_pre_start
                .iter()
                .find(|(_, p)| *p == psk)
                .map(|(pid, _)| pid)?;
            (!dc_start_pids.contains(&pid)).then_some((*psk, pid))
        })
        .collect();
    // Allow a small absolute tolerance: when the broader test suite churns the
    // kernel-logger state between back-to-back system_logger tests, DC_START
    // delivery can transiently miss a handful of PSKs that EnumProcesses still
    // sees in both snapshots. Catastrophic failure (DC_START not firing at
    // all, or massive miss rate) is still caught.
    let tolerance = (overlap_psks_start.len() / 20).max(5);
    assert!(
        missed_at_start.len() <= tolerance,
        "{} PSK(s) alive throughout the trace startup window were missing from \
         DC_START rundown (tolerance {tolerance}): {missed_at_start:?} \
         (overlap_start={}, dc_start={})",
        missed_at_start.len(),
        overlap_psks_start.len(),
        dc_start_pids.len(),
    );

    let overlap_psks_end: HashSet<u64> = snapshot_pre_stop
        .iter()
        .filter(|(pid, psk)| snapshot_post_stop.get(pid) == Some(psk))
        .map(|(_, psk)| *psk)
        .collect();
    let missed_at_end: Vec<(u64, u32)> = overlap_psks_end
        .iter()
        .filter_map(|psk| {
            let pid = *snapshot_pre_stop
                .iter()
                .find(|(_, p)| *p == psk)
                .map(|(pid, _)| pid)?;
            (!dc_end_pids.contains(&pid)).then_some((*psk, pid))
        })
        .collect();
    let tolerance_end = (overlap_psks_end.len() / 20).max(5);
    assert!(
        missed_at_end.len() <= tolerance_end,
        "{} PSK(s) alive throughout the trace stop window were missing from \
         DC_END rundown (tolerance {tolerance_end}): {missed_at_end:?} \
         (overlap_end={}, dc_end={})",
        missed_at_end.len(),
        overlap_psks_end.len(),
        dc_end_pids.len(),
    );

    // Loose floors: each process has at least one thread and one loaded image,
    // so these should be ≥ the rundown PID count. Kept as sanity checks rather
    // than ground-truth assertions because thread/image enumeration churns.
    assert!(
        threads >= dc_start_pids.len(),
        "THREAD_DC_START {threads} should be at least the process count {} \
         (each process has ≥1 thread)",
        dc_start_pids.len(),
    );
    assert!(
        images >= dc_start_pids.len(),
        "IMAGE_DC_START {images} should be at least the process count {} \
         (each process loads ≥1 image)",
        dc_start_pids.len(),
    );
}

// ─────────────────────────────────────────────────────────────────────────────

#[test]
#[ignore = "slow"]
#[serial(system_logger)]
fn test_system_logger_file_rundown_and_filename_parsing() {
    // Unique names scoped to this process so parallel test runs don't collide.
    let prefix = format!("etw_rs_rundown_{}_", std::process::id());
    let probe_names: Vec<String> = (0..PROBE_COUNT)
        .map(|i| format!("{prefix}{i}.tmp"))
        .collect();
    let probe_lc: Vec<String> = probe_names.iter().map(|n| n.to_lowercase()).collect();
    let probe_paths: Vec<_> = probe_names
        .iter()
        .map(|n| std::env::temp_dir().join(n))
        .collect();

    let mut trace = Trace::new("etw-rs_Test_FileRundown").expect("session creation");
    let _ = trace
        .set_buffer_size(64)
        .set_minimum_buffers(4)
        .set_maximum_buffers(64);
    // PERF_FILENAME keeps fileinfo.sys subscribed for the lifetime of this
    // session: EtwpUpdateFileInfoDriverState refcounts the union of
    // PERF_FILENAME | PERF_FILE_IO | PERF_FILE_IO_INIT across all live
    // system-logger sessions and unloads fileinfo.sys when the count hits
    // zero. send_file_rundown_code() only works while the driver is up, so
    // we keep this session running across the call.
    trace.set_events(&[PERF_FILENAME]);
    let Some(()) = common::skip_or_panic("trace.start", trace.start()) else {
        return;
    };

    let rt_count = Arc::new(AtomicUsize::new(0));
    let rundown_count = Arc::new(AtomicUsize::new(0));
    let rundown_names: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    let rt_count_cb = rt_count.clone();
    let rundown_count_cb = rundown_count.clone();
    let rundown_names_cb = rundown_names.clone();
    let probe_lc_cb = probe_lc.clone();

    trace.set_event_callback(move |event, ctx| {
        if event.provider_guid() != file_io::CLASS_GUID {
            return Ok(());
        }
        match event.opcode() {
            // FILE_CREATE (32): a file was opened/created during this session.
            // NAME (0): name mapping emitted at trace start for pre-existing files.
            file_io::opcode::FILE_CREATE | file_io::opcode::NAME => {
                if let Ok(mut p) = ctx.parser(event)
                    && let Ok(name) = p.get::<std::ffi::OsString>("FileName")
                {
                    let lc = name.to_string_lossy().to_lowercase();
                    if probe_lc_cb.iter().any(|probe| lc.ends_with(probe.as_str())) {
                        rt_count_cb.fetch_add(1, Relaxed);
                    }
                }
            }
            // FILE_RUNDOWN (36): emitted by the explicit send_file_rundown_code
            // trigger and automatically at stop.
            file_io::opcode::FILE_RUNDOWN => {
                rundown_count_cb.fetch_add(1, Relaxed);
                if let Ok(mut p) = ctx.parser(event)
                    && let Ok(name) = p.get::<std::ffi::OsString>("FileName")
                {
                    rundown_names_cb
                        .lock()
                        .unwrap()
                        .push(name.to_string_lossy().to_lowercase());
                }
            }
            _ => {}
        }
        Ok(())
    });

    trace
        .start_processing_thread()
        .expect("start_processing_thread");

    // Open probe files while PERF_FILENAME is active so fileinfo.sys tracks them.
    let probe_handles: Vec<File> = probe_paths
        .iter()
        .map(|p| File::create(p).expect("create probe file"))
        .collect();

    // Wait for real-time FILE_CREATE events for our probes.
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        sleep(Duration::from_millis(100));
        if rt_count.load(Relaxed) >= PROBE_COUNT {
            break;
        }
    }
    let rt = rt_count.load(Relaxed);
    println!("real-time FileName events for probes = {rt}");
    assert!(
        rt >= PROBE_COUNT,
        "{rt} real-time FileName events < PROBE_COUNT {PROBE_COUNT} — \
         PERF_FILENAME should emit FILE_CREATE for each probe file"
    );

    // Explicit trigger: fileinfo.sys walks its tracked-file table and emits
    // FILE_RUNDOWN for each entry.
    let before_trigger = rundown_count.load(Relaxed);
    trace
        .send_file_rundown_code()
        .expect("send_file_rundown_code");

    // Poll until the rundown count plateaus.
    let deadline = Instant::now() + Duration::from_secs(30);
    let idle_threshold = Duration::from_millis(1500);
    let mut last_seen = before_trigger;
    let mut last_change = Instant::now();
    while Instant::now() < deadline {
        sleep(Duration::from_millis(250));
        let now = rundown_count.load(Relaxed);
        if now != last_seen {
            last_seen = now;
            last_change = Instant::now();
        } else if last_change.elapsed() >= idle_threshold && last_seen > before_trigger {
            break;
        }
    }
    let after_trigger = rundown_count.load(Relaxed);
    let from_trigger = after_trigger.saturating_sub(before_trigger);
    println!("FILE_RUNDOWN events from explicit trigger = {from_trigger}");
    assert!(
        from_trigger >= PROBE_COUNT,
        "{from_trigger} FILE_RUNDOWN events from trigger < PROBE_COUNT {PROBE_COUNT}"
    );

    // Parser validation: every probe name must appear in a FILE_RUNDOWN
    // FileName field. FileIo_Name layout: [FileObject: Pointer][FileName: WideStr].
    let names = rundown_names.lock().unwrap();
    println!(
        "{} FileName values parsed from FILE_RUNDOWN events",
        names.len()
    );
    for probe in &probe_lc {
        assert!(
            names.iter().any(|n| n.ends_with(probe.as_str())),
            "probe {probe:?} not found in FILE_RUNDOWN FileName fields \
             ({} names parsed)",
            names.len()
        );
    }
    drop(names);

    // Hold probe handles open across stop so they're still in the table for
    // the automatic DC_END rundown.
    trace.stop().expect("stop");
    drop(probe_handles);
    for p in &probe_paths {
        let _ = fs::remove_file(p);
    }
}
