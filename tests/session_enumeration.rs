//! Tests for [`etw::query_sessions`].
//!
//! Enumeration needs no privilege, but returns a filtered view without it, so
//! the name checks below run only when elevated. Starting a system-logger
//! session does need privilege, which is what the first test exercises.

#![cfg(not(miri))] // Win32 API calls are not supported under Miri.
#![expect(
    clippy::print_stdout,
    clippy::expect_used,
    reason = "test-only assertions and diagnostics"
)]

#[path = "common/mod.rs"]
mod common;

use etw::{Trace, query_sessions, session::SYSTEM_LOGGER_MODE, system_logger::masks::PERF_PROCESS};
use serial_test::serial;

/// System-logger slots an ordinary caller can occupy.
///
/// Windows caps concurrent system loggers at 8 and keeps 2 for the loggers in
/// [`RESERVED_SYSTEM_LOGGERS`], so everyone else shares 6. Counting against 8
/// is what misleads: it reads as "2 still free" at the exact moment a start has
/// just failed for want of a slot.
///
/// Measured on Windows 11: with 6 ordinary system loggers running, a seventh
/// failed with `ERROR_NO_SYSTEM_RESOURCES`.
const USABLE_SYSTEM_LOGGER_SLOTS: usize = 6;

/// The two loggers with a slot of their own — `KERNEL_LOGGER_NAMEW` and
/// `GLOBAL_LOGGER_NAMEW` in `evntrace.h`.
///
/// The reservation is real and is not drawn from the 6: at the ceiling above,
/// where an ordinary start failed, `NT Kernel Logger` started in the same
/// instant and took the total to 7.
///
/// It has to be excluded by name because nothing else distinguishes it. A
/// running `NT Kernel Logger` enumerates like any other session and sets the
/// system-logger bit — `LogFileMode 0x02400180` — so a census that counts every
/// system logger against 6 can report 7 of 6.
const RESERVED_SYSTEM_LOGGERS: [&str; 2] = ["NT Kernel Logger", "GlobalLogger"];

/// Print who holds the system-logger slots. Called when a start fails, which is
/// the moment the information is worth having.
fn report_system_loggers() {
    match query_sessions() {
        Ok(sessions) => {
            let system: Vec<&str> = sessions
                .iter()
                .filter(|s| s.properties.LogFileMode & SYSTEM_LOGGER_MODE != 0)
                .map(|s| s.name.as_str())
                .collect();
            let (reserved, ordinary): (Vec<&str>, Vec<&str>) = system
                .iter()
                .partition(|n| RESERVED_SYSTEM_LOGGERS.contains(n));
            println!(
                "{} of {USABLE_SYSTEM_LOGGER_SLOTS} usable system-logger slots in use \
                 ({} reserved logger(s) also running, {} sessions total)",
                ordinary.len(),
                reserved.len(),
                sessions.len()
            );
            for name in &ordinary {
                println!("  system-logger: {name}");
            }
            for name in &reserved {
                println!("  system-logger: {name}  [reserved slot]");
            }
        }
        Err(e) => println!("could not enumerate sessions: {e}"),
    }
}

/// A session this process started must show up in the enumeration — the
/// strongest available proof that the two views agree.
///
/// The slot census on the failure path is the test's own diagnostic, not
/// something [`Trace::start`] provides: it returns the raw Win32 code, because
/// `ERROR_NO_SYSTEM_RESOURCES` covers both the system-logger slots and the
/// system-wide session cap and cannot say which was hit. Printing the census
/// here is what makes a failure legible without the error claiming a cause.
#[test]
#[serial(system_logger)]
fn a_running_system_logger_session_is_enumerated() {
    let name = format!("etw-rs_Test_EnumSlots_{}", std::process::id());
    let mut trace = Trace::new(&name).expect("failed to create trace");
    trace.set_events(&[PERF_PROCESS]);

    if let Err(e) = trace.start() {
        // Context, not necessarily cause — an unprivileged run fails here with
        // ERROR_ACCESS_DENIED while slots are free. Print the error first so the
        // slot census cannot be misread as the explanation.
        println!("system-logger start failed: {e}");
        println!("slot census at the time of failure:");
        report_system_loggers();
        panic!("system-logger start failed: {e}");
    }

    // The session we just started must appear in the enumeration, which is the
    // strongest available proof that the two views agree.
    let sessions = query_sessions().expect("enumeration failed while a session was running");
    let ours = sessions.iter().find(|s| s.name == name);
    let found = ours.is_some();
    let flagged_system = ours.is_some_and(|s| s.properties.LogFileMode & SYSTEM_LOGGER_MODE != 0);

    trace.stop().expect("failed to stop trace");

    assert!(
        found,
        "our own running session '{name}' was missing from query_sessions()"
    );
    assert!(
        flagged_system,
        "our own session '{name}' was not reported as a system logger"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tripwires for the query buffer sizing
// ═══════════════════════════════════════════════════════════════════════════════
//
// `enumerate.rs` sizes its name fields to ETW's own storage caps rather than to
// anything the documentation states, because a name that overruns the buffer is
// not reported short — ETW leaves the field untouched and still reports success,
// so the session comes back nameless or, worse, apparently file-less.
//
// Nothing in the reply can be used to detect that after the fact. `LogFileMode`
// carries no bit that marks a session as file-backed: sequential mode is the
// zero value, and a session may be real-time *and* write a file
// (`LogFileMode == 0x00400101` was observed doing exactly that), so neither a
// file-mode bit nor the absence of `REAL_TIME` separates the two cases. A
// sentinel pre-fill cannot either, because ETW writes nothing at all — not even
// a terminator — for a session that genuinely has no log file.
//
// So the caps are measured, and these tests exist to fail the moment a Windows
// release moves them. Each asks ETW to store one character *past* the cap and
// requires the stored value back at exactly the cap: if the cap rises, the value
// comes back longer, or vanishes because it no longer fits, and either way this
// fails loudly instead of production going quiet.

/// Longest logger name ETW will store; `LOGGER_NAME_UNITS` is this plus a
/// terminator.
const ETW_LOGGER_NAME_CAP: usize = 1024;

/// Longest log file path ETW will store; `LOG_FILE_NAME_UNITS` is this plus a
/// terminator.
const ETW_LOG_FILE_CAP: usize = 1040;

/// Uses raw `StartTraceW` because [`Trace::new`] caps session names at 63
/// characters. That asymmetry is the point: this crate cannot create such a
/// session, but a driver or another tool can, and enumeration has to survive
/// meeting one.
#[test]
#[serial(long_name)]
fn etw_still_caps_logger_names_where_the_buffer_expects() {
    let stem = format!("etw-rs_LongName_{}_", std::process::id());
    let over = ETW_LOGGER_NAME_CAP + 1;
    let name = format!("{stem}{}", "n".repeat(over - stem.len()));
    assert_eq!(name.chars().count(), over);

    let Some(_session) = raw_trace::start(&name, "", raw_trace::REAL_TIME_MODE) else {
        println!("skipping: could not start a session named past ETW's cap (needs elevation)");
        return;
    };

    let found = query_sessions()
        .expect("enumeration failed while a long-named session was running")
        .into_iter()
        .find(|s| s.name.starts_with(&stem));

    let found = found.unwrap_or_else(|| {
        panic!(
            "a session named {over} characters long was missing from query_sessions(): ETW \
             stored more than {ETW_LOGGER_NAME_CAP} characters, the name no longer fits the \
             query buffer, and the session came back nameless. Raise LOGGER_NAME_UNITS."
        )
    });
    assert_eq!(
        found.name.chars().count(),
        ETW_LOGGER_NAME_CAP,
        "ETW stored a {}-character logger name; the buffer is sized for {ETW_LOGGER_NAME_CAP}. \
         Re-measure and raise LOGGER_NAME_UNITS.",
        found.name.chars().count()
    );
}

/// The log file field is the one with no fallback: an undersized buffer reports
/// a file-backed session as real-time only, and nothing in the reply says so.
#[test]
#[serial(long_name)]
fn etw_still_caps_log_file_paths_where_the_buffer_expects() {
    let over = ETW_LOG_FILE_CAP + 1;
    // A `\\?\` path, so ETW is not held to MAX_PATH when it opens the file.
    let Some((path, root)) = long_path::build(over) else {
        println!("skipping: could not build a {over}-character directory tree");
        return;
    };
    let name = format!("etw-rs_LongPath_{}", std::process::id());

    let started = raw_trace::start(&name, &path, raw_trace::FILE_MODE_SEQUENTIAL);
    let found = started.as_ref().map(|_| {
        query_sessions()
            .expect("enumeration failed while a long-path session was running")
            .into_iter()
            .find(|s| s.name == name)
    });
    // Stop before deleting the tree: ETW holds the log file open while the
    // session runs.
    drop(started);
    long_path::remove(&root);

    let Some(found) = found else {
        println!("skipping: could not start a session logging to a {over}-character path");
        return;
    };
    let found = found.expect("our long-path session was missing from query_sessions()");

    let log_file = found.log_file.unwrap_or_else(|| {
        panic!(
            "a session logging to a {over}-character path came back with no log file at all: \
             ETW stored more than {ETW_LOG_FILE_CAP} characters, the path no longer fits the \
             query buffer, and a file-backed session was reported as real-time only. Raise \
             LOG_FILE_NAME_UNITS."
        )
    });
    assert_eq!(
        log_file.chars().count(),
        ETW_LOG_FILE_CAP,
        "ETW stored a {}-character log file path; the buffer is sized for {ETW_LOG_FILE_CAP}. \
         Re-measure and raise LOG_FILE_NAME_UNITS.",
        log_file.chars().count()
    );
}

/// Builds a directory tree deep enough to hold a path of a requested length,
/// which is the only way to make ETW store one — it validates the path even for
/// a session that never writes.
mod long_path {
    /// Returns the `\\?\`-prefixed `.etl` path of exactly `target` characters,
    /// and the root to delete afterwards.
    pub(super) fn build(target: usize) -> Option<(String, String)> {
        let root = format!("C:\\etw-rs-test-{}", std::process::id());
        // Every failure below leaves directories already created. Clean them up
        // here rather than at each `?`: the tree is 200-character segments at the
        // drive root, which is awkward to remove by hand once it is orphaned.
        let Some(path) = build_tree(&root, target) else {
            remove(&root);
            return None;
        };
        Some((path, root))
    }

    fn build_tree(root: &str, target: usize) -> Option<String> {
        let mut dir = root.to_owned();
        std::fs::create_dir_all(format!("\\\\?\\{dir}")).ok()?;
        // "\\?\" adds 4, "\p.etl" adds 6.
        let plain_target = target.checked_sub(4)?;
        while dir.len() + 6 + 201 <= plain_target {
            dir.push('\\');
            dir.push_str(&"z".repeat(200));
            std::fs::create_dir_all(format!("\\\\?\\{dir}")).ok()?;
        }
        let remaining = plain_target.checked_sub(dir.len() + 6)?;
        if remaining > 0 {
            dir.push('\\');
            dir.push_str(&"z".repeat(remaining - 1));
            std::fs::create_dir_all(format!("\\\\?\\{dir}")).ok()?;
        }
        let path = format!("\\\\?\\{dir}\\p.etl");
        (path.chars().count() == target).then_some(path)
    }

    pub(super) fn remove(root: &str) {
        let _ = std::fs::remove_dir_all(format!("\\\\?\\{root}"));
    }
}

/// Minimal `StartTraceW`/`ControlTraceW` wrapper, only for the tripwires above.
/// [`Trace`] deliberately will not build names this long, and offers no log file
/// path at all, so neither test can go through it.
mod raw_trace {
    use std::mem::{offset_of, size_of, zeroed};
    use windows::{
        Win32::System::Diagnostics::Etw::{
            CONTROLTRACE_HANDLE, ControlTraceW, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_PROPERTIES,
            StartTraceW, WNODE_FLAG_TRACED_GUID,
        },
        core::PCWSTR,
    };

    pub(super) const REAL_TIME_MODE: u32 = 0x0000_0100;
    pub(super) const FILE_MODE_SEQUENTIAL: u32 = 0x0000_0001;

    /// Room for names longer than ETW will store, so the probe never becomes the
    /// thing that truncates.
    const NAME_UNITS: usize = 4096;

    /// `EVENT_TRACE_PROPERTIES` with the trailing name space ETW writes into.
    #[repr(C)]
    struct Buffer {
        properties: EVENT_TRACE_PROPERTIES,
        log_file_name: [u16; NAME_UNITS],
        logger_name: [u16; NAME_UNITS],
    }

    fn new_buffer() -> Box<Buffer> {
        // SAFETY: EVENT_TRACE_PROPERTIES and the two arrays are plain data with no
        // niches, so all-zero is a valid value.
        let mut buffer: Box<Buffer> = Box::new(unsafe { zeroed() });
        buffer.properties.Wnode.BufferSize = size_of::<Buffer>() as u32;
        buffer.properties.LogFileNameOffset = offset_of!(Buffer, log_file_name) as u32;
        buffer.properties.LoggerNameOffset = offset_of!(Buffer, logger_name) as u32;
        buffer
    }

    /// A started session, stopped on drop.
    ///
    /// The guard is what makes the assertions in these tests safe to write: each
    /// one runs while the probe session is live, and a failing one unwinds. Left
    /// to an explicit `stop` call the panic would skip it, leaking a real ETW
    /// session until reboot — in a crate whose subject is running out of session
    /// slots, a test that loses one per failure is the wrong kind of test.
    pub(super) struct Session(CONTROLTRACE_HANDLE);

    impl Drop for Session {
        fn drop(&mut self) {
            let mut buffer = new_buffer();
            // SAFETY: same buffer contract as `start`; a null name means "use the
            // handle".
            unsafe {
                let _ = ControlTraceW(
                    self.0,
                    PCWSTR::null(),
                    std::ptr::from_mut(&mut buffer.properties),
                    EVENT_TRACE_CONTROL_STOP,
                );
            }
        }
    }

    /// A session with no providers, logging to `log_file` when one is given, or
    /// `None` if ETW refused (an unelevated run cannot start one).
    pub(super) fn start(name: &str, log_file: &str, mode: u32) -> Option<Session> {
        let mut buffer = new_buffer();
        buffer.properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        buffer.properties.Wnode.ClientContext = 1; // QPC
        buffer.properties.LogFileMode = mode;
        buffer.properties.BufferSize = 4;
        if !log_file.is_empty() {
            let path: Vec<u16> = log_file.encode_utf16().chain(std::iter::once(0)).collect();
            assert!(
                path.len() <= NAME_UNITS,
                "probe path longer than its buffer"
            );
            buffer.log_file_name[..path.len()].copy_from_slice(&path);
        }

        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let mut handle = CONTROLTRACE_HANDLE::default();

        // SAFETY: `handle` and the properties buffer are live for the call, and the
        // buffer carries the size and both name offsets StartTraceW requires, so ETW
        // writes only inside it. `wide` is null-terminated and outlives the call.
        let status = unsafe {
            StartTraceW(
                std::ptr::from_mut(&mut handle),
                PCWSTR(wide.as_ptr()),
                std::ptr::from_mut(&mut buffer.properties),
            )
        };
        status.is_ok().then_some(Session(handle))
    }
}

#[test]
fn enumerates_well_known_sessions() {
    let sessions = query_sessions().expect("enumeration failed");

    for session in &sessions {
        println!(
            "{}{}",
            session.name,
            if session.properties.LogFileMode & SYSTEM_LOGGER_MODE != 0 {
                "  [system logger]"
            } else {
                ""
            }
        );
    }

    assert!(
        !sessions.is_empty(),
        "Windows always runs ETW sessions of its own; an empty list means the query failed silently"
    );

    // Only when elevated. QueryAllTracesW returns a privilege-filtered view, and
    // the filtering is not intuitive: measured on one machine, an unelevated
    // caller saw 34 sessions against 46 elevated, with `EventLog-Application`
    // hidden while `Eventlog-Security` stayed visible. Asserting these names
    // unconditionally would fail an unelevated run for reasons that say nothing
    // about the enumeration itself.
    //
    // Casing is not consistent across the family either — hence exact names
    // rather than an `EventLog-` prefix, which would miss `Eventlog-Security`.
    if etw::is_elevated() {
        for expected in ["EventLog-Application", "EventLog-System"] {
            assert!(
                sessions.iter().any(|s| s.name == expected),
                "{expected} missing from {} enumerated sessions",
                sessions.len()
            );
        }
    } else {
        println!("unelevated: skipping well-known name checks, the view is filtered");
    }

    // Reported, not asserted. These are usual but not universal — a minimal or
    // virtualised image (a CI runner, say) may not run them, and a test that
    // fails there would be measuring the image rather than the enumeration.
    for optional in ["Circular Kernel Context Logger", "Eventlog-Security"] {
        let present = sessions.iter().any(|s| s.name == optional);
        println!(
            "well-known session '{optional}': {}",
            if present { "present" } else { "absent" }
        );
    }

    let ordinary = sessions
        .iter()
        .filter(|s| s.properties.LogFileMode & SYSTEM_LOGGER_MODE != 0)
        .filter(|s| !RESERVED_SYSTEM_LOGGERS.contains(&s.name.as_str()))
        .count();
    println!(
        "{ordinary} of {USABLE_SYSTEM_LOGGER_SLOTS} usable system-logger slots in use, \
         {} sessions total",
        sessions.len()
    );

    // Names must be readable, not truncated or full of replacement characters.
    for session in &sessions {
        assert!(
            !session.name.is_empty(),
            "enumerated a session with an empty name, so a name buffer was not read back"
        );
        assert!(
            !session.name.contains('\u{FFFD}'),
            "session name '{}' decoded to replacement characters",
            session.name
        );
    }
}
