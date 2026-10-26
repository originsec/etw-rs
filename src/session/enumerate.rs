//! Enumeration of the ETW sessions currently running on the machine.
//!
//! ETW imposes two separate ceilings, and hitting either surfaces as
//! `ERROR_NO_SYSTEM_RESOURCES` with no indication of which one or of who is
//! responsible: a system-wide cap on sessions, and a much tighter cap of 8
//! concurrent system-logger sessions with 2 reserved for the OS. Being able to
//! ask *which sessions exist* is what turns that error from a rule into a
//! diagnosis.

use crate::{Error, Result};
use std::mem::{offset_of, size_of, zeroed};
use windows_sys::Win32::{
    Foundation::{ERROR_MORE_DATA, ERROR_SUCCESS},
    System::Diagnostics::Etw::{EVENT_TRACE_PROPERTIES, QueryAllTracesW},
};

/// Sessions to size the query buffer for on the first attempt.
///
/// Windows has historically capped concurrent sessions at 64. The value is only
/// a starting guess: a short count is retried at the size the OS asks for, so a
/// raised cap costs one extra call rather than truncated results.
const INITIAL_CAPACITY: usize = 64;

/// Upper bound on the retry, so a hostile or buggy `LoggerCount` cannot make us
/// allocate without limit.
const MAX_CAPACITY: usize = 1024;

/// Longest logger name ETW will store, in UTF-16 code units, plus a terminator.
///
/// # Why this has to be exact
///
/// A name that does not fit is not clipped: `QueryAllTracesW` leaves the field
/// **untouched** and still returns `ERROR_SUCCESS`. Because the buffer starts
/// zeroed, an untouched field reads back as an empty string, so an undersized
/// buffer does not produce a short name a caller might notice — it produces
/// silence. For the log file field that silence is worse than partial: a
/// file-backed session is reported as real-time only, which is simply wrong.
///
/// The API offers no signal to detect this. It does not set `ERROR_MORE_DATA`,
/// and it echoes back the `Wnode.BufferSize` and offsets it was given, so
/// nothing in the reply distinguishes "no name" from "no room". `LogFileMode`
/// cannot stand in either — see [`LOG_FILE_NAME_UNITS`]. Sizing correctly is the
/// only defence, which is why these are measured rather than guessed.
///
/// # Measurement
///
/// Taken by driving `StartTraceW` and `QueryAllTracesW` directly — not `logman`,
/// which reports success for lengths ETW then silently stores differently, and
/// which refuses long paths its own `MAX_PATH` handling rejects before ETW ever
/// sees them. Passing the path with a `\\?\` prefix, on Windows 11:
///
/// | field         | passed | stored |
/// |---------------|--------|--------|
/// | logger name   | 1024   | 1024   |
/// | logger name   | 1040   | 1024   |
/// | log file name | 1040   | 1040   |
/// | log file name | 1041   | 1040   |
///
/// So ETW caps the two at 1024 and 1040 characters and truncates beyond that.
/// `MAX_PATH` — the sizing the ETW samples use — is nowhere near either, and
/// neither is a single round 1024 for both.
const LOGGER_NAME_UNITS: usize = 1025;

/// Longest log file path ETW will store, plus a terminator. See
/// [`LOGGER_NAME_UNITS`] for how both were measured and why they must be exact.
///
/// Note this is *not* the filesystem's limit. ETW will accept and store a path
/// well past `MAX_PATH` when given one with a `\\?\` prefix, so a caller cannot
/// assume `MAX_PATH` bounds it; but ETW does truncate its own stored copy at
/// 1040 characters, which is what makes a fixed size sufficient here.
///
/// Three ways to detect a dropped path instead of sizing for it were tried, and
/// none of them work:
///
/// - **A file-mode bit.** Across 43 live sessions the only bit set in every file-backed one was
///   `PERSIST_ON_HYBRID_SHUTDOWN`, which sessions with no log file set too. Sequential mode is the
///   zero value, so a file-backed session need set no file-mode bit at all.
/// - **The absence of `REAL_TIME_MODE`.** The live sample suggests it, but only because it happens
///   to contain no counterexample. One is easy to construct: a session started with `REAL_TIME_MODE
///   | FILE_MODE_SEQUENTIAL` reports `LogFileMode == 0x00400101` *and* a log file, so the rule
///   fails in the direction that loses data — it predicts "no path" for a session that has one.
/// - **A sentinel pre-fill.** It does distinguish "ETW wrote nothing" from "ETW wrote an empty
///   string", which is what makes the logger-name check in [`session_properties`] possible. It
///   cannot help here, because ETW writes nothing at all — not even a terminator — for a session
///   that genuinely has no log file, so "untouched" covers both cases.
///
/// Sizing is therefore the only defence, and the tripwires in
/// `tests/session_enumeration.rs` exist to fail loudly if the cap ever moves.
const LOG_FILE_NAME_UNITS: usize = 1041;

/// One `EVENT_TRACE_PROPERTIES` plus the trailing string space the API writes
/// into. `QueryAllTracesW` requires the name buffers to live immediately after
/// the header, addressed by the two offsets, so the layout must be `repr(C)`.
#[repr(C)]
struct QueryBuffer {
    properties: EVENT_TRACE_PROPERTIES,
    logger_name: [u16; LOGGER_NAME_UNITS],
    log_file_name: [u16; LOG_FILE_NAME_UNITS],
}

impl QueryBuffer {
    /// Bytes the API may write into one buffer. A few kilobytes, so the casts
    /// here are exact and resolved at compile time.
    const SIZE: u32 = size_of::<Self>() as u32;
    const LOGGER_NAME_OFFSET: u32 = offset_of!(Self, logger_name) as u32;
    const LOG_FILE_NAME_OFFSET: u32 = offset_of!(Self, log_file_name) as u32;

    /// A zeroed buffer with the size and offsets the API requires.
    const fn new() -> Self {
        // SAFETY: EVENT_TRACE_PROPERTIES and the two arrays are all plain data with
        // no niches or invalid bit patterns, so all-zero is a valid value.
        let mut buffer: Self = unsafe { zeroed() };
        buffer.properties.Wnode.BufferSize = Self::SIZE;
        buffer.properties.LoggerNameOffset = Self::LOGGER_NAME_OFFSET;
        buffer.properties.LogFileNameOffset = Self::LOG_FILE_NAME_OFFSET;
        buffer
    }
}

/// One ETW session that was running when [`query_sessions`] was called.
///
/// Decodes the two names — the one thing that cannot be read straight off the
/// raw struct — and hands back everything else in
/// [`properties`](Self::properties), the same escape hatch
/// [`Trace::properties`] offers for a session you own. It is an owned copy
/// taken at query time, so mutating it changes nothing about the running
/// session. Unlike [`Trace::properties`], which borrows a live buffer with room
/// for the names after it, this copy is the bare struct — see the field docs for
/// the three size and offset members that say so.
///
/// The buffer and event counters [`TraceStatistics`] models for a session you
/// own are in there too, as `NumberOfBuffers`, `FreeBuffers`, `BuffersWritten`,
/// `EventsLost` and `RealTimeBuffersLost`.
///
/// [`Trace::properties`]: crate::Trace::properties
/// [`TraceStatistics`]: crate::TraceStatistics
#[derive(Clone)]
pub struct SessionProperties {
    /// Session (logger) name, as `logman query -ets` would show it.
    pub name: String,
    /// File the session writes to, or `None` for a real-time-only session.
    pub log_file: Option<String>,
    /// The properties as `QueryAllTracesW` filled them in, re-described to match
    /// this struct.
    ///
    /// Only the two names are decoded above, because UTF-16 in a fixed array is
    /// the one thing a caller cannot read straight off the struct. Everything
    /// else — `LogFileMode`, `EnableFlags`, the buffer configuration, the
    /// session GUID, `LoggerThreadId`, `LogBuffersLost` — is here rather than
    /// mirrored into fields that could drift from it.
    ///
    /// The three exceptions are `Wnode.BufferSize`, `LoggerNameOffset` and
    /// `LogFileNameOffset`. As returned they described the trailing name space
    /// of a query buffer that did not outlive the call, so leaving them would
    /// have this copy claim kilobytes of storage it does not have — and ETW
    /// writes both names back through them, so handing the copy to
    /// `ControlTraceW` would overrun it. They are rewritten to describe this
    /// struct instead: `BufferSize` is its real size and both offsets are zero.
    /// Read [`name`](Self::name) and [`log_file`](Self::log_file) for the names.
    ///
    /// That rewrite makes the copy safe to hand to a Win32 trace API, not useful
    /// to. ETW insists on somewhere to write the two names back, so a bare
    /// struct with no trailing space is rejected: passing this copy to
    /// `ControlTraceW` was measured returning `ERROR_MORE_DATA` (234) without
    /// touching the session. To control a session found here, build a buffer
    /// with name space after it — as [`Trace`] does — and address it by
    /// [`name`](Self::name).
    ///
    /// [`Trace`]: crate::Trace
    ///
    /// ```no_run
    /// use etw::session::SYSTEM_LOGGER_MODE;
    ///
    /// for session in etw::query_sessions()? {
    ///     if session.properties.LogFileMode & SYSTEM_LOGGER_MODE != 0 {
    ///         println!("{} holds a system-logger slot", session.name);
    ///     }
    /// }
    /// # Ok::<(), etw::Error>(())
    /// ```
    pub properties: EVENT_TRACE_PROPERTIES,
}

impl std::fmt::Debug for SessionProperties {
    /// Hand-written because `EVENT_TRACE_PROPERTIES` contains a union and so
    /// implements no `Debug` of its own.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionProperties")
            .field("name", &self.name)
            .field("log_file", &self.log_file)
            .field(
                "log_file_mode",
                &format_args!("{:#x}", self.properties.LogFileMode),
            )
            .field(
                "enable_flags",
                &format_args!("{:#x}", self.properties.EnableFlags),
            )
            .field("buffer_size_kb", &self.properties.BufferSize)
            .field("events_lost", &self.properties.EventsLost)
            .finish_non_exhaustive()
    }
}

/// Every ETW session currently running on the machine.
///
/// Requires no privilege to call, but returns a privilege-filtered view, and the
/// filtering is not intuitive: measured on one machine, an unelevated caller saw
/// 34 sessions against 46 elevated, with `EventLog-Application` hidden while
/// `Eventlog-Security` remained visible. A short list is therefore not evidence
/// that the machine is idle, and an absent name is not evidence the session is
/// not running.
///
/// # Errors
///
/// Returns the underlying Win32 error if `QueryAllTracesW` fails for any reason
/// other than a buffer too small to hold every session, which is retried.
///
/// Returns [`Error::LimitExceeded`] instead where the limit is this module's
/// rather than Windows': more sessions running than the query will allocate
/// buffers for, or a session whose name did not fit the name buffer. Neither is
/// a Win32 failure, so neither is reported as one, and the error names the
/// operation and the limit it reached.
///
/// Either way the result is all of the sessions or none of them. A short list is
/// never returned in place of a failure, so the count can be trusted even though
/// the contents are privilege-filtered.
///
/// # Example
///
/// ```no_run
/// use etw::session::SYSTEM_LOGGER_MODE;
///
/// let busy = etw::query_sessions()?
///     .into_iter()
///     .filter(|s| s.properties.LogFileMode & SYSTEM_LOGGER_MODE != 0)
///     .count();
/// println!("{busy} of the 8 system-logger slots are in use");
/// # Ok::<(), etw::Error>(())
/// ```
pub fn query_sessions() -> Result<Vec<SessionProperties>> {
    query_sessions_from(INITIAL_CAPACITY)
}

/// [`query_sessions`] with the first-attempt buffer count as a parameter, so a
/// test can start below the real session count and drive the retry. Nothing on a
/// normal machine reaches it from `INITIAL_CAPACITY`.
fn query_sessions_from(initial_capacity: usize) -> Result<Vec<SessionProperties>> {
    query_sessions_bounded(initial_capacity, MAX_CAPACITY)
}

/// [`query_sessions_from`] with the growth ceiling as a parameter too, so a test
/// can reach the ceiling without needing [`MAX_CAPACITY`] sessions to be running.
/// Production always passes `MAX_CAPACITY`.
fn query_sessions_bounded(
    initial_capacity: usize,
    max_capacity: usize,
) -> Result<Vec<SessionProperties>> {
    let mut capacity = initial_capacity;

    loop {
        let mut buffers: Vec<QueryBuffer> = (0..capacity).map(|_| QueryBuffer::new()).collect();
        let mut pointers: Vec<*mut EVENT_TRACE_PROPERTIES> = buffers
            .iter_mut()
            .map(|buffer| std::ptr::from_mut(buffer).cast::<EVENT_TRACE_PROPERTIES>())
            .collect();
        let mut count: u32 = 0;

        // SAFETY: `pointers` holds one pointer per live element of `buffers`, which
        // outlives this call and is not aliased elsewhere. Each target carries the
        // BufferSize and the two name offsets that QueryAllTracesW requires, so the
        // API writes only within the buffer it was handed.
        //
        // Each pointer is derived from the whole `QueryBuffer`, not from its
        // `properties` field, so its provenance spans the trailing name arrays the
        // API writes into at those offsets. `QueryBuffer` is `repr(C)` with
        // `properties` first, so the address is the same either way — but a pointer
        // borrowed from the field alone would not be allowed to reach past it.
        let status = unsafe {
            QueryAllTracesW(
                pointers.as_mut_ptr(),
                pointers.len() as u32,
                std::ptr::from_mut(&mut count),
            )
        };

        let returned = count as usize;

        // A short buffer reports how many sessions there actually are. Retry at that
        // size rather than growing indefinitely. A count past MAX_CAPACITY is our own
        // guard tripping, not ETW failing, so it is reported as the guard it is —
        // returning the raw ERROR_MORE_DATA here would blame Windows for a limit this
        // module chose.
        if status == ERROR_MORE_DATA && returned > capacity {
            if returned > max_capacity {
                return Err(Error::LimitExceeded {
                    operation: "QueryAllTracesW session enumeration",
                    limit: u32::try_from(max_capacity).unwrap_or(u32::MAX),
                });
            }
            capacity = returned;
            continue;
        }

        if status != ERROR_SUCCESS {
            return Err(Error::from_win32(status));
        }

        // Collecting into `Result` fails the whole query on the first unreadable
        // session rather than dropping it from an otherwise plausible list.
        return buffers
            .iter()
            .take(returned.min(capacity))
            .map(session_properties)
            .collect();
    }
}

/// Decode a null-terminated UTF-16 field, or `None` when the API left it empty.
fn read_name(units: &[u16]) -> Option<String> {
    let end = units
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(units.len());
    (end > 0).then(|| String::from_utf16_lossy(&units[..end]))
}

/// Read one filled-in query buffer into owned [`SessionProperties`].
///
/// # Errors
///
/// Returns [`Error::LimitExceeded`] if the logger name came back empty. Every
/// session has a name, so an empty field means ETW had nowhere to put it: a name
/// too long for the buffer is left untouched rather than clipped, which a zeroed
/// buffer reads back as empty, and the status code says nothing. Failing the
/// whole query is the only honest response — a nameless entry returned alongside
/// the rest would be partial data wearing the shape of complete data.
///
/// `LimitExceeded` rather than a Win32 code because that is what happened:
/// [`LOGGER_NAME_UNITS`] was too small. `QueryAllTracesW` reported success, so
/// naming a Win32 error here would invent a failure Windows never reported and
/// send the reader looking at the API instead of at the constant to raise.
///
/// This doubles as the tripwire for [`LOGGER_NAME_UNITS`] going stale: if a
/// future Windows raises the cap past the buffer, the query fails loudly instead
/// of quietly listing unnamed sessions.
fn session_properties(buffer: &QueryBuffer) -> Result<SessionProperties> {
    let Some(name) = read_name(&buffer.logger_name) else {
        return Err(Error::LimitExceeded {
            operation: "QueryAllTracesW logger name",
            limit: u32::try_from(LOGGER_NAME_UNITS).unwrap_or(u32::MAX),
        });
    };

    let mut properties = buffer.properties;

    // These three describe the QueryBuffer, not the struct being copied out of
    // it: the API reports back the size it was given and the offsets it wrote the
    // names at, both of which reach past a bare EVENT_TRACE_PROPERTIES. Carried
    // over unchanged they would have the copy claim kilobytes of trailing name
    // space it does not own, and ETW writes the names back through those offsets,
    // so a Win32 trace API handed the copy would overrun it. Re-describe the copy
    // as what it is. That buys safety, not usability — see the field docs.
    properties.Wnode.BufferSize = size_of::<EVENT_TRACE_PROPERTIES>() as u32;
    properties.LoggerNameOffset = 0;
    properties.LogFileNameOffset = 0;

    Ok(SessionProperties {
        name,
        log_file: read_name(&buffer.log_file_name),
        properties,
    })
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test module: panics are the failure mode"
)]
mod tests {
    use super::*;

    /// Whether too few sessions are visible for the growth tests to mean anything,
    /// in which case the caller skips.
    ///
    /// Both need more than one session in view, and a non-admin token's view is
    /// filtered: measured at 2 of 61 on one host, and 1 when Visual Studio's
    /// session was not running. With one visible, a one-buffer query simply fits.
    /// `CI` runs elevated, where the view is never that small, so there a short
    /// view panics instead — the rule `tests/common::skip_or_panic` applies.
    #[expect(
        clippy::print_stdout,
        reason = "the skip line is the only report that the test's coverage was lost"
    )]
    fn too_few_sessions_visible(test: &str) -> bool {
        let visible = query_sessions().expect("enumeration failed").len();
        if visible > 1 {
            return false;
        }
        assert!(
            std::env::var_os("CI").is_none_or(|v| v.is_empty()),
            "{test}: only {visible} ETW session(s) visible; CI runs elevated, so this is a defect"
        );
        println!("Skipping {test}: only {visible} ETW session(s) visible; needs Administrator.");
        true
    }

    /// The retry is the one branch `INITIAL_CAPACITY` is chosen to avoid: at 64
    /// buffers it takes more concurrent sessions than a normal machine runs to
    /// reach, so it would never execute under test. Starting at a single buffer
    /// forces `ERROR_MORE_DATA` and pins the contract that matters — the short
    /// count is a retry instruction, not a result, so the second attempt returns
    /// the sessions rather than the one that fit.
    ///
    /// Asserted against the first attempt's capacity rather than a second call's
    /// length, because sessions start and stop between two queries.
    #[test]
    #[cfg_attr(miri, ignore = "calls QueryAllTracesW (Win32)")]
    fn short_first_attempt_retries_instead_of_truncating() {
        let sessions = query_sessions_from(1).expect("enumeration failed");
        if sessions.len() <= 1
            && too_few_sessions_visible("short_first_attempt_retries_instead_of_truncating")
        {
            return;
        }

        assert!(
            sessions.len() > 1,
            "a 1-buffer first attempt returned {} session(s): the ERROR_MORE_DATA \
             retry did not re-query at the size the OS asked for",
            sessions.len()
        );
        assert!(
            sessions.iter().all(|session| !session.name.is_empty()),
            "the retry returned a session with no name, so a buffer from the \
             grown array was read back unfilled"
        );
    }

    /// More sessions running than the query will allocate for is this module's
    /// own ceiling, not an ETW failure, and must be reported as one. Returning
    /// the raw `ERROR_MORE_DATA` would blame Windows for a limit chosen here, and
    /// `PartialEq<WIN32_ERROR>` would leave a caller unable to tell the two
    /// apart.
    ///
    /// Driven with a ceiling of 1 rather than [`MAX_CAPACITY`], because reaching
    /// the real one needs 1024 concurrent sessions. The branch under test is the
    /// same either way: a reported count past the ceiling.
    #[test]
    #[cfg_attr(miri, ignore = "calls QueryAllTracesW (Win32)")]
    fn a_count_past_the_ceiling_is_reported_as_our_limit() {
        let error = match query_sessions_bounded(1, 1) {
            Err(error) => error,
            Ok(_)
                if too_few_sessions_visible(
                    "a_count_past_the_ceiling_is_reported_as_our_limit",
                ) =>
            {
                return;
            }
            Ok(sessions) => {
                panic!("a 1-session ceiling admitted a machine running more than one: {sessions:?}")
            }
        };

        // Both fields, not just the variant: `operation` names what gave up and
        // `limit` is the number a reader has to raise, so a ceiling reported
        // without them is no more actionable than the Win32 code it replaced.
        assert!(
            matches!(
                error,
                Error::LimitExceeded {
                    operation: "QueryAllTracesW session enumeration",
                    limit: 1
                }
            ),
            "hitting our own growth ceiling was reported as {error:?}, not as the limit it is"
        );

        // Control: the same query with room to grow succeeds, so the assertion
        // above cannot pass because enumeration is simply broken.
        let sessions =
            query_sessions_bounded(1, MAX_CAPACITY).expect("enumeration failed with room to grow");
        assert!(
            sessions.len() > 1,
            "expected the ceiling to be what failed, but only {} session(s) are running",
            sessions.len()
        );
    }

    /// A session ETW could not name must fail the whole query rather than arrive
    /// with an empty one. ETW leaves a name it has no room for untouched and
    /// still reports success, so against a zeroed buffer an empty field is the
    /// only trace of a dropped name — and a caller counting or matching sessions
    /// cannot tell it from a real answer.
    #[test]
    fn a_nameless_session_fails_the_query() {
        let mut buffer = QueryBuffer::new();

        // `LimitExceeded` specifically: the failure is our buffer being too small,
        // not a Win32 call failing, and a caller told otherwise would go looking in
        // the wrong place. Asserting only `is_err()` would let that regress.
        let error = session_properties(&buffer)
            .expect_err("a buffer with no logger name yielded a session instead of an error");
        assert!(
            matches!(
                error,
                Error::LimitExceeded {
                    operation: "QueryAllTracesW logger name",
                    limit: 1025
                }
            ),
            "a name that did not fit was reported as {error:?}, not as the buffer limit it is"
        );

        // Positive control, so the assertion above cannot pass merely because a
        // zeroed buffer is unreadable for some other reason.
        buffer.logger_name[..3].copy_from_slice(&[u16::from(b'a'), u16::from(b'b'), 0]);
        let session = session_properties(&buffer).expect("a named buffer must decode");
        assert_eq!(session.name, "ab");
        assert_eq!(
            session.log_file, None,
            "no log file name was written, so none should be reported"
        );
    }

    /// A caller who passes `properties` straight to a Win32 trace API must not be
    /// handed a struct that claims storage past its own end — ETW writes both
    /// names back through these offsets, bounded only by `BufferSize`.
    #[test]
    #[cfg_attr(miri, ignore = "calls QueryAllTracesW (Win32)")]
    fn returned_properties_describe_only_themselves() {
        let sessions = query_sessions().expect("enumeration failed");
        assert!(!sessions.is_empty(), "Windows always runs ETW sessions");

        for session in &sessions {
            assert_eq!(
                session.properties.Wnode.BufferSize as usize,
                size_of::<EVENT_TRACE_PROPERTIES>(),
                "session '{}' reports a buffer larger than the struct it is in",
                session.name
            );
            assert_eq!(
                session.properties.LoggerNameOffset, 0,
                "session '{}' kept a logger-name offset into the freed query buffer",
                session.name
            );
            assert_eq!(
                session.properties.LogFileNameOffset, 0,
                "session '{}' kept a log-file-name offset into the freed query buffer",
                session.name
            );
        }
    }
}
