//! System-wide profiling configuration for ETW operations.

use crate::{Error, Result};
use windows_sys::{
    Win32::{
        Foundation::{ERROR_SUCCESS, GetLastError, HANDLE},
        Security::{
            AdjustTokenPrivileges, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
            TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
        },
        System::{
            Diagnostics::Etw::{
                CONTROLTRACE_HANDLE, TraceSampledProfileIntervalInfo, TraceSetInformation,
            },
            Threading::{GetCurrentProcess, OpenProcessToken},
        },
    },
    core::{PCWSTR, w},
};

// ═══════════════════════════════════════════════════════════════════════════════
// Profile Interval Configuration (system-wide)
// ═══════════════════════════════════════════════════════════════════════════════

/// Minimum CPU profile sampling interval in 100-nanosecond units (0.1221 ms ≈ 8.19 KHz).
///
/// This is the hardware-enforced floor set by the HAL timer resolution.
/// Verified empirically: `xperf -SetProfInt 1221` succeeds, 1220 fails.
pub const MIN_PROFILE_INTERVAL: u32 = 1_221;

/// Maximum CPU profile sampling interval in 100-nanosecond units (10 seconds).
///
/// Verified empirically: `xperf -SetProfInt 100000000` succeeds, 100000001 fails.
pub const MAX_PROFILE_INTERVAL: u32 = 100_000_000;

/// Structure for `TraceSampledProfileIntervalInfo`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct TraceProfileInterval {
    /// Profile source (from `ProfileSource` enum).
    source: u32,
    /// Sampling interval in 100-nanosecond units (for time) or events (for PMC).
    interval: u32,
}

/// Profile source types for CPU sampling.
///
/// These correspond to the `KPROFILE_SOURCE` enum in the Windows kernel.
/// Use with [`set_profile_interval()`] or [`set_pmc_interval()`] to configure CPU sampling.
///
/// # Example
///
/// ```no_run
/// use etw::system_logger::profiling::{enable_profile_privilege, set_profile_interval};
///
/// enable_profile_privilege()?;
/// set_profile_interval(10_000_000)?; // 1 second interval
/// //
/// # Ok::<(), etw::Error>(())
/// ```
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ProfileSource {
    /// Time-based sampling (default CPU profiling).
    #[default]
    ProfileTime = 0,
    /// Alignment fixups.
    ProfileAlignmentFixup = 1,
    /// Total issues (instructions issued).
    ProfileTotalIssues = 2,
    /// Pipeline dry (stalls).
    ProfilePipelineDry = 3,
    /// Load instructions.
    ProfileLoadInstructions = 4,
    /// Pipeline frozen (stalls).
    ProfilePipelineFrozen = 5,
    /// Branch instructions.
    ProfileBranchInstructions = 6,
    /// Total non-issued cycles.
    ProfileTotalNonissues = 7,
    /// Data cache misses.
    ProfileDcacheMisses = 8,
    /// Instruction cache misses.
    ProfileIcacheMisses = 9,
    /// Cache misses (combined).
    ProfileCacheMisses = 10,
    /// Branch mispredictions.
    ProfileBranchMispredictions = 11,
    /// Store instructions.
    ProfileStoreInstructions = 12,
    /// Floating point instructions.
    ProfileFpInstructions = 13,
    /// Integer instructions.
    ProfileIntegerInstructions = 14,
    /// Dual issues (2 instructions per cycle).
    ProfileDualIssue = 15,
    /// Triple issues (3 instructions per cycle).
    ProfileTripleIssue = 16,
    /// Quad issues (4 instructions per cycle).
    ProfileQuadIssue = 17,
    /// Special instructions.
    ProfileSpecialInstructions = 18,
    /// Total CPU cycles.
    ProfileTotalCycles = 19,
    /// Instruction cache issues.
    ProfileIcacheIssues = 20,
    /// Data cache accesses.
    ProfileDcacheAccesses = 21,
    /// Memory barrier cycles.
    ProfileMemoryBarrierCycles = 22,
    /// Load-linked instructions.
    ProfileLoadLinkedIssues = 23,
}

/// Enables a privilege for the current process.
///
/// # Arguments
///
/// * `privilege_name` - The privilege name (e.g., `SE_SYSTEM_PROFILE_NAME`)
///
/// # Errors
///
/// Returns an error if the privilege cannot be enabled (e.g., not held by the token).
fn enable_privilege(privilege_name: PCWSTR) -> Result<()> {
    // SAFETY: All Win32 calls are made with valid handles and properly sized buffers.
    unsafe {
        let mut token_handle: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &raw mut token_handle,
        ) == 0
        {
            return Err(Error::from_win32(GetLastError()));
        }

        let mut luid = std::mem::zeroed::<windows_sys::Win32::Foundation::LUID>();
        if LookupPrivilegeValueW(std::ptr::null(), privilege_name, &raw mut luid) == 0 {
            let _ = windows_sys::Win32::Foundation::CloseHandle(token_handle);
            return Err(Error::from_win32(GetLastError()));
        }

        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [windows_sys::Win32::Security::LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        if AdjustTokenPrivileges(
            token_handle,
            0,
            &raw const tp,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        ) == 0
        {
            let _ = windows_sys::Win32::Foundation::CloseHandle(token_handle);
            return Err(Error::from_win32(GetLastError()));
        }

        // AdjustTokenPrivileges returns success even if it couldn't enable the
        // privilege (e.g. ERROR_NOT_ALL_ASSIGNED). Check GetLastError() to
        // detect this partial-failure case.
        let last_error = GetLastError();
        let _ = windows_sys::Win32::Foundation::CloseHandle(token_handle);
        if last_error != ERROR_SUCCESS {
            return Err(Error::from_win32(last_error));
        }
        Ok(())
    }
}

/// Enables the `SeSystemProfilePrivilege` for the current process.
///
/// This privilege is required to use CPU profiling features like `PERF_PROFILE`
/// events and to set the system profile interval.
///
/// # Errors
///
/// Returns an error if the privilege cannot be enabled. This typically means
/// the process is not running with administrator privileges.
///
/// # Example
///
/// ```no_run
/// use etw::{
///     Trace,
///     system_logger::{
///         masks::PERF_PROFILE,
///         profiling::{enable_profile_privilege, set_profile_interval},
///     },
/// };
///
/// enable_profile_privilege()?;
/// set_profile_interval(10_000_000)?; // 1 second
///
/// let mut trace = Trace::new("ProfileTrace")?;
/// trace.set_events(&[PERF_PROFILE]);
/// # Ok::<(), etw::Error>(())
/// ```
pub fn enable_profile_privilege() -> Result<()> {
    // SE_SYSTEM_PROFILE_NAME = "SeSystemProfilePrivilege"
    enable_privilege(w!("SeSystemProfilePrivilege"))
}

/// Set the system-wide CPU profile sampling interval to `interval_100ns`.
///
/// `interval_100ns` is in 100-nanosecond units. Accepted range:
/// [`MIN_PROFILE_INTERVAL`] (0.1221 ms ≈ 8 KHz) to [`MAX_PROFILE_INTERVAL`] (10 s).
/// Common values: `1_221` (max rate), `10_000` (1 ms default), `10_000_000` (1 s).
///
/// This sets the interval for time-based CPU sampling using `ProfileTime` source.
/// The setting is system-wide and affects all profile trace sessions.
///
/// # Errors
///
/// Returns an error if the interval cannot be set. This typically means
/// `SeSystemProfilePrivilege` is not enabled.
///
/// # Example
///
/// ```no_run
/// use etw::system_logger::profiling::{enable_profile_privilege, set_profile_interval};
///
/// enable_profile_privilege()?;
/// set_profile_interval(10_000_000)?; // 1 second interval
/// //
/// # Ok::<(), etw::Error>(())
/// ```
pub fn set_profile_interval(interval_100ns: u32) -> Result<()> {
    // Bounds are empirically determined and could change with future Windows builds,
    // so warn rather than error — let the OS reject it if truly invalid.
    if !(MIN_PROFILE_INTERVAL..=MAX_PROFILE_INTERVAL).contains(&interval_100ns) {
        log::warn!(
            "Profile interval {interval_100ns} outside known range [{MIN_PROFILE_INTERVAL}, {MAX_PROFILE_INTERVAL}]"
        );
    }

    let interval = TraceProfileInterval {
        source: ProfileSource::ProfileTime as u32,
        interval: interval_100ns,
    };

    // SAFETY: TraceSetInformation is a Win32 API. The buffer contains a valid struct.
    // Handle 0 is used because this sets the system-wide interval, not per-session.
    let status = unsafe {
        TraceSetInformation(
            CONTROLTRACE_HANDLE { Value: 0 },
            TraceSampledProfileIntervalInfo,
            std::ptr::from_ref(&interval).cast(),
            size_of::<TraceProfileInterval>() as u32,
        )
    };

    if status != ERROR_SUCCESS {
        return Err(Error::from_win32(status));
    }

    Ok(())
}

/// Set the system-wide PMC (Performance Monitor Counter) sampling interval.
///
/// This sets the interval for PMC-based sampling. The interval is measured in
/// **events**, not time. For example, with `ProfileTotalCycles`, an interval of
/// 1,000,000 means sample every 1 million CPU cycles.
///
/// The setting is system-wide and affects all profile trace sessions.
///
/// No empirical bounds for the interval have been established for PMC sources.
/// The OS will reject truly invalid values and the error will propagate from
/// this function.  Use [`set_profile_interval`] as a reference — it enforces
/// [`MIN_PROFILE_INTERVAL`]/[`MAX_PROFILE_INTERVAL`] bounds that are specific
/// to time-based profiling and do not apply here.
///
/// `source` selects the counter to sample (e.g., `ProfileSource::ProfileTotalCycles`).
/// `interval` is measured in events, not time — e.g., `1_000_000` means every 1M cycles.
///
/// # Errors
///
/// Returns an error if the interval cannot be set. This typically means
/// `SeSystemProfilePrivilege` is not enabled or the profile source is not supported.
///
/// # Example
///
/// ```no_run
/// use etw::system_logger::profiling::{
///     ProfileSource, enable_profile_privilege, set_pmc_interval,
/// };
///
/// enable_profile_privilege()?;
/// // Sample every 1M CPU cycles
/// set_pmc_interval(ProfileSource::ProfileTotalCycles, 1_000_000)?;
/// # Ok::<(), etw::Error>(())
/// ```
pub fn set_pmc_interval(source: ProfileSource, interval: u32) -> Result<()> {
    let profile_interval = TraceProfileInterval {
        source: source as u32,
        interval,
    };

    // SAFETY: TraceSetInformation is a Win32 API. The buffer contains a valid struct.
    // Handle 0 is used because this sets the system-wide interval, not per-session.
    let status = unsafe {
        TraceSetInformation(
            CONTROLTRACE_HANDLE { Value: 0 },
            TraceSampledProfileIntervalInfo,
            std::ptr::from_ref(&profile_interval).cast(),
            size_of::<TraceProfileInterval>() as u32,
        )
    };

    if status != ERROR_SUCCESS {
        return Err(Error::from_win32(status));
    }

    Ok(())
}

#[cfg(test)]
#[expect(clippy::assertions_on_constants, reason = "test-only assertions")]
mod tests {
    use super::*;

    #[test]
    fn test_profile_source_default() {
        assert_eq!(ProfileSource::default(), ProfileSource::ProfileTime);
    }

    #[test]
    fn test_profile_source_eq_and_clone() {
        let a = ProfileSource::ProfileTotalCycles;
        let b = a;
        assert_eq!(a, b);
        assert_ne!(a, ProfileSource::ProfileTime);
    }

    #[test]
    fn test_profile_source_debug() {
        let s = format!("{:?}", ProfileSource::ProfileTotalCycles);
        assert!(s.contains("ProfileTotalCycles"), "got: {s}");
        let s2 = format!("{:?}", ProfileSource::ProfileTime);
        assert!(s2.contains("ProfileTime"), "got: {s2}");
    }

    #[test]
    fn test_profile_source_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(ProfileSource::ProfileTotalCycles);
        set.insert(ProfileSource::ProfileTime);
        set.insert(ProfileSource::ProfileTotalCycles); // duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_profile_interval_constants() {
        assert_eq!(MIN_PROFILE_INTERVAL, 1_221);
        assert_eq!(MAX_PROFILE_INTERVAL, 100_000_000);
        assert!(MIN_PROFILE_INTERVAL < MAX_PROFILE_INTERVAL);
    }

    #[test]
    fn test_profile_source_as_u32() {
        assert_eq!(ProfileSource::ProfileTime as u32, 0);
        assert_eq!(ProfileSource::ProfileTotalCycles as u32, 19);
        assert_eq!(ProfileSource::ProfileTotalIssues as u32, 2);
    }
}
