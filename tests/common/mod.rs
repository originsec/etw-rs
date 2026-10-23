//! Shared helpers for integration tests.
//!
//! Imported per test file with `#[path = "common/mod.rs"] mod common;`.
//! Not a public crate API.

// Must stay an `allow`: this module is compiled into many test binaries and
// `dead_code` fires in some but not in any that happens to use every item, so an
// `expect` would report itself unfulfilled there.
#![allow(
    dead_code,
    reason = "shared across many tests; only some use each item"
)]
#![expect(
    unreachable_pub,
    reason = "tests/common/mod.rs is a leaf module of each integration test binary"
)]

use etw::{Error, Error::Win32Error, Trace};
use example_providers::kernel::process;
use std::env;
use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_NOT_ALL_ASSIGNED};

/// Set to a non-empty value to accept a run whose privileged tests all skipped.
const ALLOW_SKIPS: &str = "ETW_RS_ALLOW_SKIPS";

/// Set by CI providers. Privilege is guaranteed there, so skips are refused.
const CI: &str = "CI";

/// Whether an environment variable is set to a non-empty value.
///
/// Empty counts as unset for both flags below, so a `CI=` left in a shell
/// profile cannot turn a developer's legitimate skip into a confusing panic.
fn env_flag(name: &str) -> bool {
    env::var_os(name).is_some_and(|value| !value.is_empty())
}

/// Unwrap an ETW result; on an insufficient-privilege error print a skip line
/// and return `None`. Any other error panics with the supplied label.
///
/// ETW privilege failures surface as one of two Win32 codes depending on the
/// API: `ERROR_ACCESS_DENIED` (5) when opening a kernel/system-logger session
/// or enabling a kernel provider without Administrator (or Performance Log
/// Users) rights, and `ERROR_NOT_ALL_ASSIGNED` (1300) when a required token
/// privilege — e.g. `SeSystemProfilePrivilege` for PMC/LBR profiling — is not
/// held. Both codes are observed exactly (not guessed): see the per-test panic
/// evidence that motivated this helper.
///
/// The returned code is the only trustworthy signal that the capability is
/// absent. An elevated-looking token is not sufficient: a Safer-restricted
/// token — `runas /trustlevel:0x20000`, and by extension sandboxes built the
/// same way — still reports `TokenIsElevated`, yet is denied a system-logger
/// session (while, confusingly, still being allowed a plain realtime one). So
/// `is_elevated()` cannot stand in for "may start a trace", and this helper
/// deliberately does not consult it.
///
/// Under CI the skip is refused. CI always runs elevated, so one of these codes
/// there is a defect — wrong session flags, a provider that was never enabled,
/// a regression in the privilege-enabling path — and skipping would hide it
/// behind a passing test.
///
/// Call it as `common::skip_or_panic("trace.start", trace.start())` and
/// early-return on `None`, so a skipped step leaves the rest of the test unrun.
/// Deliberately not a fenced example: doctests only run for library targets, so
/// nothing here would ever be compile-checked, and a fence would imply otherwise.
pub fn skip_or_panic<T>(label: &str, result: Result<T, Error>) -> Option<T> {
    match result {
        Ok(v) => Some(v),
        Err(e @ Win32Error(ERROR_ACCESS_DENIED | ERROR_NOT_ALL_ASSIGNED)) => {
            assert!(
                !env_flag(CI),
                "{label}: {e}\nCI runs elevated, so insufficient privilege cannot explain this. \
                 Treat it as a defect in the session or provider setup, not a host limitation."
            );
            println!("Skipping: {label} — insufficient privilege ({e}); requires Administrator.");
            None
        }
        Err(e) => panic!("{label}: {e}"),
    }
}

/// Fails when this host cannot enable a kernel ETW provider, so that a run whose
/// privileged tests all skipped is never mistaken for a passing one.
///
/// Every test binary that includes this module needs a privileged session
/// somewhere, so without this guard an under-privileged run trades coverage for
/// green ticks: [`skip_or_panic`] returns `None` and its caller early-returns
/// `Ok`. The `Skipping:` lines do not make that visible, because libtest
/// captures the stdout of passing tests — a default `cargo test` prints none of
/// them. One failing test per binary is the signal that is actually seen.
///
/// It probes *enabling a kernel provider* — `Microsoft-Windows-Kernel-Process`,
/// a manifest provider, so no system-logger slot is involved — which is the
/// narrowest thing that separates a host able to run these tests from one that
/// merely looks able. Creating a session is not that thing, and neither is the
/// elevation flag. Measured on four token shapes:
///
/// | token | `is_elevated()` | realtime session | enable kernel provider |
/// |---|---|---|---|
/// | elevated Administrator | true | starts | **allowed** |
/// | Safer-restricted (`runas /trustlevel:0x20000`) | true | starts | denied |
/// | medium IL + `Performance Log Users` | false | starts | denied |
/// | plain unprivileged | false | denied | denied |
///
/// `Performance Log Users` grants session creation and user-mode providers — the
/// DNS-Client test really does pass on that host — but not kernel providers and
/// not `MSNT_SystemTrace`, so the great majority of this suite still skips
/// there. A session-creation probe passes on those middle rows and is therefore
/// close to useless; the elevation flag is worse still, since a restricted token
/// reports `true`.
///
/// Deliberately not probed:
///
/// - `MSNT_SystemTrace`. It would be stricter, but Windows caps concurrent system-logger traces at
///   8 with 2 reserved, and a box can sit at that cap for unrelated reasons — the probe then fails
///   with `ERROR_NO_SYSTEM_RESOURCES` in every binary and blames privilege for a resource limit.
///   Suite-wide flakiness was the worse trade.
/// - `SeSystemProfilePrivilege`, so the PMC and LBR tests can still skip on
///   `ERROR_NOT_ALL_ASSIGNED` where policy withholds it.
///
/// Only `ERROR_ACCESS_DENIED` is read as absent privilege. A probe that fails any
/// other way still fails the test, but says it was inconclusive rather than
/// sending the reader to an elevated prompt that will not help.
///
/// An elevated host short-circuits before probing, so CI and ordinary developer
/// boxes create no session at all. The cost of that shortcut is the second row:
/// a token that reports elevated is taken at its word. That also means a
/// `Performance Log Users` host fails this guard even in the DNS-Client binary,
/// which could have run — `ETW_RS_ALLOW_SKIPS=1` is the answer there. The suites
/// that need no privilege do not include this module and pass either way.
#[test]
fn can_enable_kernel_provider() {
    if env_flag(ALLOW_SKIPS) || etw::is_elevated() {
        return;
    }

    let name = format!("etw-rs_Guard_{}", std::process::id());
    let probe = Trace::new(&name).and_then(|mut trace| {
        trace.start()?;
        trace.enable_provider(process::GUID, process::keyword::PROCESS)
    });

    match probe {
        Ok(()) => {}
        // Only ERROR_ACCESS_DENIED means "this host lacks the capability". Any other
        // code is the probe itself failing and must not be blamed on privilege —
        // the same misdiagnosis that ruled out an `MSNT_SystemTrace` probe above.
        Err(e @ Win32Error(ERROR_ACCESS_DENIED)) => panic!(
            "cannot enable a kernel ETW provider ({e}): the tests in this binary that need one \
             will soft-skip and still report success. Re-run as Administrator, or set \
             {ALLOW_SKIPS}=1 to accept the reduced coverage."
        ),
        Err(e) => panic!(
            "kernel-provider privilege probe was inconclusive ({e}): this is not \
             ERROR_ACCESS_DENIED, so privilege is not the explanation — do not re-run elevated \
             expecting a fix. Diagnose this code, or set {ALLOW_SKIPS}=1 to skip the probe and \
             accept the reduced coverage."
        ),
    }
}
