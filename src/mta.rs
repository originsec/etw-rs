//! Debug-build warning for TDH calls that create and tear down the process MTA.
//!
//! TDH reads classic (MOF) schemas and the provider list from WMI. Each such
//! call runs `CoInitializeEx(COINIT_MULTITHREADED)` … `CoUninitialize` on the
//! calling thread. When no thread holds the multithreaded apartment, that pair
//! creates the MTA and destroys it on return, disconnecting any COM object
//! another thread made in the implicit MTA meanwhile. See `src/README.md`.

/// Logs a warning if `call` is about to create the process MTA.
///
/// Fires when the calling thread has no COM apartment, explicit or implicit,
/// which means no thread in the process held the MTA at the time of the check.
/// A thread in an STA, or any thread once something pins the MTA
/// (`CoIncrementMTAUsage`), stays quiet. Another thread's transient hold racing
/// the check can hide or fake one occurrence; only a process-lifetime pin makes
/// the outcome certain.
/// Compiled out of release builds.
pub(crate) fn warn_if_no_mta(call: std::fmt::Arguments<'_>) {
    #[cfg(debug_assertions)]
    {
        use windows_sys::Win32::{
            Foundation::CO_E_NOTINITIALIZED,
            System::Com::{APTTYPE, APTTYPEQUALIFIER, CoGetApartmentType},
        };

        let mut apartment: APTTYPE = 0;
        let mut qualifier: APTTYPEQUALIFIER = 0;
        // SAFETY: both out-pointers are valid for writes. The call only queries
        // apartment state; it never initialises COM.
        let hr = unsafe { CoGetApartmentType(&raw mut apartment, &raw mut qualifier) };
        if hr == CO_E_NOTINITIALIZED {
            log::warn!(
                "{call} will create the process MTA and tear it down on return, \
                 disconnecting COM objects other threads create in the implicit MTA \
                 meanwhile. If this process uses COM, pin the MTA with CoIncrementMTAUsage."
            );
        }
    }
    #[cfg(not(debug_assertions))]
    let _ = call;
}
