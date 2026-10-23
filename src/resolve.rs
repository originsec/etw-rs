//! Provider name and GUID resolution.
//!
//! Convenience functions for looking up registered ETW providers by name or GUID.

// TODO(jdu) FUTURE These functions could benefit from caching, but are used infrequently

use crate::{Error, Result};
use windows_sys::Win32::{
    Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS},
    System::Diagnostics::Etw::{
        PROVIDER_ENUMERATION_INFO, TRACE_PROVIDER_INFO, TdhEnumerateProviders,
    },
};

/// Looks up a registered ETW provider GUID by name.
///
/// # Example
///
/// ```no_run
/// use etw::resolve::provider_guid_from_name;
///
/// if let Ok(guid) = provider_guid_from_name("Microsoft-Windows-DNS-Client") {
///     println!("{guid:?}");
/// }
/// ```
///
/// # Errors
///
/// - [`Error::ProviderNotFound`] if no registered provider carries `name`.
/// - [`Error::ProviderAmbiguous`] if more than one does, so `name` does not identify a single GUID.
///   Look the provider up by GUID instead.
/// - [`Error::Win32Error`] if enumerating the registered providers fails.
pub fn provider_guid_from_name(name: &str) -> Result<crate::Guid> {
    let mut first_match: Option<crate::Guid> = None;
    let duplicate = scan_providers(|provider, provider_name| {
        if provider_name != name {
            return None;
        }
        if first_match.is_some() {
            return Some(()); // duplicate — stop early
        }
        first_match = Some(crate::Guid::from_sys(provider.ProviderGuid));
        None // continue scanning to detect duplicates
    })?;

    if duplicate.is_some() {
        return Err(Error::ProviderAmbiguous {
            name: name.to_owned(),
        });
    }
    first_match.ok_or_else(|| Error::ProviderNotFound {
        name: name.to_owned(),
    })
}

/// Looks up a registered ETW provider name from its GUID.
///
/// Returns `None` if the provider is not found, or if enumeration fails (e.g. out of
/// memory). Use [`provider_guid_from_name`] if you need to distinguish between "not
/// found" and enumeration failure.
///
/// # Example
///
/// ```no_run
/// use etw::{Guid, resolve::provider_name_from_guid};
///
/// let guid = Guid::from_u128(0x1c95126e_7eea_49a9_a3fe_a378b03ddb4d);
/// if let Some(name) = provider_name_from_guid(&guid) {
///     println!("Provider: {name}"); // "Microsoft-Windows-DNS-Client"
/// }
/// ```
pub fn provider_name_from_guid(guid: &crate::Guid) -> Option<String> {
    // `then`, not `then_some`: the eager form allocated for every provider
    // scanned, matching or not.
    scan_providers(|provider, name| {
        (crate::Guid::from_sys(provider.ProviderGuid) == *guid).then(|| name.to_owned())
    })
    .ok()
    .flatten()
}

/// Scans registered ETW providers, applying `callback` to each.
///
/// Stops early and returns `Some(T)` if the callback returns `Some(T)`.
/// Analogous to [`Iterator::find_map`].
fn scan_providers<T>(
    mut callback: impl FnMut(&TRACE_PROVIDER_INFO, &str) -> Option<T>,
) -> Result<Option<T>> {
    let mut buffer_size = 0u32;

    // SAFETY: First call with null buffer to query the required size.
    let status = unsafe { TdhEnumerateProviders(std::ptr::null_mut(), &raw mut buffer_size) };

    if status != ERROR_INSUFFICIENT_BUFFER {
        // ERROR_SUCCESS here means no providers are registered.
        return if status == ERROR_SUCCESS {
            Ok(None)
        } else {
            Err(Error::from_win32(status))
        };
    }

    // Retry loop: a provider may register between the size query and the fill call,
    // requiring a larger buffer.
    const MAX_RETRIES: u32 = 8;
    let mut retries = 0u32;

    loop {
        // Add 1024 bytes of headroom to reduce retry chance due to TOCTOU.
        buffer_size += 1024;
        // Allocate as u32 to exactly match the 4-byte alignment of PROVIDER_ENUMERATION_INFO.
        const _: () = assert!(
            align_of::<PROVIDER_ENUMERATION_INFO>() == align_of::<u32>(),
            "PROVIDER_ENUMERATION_INFO alignment changed — update allocation type"
        );
        let word_count = buffer_size.div_ceil(4) as usize;
        let mut buffer: Vec<u32> = vec![0u32; word_count];
        let enum_info = buffer.as_mut_ptr().cast::<PROVIDER_ENUMERATION_INFO>();

        // SAFETY: `buffer` is 4-byte aligned and has at least `buffer_size` bytes
        // capacity, which is at least the TDH-reported minimum.
        let status = unsafe { TdhEnumerateProviders(enum_info, &raw mut buffer_size) };

        if status == ERROR_INSUFFICIENT_BUFFER {
            retries += 1;
            if retries >= MAX_RETRIES {
                return Err(Error::LimitExceeded {
                    operation: "TdhEnumerateProviders retry",
                    limit: MAX_RETRIES,
                });
            }
            // retries > 1: the first retry (TOCTOU — a provider registered between the
            // size probe and the fill call) is expected and not worth logging; only
            // subsequent failures suggest something unusual.
            if retries > 1 {
                log::debug!(
                    "TdhEnumerateProviders retry {retries}/{MAX_RETRIES}, buffer grew to {buffer_size}"
                );
            }
            continue;
        }

        if status != ERROR_SUCCESS {
            return Err(Error::from_win32(status));
        }

        // SAFETY: TdhEnumerateProviders succeeded; enum_info is valid and all
        // ProviderNameOffsets are within `buffer`. On success, TDH updates buffer_size
        // to the number of bytes written, which is ≤ word_count * 4.
        let (count, providers_ptr) = unsafe {
            let info = &*enum_info;
            (info.NumberOfProviders, info.TraceProviderInfoArray.as_ptr())
        };

        // SAFETY: TDH wrote `buffer_size` bytes into `buffer`; u32 memory is valid as
        // a byte slice. `buffer_size` ≤ word_count * 4 (the allocated capacity).
        let buffer_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), buffer_size as usize)
        };

        for i in 0..count {
            // SAFETY: `providers_ptr` points to `count` valid entries within `buffer`.
            let provider = unsafe { &*providers_ptr.add(i as usize) };

            if provider.ProviderNameOffset > 0 {
                // SAFETY: ProviderNameOffset is a valid byte offset within `buffer_bytes`.
                let name = unsafe { read_name(buffer_bytes, provider.ProviderNameOffset as usize) };
                if let Some(result) = callback(provider, &name) {
                    return Ok(Some(result));
                }
            }
        }

        return Ok(None);
    }
}

/// Reads a null-terminated UTF-16 string from `buffer` at `offset`.
///
/// # Safety
///
/// `offset` must be a valid byte offset into `buffer` pointing to a null-terminated
/// UTF-16 string fully contained within `buffer`.
unsafe fn read_name(buffer: &[u8], offset: usize) -> String {
    // A `ProviderNameOffset` past the end of the buffer would make `add(offset)`
    // compute an out-of-bounds pointer (UB even before any read) and underflow the
    // `buffer.len() - offset` length below. Bail on an out-of-range offset.
    if offset > buffer.len() {
        return String::new();
    }
    // SAFETY: `offset <= buffer.len()`, so this stays within (or one past) the allocation.
    let name_ptr = unsafe { buffer.as_ptr().add(offset).cast::<u16>() };
    let max_len = (buffer.len() - offset) / 2;
    let mut units = Vec::with_capacity(64);
    for i in 0..max_len {
        // SAFETY: i < max_len ensures we stay within buffer. read_unaligned handles any
        // potential misalignment of ProviderNameOffset (ETW always aligns, but the type
        // system cannot guarantee it).
        let unit = unsafe { name_ptr.add(i).read_unaligned() };
        if unit == 0 {
            break;
        }
        units.push(unit);
    }
    String::from_utf16_lossy(&units)
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "test-only assertions")]
mod tests {
    use super::*;

    // Microsoft-Windows-DNS-Client: stable GUID present on all modern Windows.
    const DNS_CLIENT_NAME: &str = "Microsoft-Windows-DNS-Client";
    const DNS_CLIENT_GUID: crate::Guid =
        crate::Guid::from_u128(0x1c95126e_7eea_49a9_a3fe_a378b03ddb4d);

    #[test]
    #[cfg_attr(miri, ignore = "calls TdhEnumerateProviders (Win32)")]
    fn test_provider_guid_from_name_known_provider() {
        let guid =
            provider_guid_from_name(DNS_CLIENT_NAME).expect("DNS-Client should be registered");
        assert_eq!(guid, DNS_CLIENT_GUID);
    }

    // An absent name must report *absence* specifically. `is_err()` alone would also
    // accept ProviderAmbiguous or a Win32 enumeration failure, so it could not tell a
    // working lookup from one that had stopped distinguishing its failure modes — which
    // is the whole reason the two are separate variants. The name is asserted too, since
    // carrying it as a field rather than baked into prose is the point of the struct form.
    #[test]
    #[cfg_attr(miri, ignore = "calls TdhEnumerateProviders (Win32)")]
    fn test_provider_guid_from_name_not_found() {
        const MISSING: &str = "This-Provider-Does-Not-Exist-etw-rs-test";
        match provider_guid_from_name(MISSING) {
            Err(Error::ProviderNotFound { name }) => assert_eq!(name, MISSING),
            other => panic!("expected ProviderNotFound({MISSING:?}), got {other:?}"),
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls TdhEnumerateProviders (Win32)")]
    fn test_provider_guid_from_name_case_sensitive() {
        // Lowercase should not match the PascalCase registration — and must be reported
        // as not-found, not as some other failure.
        const LOWERCASE: &str = "microsoft-windows-dns-client";
        match provider_guid_from_name(LOWERCASE) {
            Err(Error::ProviderNotFound { name }) => assert_eq!(name, LOWERCASE),
            other => panic!("expected ProviderNotFound({LOWERCASE:?}), got {other:?}"),
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls TdhEnumerateProviders (Win32)")]
    fn test_provider_name_from_guid_known_provider() {
        let name = provider_name_from_guid(&DNS_CLIENT_GUID);
        assert_eq!(name.as_deref(), Some(DNS_CLIENT_NAME));
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls TdhEnumerateProviders (Win32)")]
    fn test_provider_name_from_guid_unknown() {
        // A GUID that is not a registered provider.
        let guid = crate::Guid::from_u128(0x00000000_0000_0000_0000_000000000001);
        assert_eq!(provider_name_from_guid(&guid), None);
    }

    #[test]
    #[cfg_attr(miri, ignore = "calls TdhEnumerateProviders (Win32)")]
    fn test_round_trip() {
        let guid =
            provider_guid_from_name(DNS_CLIENT_NAME).expect("DNS-Client should be registered");
        let name = provider_name_from_guid(&guid).expect("reverse lookup should succeed");
        assert_eq!(name, DNS_CLIENT_NAME);
    }

    #[test]
    fn read_name_offset_past_buffer_is_empty() {
        // "AB" as UTF-16LE, no terminator.
        let buf = [0x41u8, 0x00, 0x42, 0x00];
        // A ProviderNameOffset past the end of the buffer must not compute an
        // out-of-bounds pointer or underflow the scan length — it yields an empty
        // name rather than an unbounded over-read.
        // SAFETY: read_name tolerates any offset (the out-of-range guard runs first).
        assert_eq!(unsafe { read_name(&buf, buf.len() + 8) }, "");
        // offset == len is the one-past-the-end boundary: also empty, not UB.
        // SAFETY: as above.
        assert_eq!(unsafe { read_name(&buf, buf.len()) }, "");
        // A valid offset still reads the string.
        // SAFETY: offset 0 is within the buffer.
        assert_eq!(unsafe { read_name(&buf, 0) }, "AB");
    }
}
