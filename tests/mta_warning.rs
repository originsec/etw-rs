//! Debug builds warn before a TDH call that would create the process COM MTA:
//! a MOF schema lookup or a provider enumeration. They stay quiet for manifest
//! lookups, and for everything once the MTA is pinned. See `src/README.md`,
//! "TDH and the Process MTA".
//!
//! One test, because the MTA and the logger are process-wide: a second test
//! running in parallel would see this one's apartment state.

#![cfg(debug_assertions)]
#![expect(
    clippy::expect_used,
    reason = "test binary: panics are the failure mode"
)]

use etw::{Guid, RawEvent, processing_context::lookup_schema, resolve::provider_name_from_guid};
use std::sync::Mutex;
use windows_sys::Win32::{
    Foundation::{CO_E_NOTINITIALIZED, S_OK},
    System::{
        Com::{CoDecrementMTAUsage, CoGetApartmentType, CoIncrementMTAUsage},
        Diagnostics::Etw::{
            EVENT_HEADER_FLAG_64_BIT_HEADER, EVENT_HEADER_FLAG_CLASSIC_HEADER, EVENT_RECORD,
        },
    },
};

static WARNINGS: Mutex<Vec<String>> = Mutex::new(Vec::new());

struct Capture;

impl log::Log for Capture {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= log::Level::Warn
    }

    fn log(&self, record: &log::Record<'_>) {
        if self.enabled(record.metadata()) {
            WARNINGS
                .lock()
                .expect("capture lock")
                .push(record.args().to_string());
        }
    }

    fn flush(&self) {}
}

fn take_warnings() -> Vec<String> {
    std::mem::take(&mut *WARNINGS.lock().expect("capture lock"))
}

fn has_apartment() -> bool {
    let (mut apartment, mut qualifier) = (0, 0);
    // SAFETY: both out-pointers are valid for writes.
    unsafe { CoGetApartmentType(&raw mut apartment, &raw mut qualifier) != CO_E_NOTINITIALIZED }
}

/// Looks up a synthetic event's schema; whether TDH finds one is irrelevant here.
fn lookup(provider: Guid, id: u16, opcode: u8, version: u8, flags: u32) {
    // SAFETY: EVENT_RECORD is a plain C struct; all-zero is a valid value.
    let mut record: EVENT_RECORD = unsafe { std::mem::zeroed() };
    record.EventHeader.ProviderId = windows_sys::core::GUID::from_u128(provider.to_u128());
    record.EventHeader.EventDescriptor.Id = id;
    record.EventHeader.EventDescriptor.Opcode = opcode;
    record.EventHeader.EventDescriptor.Version = version;
    record.EventHeader.Flags = u16::try_from(flags).expect("header flags fit in u16");
    // SAFETY: `record` outlives `event` and carries no UserData.
    let event = unsafe { RawEvent::from_ptr((&raw const record).cast()) };
    let _ = lookup_schema(event);
}

const KERNEL_PROCESS_CLASS: Guid = Guid::from_u128(0x3d6fa8d0_fe05_11d0_9dda_00c04fd7ba7c);
const DNS_CLIENT: Guid = Guid::from_u128(0x1c95126e_7eea_49a9_a3fe_a378b03ddb4d);
const CLASSIC_64: u32 = EVENT_HEADER_FLAG_CLASSIC_HEADER | EVENT_HEADER_FLAG_64_BIT_HEADER;

#[test]
#[cfg_attr(
    miri,
    ignore = "calls TdhGetEventInformation and TdhEnumerateProviders (Win32)"
)]
fn warns_only_when_the_call_would_create_the_mta() {
    log::set_logger(&Capture).expect("no other logger in this test binary");
    log::set_max_level(log::LevelFilter::Warn);
    assert!(
        !has_apartment(),
        "precondition: no thread in this process holds the MTA"
    );

    lookup(DNS_CLIENT, 3008, 0, 0, EVENT_HEADER_FLAG_64_BIT_HEADER);
    let warnings = take_warnings();
    assert!(
        warnings.is_empty(),
        "a manifest lookup never reaches WMI: {warnings:?}"
    );

    lookup(KERNEL_PROCESS_CLASS, 0, 1, 2, CLASSIC_64);
    let _ = provider_name_from_guid(&DNS_CLIENT);
    let warnings = take_warnings();
    assert!(
        warnings.iter().any(|w| w.starts_with(&format!(
            "TdhGetEventInformation for MOF class {KERNEL_PROCESS_CLASS}"
        ))),
        "{warnings:?}"
    );
    assert!(
        warnings
            .iter()
            .any(|w| w.starts_with("TdhEnumerateProviders ")),
        "{warnings:?}"
    );
    assert!(!has_apartment(), "TDH tore the MTA down again on return");

    let mut cookie = std::ptr::null_mut();
    // SAFETY: `cookie` is valid for writes; released below.
    assert_eq!(unsafe { CoIncrementMTAUsage(&raw mut cookie) }, S_OK);
    lookup(KERNEL_PROCESS_CLASS, 0, 1, 3, CLASSIC_64);
    let _ = provider_name_from_guid(&DNS_CLIENT);
    let warnings = take_warnings();
    assert!(
        warnings.is_empty(),
        "a pinned MTA silences the warning: {warnings:?}"
    );
    // SAFETY: `cookie` came from the successful CoIncrementMTAUsage above.
    assert_eq!(unsafe { CoDecrementMTAUsage(cookie) }, S_OK);
}
