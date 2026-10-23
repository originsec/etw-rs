//! MOF (classic) ETW provider support.
//!
//! This module provides:
//! - **WMI-based discovery**: Enumerating MOF providers registered in `root\WMI`
//! - **TDH-based schema queries**: Retrieving field definitions and event names for MOF events via
//!   synthetic `EVENT_RECORD` structures
//!
//! MOF providers register their event schemas in the WMI `root\WMI` namespace
//! as classes derived from `EventTrace`. This module enumerates those classes
//! to discover provider GUIDs, event class GUIDs, opcodes, and version info.

use crate::{
    Error, Result,
    manifest::{
        EventFieldInfo, extract_fields_from_trace_event_info, extract_string_from_buffer,
        trace_event_info_from_buffer,
    },
};
use std::collections::HashMap;
use windows::{
    Win32::{
        Foundation::{
            ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, RPC_E_CHANGED_MODE, S_FALSE, S_OK,
            WIN32_ERROR as WIN32_ERROR_CODE,
        },
        System::{
            Com::{
                CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
                CoUninitialize,
            },
            Diagnostics::Etw::{
                EVENT_HEADER_FLAG_64_BIT_HEADER as EVENT_HEADER_FLAG_64_BIT_HEADER_U32,
                EVENT_HEADER_FLAG_CLASSIC_HEADER as EVENT_HEADER_FLAG_CLASSIC_HEADER_U32,
                EVENT_RECORD, TRACE_EVENT_INFO, TdhGetEventInformation,
            },
            Variant::VARIANT,
            Wmi::{
                IEnumWbemClassObject, IWbemClassObject, IWbemLocator, IWbemServices,
                WBEM_FLAG_FORWARD_ONLY, WBEM_FLAG_RETURN_IMMEDIATELY, WBEM_INFINITE, WbemLocator,
            },
        },
    },
    core::{BSTR, GUID, w},
};

// =============================================================================
// Public types
// =============================================================================

/// A MOF event class discovered via WMI.
#[derive(Debug, Clone)]
pub struct MofEventClass {
    /// Event class GUID (used as `ProviderId` in `EVENT_RECORD`).
    pub class_guid: GUID,
    /// WMI category class name (e.g., "Process", "Thread_V2", "DiskIo").
    pub class_name: String,
    /// WMI event class name (e.g., "Process_TypeGroup1", "DriverMajorFunctionCall").
    pub wmi_class_name: String,
    /// Opcode value identifying this event within the class.
    pub opcode: u8,
    /// Event version.
    pub version: u8,
    /// Human-readable event type name from WMI (e.g., "Start", "End").
    pub event_type_name: String,
}

/// A MOF provider discovered via WMI.
#[derive(Debug, Clone)]
pub struct MofProvider {
    /// Provider registration name (WMI class name).
    pub name: String,
    /// Provider registration GUID.
    pub provider_guid: GUID,
    /// Events discovered from child classes.
    pub events: Vec<MofEventClass>,
}

// =============================================================================
// Shared helpers
// =============================================================================

/// Strips a trailing `_V{digits}` version suffix from a MOF/WMI class name.
///
/// E.g. `"FileIo_V2"` → `"FileIo"`, `"FileIo"` → `"FileIo"`.
pub(crate) fn strip_version_suffix(name: &str) -> &str {
    if let Some(pos) = name.rfind("_V")
        && name.len() > pos + 2
        && name[pos + 2..].bytes().all(|b| b.is_ascii_digit())
    {
        return &name[..pos];
    }
    name
}

// =============================================================================
// Public API
// =============================================================================

/// Enumerates all MOF providers registered in the WMI `root\WMI` namespace.
///
/// Connects to WMI via COM and queries for all classes derived from `EventTrace`.
/// For each provider base class, discovers child event classes with their opcodes
/// and version information.
///
/// # Errors
///
/// Returns an error if COM initialisation or WMI queries fail.
pub fn enumerate_mof_providers() -> Result<Vec<MofProvider>> {
    // SAFETY: COM initialisation and WMI queries use well-defined COM interfaces.
    // All COM objects are released when dropped.
    unsafe { enumerate_mof_providers_inner() }
}

/// Discovers events for a specific MOF provider by name.
///
/// Searches WMI for a provider class matching `name` (case-insensitive)
/// and returns its event definitions, or `None` if not found.
///
/// Tries matching by WMI class name first. If that fails, resolves the
/// name via TDH to obtain the provider GUID and matches by GUID instead.
/// This allows using either the WMI class name (e.g., `MSNT_SystemTrace`)
/// or the TDH provider name (e.g., `Windows Kernel Trace`).
///
/// # Errors
///
/// Returns an error if COM initialisation or WMI queries fail.
pub fn get_mof_provider(name: &str) -> Result<Option<MofProvider>> {
    let providers = enumerate_mof_providers()?;
    let name_lower = name.to_lowercase();

    // Try exact WMI class name match first (provider base class).
    if let Some(idx) = providers
        .iter()
        .position(|p| p.name.to_lowercase() == name_lower)
    {
        let mut providers = providers;
        return Ok(Some(providers.swap_remove(idx)));
    }

    // Fallback: resolve the name via TDH to get the GUID, then match by GUID.
    if let Ok(guid) = etw::resolve::provider_guid_from_name(name)
        && let Some(idx) = providers
            .iter()
            .position(|p| p.provider_guid.to_u128() == guid.to_u128())
    {
        let mut providers = providers;
        return Ok(Some(providers.swap_remove(idx)));
    }

    // Fallback: match against category class names (e.g. "FileIo" under
    // MSNT_SystemTrace). This allows querying descendants of EventTrace that
    // are not direct children. Versioned categories like "FileIo_V2" are
    // matched by stripping the version suffix so they group with "FileIo".
    for mut provider in providers {
        let has_match = provider
            .events
            .iter()
            .any(|e| strip_version_suffix(&e.class_name).to_lowercase() == name_lower);
        if has_match {
            provider
                .events
                .retain(|e| strip_version_suffix(&e.class_name).to_lowercase() == name_lower);
            return Ok(Some(provider));
        }
    }

    Ok(None)
}

// =============================================================================
// Internal implementation
// =============================================================================

/// RAII guard for COM initialisation on the current thread.
///
/// When `owns_init` is `true`, [`CoUninitialize`] is called on drop.
/// When COM was already initialised in a different mode (`RPC_E_CHANGED_MODE`),
/// the guard is inert and drop is a no-op.
struct ComGuard {
    owns_init: bool,
}

impl ComGuard {
    /// Initialises COM on the current thread.
    ///
    /// # Safety
    ///
    /// Must be called at most once per thread scope. The returned guard
    /// calls `CoUninitialize` on drop when it owns the initialisation.
    unsafe fn init() -> Result<Self> {
        // SAFETY: CoInitializeEx with COINIT_MULTITHREADED is safe to call.
        // S_OK means success, S_FALSE means already initialised (both are ok).
        // RPC_E_CHANGED_MODE means the thread is already STA — COM is usable
        // but we must not call CoUninitialize.
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        match hr {
            S_OK | S_FALSE => Ok(Self { owns_init: true }),
            RPC_E_CHANGED_MODE => {
                // Thread already STA — COM is still usable, but we don't own
                // the initialisation so must not call CoUninitialize.
                Ok(Self { owns_init: false })
            }
            other => Err(Error::Com(other.into())),
        }
    }
}

impl Drop for ComGuard {
    fn drop(&mut self) {
        if self.owns_init {
            // SAFETY: Matching the CoInitializeEx call from init().
            unsafe { CoUninitialize() };
        }
    }
}

/// Connects to WMI and returns an `IWbemServices` for `root\WMI`.
///
/// # Safety
///
/// COM must already be initialised on the current thread.
unsafe fn connect_wmi() -> Result<IWbemServices> {
    // SAFETY: COM is initialised. CoCreateInstance creates an in-process COM object.
    let locator: IWbemLocator =
        unsafe { CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER).map_err(Error::Com)? };

    // SAFETY: ConnectServer with empty credentials uses the current user's context.
    let services = unsafe {
        locator
            .ConnectServer(
                &BSTR::from("root\\WMI"),
                &BSTR::new(),
                &BSTR::new(),
                &BSTR::new(),
                0,
                &BSTR::new(),
                None,
            )
            .map_err(Error::Com)?
    };

    Ok(services)
}

/// Core implementation of provider enumeration.
///
/// # Safety
///
/// Calls COM functions. Caller must ensure COM is not in a conflicting state.
unsafe fn enumerate_mof_providers_inner() -> Result<Vec<MofProvider>> {
    // SAFETY: Initialises COM for this thread and balances with drop via ComGuard.
    let _com = unsafe { ComGuard::init()? };
    // SAFETY: COM is initialised above; creates a valid WMI services connection.
    let services = unsafe { connect_wmi()? };

    // Fetch the whole EventTrace subtree in one query and rebuild the hierarchy
    // from __SUPERCLASS, rather than walking it a level at a time.
    //
    // The walk cost one round trip per class — 1 for the providers, then one per
    // provider for its categories, then one per category for its events, which
    // on this machine is 378 queries for 186 providers. `ISA` returns every
    // descendant at once: 932 rows in ~0.2 s against ~1.1 s for the walk.
    //
    // SAFETY: Query string is static and services is a valid IWbemServices handle.
    let subtree = unsafe {
        wmi_query(
            &services,
            "SELECT * FROM meta_class WHERE __this ISA 'EventTrace'",
        )?
    };

    // Index every class by its parent so each level is a lookup, not a query.
    let mut children: HashMap<String, Vec<&IWbemClassObject>> = HashMap::new();
    for obj in &subtree {
        // SAFETY: obj is a valid row from the WMI enumeration above.
        if let Some(superclass) = unsafe { get_superclass(obj) } {
            children.entry(superclass).or_default().push(obj);
        }
    }

    let base_classes: Vec<&IWbemClassObject> =
        children.get("EventTrace").cloned().unwrap_or_default();

    let mut providers = Vec::new();

    for base_obj in base_classes {
        // SAFETY: base_obj is returned by WMI enumeration and remains valid for this scope.
        let Some(class_name) = (unsafe { get_class_name(base_obj) }) else {
            continue;
        };
        // SAFETY: base_obj is valid and qualifier access is read-only.
        let Some(provider_guid) = (unsafe { get_class_guid_qualifier(base_obj) }) else {
            continue;
        };

        // Category classes: children of this provider base class. These have
        // their own class GUID and EventVersion qualifier.
        let category_classes: &[&IWbemClassObject] =
            children.get(&class_name).map_or(&[], Vec::as_slice);

        let mut events = Vec::new();

        for cat_obj in category_classes {
            // SAFETY: cat_obj is a valid row from WMI enumeration.
            let Some(class_guid) = (unsafe { get_class_guid_qualifier(cat_obj) }) else {
                continue;
            };
            // SAFETY: cat_obj is valid; qualifier read is non-mutating.
            let version = unsafe { get_event_version_qualifier(cat_obj) }.unwrap_or(0);
            // SAFETY: cat_obj is valid; __CLASS read is non-mutating.
            let cat_name = unsafe { get_class_name(cat_obj) }.unwrap_or_default();

            // Event classes: children of the category, so grandchildren of the
            // provider. These have EventType (opcode) and EventTypeName qualifiers.
            let event_classes: &[&IWbemClassObject] =
                children.get(&cat_name).map_or(&[], Vec::as_slice);

            if event_classes.is_empty() {
                // The category itself might have EventType/EventTypeName qualifiers
                // (some providers have a flat hierarchy).
                // SAFETY: cat_obj is valid and qualifier reads are non-mutating.
                let opcodes = unsafe { get_event_types(cat_obj) };
                for (opcode, name) in opcodes {
                    events.push(MofEventClass {
                        class_guid,
                        class_name: cat_name.clone(),
                        wmi_class_name: cat_name.clone(),
                        opcode,
                        version,
                        event_type_name: name,
                    });
                }
            } else {
                for ev_obj in event_classes {
                    // SAFETY: ev_obj is a valid WMI object from enumeration.
                    let ev_class_name = unsafe { get_class_name(ev_obj) }.unwrap_or_default();
                    // Grandchild events inherit the category's class GUID.
                    // SAFETY: ev_obj is valid and qualifier read is non-mutating.
                    let ev_version =
                        unsafe { get_event_version_qualifier(ev_obj) }.unwrap_or(version);
                    // SAFETY: ev_obj is valid and qualifier reads are non-mutating.
                    let opcodes = unsafe { get_event_types(ev_obj) };
                    for (opcode, name) in opcodes {
                        events.push(MofEventClass {
                            class_guid,
                            class_name: cat_name.clone(),
                            wmi_class_name: ev_class_name.clone(),
                            opcode,
                            version: ev_version,
                            event_type_name: name,
                        });
                    }
                }
            }
        }

        providers.push(MofProvider {
            name: class_name,
            provider_guid,
            events,
        });
    }

    Ok(providers)
}

// =============================================================================
// WMI helpers
// =============================================================================

/// Executes a WQL query and collects all result objects.
///
/// # Safety
///
/// `services` must be a valid WMI connection.
unsafe fn wmi_query(services: &IWbemServices, query: &str) -> Result<Vec<IWbemClassObject>> {
    // SAFETY: ExecQuery with valid BSTR parameters on a connected IWbemServices.
    let enumerator: IEnumWbemClassObject = unsafe {
        services
            .ExecQuery(
                &BSTR::from("WQL"),
                &BSTR::from(query),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                None,
            )
            .map_err(Error::Com)?
    };

    let mut results = Vec::new();
    loop {
        let mut row = [None];
        let mut returned = 0u32;
        // SAFETY: Enumerating WMI results with a valid enumerator.
        let _hr = unsafe { enumerator.Next(WBEM_INFINITE, &mut row, &raw mut returned) };
        if returned == 0 {
            break;
        }
        if let Some(obj) = row[0].take() {
            results.push(obj);
        }
    }

    Ok(results)
}

/// Reads the `__CLASS` system property from a WMI object.
///
/// # Safety
///
/// `obj` must be a valid `IWbemClassObject`.
unsafe fn get_class_name(obj: &IWbemClassObject) -> Option<String> {
    let mut val = VARIANT::default();
    // SAFETY: Reading a system property from a valid WMI object.
    unsafe { obj.Get(w!("__CLASS"), 0, &raw mut val, None, None).ok()? };
    bstr_from_variant(&val)
}

/// Reads the `__SUPERCLASS` system property, naming this class's parent.
///
/// `None` for a root class, which is how the subtree index skips anything that
/// cannot be attached to a parent.
unsafe fn get_superclass(obj: &IWbemClassObject) -> Option<String> {
    let mut val = VARIANT::default();
    // SAFETY: Reading a system property from a valid WMI object.
    let result = unsafe { obj.Get(w!("__SUPERCLASS"), 0, &raw mut val, None, None) };
    result.ok()?;
    bstr_from_variant(&val)
}

/// Reads the `Guid` qualifier from a WMI class object and parses it as a GUID.
///
/// # Safety
///
/// `obj` must be a valid `IWbemClassObject`.
unsafe fn get_class_guid_qualifier(obj: &IWbemClassObject) -> Option<GUID> {
    // SAFETY: Getting the qualifier set from a valid WMI object.
    let qual_set = unsafe { obj.GetQualifierSet().ok()? };
    let mut val = VARIANT::default();
    let mut flavor = 0i32;
    // SAFETY: Reading a named qualifier from a valid qualifier set.
    unsafe {
        qual_set
            .Get(w!("Guid"), 0, &raw mut val, &raw mut flavor)
            .ok()?;
    };
    let guid_str = bstr_from_variant(&val)?;
    parse_wmi_guid(&guid_str)
}

/// Reads the `EventVersion` qualifier (u32) from a WMI class.
///
/// # Safety
///
/// `obj` must be a valid `IWbemClassObject`.
unsafe fn get_event_version_qualifier(obj: &IWbemClassObject) -> Option<u8> {
    // SAFETY: Getting the qualifier set from a valid WMI object.
    let qual_set = unsafe { obj.GetQualifierSet().ok()? };
    let mut val = VARIANT::default();
    let mut flavor = 0i32;
    // SAFETY: Reading a named qualifier from a valid qualifier set.
    unsafe {
        qual_set
            .Get(w!("EventVersion"), 0, &raw mut val, &raw mut flavor)
            .ok()?;
    };
    i32_from_variant(&val).and_then(|v| u8::try_from(v).ok())
}

/// Reads `EventType` and `EventTypeName` qualifiers from a WMI event class.
///
/// `EventType` is a VT_I4 or array of VT_I4 containing opcode values.
/// `EventTypeName` is a BSTR or array of BSTR with corresponding names.
///
/// # Safety
///
/// `obj` must be a valid `IWbemClassObject`.
unsafe fn get_event_types(obj: &IWbemClassObject) -> Vec<(u8, String)> {
    // SAFETY: Getting the qualifier set from a valid WMI object.
    let Ok(qual_set) = (unsafe { obj.GetQualifierSet() }) else {
        return Vec::new();
    };

    // Read EventType qualifier — may be a single value or an array.
    let mut type_val = VARIANT::default();
    let mut flavor = 0i32;
    // SAFETY: Reading a named qualifier from a valid qualifier set.
    if unsafe { qual_set.Get(w!("EventType"), 0, &raw mut type_val, &raw mut flavor) }.is_err() {
        return Vec::new();
    }

    let opcodes = variant_to_i32_list(&type_val);
    if opcodes.is_empty() {
        return Vec::new();
    }

    // Read EventTypeName qualifier — parallel array of names.
    let mut name_val = VARIANT::default();
    // SAFETY: Reading a named qualifier from a valid qualifier set.
    let names =
        if unsafe { qual_set.Get(w!("EventTypeName"), 0, &raw mut name_val, &raw mut flavor) }
            .is_ok()
        {
            variant_to_string_list(&name_val)
        } else {
            Vec::new()
        };

    opcodes
        .into_iter()
        .enumerate()
        .filter_map(|(i, op)| {
            let opcode = u8::try_from(op).ok()?;
            let name = names.get(i).cloned().unwrap_or_default();
            Some((opcode, name))
        })
        .collect()
}

// =============================================================================
// VARIANT helpers
// =============================================================================

/// Extracts a `String` from a `VARIANT` containing a `BSTR`.
fn bstr_from_variant(val: &VARIANT) -> Option<String> {
    use windows::Win32::System::Variant::VT_BSTR;

    // SAFETY: We check the type tag before accessing the union field.
    unsafe {
        let inner = &val.Anonymous.Anonymous;
        if inner.vt != VT_BSTR {
            return None;
        }
        let bstr = &inner.Anonymous.bstrVal;
        Some(bstr.to_string())
    }
}

/// Extracts an `i32` from a `VARIANT` containing a `VT_I4`.
fn i32_from_variant(val: &VARIANT) -> Option<i32> {
    use windows::Win32::System::Variant::VT_I4;

    // SAFETY: We check the type tag before accessing the union field.
    unsafe {
        let inner = &val.Anonymous.Anonymous;
        if inner.vt != VT_I4 {
            return None;
        }
        Some(inner.Anonymous.lVal)
    }
}

/// Extracts a list of `i32` values from a VARIANT.
///
/// Handles both scalar VT_I4 and VT_ARRAY|VT_I4 cases.
fn variant_to_i32_list(val: &VARIANT) -> Vec<i32> {
    // Try scalar first
    if let Some(v) = i32_from_variant(val) {
        return vec![v];
    }

    // Try SAFEARRAY of i32
    extract_safearray_i32(val).unwrap_or_default()
}

/// Extracts a list of `String` values from a VARIANT.
///
/// Handles both scalar VT_BSTR and VT_ARRAY|VT_BSTR cases.
fn variant_to_string_list(val: &VARIANT) -> Vec<String> {
    // Try scalar first
    if let Some(s) = bstr_from_variant(val) {
        return vec![s];
    }

    // Try SAFEARRAY of BSTR
    extract_safearray_bstr(val).unwrap_or_default()
}

/// Extracts i32 values from a SAFEARRAY VARIANT.
fn extract_safearray_i32(val: &VARIANT) -> Option<Vec<i32>> {
    use windows::Win32::System::{
        Ole::{SafeArrayAccessData, SafeArrayGetLBound, SafeArrayGetUBound, SafeArrayUnaccessData},
        Variant::{VT_ARRAY, VT_I4},
    };

    // SAFETY: We check the type tag before accessing the parray union field.
    unsafe {
        let inner = &val.Anonymous.Anonymous;
        if inner.vt != VT_ARRAY | VT_I4 {
            return None;
        }

        let psa = inner.Anonymous.parray;
        if psa.is_null() {
            return None;
        }

        let lower = SafeArrayGetLBound(&raw const *psa, 1).ok()?;
        let upper = SafeArrayGetUBound(&raw const *psa, 1).ok()?;

        let count = (upper - lower + 1) as usize;
        let mut data_ptr: *mut std::ffi::c_void = std::ptr::null_mut();
        SafeArrayAccessData(&raw const *psa, &raw mut data_ptr).ok()?;

        let slice = std::slice::from_raw_parts(data_ptr.cast::<i32>(), count);
        let result = slice.to_vec();

        // Data is already copied — failure to unaccess is non-fatal.
        if let Err(e) = SafeArrayUnaccessData(&raw const *psa) {
            log::warn!("SafeArrayUnaccessData failed: {e}");
        }
        Some(result)
    }
}

/// Extracts BSTR values from a SAFEARRAY VARIANT.
fn extract_safearray_bstr(val: &VARIANT) -> Option<Vec<String>> {
    use windows::Win32::System::{
        Ole::{SafeArrayAccessData, SafeArrayGetLBound, SafeArrayGetUBound, SafeArrayUnaccessData},
        Variant::{VT_ARRAY, VT_BSTR},
    };

    // SAFETY: We check the type tag before accessing the parray union field.
    // Each element is a raw BSTR pointer (wide string with length prefix).
    unsafe {
        let inner = &val.Anonymous.Anonymous;
        if inner.vt != VT_ARRAY | VT_BSTR {
            return None;
        }

        let psa = inner.Anonymous.parray;
        if psa.is_null() {
            return None;
        }

        let lower = SafeArrayGetLBound(&raw const *psa, 1).ok()?;
        let upper = SafeArrayGetUBound(&raw const *psa, 1).ok()?;

        let count = (upper - lower + 1) as usize;
        let mut data_ptr: *mut std::ffi::c_void = std::ptr::null_mut();
        SafeArrayAccessData(&raw const *psa, &raw mut data_ptr).ok()?;

        let bstr_ptrs: &[*const u16] =
            std::slice::from_raw_parts(data_ptr.cast::<*const u16>(), count);
        let mut result = Vec::with_capacity(count);
        for &ptr in bstr_ptrs {
            if ptr.is_null() {
                result.push(String::new());
            } else {
                // BSTR: find length by scanning for null terminator.
                let mut len = 0;
                while *ptr.add(len) != 0 {
                    len += 1;
                }
                let slice = std::slice::from_raw_parts(ptr, len);
                result.push(String::from_utf16_lossy(slice));
            }
        }

        // Data is already copied — failure to unaccess is non-fatal.
        if let Err(e) = SafeArrayUnaccessData(&raw const *psa) {
            log::warn!("SafeArrayUnaccessData failed: {e}");
        }
        Some(result)
    }
}

// =============================================================================
// GUID parsing
// =============================================================================

/// Parses a WMI GUID string like `{12345678-1234-1234-1234-123456789ABC}`
/// into a `GUID`. Also handles unbraced format.
fn parse_wmi_guid(s: &str) -> Option<GUID> {
    let s = s.trim().trim_start_matches('{').trim_end_matches('}');
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 {
        return None;
    }

    let data1 = u32::from_str_radix(parts[0], 16).ok()?;
    let data2 = u16::from_str_radix(parts[1], 16).ok()?;
    let data3 = u16::from_str_radix(parts[2], 16).ok()?;

    // data4 is parts[3] (2 bytes) + parts[4] (6 bytes) = 8 bytes
    let d4_high = u16::from_str_radix(parts[3], 16).ok()?;
    let d4_low = u64::from_str_radix(parts[4], 16).ok()?;

    let data4 = [
        (d4_high >> 8) as u8,
        d4_high as u8,
        (d4_low >> 40) as u8,
        (d4_low >> 32) as u8,
        (d4_low >> 24) as u8,
        (d4_low >> 16) as u8,
        (d4_low >> 8) as u8,
        d4_low as u8,
    ];

    Some(GUID {
        data1,
        data2,
        data3,
        data4,
    })
}

// =============================================================================
// MOF TDH query functions
// =============================================================================

/// Indicates a classic/MOF event format (`EventHeader.Flags` is `u16`).
const EVENT_HEADER_FLAG_CLASSIC_HEADER: u16 = EVENT_HEADER_FLAG_CLASSIC_HEADER_U32 as u16;

/// Pointer size is 64-bit (`EventHeader.Flags` is `u16`).
const EVENT_HEADER_FLAG_64_BIT_HEADER: u16 = EVENT_HEADER_FLAG_64_BIT_HEADER_U32 as u16;

/// Retrieves field definitions for MOF event `(class_guid, opcode, version)`.
///
/// `class_guid` is the event class GUID (not the provider registration GUID).
/// Constructs a synthetic `EVENT_RECORD` with the classic header flag and
/// probes TDH for the event schema. MOF events are identified by
/// `(class_guid, opcode, version)` rather than `(provider_guid, event_id, version)`.
/// Returns an empty vector if TDH has no schema for this event.
///
/// # Errors
///
/// Returns an error if the TDH API call fails (other than "not found").
pub fn get_mof_event_fields(
    class_guid: &GUID,
    opcode: u8,
    version: u8,
) -> Result<Vec<EventFieldInfo>> {
    let Some(buffer) = get_mof_trace_event_info(class_guid, opcode, version) else {
        return Ok(Vec::new());
    };

    // SAFETY: buffer is a Vec<u64> filled by TdhGetEventInformation; viewing as bytes is valid.
    let buffer_bytes: &[u8] =
        unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), buffer.len() * 8) };
    // SAFETY: Buffer was filled by a successful TdhGetEventInformation call.
    let info = unsafe { trace_event_info_from_buffer(buffer_bytes) };

    // SAFETY: Accessing TRACE_EVENT_INFO fields and property array within the buffer.
    Ok(unsafe { extract_fields_from_trace_event_info(info, buffer_bytes) })
}

/// Gets the name for a MOF event from TDH metadata.
///
/// Constructs a synthetic `EVENT_RECORD` and reads the task and opcode names
/// from the resulting `TRACE_EVENT_INFO`. Returns a combined name where possible.
pub fn get_mof_event_name(class_guid: &GUID, opcode: u8, version: u8) -> Option<String> {
    let buffer = get_mof_trace_event_info(class_guid, opcode, version)?;

    // SAFETY: buffer is a Vec<u64> filled by TdhGetEventInformation; viewing as bytes is valid.
    let buffer_bytes: &[u8] =
        unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), buffer.len() * 8) };
    // SAFETY: Buffer was filled by a successful TdhGetEventInformation call.
    let info = unsafe { trace_event_info_from_buffer(buffer_bytes) };

    let task_name = if info.TaskNameOffset > 0 {
        extract_string_from_buffer(buffer_bytes, info.TaskNameOffset as usize)
            .trim()
            .to_owned()
    } else {
        String::new()
    };

    let opcode_name = if info.OpcodeNameOffset > 0 {
        extract_string_from_buffer(buffer_bytes, info.OpcodeNameOffset as usize)
            .trim()
            .to_owned()
    } else {
        String::new()
    };

    if !task_name.is_empty() && !opcode_name.is_empty() {
        // Strip the "task_name/" prefix that TDH sometimes adds to opcode names
        let clean_opcode = opcode_name
            .strip_prefix(&format!("{task_name}/"))
            .unwrap_or(&opcode_name);

        // Also strip the task_name prefix without separator — TDH sometimes
        // includes it directly (e.g., "ALPC_Send_Message" for task "ALPC")
        let clean_opcode = if clean_opcode.len() > task_name.len()
            && clean_opcode[..task_name.len()].eq_ignore_ascii_case(&task_name)
        {
            &clean_opcode[task_name.len()..]
        } else {
            clean_opcode
        };
        Some(format!("{task_name}{clean_opcode}"))
    } else if !opcode_name.is_empty() {
        Some(opcode_name)
    } else if !task_name.is_empty() {
        Some(task_name)
    } else {
        None
    }
}

/// Internal helper: builds a synthetic EVENT_RECORD and calls `TdhGetEventInformation`.
///
/// Returns the raw buffer containing a `TRACE_EVENT_INFO` at its start,
/// or `None` if TDH has no schema for this event. Callers should use
/// [`trace_event_info_from_buffer`] to obtain a reference.
fn get_mof_trace_event_info(class_guid: &GUID, opcode: u8, version: u8) -> Option<Vec<u64>> {
    // Build a synthetic EVENT_RECORD with the classic header flag.
    // SAFETY: EVENT_RECORD is a plain C struct; zeroing is a valid initialisation.
    let mut record: EVENT_RECORD = unsafe { std::mem::zeroed() };
    record.EventHeader.ProviderId = *class_guid;
    record.EventHeader.EventDescriptor.Opcode = opcode;
    record.EventHeader.EventDescriptor.Version = version;
    record.EventHeader.EventDescriptor.Id = 0;
    record.EventHeader.Flags = EVENT_HEADER_FLAG_CLASSIC_HEADER | EVENT_HEADER_FLAG_64_BIT_HEADER;

    let mut buffer_size: u32 = 0;

    // SAFETY: First call with null buffer to query required size.
    let status = WIN32_ERROR_CODE(unsafe {
        TdhGetEventInformation(
            std::ptr::from_ref(&record),
            None,
            None,
            &raw mut buffer_size,
        )
    });

    if status != ERROR_INSUFFICIENT_BUFFER || buffer_size == 0 {
        return None;
    }

    // Allocate as u64 to exactly match the 8-byte alignment of TRACE_EVENT_INFO.
    const _: () = assert!(
        align_of::<TRACE_EVENT_INFO>() == align_of::<u64>(),
        "TRACE_EVENT_INFO alignment changed — update allocation type"
    );
    let mut buffer = vec![0u64; buffer_size.div_ceil(8) as usize];
    let info_ptr = buffer.as_mut_ptr().cast::<TRACE_EVENT_INFO>();

    // SAFETY: Buffer is 8-byte aligned with at least buffer_size bytes capacity.
    let status = WIN32_ERROR_CODE(unsafe {
        TdhGetEventInformation(
            std::ptr::from_ref(&record),
            None,
            Some(info_ptr),
            &raw mut buffer_size,
        )
    });

    if status != ERROR_SUCCESS {
        return None;
    }

    Some(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_wmi_guid_braced() {
        let Some(guid) = parse_wmi_guid("{3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c}") else {
            panic!("expected valid braced GUID");
        };
        assert_eq!(
            guid,
            GUID::from_u128(0x3d6fa8d0_fe05_11d0_9dda_00c04fd7ba7c)
        );
    }

    #[test]
    fn test_parse_wmi_guid_unbraced() {
        let Some(guid) = parse_wmi_guid("3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c") else {
            panic!("expected valid unbraced GUID");
        };
        assert_eq!(
            guid,
            GUID::from_u128(0x3d6fa8d0_fe05_11d0_9dda_00c04fd7ba7c)
        );
    }

    #[test]
    fn test_parse_wmi_guid_invalid() {
        assert!(parse_wmi_guid("not-a-guid").is_none());
        assert!(parse_wmi_guid("").is_none());
    }
}
