//! TDH (Trace Data Helper) query functions for manifest-based ETW providers.
//!
//! Provides functions to query provider manifests via the Windows TDH APIs.
//! Includes keyword/level/opcode/task enumeration, event field introspection,
//! and name generation helpers.

use crate::{Error, Result};
use windows::{
    Win32::{
        Foundation::{
            ERROR_INSUFFICIENT_BUFFER, ERROR_NOT_FOUND, ERROR_SUCCESS, WIN32_ERROR,
            WIN32_ERROR as WIN32_ERROR_CODE,
        },
        System::Diagnostics::Etw::{
            EVENT_DESCRIPTOR, EVENT_FIELD_TYPE, PROVIDER_ENUMERATION_INFO, PROVIDER_EVENT_INFO,
            PROVIDER_FIELD_INFO, PROVIDER_FIELD_INFOARRAY, PropertyParamCount, PropertyParamLength,
            PropertyStruct, TRACE_EVENT_INFO, TdhEnumerateManifestProviderEvents,
            TdhEnumerateProviderFieldInformation, TdhEnumerateProviders,
            TdhGetManifestEventInformation,
        },
    },
    core::GUID,
};

// TDH property flags — `u32` versions of the `PROPERTY_FLAGS` constants from the
// `windows` crate, matching the type used in [`EventFieldInfo::flags`].
/// Property is a nested struct containing child properties.
pub const PROPERTY_STRUCT: u32 = PropertyStruct.0 as u32;
/// Property length is specified by another property's value.
pub const PROPERTY_PARAM_LENGTH: u32 = PropertyParamLength.0 as u32;
/// Property array count is specified by another property's value.
pub const PROPERTY_PARAM_COUNT: u32 = PropertyParamCount.0 as u32;

// =============================================================================
// Types
// =============================================================================

/// Information about an ETW provider field (keyword, level, opcode, task, or channel).
///
/// Retrieved from the provider's manifest via TDH APIs.
#[derive(Debug, Clone)]
pub struct ProviderFieldInfo {
    /// The name of the field (e.g., "PROCESS" for a keyword).
    pub name: String,
    /// Optional description from the manifest's string table.
    pub description: Option<String>,
    /// The numeric value (mask for keywords, ID for others).
    pub value: u64,
}

/// Information about an ETW provider event.
///
/// Retrieved from the provider's manifest via TDH APIs.
#[derive(Debug, Clone)]
pub struct ProviderEventInfo {
    /// The event ID.
    pub id: u16,
    /// The event version.
    pub version: u8,
    /// The channel.
    pub channel: u8,
    /// The trace level.
    pub level: u8,
    /// The opcode.
    pub opcode: u8,
    /// The task ID.
    pub task: u16,
    /// The keyword mask.
    pub keyword: u64,
}

/// Information about a single field (property) within an ETW event.
///
/// Retrieved from the provider's manifest via `TdhGetManifestEventInformation`,
/// or from MOF schemas via [`mof::get_mof_event_fields`](super::mof::get_mof_event_fields).
#[derive(Debug, Clone)]
pub struct EventFieldInfo {
    /// The field name (e.g., "FileName", "ProcessId").
    pub name: String,
    /// The TDH InType value (e.g., 1 = UnicodeString, 8 = UInt32, 16 = Pointer).
    /// For struct properties ([`PROPERTY_STRUCT`]), this is 0 (not meaningful).
    pub in_type: u16,
    /// The TDH OutType value (e.g., 35 = Utf8). 0 for struct properties.
    pub out_type: u16,
    /// Property flags from TDH ([`PROPERTY_STRUCT`], [`PROPERTY_PARAM_LENGTH`],
    /// [`PROPERTY_PARAM_COUNT`]).
    pub flags: u32,
    /// If [`PROPERTY_PARAM_LENGTH`] is set in `flags`, this is the index of the
    /// field that contains the length value.
    pub length_property_index: Option<u16>,
    /// Fixed array element count (1 = scalar, >1 = fixed-length array).
    ///
    /// Only valid when [`PROPERTY_PARAM_COUNT`] is NOT set in `flags`.
    /// When set, use [`count_property_index`](Self::count_property_index) instead.
    pub count: u16,
    /// If [`PROPERTY_PARAM_COUNT`] is set in `flags`, this is the index of the
    /// field that contains the element count.
    pub count_property_index: Option<u16>,
    /// Fixed byte length of this field (0 = unknown/variable).
    ///
    /// Only valid when [`PROPERTY_PARAM_LENGTH`] is NOT set in `flags`.
    /// When set, this value is a property index instead.
    pub length: u16,
    /// For struct properties ([`PROPERTY_STRUCT`]): computed total byte size per
    /// struct element.
    /// `None` if any member is variable-length or nested, or if the property is not a struct.
    pub struct_byte_size: Option<u32>,
}

impl EventFieldInfo {
    /// Returns the effective byte length for this field given a per-element byte size.
    ///
    /// Uses the property's `length` if set, otherwise falls back to `count * element_size`.
    /// A count of 0 is treated as 1 (scalar).
    pub const fn effective_byte_length(&self, element_size: u16) -> u16 {
        if self.length > 0 {
            self.length
        } else {
            let count = if self.count == 0 { 1 } else { self.count };
            count * element_size
        }
    }
}

// =============================================================================
// Manifest query functions
// =============================================================================

/// Retrieves keyword definitions from a provider's manifest.
///
/// Uses `TdhEnumerateProviderFieldInformation` to query the operating system
/// for the keywords defined in `provider_guid`'s instrumentation manifest.
/// Returns an empty vector if the provider has no keywords or no manifest.
///
/// # Errors
///
/// Returns an error if the TDH API call fails (other than "not found").
///
/// # Example
///
/// ```no_run
/// use generate_provider::manifest::get_provider_keywords;
/// use windows::core::GUID;
///
/// fn main() -> generate_provider::Result<()> {
///     let guid = GUID::from_u128(0x151f55dc_467d_471f_83b5_5f889d46ff66);
///     let keywords = get_provider_keywords(&guid)?;
///     for kw in &keywords {
///         println!("{}: 0x{:X}", kw.name, kw.value);
///     }
///     Ok(())
/// }
/// ```
pub fn get_provider_keywords(provider_guid: &GUID) -> Result<Vec<ProviderFieldInfo>> {
    // EventKeywordInformation = 0
    get_provider_field_info(provider_guid, EVENT_FIELD_TYPE(0))
}

/// Retrieves level definitions from a provider's manifest.
///
/// Uses `TdhEnumerateProviderFieldInformation` to query the operating system
/// for the trace levels defined in `provider_guid`'s instrumentation manifest.
/// Returns an empty vector if the provider has no levels or no manifest.
///
/// # Errors
///
/// Returns an error if the TDH API call fails (other than "not found").
pub fn get_provider_levels(provider_guid: &GUID) -> Result<Vec<ProviderFieldInfo>> {
    // EventLevelInformation = 1
    get_provider_field_info(provider_guid, EVENT_FIELD_TYPE(1))
}

/// Retrieves opcode definitions from a provider's manifest.
///
/// Uses `TdhEnumerateProviderFieldInformation` to query the operating system
/// for the opcodes defined in `provider_guid`'s instrumentation manifest.
/// Returns an empty vector if the provider has no opcodes or no manifest.
///
/// # Errors
///
/// Returns an error if the TDH API call fails (other than "not found").
pub fn get_provider_opcodes(provider_guid: &GUID) -> Result<Vec<ProviderFieldInfo>> {
    // EventOpcodeInformation = 3
    get_provider_field_info(provider_guid, EVENT_FIELD_TYPE(3))
}

/// Retrieves task definitions from a provider's manifest.
///
/// Uses `TdhEnumerateProviderFieldInformation` to query the operating system
/// for the tasks defined in `provider_guid`'s instrumentation manifest.
/// Returns an empty vector if the provider has no tasks or no manifest.
///
/// # Errors
///
/// Returns an error if the TDH API call fails (other than "not found").
pub fn get_provider_tasks(provider_guid: &GUID) -> Result<Vec<ProviderFieldInfo>> {
    // EventTaskInformation = 2
    get_provider_field_info(provider_guid, EVENT_FIELD_TYPE(2))
}

/// Retrieves event definitions from a provider's manifest.
///
/// Uses `TdhEnumerateManifestProviderEvents` to query the operating system
/// for all events defined in `provider_guid`'s instrumentation manifest.
/// Returns an empty vector if the provider has no events or no manifest.
///
/// # Errors
///
/// Returns an error if the TDH API call fails (other than "not found").
///
/// # Example
///
/// ```no_run
/// use generate_provider::manifest::get_provider_events;
/// use windows::core::GUID;
///
/// fn main() -> generate_provider::Result<()> {
///     let guid = GUID::from_u128(0x151f55dc_467d_471f_83b5_5f889d46ff66);
///     let events = get_provider_events(&guid)?;
///     for ev in &events {
///         println!(
///             "Event ID {}: level={}, opcode={}",
///             ev.id, ev.level, ev.opcode
///         );
///     }
///     Ok(())
/// }
/// ```
pub fn get_provider_events(provider_guid: &GUID) -> Result<Vec<ProviderEventInfo>> {
    let mut buffer_size = 0u32;

    // First call to get required buffer size
    // SAFETY: First call with null buffer to query required size.
    let status = WIN32_ERROR_CODE(unsafe {
        TdhEnumerateManifestProviderEvents(provider_guid, None, &raw mut buffer_size)
    });

    // Provider may not have a manifest
    if status == ERROR_NOT_FOUND {
        return Ok(Vec::new());
    }

    // Some providers return empty - handle ERROR_SUCCESS with zero size
    if status == ERROR_SUCCESS && buffer_size == 0 {
        return Ok(Vec::new());
    }

    if status != ERROR_INSUFFICIENT_BUFFER && status != ERROR_SUCCESS {
        return Err(Error::from(WIN32_ERROR(status.0)));
    }

    // Allocate buffer aligned for PROVIDER_EVENT_INFO (8-byte aligned).
    const _: () = assert!(
        align_of::<PROVIDER_EVENT_INFO>() == align_of::<u64>(),
        "PROVIDER_EVENT_INFO alignment changed — update allocation type"
    );
    let mut buffer = vec![0u64; buffer_size.div_ceil(8) as usize];
    let event_info = buffer.as_mut_ptr().cast::<PROVIDER_EVENT_INFO>();

    // SAFETY: Buffer is 8-byte aligned with at least buffer_size bytes capacity.
    let status = WIN32_ERROR_CODE(unsafe {
        TdhEnumerateManifestProviderEvents(provider_guid, Some(event_info), &raw mut buffer_size)
    });

    if status != ERROR_SUCCESS {
        return Err(Error::from(WIN32_ERROR(status.0)));
    }

    // SAFETY: TdhEnumerateManifestProviderEvents succeeded, so event_info is valid.
    let events = unsafe {
        let info = &*event_info;
        let count = info.NumberOfEvents as usize;
        let events_ptr = info.EventDescriptorsArray.as_ptr();

        let mut result = Vec::with_capacity(count);
        for i in 0..count {
            let event: &EVENT_DESCRIPTOR = &*events_ptr.add(i);
            result.push(ProviderEventInfo {
                id: event.Id,
                version: event.Version,
                channel: event.Channel,
                level: event.Level,
                opcode: event.Opcode,
                task: event.Task,
                keyword: event.Keyword,
            });
        }
        result
    };

    Ok(events)
}

/// Retrieves field definitions for event `event_id`/`version` from a provider's manifest.
///
/// Uses `TdhGetManifestEventInformation` to query the operating system for the
/// fields (properties) of the specified event in `provider_guid`'s manifest.
/// Returns an empty vector if the event has no fields or cannot be found.
///
/// # Errors
///
/// Returns an error if the TDH API call fails.
pub fn get_event_fields(
    provider_guid: &GUID,
    event: &ProviderEventInfo,
) -> Result<Vec<EventFieldInfo>> {
    let event_descriptor = EVENT_DESCRIPTOR {
        Id: event.id,
        Version: event.version,
        Channel: event.channel,
        Level: event.level,
        Opcode: event.opcode,
        Task: event.task,
        Keyword: event.keyword,
    };

    let mut buffer_size = 0u32;

    // SAFETY: First call with null buffer to query required size.
    let status = WIN32_ERROR_CODE(unsafe {
        TdhGetManifestEventInformation(
            provider_guid,
            &raw const event_descriptor,
            None,
            &raw mut buffer_size,
        )
    });

    if status != ERROR_INSUFFICIENT_BUFFER {
        return Ok(Vec::new());
    }

    // Allocate as u64 to exactly match the 8-byte alignment of TRACE_EVENT_INFO.
    const _: () = assert!(
        align_of::<TRACE_EVENT_INFO>() == align_of::<u64>(),
        "TRACE_EVENT_INFO alignment changed — update allocation type"
    );
    let mut buffer = vec![0u64; buffer_size.div_ceil(8) as usize];
    let event_info = buffer.as_mut_ptr().cast::<TRACE_EVENT_INFO>();

    // SAFETY: Buffer is 8-byte aligned with at least buffer_size bytes capacity.
    let status = WIN32_ERROR_CODE(unsafe {
        TdhGetManifestEventInformation(
            provider_guid,
            &raw const event_descriptor,
            Some(event_info),
            &raw mut buffer_size,
        )
    });

    if status != ERROR_SUCCESS {
        return Err(Error::from(WIN32_ERROR(status.0)));
    }

    // SAFETY: TdhGetManifestEventInformation succeeded, so event_info is valid.
    // buffer_size is updated by TDH to the number of bytes written.
    let buffer_bytes: &[u8] =
        unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), buffer_size as usize) };
    // SAFETY: TdhGetManifestEventInformation succeeded, so event_info is valid.
    Ok(unsafe {
        let info = &*event_info;
        extract_fields_from_trace_event_info(info, buffer_bytes)
    })
}

/// Gets the name of an event from the provider's manifest.
///
/// Returns `None` if the event name cannot be retrieved or is unsuitable
/// (too long, contains invalid characters, or is a generic name).
///
/// For events that share a task but differ by opcode (like Start/Stop pairs),
/// the function combines the task name with the opcode to create a unique name.
/// Event name candidates returned by [`get_event_name`].
#[derive(Debug)]
pub struct EventNameInfo {
    /// Best name (task-only when unique, or task+opcode for disambiguation).
    pub full: String,
    /// Opcode name alone, if valid. Shorter alternative when the opcode is
    /// globally unique across the provider.
    pub opcode_only: Option<String>,
}

/// Gets the task/opcode name for an event from its provider's manifest.
///
/// Returns an [`EventNameInfo`] containing the best composite name and an
/// optional shorter opcode-only alternative.  Returns `None` if the manifest
/// is unavailable or names cannot be determined.
pub fn get_event_name(provider_guid: &GUID, event_id: u16) -> Option<EventNameInfo> {
    let events = get_provider_events(provider_guid).ok()?;
    let event = events.iter().find(|e| e.id == event_id)?;
    let all: Vec<&ProviderEventInfo> = events.iter().collect();
    get_event_name_for(provider_guid, event, &all)
}

/// [`get_event_name`] for an event the caller already has, with the provider's
/// event list supplied rather than re-queried.
///
/// The id-taking form enumerates the provider twice over: once to find the
/// descriptor and once more inside, to see how many event ids share this task.
/// Called once per event during generation, that is an enumeration per event.
/// Generation holds both the event and the list, so it passes them.
pub fn get_event_name_for(
    provider_guid: &GUID,
    event: &ProviderEventInfo,
    events: &[&ProviderEventInfo],
) -> Option<EventNameInfo> {
    let event_descriptor = EVENT_DESCRIPTOR {
        Id: event.id,
        Version: event.version,
        Channel: event.channel,
        Level: event.level,
        Opcode: event.opcode,
        Task: event.task,
        Keyword: event.keyword,
    };

    let mut buffer_size = 0u32;

    // First call to get required buffer size
    // SAFETY: First call with null buffer to query required size.
    let status = WIN32_ERROR_CODE(unsafe {
        TdhGetManifestEventInformation(
            provider_guid,
            &raw const event_descriptor,
            None,
            &raw mut buffer_size,
        )
    });

    if status != ERROR_INSUFFICIENT_BUFFER {
        return None;
    }

    // Allocate buffer aligned for TRACE_EVENT_INFO (8-byte aligned).
    let mut buffer = vec![0u64; buffer_size.div_ceil(8) as usize];
    let event_info = buffer.as_mut_ptr().cast::<TRACE_EVENT_INFO>();

    // SAFETY: Buffer is 8-byte aligned with at least buffer_size bytes capacity.
    let status = WIN32_ERROR_CODE(unsafe {
        TdhGetManifestEventInformation(
            provider_guid,
            &raw const event_descriptor,
            Some(event_info),
            &raw mut buffer_size,
        )
    });

    if status != ERROR_SUCCESS {
        return None;
    }

    // SAFETY: TdhGetManifestEventInformation succeeded, so event_info is valid.
    // buffer_size is updated by TDH to the number of bytes written.
    let buffer_bytes: &[u8] =
        unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), buffer_size as usize) };
    // SAFETY: TdhGetManifestEventInformation succeeded, so event_info is valid.
    unsafe {
        let info = &*event_info;

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

        // Opcode names from TDH can be human-readable sentences like "Data sent."
        // Strip trailing punctuation so they convert to clean identifiers.
        let opcode_name = opcode_name.trim_end_matches('.').trim().to_owned();

        // Helper to validate a name for use as a Rust identifier source
        let is_valid_name = |name: &str| -> bool {
            !name.is_empty()
                && name.len() <= 50
                && !name.contains('.')
                && name != "Info"
                && name != "Start"
                && name != "Stop"
        };

        // Check if task name is usable
        let task_valid = event.task != 0 && is_valid_name(&task_name);

        // Opcode names may contain spaces (e.g., "Data sent") — that's fine since
        // event_name_to_rust() converts them to underscores. Only reject truly
        // unusable names.
        let opcode_valid = !opcode_name.is_empty()
            && opcode_name.len() <= 60
            && opcode_name != "Info"
            && opcode_name != "Start"
            && opcode_name != "Stop";

        let opcode_only = opcode_valid.then(|| opcode_name.clone());

        if task_valid {
            // Check if multiple unique event IDs share this task (need to disambiguate with opcode)
            let unique_ids_with_same_task: std::collections::HashSet<u16> = events
                .iter()
                .filter(|e| e.task == event.task)
                .map(|e| e.id)
                .collect();

            if unique_ids_with_same_task.len() > 1 && opcode_valid {
                // Combine task + opcode for disambiguation (e.g., "TCPIP Data sent")
                return Some(EventNameInfo {
                    full: format!("{task_name} {opcode_name}"),
                    opcode_only,
                });
            }

            Some(EventNameInfo {
                full: task_name,
                opcode_only: None, // Task is already unique — no shorter alternative
            })
        } else if opcode_valid {
            // Fall back to opcode name (e.g., kernel_registry uses opcode for event names)
            Some(EventNameInfo {
                full: opcode_name,
                opcode_only: None, // Already using opcode alone
            })
        } else {
            None
        }
    }
}

// =============================================================================
// Name generation helpers
// =============================================================================

/// Returns `true` if a keyword name is a channel/system keyword that we don't define.
///
/// These are things like `"Microsoft-Windows-X/Analytic"` or `"win:ResponseTime"`.
pub fn is_channel_keyword(name: &str) -> bool {
    name.contains('/') || name.starts_with("win:")
}

/// Converts a manifest keyword name to a valid Rust `SCREAMING_SNAKE_CASE` identifier.
///
/// Strips common prefixes like `WINEVENT_KEYWORD_`, `ut:`, `Keyword.`, etc.
pub fn keyword_name_to_rust(name: &str) -> String {
    // Remove common prefixes like "WINEVENT_KEYWORD_", "KERNEL_FILE_KEYWORD_", etc.
    let name = name
        .strip_prefix("ut:")
        .or_else(|| name.strip_prefix("Keyword."))
        .unwrap_or(name);

    // Strip any *_KEYWORD_ prefix (e.g., WINEVENT_KEYWORD_, KERNEL_FILE_KEYWORD_)
    let name = name.find("_KEYWORD_").map_or(name, |pos| &name[pos + 9..]);

    // Convert to SCREAMING_SNAKE_CASE
    let mut result = String::new();
    for (i, ch) in name.chars().enumerate() {
        if ch.is_uppercase() && i > 0 {
            let prev = name.chars().nth(i - 1).unwrap_or('_');
            if prev.is_lowercase() || prev.is_numeric() {
                result.push('_');
            }
        }
        result.push(ch.to_ascii_uppercase());
    }
    result.replace(['-', '.', '/'], "_")
}

/// Converts a manifest event/task name to a valid Rust `SCREAMING_SNAKE_CASE` identifier.
///
/// Strips provider namespace prefixes like `*_TASK_`, `*_KEYWORD_`, and
/// `KERNEL_*_` (e.g. `KERNEL_THREATINT_PROCESS_X` → `PROCESS_X`).
pub fn event_name_to_rust(name: &str) -> String {
    // Strip any *_TASK_ prefix (e.g., KERNEL_THREATINT_TASK_, KERNEL_NETWORK_TASK_)
    let name = name.find("_TASK_").map_or(name, |pos| &name[pos + 6..]);

    // Also strip any *_KEYWORD_ prefix that appears in event task names
    let name = name.find("_KEYWORD_").map_or(name, |pos| &name[pos + 9..]);

    // Strip KERNEL_*_ namespace prefixes (e.g. KERNEL_THREATINT_PROCESS_X → PROCESS_X).
    // These are Windows kernel provider internal namespaces that are redundant when the
    // provider context is already known.
    let name = name.strip_prefix("KERNEL_").map_or(name, |rest| {
        // Skip the provider segment after "KERNEL_" (e.g. "THREATINT_" → "PROCESS_X")
        rest.find('_').map_or(name, |pos| &rest[pos + 1..])
    });

    // Convert to SCREAMING_SNAKE_CASE
    let mut result = String::new();
    let mut prev_was_upper = false;

    for (i, ch) in name.chars().enumerate() {
        if ch == '_' || ch == '-' || ch == ' ' || ch == '.' {
            // Convert separators to underscore
            if !result.ends_with('_') {
                result.push('_');
            }
            prev_was_upper = false;
        } else if ch.is_uppercase() {
            // Insert underscore before uppercase if previous wasn't uppercase
            // and we're not at the start
            if i > 0 && !prev_was_upper && !result.ends_with('_') {
                result.push('_');
            }
            result.push(ch.to_ascii_uppercase());
            prev_was_upper = true;
        } else if ch.is_alphanumeric() {
            // Acronym→word boundary: when lowercase follows 3+ uppercase chars,
            // split before the last uppercase (e.g., "LBRRecord" → "LBR_RECORD",
            // "TCPCopy" → "TCP_COPY"). We require 3+ to avoid splitting short
            // PascalCase like "CSwitch" or "IPv6".
            if prev_was_upper && result.len() >= 3 {
                let bytes = result.as_bytes();
                if bytes[bytes.len() - 2].is_ascii_uppercase()
                    && bytes[bytes.len() - 3].is_ascii_uppercase()
                    && let Some(last) = result.pop()
                {
                    result.push('_');
                    result.push(last);
                }
            }
            result.push(ch.to_ascii_uppercase());
            prev_was_upper = false;
        }
        // Skip any other non-alphanumeric characters
    }

    // Clean up any double underscores
    while result.contains("__") {
        result = result.replace("__", "_");
    }

    // Remove leading/trailing underscores
    result.trim_matches('_').to_owned()
}

/// Gets the keyword name for an event based on its keyword mask.
///
/// Returns the most specific single-bit keyword name that is set in the mask.
/// Prefers more specific (higher bit value) keywords over generic ones.
pub fn get_event_keyword_name(provider_guid: &GUID, keyword_mask: u64) -> Option<String> {
    if keyword_mask == 0 {
        return None;
    }
    let keywords = get_provider_keywords(provider_guid).ok()?;
    get_event_keyword_name_in(&keywords, keyword_mask)
}

/// [`get_event_keyword_name`] against a keyword list the caller already has.
///
/// The querying form re-reads the provider's keywords on every call, which
/// generation makes once per event.
pub fn get_event_keyword_name_in(
    keywords: &[ProviderFieldInfo],
    keyword_mask: u64,
) -> Option<String> {
    if keyword_mask == 0 {
        return None;
    }

    // If the keyword mask exactly matches a single keyword, use it (if it's a valid name)
    if let Some(exact) = keywords.iter().find(|k| {
        k.value == keyword_mask
            && !is_channel_keyword(&k.name)
            && !k.name.contains('/')
            && !k.name.contains("Diagnostic")
    }) {
        return Some(exact.name.clone());
    }

    // Otherwise, find the most specific single-bit keyword that is set in the mask.
    // Sort by value descending to prefer more specific (higher) keywords.
    let mut matching: Vec<_> = keywords
        .iter()
        .filter(|k| {
            k.value != 0
                && k.value.is_power_of_two() // Single-bit keyword
                && (keyword_mask & k.value) == k.value // Bit is set in mask
                && !is_channel_keyword(&k.name) // Not a channel keyword
                && !k.name.contains('/') // Not a diagnostic/tracing keyword
                && !k.name.contains("Diagnostic")
        })
        .collect();

    matching.sort_by_key(|b| std::cmp::Reverse(b.value)); // Prefer higher values (more specific)
    matching.first().map(|k| k.name.clone())
}

/// Gets the best name for an event, trying the task name first, then keyword name.
///
/// Returns `(full_name, opcode_only_alternative)`. The `opcode_only` variant is
/// `Some` when the full name is a task+opcode composite and a shorter opcode-only
/// form exists.
pub fn get_best_event_name(
    provider_guid: &GUID,
    event: &ProviderEventInfo,
    events: &[&ProviderEventInfo],
    keywords: &[ProviderFieldInfo],
) -> Option<(String, Option<String>)> {
    // First try the task-based name
    if let Some(info) = get_event_name_for(provider_guid, event, events) {
        return Some((info.full, info.opcode_only));
    }

    // Fall back to keyword name for providers like threat_intelligence
    if let Some(keyword_name) = get_event_keyword_name_in(keywords, event.keyword) {
        // Validate keyword name
        let name = keyword_name.trim();
        if !name.is_empty()
            && name.len() <= 50
            && !name.contains('.')
            && !name.contains(' ')
            && !name.contains('/')
            && !name.starts_with("win:")
        {
            return Some((name.to_owned(), None));
        }
    }

    None
}

// =============================================================================
// Internal helpers
// =============================================================================

/// Internal helper to query provider field information from TDH.
fn get_provider_field_info(
    provider_guid: &GUID,
    field_type: EVENT_FIELD_TYPE,
) -> Result<Vec<ProviderFieldInfo>> {
    let mut buffer_size = 0u32;

    // First call to get required buffer size
    // SAFETY: First call with null buffer to query required size.
    let status = WIN32_ERROR_CODE(unsafe {
        TdhEnumerateProviderFieldInformation(provider_guid, field_type, None, &raw mut buffer_size)
    });

    // Provider may not have a manifest or the requested field type
    if status == ERROR_NOT_FOUND {
        return Ok(Vec::new());
    }

    // Some providers return SUCCESS with zero size for empty field lists
    if status == ERROR_SUCCESS && buffer_size == 0 {
        return Ok(Vec::new());
    }

    if status != ERROR_INSUFFICIENT_BUFFER && status != ERROR_SUCCESS {
        return Err(Error::from(WIN32_ERROR(status.0)));
    }

    // Allocate buffer aligned for PROVIDER_FIELD_INFOARRAY (8-byte aligned).
    const _: () = assert!(
        align_of::<PROVIDER_FIELD_INFOARRAY>() == align_of::<u64>(),
        "PROVIDER_FIELD_INFOARRAY alignment changed — update allocation type"
    );
    let mut buffer = vec![0u64; buffer_size.div_ceil(8) as usize];
    let field_info = buffer.as_mut_ptr().cast::<PROVIDER_FIELD_INFOARRAY>();

    // SAFETY: Buffer is 8-byte aligned with at least buffer_size bytes capacity.
    let status = WIN32_ERROR_CODE(unsafe {
        TdhEnumerateProviderFieldInformation(
            provider_guid,
            field_type,
            Some(field_info),
            &raw mut buffer_size,
        )
    });

    if status != ERROR_SUCCESS {
        return Err(Error::from(WIN32_ERROR(status.0)));
    }

    // SAFETY: TdhEnumerateProviderFieldInformation succeeded, so field_info is valid.
    // buffer_size is updated by TDH to the number of bytes written.
    let buffer_bytes: &[u8] =
        unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), buffer_size as usize) };
    // SAFETY: TdhEnumerateProviderFieldInformation succeeded, so field_info is valid.
    let fields = unsafe {
        let info = &*field_info;
        let count = info.NumberOfElements;
        let fields_ptr = info.FieldInfoArray.as_ptr();

        let mut result = Vec::with_capacity(count as usize);
        for i in 0..count {
            let field: &PROVIDER_FIELD_INFO = &*fields_ptr.add(i as usize);

            // Extract name string
            let name = if field.NameOffset > 0 {
                extract_string_from_buffer(buffer_bytes, field.NameOffset as usize)
            } else {
                String::new()
            };

            // Extract description string (may not be present)
            let description = if field.DescriptionOffset > 0 {
                let desc =
                    extract_string_from_buffer(buffer_bytes, field.DescriptionOffset as usize);
                if desc.is_empty() { None } else { Some(desc) }
            } else {
                None
            };

            result.push(ProviderFieldInfo {
                name,
                description,
                value: field.Value,
            });
        }
        result
    };

    Ok(fields)
}

/// Returns the fixed byte size for a TDH InType, or `None` for variable-length types.
///
/// Assumes 64-bit pointer size for Pointer/SizeT types.
const fn intype_fixed_byte_size(in_type: u16) -> Option<u32> {
    match in_type {
        // Int8, UInt8, AnsiChar
        3 | 4 | 307 => Some(1),
        // Int16, UInt16, UnicodeChar
        5 | 6 | 306 => Some(2),
        // Int32, UInt32, Float, Boolean, HexInt32
        7 | 8 | 11 | 13 | 20 => Some(4),
        // Int64, UInt64, Double, FileTime, HexInt64, Pointer, SizeT
        9 | 10 | 12 | 16 | 17 | 21 | 308 => Some(8),
        // GUID, SystemTime
        15 | 18 => Some(16),
        _ => None,
    }
}

/// Computes the total byte size of a struct property from its member properties.
///
/// Returns `None` if any member is variable-length, nested, or unresolvable.
///
/// # Safety
///
/// `props_ptr` must point to a valid `EVENT_PROPERTY_INFO` array with at least
/// `start + count` elements, as returned by a successful TDH call.
unsafe fn compute_struct_byte_size(
    props_ptr: *const windows::Win32::System::Diagnostics::Etw::EVENT_PROPERTY_INFO,
    start: u16,
    count: u16,
) -> Option<u32> {
    let mut total = 0u32;
    for i in start..start + count {
        // SAFETY: Caller guarantees the array has at least start+count elements.
        let member = unsafe { &*props_ptr.add(i as usize) };
        let mflags = member.Flags.0 as u32;
        // Nested struct, param-length, or param-count — bail (cannot compute static size).
        if (mflags & (PROPERTY_STRUCT | PROPERTY_PARAM_LENGTH | PROPERTY_PARAM_COUNT)) != 0 {
            return None;
        }
        // SAFETY: PROPERTY_STRUCT not set, so nonStructType is the active variant.
        let in_type = unsafe { member.Anonymous1.nonStructType.InType };
        // SAFETY: PROPERTY_PARAM_LENGTH not set, so `length` is the active variant.
        let length = unsafe { member.Anonymous3.length };
        let size = if length > 0 {
            length as u32
        } else {
            intype_fixed_byte_size(in_type)?
        };
        // SAFETY: PROPERTY_PARAM_COUNT not set, so `count` is the active variant.
        let n = unsafe { member.Anonymous2.count };
        let n = if n == 0 { 1 } else { n as u32 };
        total += size * n;
    }
    Some(total)
}

/// Extracts field information from a `TRACE_EVENT_INFO` structure.
///
/// # Safety
///
/// `info` must point to a valid `TRACE_EVENT_INFO` within `buffer`, as returned
/// by a successful TDH call.
pub(crate) unsafe fn extract_fields_from_trace_event_info(
    info: &TRACE_EVENT_INFO,
    buffer: &[u8],
) -> Vec<EventFieldInfo> {
    // Use TopLevelPropertyCount — struct member properties are not top-level fields.
    let top_level_count = info.TopLevelPropertyCount as usize;
    let properties_ptr = info.EventPropertyInfoArray.as_ptr();

    let mut fields = Vec::with_capacity(top_level_count);
    for i in 0..top_level_count {
        // SAFETY: Caller guarantees info and buffer are from a successful TDH call.
        let prop = unsafe { &*properties_ptr.add(i) };

        // Read the field name from the buffer
        let name = if prop.NameOffset > 0 {
            extract_string_from_buffer(buffer, prop.NameOffset as usize)
        } else {
            String::new()
        };

        let flags = prop.Flags.0 as u32;
        let is_struct = (flags & PROPERTY_STRUCT) != 0;

        // For struct properties, read from structType union variant;
        // for non-struct properties, read from nonStructType.
        let (in_type, out_type, struct_byte_size) = if is_struct {
            // SAFETY: is_struct flag checked, so structType is the active variant.
            let start = unsafe { prop.Anonymous1.structType.StructStartIndex };
            // SAFETY: is_struct flag checked, so structType is the active variant.
            let count = unsafe { prop.Anonymous1.structType.NumOfStructMembers };
            // SAFETY: properties_ptr has at least start+count elements.
            let byte_size = unsafe { compute_struct_byte_size(properties_ptr, start, count) };
            (0u16, 0u16, byte_size)
        } else {
            // SAFETY: Not a struct, so nonStructType is the active variant.
            let types = unsafe { prop.Anonymous1.nonStructType };
            (types.InType, types.OutType, None)
        };

        // PropertyParamLength: Anonymous3 is a property index, not a byte length.
        let has_param_length = (flags & PROPERTY_PARAM_LENGTH) != 0;
        let length_property_index =
            // SAFETY: Union access is correct for the given flag.
            has_param_length.then_some(unsafe { prop.Anonymous3.lengthPropertyIndex });

        // When the param flags are NOT set, the union fields contain fixed values.
        let length = if has_param_length {
            0
        } else {
            // SAFETY: No param-length flag, so `length` is the active variant.
            unsafe { prop.Anonymous3.length }
        };
        // PropertyParamCount: Anonymous2 is a property index, not an element count.
        let has_param_count = (flags & PROPERTY_PARAM_COUNT) != 0;
        let count = if has_param_count {
            1
        } else {
            // SAFETY: No param-count flag, so `count` is the active variant.
            unsafe { prop.Anonymous2.count }
        };
        let count_property_index =
            // SAFETY: Union access is correct for the given flag.
            has_param_count.then_some(unsafe { prop.Anonymous2.countPropertyIndex });

        fields.push(EventFieldInfo {
            name,
            in_type,
            out_type,
            flags,
            length_property_index,
            count,
            count_property_index,
            length,
            struct_byte_size,
        });
    }

    fields
}

/// Extracts a null-terminated UTF-16 string from a buffer at the given offset.
pub(crate) fn extract_string_from_buffer(buffer: &[u8], offset: usize) -> String {
    if offset >= buffer.len() {
        return String::new();
    }

    // SAFETY: We've verified offset is within bounds. The string is null-terminated UTF-16.
    unsafe {
        let ptr = buffer.as_ptr().add(offset).cast::<u16>();
        let max_len = (buffer.len() - offset) / 2;

        // Find null terminator
        let mut len = 0;
        while len < max_len && *ptr.add(len) != 0 {
            len += 1;
        }

        let slice = std::slice::from_raw_parts(ptr, len);
        String::from_utf16_lossy(slice)
    }
}

/// Casts a buffer to a `TRACE_EVENT_INFO` reference.
///
/// # Safety
///
/// The buffer must have been filled by a successful `TdhGetEventInformation` call.
pub(crate) const unsafe fn trace_event_info_from_buffer(buffer: &[u8]) -> &TRACE_EVENT_INFO {
    // SAFETY: Caller guarantees buffer contains a valid TRACE_EVENT_INFO.
    unsafe { &*buffer.as_ptr().cast::<TRACE_EVENT_INFO>() }
}

/// Enumerates all manifest-based (XML) providers registered on the system.
///
/// Returns `(name, GUID)` pairs for providers registered via instrumentation manifests.
/// Excludes WMI/MOF, WPP, and TraceLogging providers.
///
/// # Errors
///
/// Returns an error if the enumeration fails.
pub fn enumerate_manifest_providers() -> Result<Vec<(String, GUID)>> {
    // SchemaSource 0 = XML/manifest
    const DECODING_SOURCE_XML_FILE: u32 = 0;

    let mut buffer_size = 0u32;
    // SAFETY: First call with null buffer to query the required size.
    let status = WIN32_ERROR(unsafe { TdhEnumerateProviders(None, &raw mut buffer_size) });

    if status != ERROR_INSUFFICIENT_BUFFER {
        return Err(status.into());
    }

    // Allocate as u32 to exactly match the 4-byte alignment of PROVIDER_ENUMERATION_INFO.
    const _: () = assert!(
        align_of::<PROVIDER_ENUMERATION_INFO>() == align_of::<u32>(),
        "PROVIDER_ENUMERATION_INFO alignment changed — update allocation type"
    );
    let mut buffer = vec![0u32; buffer_size.div_ceil(4) as usize];
    let enum_info = buffer.as_mut_ptr().cast::<PROVIDER_ENUMERATION_INFO>();

    // SAFETY: Buffer is 4-byte aligned with at least buffer_size bytes capacity.
    let status =
        WIN32_ERROR(unsafe { TdhEnumerateProviders(Some(enum_info), &raw mut buffer_size) });

    if status != ERROR_SUCCESS {
        return Err(status.into());
    }

    let mut result = Vec::new();

    // SAFETY: TdhEnumerateProviders succeeded; enum_info points into our buffer.
    // buffer_size is updated by TDH to the number of bytes written.
    let buffer_bytes: &[u8] =
        unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), buffer_size as usize) };
    // SAFETY: TdhEnumerateProviders succeeded; enum_info points into our buffer.
    unsafe {
        let info = &*enum_info;
        let providers_ptr = info.TraceProviderInfoArray.as_ptr();

        for i in 0..info.NumberOfProviders {
            let provider = &*providers_ptr.add(i as usize);
            if provider.SchemaSource != DECODING_SOURCE_XML_FILE {
                continue;
            }
            if provider.ProviderNameOffset > 0 {
                let name =
                    extract_string_from_buffer(buffer_bytes, provider.ProviderNameOffset as usize);
                result.push((name, provider.ProviderGuid));
            }
        }
    }

    Ok(result)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_field_info_debug() {
        let info = ProviderFieldInfo {
            name: "TEST".to_owned(),
            description: Some("A test keyword".to_owned()),
            value: 0x1234,
        };
        let debug_str = format!("{info:?}");
        assert!(debug_str.contains("TEST"));
        assert!(debug_str.contains("0x1234") || debug_str.contains("4660"));
    }

    /// Test that get_event_name returns proper task names.
    #[test]
    #[cfg_attr(miri, ignore = "calls TdhEnumerateManifestProviderEvents")]
    fn test_get_event_name() {
        // Microsoft-Windows-Kernel-Process GUID
        let guid = GUID::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716);

        // Event 1 should be "ProcessStart"
        let info = get_event_name(&guid, 1);
        assert_eq!(info.as_ref().map(|i| i.full.as_str()), Some("ProcessStart"));

        // Event 2 should be "ProcessStop"
        let info = get_event_name(&guid, 2);
        assert_eq!(info.as_ref().map(|i| i.full.as_str()), Some("ProcessStop"));

        // Event 3 should be "ThreadStart"
        let info = get_event_name(&guid, 3);
        assert_eq!(info.as_ref().map(|i| i.full.as_str()), Some("ThreadStart"));

        // Event 5 should be "ImageLoad"
        let info = get_event_name(&guid, 5);
        assert_eq!(info.as_ref().map(|i| i.full.as_str()), Some("ImageLoad"));

        // Non-existent event should return None
        let info = get_event_name(&guid, 9999);
        assert!(info.is_none());
    }
}
