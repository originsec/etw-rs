//! Tests for the provider generation pipeline.
//!
//! Verifies that `generate_full_file` and `generate_mof_file` produce valid
//! output for real providers registered on the system.

#![cfg(windows)]
#![expect(
    clippy::print_stdout,
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code"
)]

use etw::resolve::provider_guid_from_name;
use generate_provider::{
    generate::{generate_full_file, generate_mof_file, generate_schema_block},
    manifest::{get_provider_events, get_provider_keywords, is_channel_keyword},
    mof,
};

/// Generate a manifest provider's full file. Panics if not found or no events.
fn generate_manifest(name: &str) -> String {
    let guid = provider_guid_from_name(name)
        .unwrap_or_else(|e| panic!("{name}: provider not found — {e}"));
    let guid = windows::core::GUID::from_u128(guid.to_u128());
    let events =
        get_provider_events(&guid).unwrap_or_else(|e| panic!("{name}: failed to get events — {e}"));
    assert!(!events.is_empty(), "{name}: provider has no events");
    let keywords: Vec<_> = get_provider_keywords(&guid)
        .unwrap_or_default()
        .into_iter()
        .filter(|k| !is_channel_keyword(&k.name))
        .collect();
    generate_full_file(name, &guid, &events, &keywords, None, "", false)
}

/// Generate a MOF provider's full file. Panics if not found or no events.
fn generate_mof(name: &str) -> String {
    let provider = mof::get_mof_provider(name)
        .unwrap_or_else(|e| panic!("{name}: WMI query failed — {e}"))
        .unwrap_or_else(|| panic!("{name}: MOF provider not found in WMI"));
    assert!(
        !provider.events.is_empty(),
        "{name}: MOF provider has no events"
    );
    let keywords = get_provider_keywords(&provider.provider_guid).unwrap_or_default();
    generate_mof_file(&provider, None, &keywords, None, "", false)
}

/// Generate a provider by trying manifest first, then MOF.
fn generate_provider(name: &str) -> String {
    if let Ok(guid) = provider_guid_from_name(name)
        && let Ok(events) = get_provider_events(&windows::core::GUID::from_u128(guid.to_u128()))
        && !events.is_empty()
    {
        return generate_manifest(name);
    }
    generate_mof(name)
}

fn assert_valid_output(name: &str, output: &str) {
    assert!(!output.is_empty(), "{name}: output is empty");
    assert!(
        output.contains("pub const GUID"),
        "{name}: missing 'pub const GUID'"
    );
    assert!(
        output.contains("provider_schema!"),
        "{name}: missing 'provider_schema!'"
    );
}

fn assert_no_truncated_events(name: &str, output: &str) {
    let truncated: Vec<_> = output
        .lines()
        .filter(|l| l.contains("truncated: true"))
        .collect();
    assert!(
        truncated.is_empty(),
        "{name}: {} event version(s) have unresolved fields:\n  {}",
        truncated.len(),
        truncated.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// Curated provider list
// ---------------------------------------------------------------------------

/// Providers with complex struct or variable-count fields that legitimately
/// cannot be fully statically resolved. All other curated providers must have
/// every event version fully resolved (no `truncated: true`).
const PARTIALLY_RESOLVED_PROVIDERS: &[&str] = &[
    "Microsoft-Windows-DotNETRuntime",
    "Microsoft-Windows-Threat-Intelligence",
    "Microsoft-Windows-RPC",
    "Windows Kernel Trace",
];

fn check_curated_provider(name: &str) {
    let output = generate_provider(name);
    assert_valid_output(name, &output);
    if !PARTIALLY_RESOLVED_PROVIDERS.contains(&name) {
        assert_no_truncated_events(name, &output);
    }
    println!("OK: {name} ({} bytes)", output.len());
}

/// One `#[test]` per provider, so libtest runs them concurrently.
///
/// None is tagged `slow`. These check that the generator still produces sound
/// output for the providers whose shapes are hardest — a check worth having on
/// every run, not one hidden behind `--include-ignored` where nobody sees it
/// until CI.
///
/// Chasing why the largest were slow was worth more than the split itself: the
/// generator re-queried the provider's whole manifest once per event, in three
/// places. Removing that took TCPIP from 26 s to 0.7 s and Security-Auditing
/// from 14 s to 0.8 s.
///
/// `Windows Kernel Trace` is the exception at ~23 s, and it dominates the
/// binary's wall clock on its own. Its cost is 515 `TdhGetEventInformation`
/// calls — one per classic event, each resolving a MOF schema from scratch.
/// The same field definitions are in the WMI class properties the sweep already
/// holds, so this is fixable, but it means reimplementing TDH's MOF decoding
/// rather than deleting redundant work.
macro_rules! curated_provider_tests {
    ($($name:ident => $provider:literal,)+) => {
        $(
            #[test]
            // Miri aborts the whole binary on the first Win32 call rather than
            // skipping the test, and these no longer carry `#[ignore]` to keep
            // them out of its run.
            #[cfg_attr(miri, ignore = "calls TdhEnumerateProviders (Win32)")]
            fn $name() {
                check_curated_provider($provider);
            }
        )+
    };
}

// Providers that exercise different type patterns. Must all be present on any
// standard Windows installation. Includes both manifest and classic (MOF).
//
// Times are uncontended — `--test-threads=1` on an idle box. Measure that way
// before moving a provider between the groups: run concurrently these same
// tests report three to five times longer, because they contend for the CPU,
// and classifying on those numbers puts fast providers in the slow group.
//
//   cargo +nightly test -p generate-provider --test generate_provider -- \
//       curated_ --include-ignored --test-threads=1 -Z unstable-options --report-time
curated_provider_tests! {
    // Manifest providers
    curated_kernel_event_tracing => "Microsoft-Windows-Kernel-EventTracing", //  0.44 s
    curated_kernel_file => "Microsoft-Windows-Kernel-File",                  //  0.45 s
    curated_kernel_registry => "Microsoft-Windows-Kernel-Registry",          //  0.53 s
    curated_dns_client => "Microsoft-Windows-DNS-Client",                    //  0.56 s
    curated_dotnet_runtime => "Microsoft-Windows-DotNETRuntime",             //  0.59 s
    curated_kernel_process => "Microsoft-Windows-Kernel-Process",            //  0.60 s
    curated_tcpip => "Microsoft-Windows-TCPIP",                              //  0.68 s
    curated_threat_intelligence => "Microsoft-Windows-Threat-Intelligence",  //  0.68 s
    curated_security_auditing => "Microsoft-Windows-Security-Auditing",      //  0.76 s
    curated_rpc => "Microsoft-Windows-RPC",                                  //  1.1 s
    // Classic (MOF) providers
    curated_thread_pool => "Thread Pool",                                    //  1.4 s
    curated_windows_kernel_trace => "Windows Kernel Trace",                  // 23 s
}

// ---------------------------------------------------------------------------
// Schema-only mode
// ---------------------------------------------------------------------------

#[test]
#[cfg_attr(miri, ignore = "calls TdhEnumerateProviders (Win32)")]
fn test_generate_schema_only() {
    let name = "Microsoft-Windows-Kernel-Process";
    let guid = provider_guid_from_name(name).expect("provider not found");
    let guid = windows::core::GUID::from_u128(guid.to_u128());

    let events = get_provider_events(&guid).unwrap();
    assert!(!events.is_empty(), "{name} has no events");

    let keywords: Vec<_> = get_provider_keywords(&guid)
        .unwrap_or_default()
        .into_iter()
        .filter(|k| !is_channel_keyword(&k.name))
        .collect();

    let schema = generate_schema_block(
        name,
        &guid,
        &events,
        &keywords,
        " --schema-only",
        None,
        false,
    );

    assert!(schema.contains("Auto-generated by etw-rs generate-provider"));
    assert!(schema.contains("provider_schema!"));
    assert!(!schema.contains("pub const NAME"));
    assert!(!schema.contains("use windows::core::GUID"));

    println!("OK: schema-only for {name} — {} bytes", schema.len());
}
