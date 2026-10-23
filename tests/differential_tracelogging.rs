//! Live differential tests over a TraceLogging provider we emit ourselves.
//!
//! # Why this layer exists on top of the offline manifest tests
//!
//! Manifests cannot express a counted string. `TDH_INTYPE_COUNTEDSTRING` reaches a
//! consumer through the TraceLogging (self-describing) decode path and through MOF,
//! not through `DecodingSourceXMLFile` — which is why the offline fixture set,
//! thorough as it is over the manifest path, cannot cover the very type whose
//! byte-count-versus-character-count bug prompted this harness. The provider that
//! exposed that bug in the field, `KernelProcess`, is a TraceLogging provider.
//!
//! # Why the payload is not hand-encoded here
//!
//! Field bytes are produced by `tracelogging_dynamic`, Microsoft's own TraceLogging
//! encoder (MIT, `github.com/microsoft/tracelogging`). Nothing in etw-rs — and
//! nothing in this test — decides how a counted string is laid out. So the value we
//! pass to `add_str16` is ground truth by construction: if etw-rs reads back
//! something else, etw-rs is wrong, and no shared misconception between test and
//! parser can make that agree.
//!
//! Each event still carries the `Lead`/`Sentinel` sandwich, so an over-read shows up
//! as drift rather than as a quietly wrong field.

#![cfg(not(miri))]
#![expect(
    clippy::print_stdout,
    clippy::expect_used,
    reason = "test binary: printing aids diagnosis and panics are the failure mode"
)]

#[path = "common/mod.rs"]
mod common;
#[path = "common/differential.rs"]
mod differential;

use differential::{LEAD, SENTINEL, compare_event_with_tdh};
use etw::{ALL_KEYWORDS, Trace};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tracelogging_dynamic as tld;

/// TraceLogging derives a provider GUID by hashing the provider name, so the
/// emitter and the consuming session agree without registering anything.
const PROVIDER_NAME: &str = "Etw-Rs-Differential-Tlg";

/// Keyword every fixture event is written under.
const KEYWORD: u64 = 0x1;

/// What one captured event yielded, gathered inside the callback and asserted
/// after the session stops so failures are not swallowed by the ETW plumbing.
#[derive(Debug, Default)]
struct Captured {
    name: String,
    problems: Vec<String>,
    lead: Option<u8>,
    sentinel: Option<u32>,
    text_fields: Vec<(String, String)>,
}

/// The text fields each fixture event carries, as passed to the encoder.
///
/// This is the intent side of the assertion: whatever `tracelogging_dynamic` wrote
/// for these strings, etw-rs must read back exactly these values.
fn expected_text(event_name: &str) -> Vec<(&'static str, &'static str)> {
    match event_name {
        // The regression case. `add_str16` emits TlgIn_COUNTEDSTRING, whose 16-bit
        // prefix is a byte count. Reading it as a character count doubles the span,
        // appending garbage and drifting every later field.
        "CountedStr16" => vec![(
            "Subject",
            r"\Device\HarddiskVolume3\Windows\System32\cmd.exe",
        )],
        "CountedStr8" => vec![("Subject", "counted-ansi-subject")],
        "CStr16" => vec![("Subject", "nul-terminated-wide")],
        "CStr8" => vec![("Subject", "nul-terminated-ansi")],
        // Back-to-back counted strings: the shape where a length mistake in the
        // first field is most visible in the second.
        "CountedStr16Pair" => vec![("First", "first-counted"), ("Second", "second-counted")],
        "CountedAfterCStr" => vec![("Nt", "nul-terminated"), ("Counted", "counted-after")],
        _ => Vec::new(),
    }
}

/// Emits one event per shape under test. Every event is
/// `Lead(u8) | <subject fields> | Sentinel(u32)`.
fn emit_fixture_events(provider: &tld::Provider) -> usize {
    let mut eb = tld::EventBuilder::new();
    let mut emitted = 0usize;

    let mut write = |eb: &mut tld::EventBuilder| {
        eb.add_u32("Sentinel", SENTINEL, tld::OutType::Default, 0);
        let rc = eb.write(provider, None, None);
        assert_eq!(rc, 0, "EventWrite failed with Win32 {rc}");
        emitted += 1;
    };

    let counted16: Vec<u16> = expected_text("CountedStr16")[0].1.encode_utf16().collect();
    eb.reset("CountedStr16", tld::Level::Informational, KEYWORD, 0);
    eb.add_u8("Lead", LEAD, tld::OutType::Default, 0);
    eb.add_str16("Subject", &counted16, tld::OutType::Default, 0);
    write(&mut eb);

    eb.reset("CountedStr8", tld::Level::Informational, KEYWORD, 0);
    eb.add_u8("Lead", LEAD, tld::OutType::Default, 0);
    eb.add_str8(
        "Subject",
        expected_text("CountedStr8")[0].1.as_bytes(),
        tld::OutType::Utf8,
        0,
    );
    write(&mut eb);

    let cstr16: Vec<u16> = expected_text("CStr16")[0].1.encode_utf16().collect();
    eb.reset("CStr16", tld::Level::Informational, KEYWORD, 0);
    eb.add_u8("Lead", LEAD, tld::OutType::Default, 0);
    eb.add_cstr16("Subject", &cstr16, tld::OutType::Default, 0);
    write(&mut eb);

    eb.reset("CStr8", tld::Level::Informational, KEYWORD, 0);
    eb.add_u8("Lead", LEAD, tld::OutType::Default, 0);
    eb.add_cstr8(
        "Subject",
        expected_text("CStr8")[0].1.as_bytes(),
        tld::OutType::Utf8,
        0,
    );
    write(&mut eb);

    let pair = expected_text("CountedStr16Pair");
    let first: Vec<u16> = pair[0].1.encode_utf16().collect();
    let second: Vec<u16> = pair[1].1.encode_utf16().collect();
    eb.reset("CountedStr16Pair", tld::Level::Informational, KEYWORD, 0);
    eb.add_u8("Lead", LEAD, tld::OutType::Default, 0);
    eb.add_str16("First", &first, tld::OutType::Default, 0);
    eb.add_str16("Second", &second, tld::OutType::Default, 0);
    write(&mut eb);

    let mixed = expected_text("CountedAfterCStr");
    let nt: Vec<u16> = mixed[0].1.encode_utf16().collect();
    let counted: Vec<u16> = mixed[1].1.encode_utf16().collect();
    eb.reset("CountedAfterCStr", tld::Level::Informational, KEYWORD, 0);
    eb.add_u8("Lead", LEAD, tld::OutType::Default, 0);
    eb.add_cstr16("Nt", &nt, tld::OutType::Default, 0);
    eb.add_str16("Counted", &counted, tld::OutType::Default, 0);
    write(&mut eb);

    // Non-string shapes on the same decode path, so the TraceLogging layer is not
    // only exercised for strings.
    eb.reset("BinaryAndSid", tld::Level::Informational, KEYWORD, 0);
    eb.add_u8("Lead", LEAD, tld::OutType::Default, 0);
    eb.add_binary("Blob", [0xDEu8, 0xAD, 0xBE, 0xEF], tld::OutType::Default, 0);
    eb.add_u64("Big", 0x1122_3344_5566_7788, tld::OutType::Default, 0);
    write(&mut eb);

    emitted
}

/// Every TraceLogging field must agree with TDH and with the value handed to the
/// encoder, and the trailing sentinel must survive.
#[test]
fn tracelogging_fields_agree_with_tdh_and_intent() {
    let guid = etw::Guid::from_u128(tld::Guid::from_name(PROVIDER_NAME).to_u128());

    let mut trace =
        Trace::new("etw-rs_Test_Differential_Tlg").expect("failed to create trace session");

    let Some(()) = common::skip_or_panic("trace.start", trace.start()) else {
        return;
    };

    trace
        .enable_provider(guid, ALL_KEYWORDS)
        .expect("failed to enable the test TraceLogging provider");

    let captured: Arc<Mutex<Vec<Captured>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&captured);

    trace.set_event_callback(move |event, _context| {
        if event.provider_guid() != guid {
            return Ok(());
        }

        let mut entry = Captured::default();

        // A fresh context per event, deliberately, rather than the session's shared
        // one. Every TraceLogging event carries EventDescriptor.Id/Version/Opcode of
        // zero — the event's identity lives in its metadata blob — so the shared
        // cache, keyed on those fields, hands back the first event's schema for all
        // of them. That defect has its own regression test in
        // `tests/tracelogging_schema_cache.rs`; isolating it here keeps this test
        // measuring field decoding rather than failing for an unrelated reason.
        let mut ctx = etw::processing_context::ProcessingContext::new();

        let Ok(mut parser) = ctx.parser(event) else {
            entry.problems.push("parser construction failed".to_owned());
            sink.lock().expect("captured mutex poisoned").push(entry);
            return Ok(());
        };
        entry.name = parser.schema().event_name().unwrap_or_default();
        entry.lead = parser.get::<u8>("Lead").ok();
        entry.sentinel = parser.get::<u32>("Sentinel").ok();
        for (field, _) in expected_text(&entry.name) {
            match parser.get::<String>(field) {
                Ok(v) => entry.text_fields.push((field.to_owned(), v)),
                Err(e) => entry.problems.push(format!(
                    "{}.{field}: etw-rs failed to decode: {e}",
                    entry.name
                )),
            }
        }
        let mut cmp_ctx = etw::processing_context::ProcessingContext::new();
        entry
            .problems
            .extend(compare_event_with_tdh(&entry.name, event, &mut cmp_ctx));

        sink.lock().expect("captured mutex poisoned").push(entry);
        Ok(())
    });

    trace
        .start_processing_thread()
        .expect("failed to start event processing");

    let provider = Box::pin(tld::Provider::new(PROVIDER_NAME, &tld::Provider::options()));
    // SAFETY: the provider is pinned for the remainder of this function and is
    // dropped (which unregisters it) only after the session has stopped.
    let rc = unsafe { provider.as_ref().register() };
    assert_eq!(rc, 0, "provider registration failed with Win32 {rc}");

    // ETW delivers the enable callback asynchronously, and until it lands
    // `EventBuilder::write()` is a documented no-op that still returns 0. Emitting
    // straight after `register()` therefore drops events silently and intermittently.
    // Wait for the provider to actually observe the session's enablement first.
    let mut enabled = false;
    for _ in 0..50 {
        if provider.enabled(tld::Level::Informational, KEYWORD) {
            enabled = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        enabled,
        "provider never became enabled for keyword {KEYWORD:#x}; every write would \
         have been a silent no-op"
    );

    let expected_events = emit_fixture_events(&provider);

    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(100));
        if captured.lock().expect("captured mutex poisoned").len() >= expected_events {
            break;
        }
    }
    trace.stop().expect("failed to stop session");

    let captured = captured.lock().expect("captured mutex poisoned");
    assert_eq!(
        captured.len(),
        expected_events,
        "captured {} of {expected_events} emitted events; the rest never arrived, so \
         their assertions did not run",
        captured.len()
    );

    let mut failures = Vec::new();
    for entry in captured.iter() {
        for p in &entry.problems {
            failures.push(format!("TDH disagreement: {p}"));
        }
        if entry.lead != Some(LEAD) {
            failures.push(format!(
                "{}: Lead = {:?}, want {LEAD:#04x}",
                entry.name, entry.lead
            ));
        }
        if entry.sentinel != Some(SENTINEL) {
            failures.push(format!(
                "{}: Sentinel = {:?}, want {SENTINEL:#010x} — a field before it over- or under-read",
                entry.name, entry.sentinel
            ));
        }
        let want = expected_text(&entry.name);
        if entry.text_fields.len() != want.len() {
            // Collected rather than asserted so one run reports every shape that
            // failed, not just the first.
            failures.push(format!(
                "{}: read {} text field(s) but {} were expected; a field failed to decode",
                entry.name,
                entry.text_fields.len(),
                want.len()
            ));
        }
        for ((got_name, got), (want_name, want_val)) in entry.text_fields.iter().zip(want) {
            assert_eq!(got_name, want_name, "field order changed unexpectedly");
            if got != want_val {
                failures.push(format!(
                    "{}.{got_name}: etw-rs read {got:?}, encoder was given {want_val:?}",
                    entry.name
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "{} TraceLogging assertion failure(s):\n{}",
        failures.len(),
        failures.join("\n")
    );

    println!(
        "verified {} TraceLogging events against TDH and against the encoder's input",
        captured.len()
    );
}
