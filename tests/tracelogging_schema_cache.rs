//! Regression test: `ProcessingContext` must not confuse two TraceLogging events.
//!
//! # The defect
//!
//! `SchemaKey` identifies a cached schema by provider GUID plus the packed
//! `EventDescriptor` triple `Id | Version << 16 | Opcode << 24`. That is sufficient
//! for manifest and MOF providers, where the descriptor names the event.
//!
//! TraceLogging does not put the event's identity in the descriptor. A
//! self-describing event carries its name and field layout in a metadata blob, and
//! leaves `Id`, `Version` and `Opcode` at zero unless the emitter goes out of its
//! way to set them — most do not. Every event from a given TraceLogging provider
//! therefore hashes to the same `SchemaKey`, and the first one to arrive populates
//! the cache for all the rest.
//!
//! The failure is silent: the parser applies the wrong schema and returns
//! plausible-looking values from the wrong offsets, rather than reporting an error.
//! It scales with how many event shapes a provider emits, and Origin consumes
//! several multi-shape TraceLogging providers.
//!
//! # Why this test is separate
//!
//! `tests/differential_tracelogging.rs` builds a fresh context per event so that it
//! measures field decoding. This file is the one that pins the caching contract, so
//! neither concern can quietly absorb the other's failure.

#![cfg(not(miri))]
#![expect(
    clippy::print_stdout,
    clippy::expect_used,
    reason = "test binary: printing aids diagnosis and panics are the failure mode"
)]

#[path = "common/mod.rs"]
mod common;

use etw::{ALL_KEYWORDS, Trace};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tracelogging_dynamic as tld;

const PROVIDER_NAME: &str = "Etw-Rs-Schema-Cache-Test";

/// Distinct event shapes, each with a different name and a different field layout,
/// so a mixed-up schema shows as both a wrong name and a wrong field set.
const SHAPES: [&str; 3] = ["AlphaEvent", "BetaEvent", "GammaEvent"];

/// What the shared-context parser reported for each arriving event.
#[derive(Debug)]
struct Seen {
    descriptor_id: u16,
    name_via_shared_context: String,
    name_via_fresh_context: String,
}

#[test]
fn shared_context_distinguishes_tracelogging_events() {
    let guid = etw::Guid::from_u128(tld::Guid::from_name(PROVIDER_NAME).to_u128());

    let mut trace =
        Trace::new("etw-rs_Test_TlgSchemaCache").expect("failed to create trace session");

    let Some(()) = common::skip_or_panic("trace.start", trace.start()) else {
        return;
    };

    trace
        .enable_provider(guid, ALL_KEYWORDS)
        .expect("failed to enable the test TraceLogging provider");

    let seen: Arc<Mutex<Vec<Seen>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);

    trace.set_event_callback(move |event, context| {
        if event.provider_guid() != guid {
            return Ok(());
        }

        let name_via_shared_context = context
            .tracelogging_parser(event)
            .ok()
            .and_then(|p| p.schema().event_name())
            .unwrap_or_default();

        // The control. A context that has never seen another event cannot have a
        // stale entry, so this shows what the schema lookup yields when caching is
        // taken out of the picture.
        let mut fresh = etw::processing_context::ProcessingContext::new();
        let name_via_fresh_context = fresh
            .tracelogging_parser(event)
            .ok()
            .and_then(|p| p.schema().event_name())
            .unwrap_or_default();

        sink.lock().expect("seen mutex poisoned").push(Seen {
            descriptor_id: event.id(),
            name_via_shared_context,
            name_via_fresh_context,
        });
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
    let mut enabled = false;
    for _ in 0..50 {
        if provider.enabled(tld::Level::Informational, 0x1) {
            enabled = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        enabled,
        "provider never became enabled; every write would have been a silent no-op"
    );

    let mut eb = tld::EventBuilder::new();
    for (i, shape) in SHAPES.iter().enumerate() {
        eb.reset(shape, tld::Level::Informational, 0x1, 0);
        // A different field layout per shape, so applying the wrong schema cannot
        // coincidentally produce the right answer.
        for f in 0..=i {
            eb.add_u32(
                &format!("Field{f}"),
                0x1000 + f as u32,
                tld::OutType::Default,
                0,
            );
        }
        let rc = eb.write(&provider, None, None);
        assert_eq!(rc, 0, "EventWrite for {shape} failed with Win32 {rc}");
    }

    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(100));
        if seen.lock().expect("seen mutex poisoned").len() >= SHAPES.len() {
            break;
        }
    }
    trace.stop().expect("failed to stop session");

    let seen = seen.lock().expect("seen mutex poisoned");
    assert_eq!(
        seen.len(),
        SHAPES.len(),
        "captured {} of {} emitted events",
        seen.len(),
        SHAPES.len()
    );

    for s in seen.iter() {
        println!(
            "descriptor.id={} shared={:?} fresh={:?}",
            s.descriptor_id, s.name_via_shared_context, s.name_via_fresh_context
        );
    }

    // The premise: TraceLogging really does leave the descriptor empty. If a future
    // Windows or encoder change started populating Id, the collision would no longer
    // be reachable and this test would be passing for the wrong reason.
    assert!(
        seen.iter().all(|s| s.descriptor_id == 0),
        "expected every TraceLogging event to carry EventDescriptor.Id == 0; \
         the cache-collision premise no longer holds and this test needs revisiting"
    );

    // The control must distinguish the shapes, or the comparison below is vacuous.
    let fresh_names: Vec<&str> = seen
        .iter()
        .map(|s| s.name_via_fresh_context.as_str())
        .collect();
    assert_eq!(
        fresh_names, SHAPES,
        "an uncached lookup should resolve each event's own schema"
    );

    let shared_names: Vec<&str> = seen
        .iter()
        .map(|s| s.name_via_shared_context.as_str())
        .collect();
    assert_eq!(
        shared_names, SHAPES,
        "ProcessingContext returned a stale schema: every TraceLogging event from a \
         provider shares EventDescriptor.Id/Version/Opcode == 0, so SchemaKey collides \
         and the first event's schema is reused for the rest. Fields then decode from \
         the wrong offsets with no error raised."
    );
}
