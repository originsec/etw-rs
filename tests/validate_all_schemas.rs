//! Integration tests for the schema validator registration and invocation pipeline.
//!
//! Verifies that `__register_schema_validator` correctly enqueues validators and
//! that `validate_all_schemas()` invokes them, propagating any errors.
//!
//! Note: this file contains no `provider_schema!` invocations, so no CRT constructors
//! register validators. Any validators present came from other tests in this binary
//! via `__register_schema_validator` — all of which return `Ok(())`.

#![cfg(windows)]

use etw::{__register_schema_validator, __run_validators, validate_all_schemas};

#[expect(
    clippy::unnecessary_wraps,
    clippy::missing_const_for_fn,
    reason = "signature must match `ValidatorFn = fn() -> Result<(), Error>` for `__register_schema_validator`"
)]
fn ok_validator() -> etw::Result<()> {
    Ok(())
}

fn err_validator() -> etw::Result<()> {
    Err(etw::Error::parse("sentinel"))
}

/// Exercises `__run_validators` directly with a controlled slice, bypassing the
/// `AtomicBool` short-circuit in `validate_all_schemas`. This avoids a race
/// against other tests in the binary that may have already set the success cache.
#[test]
fn ok_validator_passes() {
    assert!(__run_validators(&[ok_validator]).is_ok());
}

#[test]
fn err_validator_propagates() {
    assert!(__run_validators(&[err_validator]).is_err());
}

#[test]
fn ok_then_err_propagates() {
    assert!(__run_validators(&[ok_validator, err_validator]).is_err());
}

/// Exercises the registration path: a registered validator must not cause
/// `validate_all_schemas()` to fail (provided all registered validators return `Ok`).
#[test]
fn registered_ok_validator_does_not_fail_validate_all_schemas() {
    __register_schema_validator(ok_validator);
    assert!(validate_all_schemas().is_ok());
}
