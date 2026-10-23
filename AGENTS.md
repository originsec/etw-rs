# Agent Instructions for etw-rs

## Before Completing Any Task

Run every CI check and fix any issues before declaring work done:

```powershell
./ci/check.ps1 fmt -Fix   # format in place first
./ci/check.ps1 all        # every Windows CI job; `test` needs Administrator
```

Each Windows CI job is one step of `ci/check.ps1`, which also holds every
toolchain pin; the `docs` job's greps run only in `.github/workflows/ci.yml`.
Run the script rather than cargo with a hand-typed `+toolchain`: a floating
clippy or rustfmt disagrees with CI's pinned one.

## Lint Policy

- Lint config is `[workspace.lints]` in the root `Cargo.toml`, inherited by each
  published crate with `[lints] workspace = true` — `all` + `pedantic` as groups,
  plus cherry-picked `restriction` and `nursery` lints. Inheritance is
  all-or-nothing, so a crate-specific lint goes in source as an attribute
  (`etw-rs-macros` has `#![forbid(unsafe_code)]`)
- Fix warnings, don't suppress them, unless there's a documented reason
- Suppressions use `#[expect(lint, reason = "…")]`, never `#[allow(...)]` — both the
  item-level `#[expect]` and the file-level `#![expect]` form. An
  `#[expect]` whose lint stops firing reports itself via
  `unfulfilled_lint_expectations`, so a suppression that is no longer needed shows
  up as a warning instead of rotting silently. Each lint in a multi-lint
  `#[expect(a, b)]` is tracked separately, so a dead entry in the list is caught too
- Exception — generated code keeps `#[allow(...)]`: attributes emitted inside
  `quote!` by `etw-rs-macros`, and the file-level attributes written by
  `tools/generate-provider`. Whether those lints fire depends on the caller's
  schema, so `#[expect]` there would warn in every build where the lint happens not
  to trigger, turning a silent no-op into a downstream build failure
- Exception — a module compiled into several binaries keeps `#[allow(...)]` when the
  lint fires in some of them and not others. `tests/common/mod.rs` is the live case:
  it is `#[path]`-included into most test binaries, and its `dead_code` fires in
  some but not all, so an `#[expect]` would report itself unfulfilled in the rest. Deleting
  the suppression is wrong there — unlike a single-target file, "unfulfilled" means
  "not needed in *this* binary", not "dead"
- Examples and benches: file-level `#![expect(clippy::print_stdout, clippy::unwrap_used, reason = "…")]` is acceptable

## Code Style

- Minimal abstraction — this is a low-level ETW library
- Never use `ignore` in doc examples (CI rejects it) — use `no_run` instead
- See `CONTRIBUTING.md` for full guidelines

## Code Comments

Prefer self-documenting code over comments. A comment costs tokens on every read, is checked by no compiler or test, and rots when the code moves on — a stale comment misleads the next reader (human or agent).

- **Default to few.** Write one only when it earns its place. Governs inline/explanatory comments — not the `//!`/`///` doc comments public APIs still require.
- **Comment the WHY, never the WHAT.** Explain a non-obvious constraint, invariant, workaround, or surprising behaviour — not what the next line plainly does. If code needs narrating, rename or simplify it instead.
- **Be terse.** One clause beats a paragraph — don't pad the WHY with the WHAT.
- **No point-in-time rationale.** Decision history, "changed because…", and migration notes go in the commit, not the source. Don't replicate `git blame`.
- **Enforce, don't narrate.** "Should always be X" → an assertion, not a comment.
- **Fix comments you invalidate.** Update or delete any comment your change makes false; keep ones that still flag a real pitfall.
- `unsafe` blocks require `// SAFETY:` comments
- Australian English in comments

## Project Structure

- `src/` — library code (strict lints)
  - `src/session/` — unified trace session
  - `src/session/system_logger/` — system logger mode (group masks, PMC profiling, LBR)
  - `src/resolve.rs` — provider name/GUID lookup
- `tools/generate-provider/` — `generate-provider` CLI tool (workspace member; TDH/WMI metadata queries and Rust code generation)
- `etw-rs-macros/` — proc macro crate
- `example-providers/` — provider definitions for examples and tests
- `examples/` — runnable examples (relaxed print/unwrap lints)
- `tests/` — integration and unit tests (see `tests/README.md`)
- `benches/` — criterion benchmarks and C++ comparison benchmarks (krabsetw)
- `docs/` — design docs and coverage references
- `ci/check.ps1` — the CI checks and their toolchain pins, shared by CI and local runs

## README Files

Key directories have `README.md` files containing both structural overview and developer-facing invariants (constraints, pitfalls, things that break if done wrong). These are distinct from `//!` doc comments, which are public API documentation for `cargo doc`.

- **Read first**: When exploring a directory, always read its `README.md` before diving into source files. This gives you the module relationships, key invariants, and common pitfalls up front — saving you from reading thousands of lines to discover constraints buried deep in implementation.
- **Keep up to date**: When adding, removing, or renaming files or modules, update the relevant `README.md`. When changing invariants or discovering new pitfalls, document them in the appropriate README's "Key Invariants" section.

Directories with READMEs: `src/`, `src/session/`, `examples/`, `tests/`, `benches/`.

## Testing

- `./ci/check.ps1 test` — the full pass, as CI runs it. Requires Administrator.
  `./ci/check.ps1 unit` runs only the lib tests, which need no Administrator.
- Without Administrator, each privileged test binary fails one
  `common::can_enable_kernel_provider` guard, because the privileged tests soft-skip
  and would otherwise report success with the coverage silently gone. Set
  `ETW_RS_ALLOW_SKIPS=1` to accept a reduced run. See `tests/README.md`.
- Benchmarks require Administrator (ETW sessions need elevated privileges)

### Miri

`./ci/check.ps1 miri` — as CI runs it.
Miri interprets the raw-pointer work (provenance, alignment, aliasing) that
clippy and the normal test pass cannot see. No Administrator required.

Miri cannot call Win32. On the first foreign call it aborts the **whole test
binary** rather than skipping that one test, so a single unmarked test takes the
job from green to "ran 2 of 520". Any test reaching a Win32 API must therefore
carry:

```rust
#[cfg_attr(miri, ignore = "calls TdhEnumerateProviders (Win32)")]
```

**Use `cfg_attr(… ignore)`, not `cfg(not(miri))`, for whole-test gates.** A
`cfg`-gated test ceases to exist under Miri, so the excluded set is invisible in
the test count and cannot be enumerated. With `ignore` the test still compiles,
appears in the run as `ignored, <reason>`, and is listed by
`cargo miri test -- --list --ignored`.

That visibility is the check. Adding or removing a gate moves the ignored count
the Miri job prints, so it shows up in the diff that caused it. The one case
that count misses — a gate that quietly stops being necessary because a Win32
call moved out of the path — is what the **Miri gate audit** workflow is for.
It is `workflow_dispatch` only: run it by hand after a refactor that moves Win32
calls between functions. It is not scheduled, because a periodic job that passes
for a year gets ignored and then muted.

Reserve plain `#[cfg(not(miri))]` for *structural* exclusions that must vanish at
compile time — dropping a schema field and its payload bytes, or an assertion
inside a test body. Those cannot be expressed as `ignore`.

Prefer the narrowest exclusion that works. Skipping one field or one assertion,
where the rest of the test still exercises real logic, beats skipping the test.
Skipping a test beats gating its whole module — a module-level gate is a default
landing spot for new tests and silently denies them coverage.

The remaining blind spot: integration files that are wholly ETW-session tests
(`tests/dns_client.rs`, `tests/lbr.rs`, …) keep a file-level
`#![cfg(not(miri))]`. Every test in them opens a real session, so per-test
markers would be noise — but the audit cannot see them. If you add a
pure-logic test, put it somewhere else. Put the file's `//!` docs *above* that
`#![cfg]`: Miri strips everything after it, docs included, and warns
`missing documentation for the crate` for each such file.

The nightly is pinned because Miri's aliasing model tightens between releases;
bump it deliberately rather than absorbing a regression on an unrelated PR. The
pin is in `ci/check.ps1`; `miri-gate-audit.yml` reads it from there.
