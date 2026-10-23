# Contributing to etw-rs

Contributions are welcome! This document outlines the development workflow and requirements.

## Development Setup

1. Clone the repository
2. Install Rust through [rustup](https://rustup.rs) (1.88 or later). The check
   script installs the pinned toolchains it needs
3. Windows 10, version 1703 or later is required (ETW is Windows-only; see the
   support matrix in `DESIGN.md`)

## Code Quality Requirements

All contributions must pass the checks CI runs. `ci/check.ps1` runs them on the
same toolchains CI uses:

```powershell
./ci/check.ps1              # fmt, lint and unit tests: no Administrator, a few minutes
./ci/check.ps1 all          # every Windows CI job; the integration tests need Administrator
./ci/check.ps1 test miri    # named steps: fmt, lint, unit, test, msrv, miri
```

### Formatting

Formatting uses nightly-only `rustfmt` options (see `rustfmt.toml`), so it must
run on the pinned nightly — another nightly can disagree with CI:

```powershell
./ci/check.ps1 fmt -Fix     # format in place
./ci/check.ps1 fmt          # check only, as CI does
```

### Linting

This project uses strict clippy linting with `clippy::pedantic` enabled. Lint configuration is in the root `Cargo.toml` under `[workspace.lints]`, shared by every published crate.

Code must pass clippy and rustdoc with no warnings:

```powershell
./ci/check.ps1 lint
```

**Lint Philosophy**: We enable strict linting by default and allow specific lints only where necessary, with documented justification. Global exceptions are listed in `Cargo.toml` with comments explaining why. Local exceptions use `#[expect(lint, reason = "…")]`, not `#[allow(...)]`, so a suppression that is no longer needed reports itself as unfulfilled. See `AGENTS.md` for the few places `#[allow]` is kept deliberately.

### Testing

```powershell
./ci/check.ps1 unit         # unit tests: schemas, parsing, internal logic; no Administrator
./ci/check.ps1 test         # as Administrator: every test including #[ignore = "slow"],
                            # the doc tests, and the benchmark build
./ci/check.ps1 miri         # the unit and integration tests under Miri; no Administrator
```

There is no separate build step: `lint` runs clippy with `--all-targets`, which
compiles the library, examples, tests and benchmarks.

Without Administrator each privileged test binary fails its
`common::can_enable_kernel_provider` guard — set `ETW_RS_ALLOW_SKIPS=1` to accept
a reduced run. To see the `Skipping:` lines from `common::skip_or_panic`, which
libtest hides for passing tests, run the suite directly with `--nocapture`. They
only appear when something was skipped, so this is the reduced run:

```powershell
$env:ETW_RS_ALLOW_SKIPS = '1'
cargo test --workspace --lib --tests -- --include-ignored --nocapture
```

Any test that reaches a Win32 API needs `#[cfg_attr(miri, ignore = "…")]`, since
Miri aborts the whole test binary on the first foreign call. See `AGENTS.md` and
`tests/README.md`.

### Documentation

`./ci/check.ps1 lint` builds the docs with rustdoc warnings denied. To browse them:

```powershell
cargo doc --no-deps --open
```

## Before Submitting

Run `./ci/check.ps1 all`, as Administrator — or with `ETW_RS_ALLOW_SKIPS=1` to
accept a reduced run. CI's `docs` job also rejects ` ```ignore ` doc examples,
documented `cargo test` commands that pass `--ignored` to the test binary (use
`--include-ignored`), and `#[ignore]` reasons other than `"slow"`; those checks
are greps in `.github/workflows/ci.yml`, not steps of `ci/check.ps1`.

## What to Contribute

We especially welcome:

- **Test cases** - Integration tests for common providers in `tests/`
- **Documentation** - Improvements to docs, examples, and README
- **Bug fixes** - With regression tests where applicable

## Provider Definitions

Provider definitions (GUIDs, keywords, event IDs) are not part of the main crate. Users should generate their own using the `generate-provider` tool:

```bash
cargo run -p etw-rs-generate-provider -- Microsoft-Windows-Kernel-File
```

The `example-providers/` workspace crate contains provider definitions used by examples and tests.

## Code Style

- Follow Rust idioms and conventions
- Use `unsafe` sparingly and document safety invariants
- Prefer explicit over implicit behaviour
- Keep abstractions minimal - this is a low-level library

### Documentation Examples

**Never use ` ```ignore ` in doc examples.** All doc examples must be compile-checked.

Use one of these patterns instead:

- ` ```no_run ` - Compiles but doesn't run (for code that needs runtime context)
- ` ```compile_fail ` - For examples demonstrating what doesn't compile
- ` ``` ` (no tag) - Compiles and runs (preferred when possible)

For examples that need context (like an `EventParser`), use hidden lines:

```rust
/// ```no_run
/// # fn example(parser: &mut etw::EventParser) -> etw::Result<()> {
/// let pid: u32 = parser.get("ProcessId")?;
/// # Ok(())
/// # }
/// ```
```

The `# ` prefix hides lines from rendered docs while keeping them for compilation.

## Pull Request Process

1. Ensure all checks pass locally
2. Update documentation for any API changes
3. Add tests for new functionality
4. Keep commits focused and well-described
