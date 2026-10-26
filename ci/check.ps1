#Requires -Version 5.1
<#
.SYNOPSIS
Runs the checks CI runs, on the toolchains CI pins.

.DESCRIPTION
Each Windows CI job is one step of this script, so a local run and CI cannot
drift. The ubuntu `docs` job is greps in ci.yml and is not run here.
Toolchains are installed through rustup on first use.

With no arguments it runs fmt, lint and unit: no Administrator, a couple of
minutes. `all` runs every Windows CI job (fmt, lint, test, msrv, miri); `test` needs
Administrator — without it, set ETW_RS_ALLOW_SKIPS=1 to accept a reduced run.

.EXAMPLE
./ci/check.ps1
./ci/check.ps1 all
./ci/check.ps1 test miri
./ci/check.ps1 fmt -Fix
#>
[CmdletBinding(DefaultParameterSetName = 'Run')]
param(
    [Parameter(ParameterSetName = 'Run', Position = 0, ValueFromRemainingArguments)]
    [ValidateSet('fmt', 'lint', 'unit', 'test', 'msrv', 'miri', 'all')]
    [string[]] $Step = @('fmt', 'lint', 'unit'),

    # Format in place instead of checking.
    [Parameter(ParameterSetName = 'Run')]
    [switch] $Fix,

    # Install the named step's toolchain and print its name, for workflows that
    # drive cargo themselves (miri-gate-audit.yml).
    [Parameter(ParameterSetName = 'Toolchain', Mandatory)]
    [ValidateSet('fmt', 'lint', 'unit', 'test', 'msrv', 'miri')]
    [string] $Toolchain
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Windows PowerShell 5.1 has no $PSNativeCommandUseErrorActionPreference, so a
# failing native command would not stop the script. A script block rather than
# `@args`: 5.1 strips `--` from arguments passed to a function.
function Invoke-Native([scriptblock] $Command) {
    & $Command
    if ($LASTEXITCODE -ne 0) { throw "exit code ${LASTEXITCODE}:$Command" }
}

# Every pin a check depends on lives here and nowhere else.
#
# - fmt: rustfmt.toml uses nightly-only options, which carry no formatting
#   stability guarantee, so a floating nightly can reformat untouched code.
#   Independent of the Miri pin, even while the dates match.
# - lint: `-D warnings` against a floating clippy makes every new lint a merge
#   blocker on unrelated PRs.
# - unit/test: deliberately floating, so genuine breakage from a new Rust
#   release is still caught early.
# - msrv: the declared `rust-version` in Cargo.toml; keep the two in step.
# - miri: Miri's aliasing model tightens between releases. Without rust-src,
#   cargo-miri stops to ask permission to add it — nowhere to answer on a runner.
$Toolchains = @{
    fmt  = @{ Name = 'nightly-2026-07-23'; Components = @('rustfmt') }
    lint = @{ Name = '1.97'; Components = @('clippy') }
    unit = @{ Name = 'stable'; Components = @() }
    test = @{ Name = 'stable'; Components = @() }
    msrv = @{ Name = '1.88.0'; Components = @() }
    miri = @{ Name = 'nightly-2026-07-23'; Components = @('miri', 'rust-src') }
}

function Install-Toolchain([string] $For) {
    $tc = $Toolchains[$For]
    # Installing an already-installed `stable` updates it; do that only in CI,
    # rather than moving a contributor's default toolchain on every run.
    if ($tc.Name -eq 'stable' -and $env:CI -ne 'true' -and
        (Invoke-Native { rustup toolchain list }) -match '^stable-') {
        return $tc.Name
    }
    $install = @('toolchain', 'install', $tc.Name, '--profile', 'minimal', '--no-self-update')
    foreach ($c in $tc.Components) { $install += @('--component', $c) }
    # stdout to stderr, not Out-Host: under `-File` the host is stdout, and
    # `-Toolchain` callers capture stdout for the name alone. No `2>&1`: under
    # `Stop`, 5.1 turns redirected native stderr into a terminating error.
    Invoke-Native { rustup @install } | ForEach-Object { [Console]::Error.WriteLine($_) }
    $tc.Name
}

function Invoke-Step([string] $Name) {
    Write-Host "==> $Name" -ForegroundColor Cyan
    $tc = "+$(Install-Toolchain $Name)"
    switch ($Name) {
        'fmt' {
            if ($Fix) { Invoke-Native { cargo $tc fmt --all } } else { Invoke-Native { cargo $tc fmt --all --check } }
        }
        'lint' {
            # `--all-targets` builds everything, so there is no separate build step.
            Invoke-Native { cargo $tc clippy --all-targets --workspace -- -D warnings }
            # Consumers get windows-sys only; the typed `windows` crate is dev-only.
            # `example-providers` stands in for a downstream crate, so code the
            # macros generate is held to the same rule. `-i windows` cannot express
            # this: it errors as ambiguous while two `windows` versions are locked.
            $graph = Invoke-Native {
                cargo $tc tree -p etw-rs -p etw-rs-macros -p example-providers `
                    -e normal,build --target all --prefix none --format '{p}'
            }
            $leaked = $graph | ForEach-Object { ($_ -split ' ')[0] } |
                Where-Object { $_ -like 'windows*' -and $_ -notmatch '^(windows-sys|windows-link|windows-targets|windows_.+)$' } |
                Sort-Object -Unique
            if ($leaked) {
                throw "non-windows-sys Win32 crates in the published dependency graph: $($leaked -join ', '). Move them to [dev-dependencies]."
            }
            # Rustdoc warnings (broken or private intra-doc links) do not fail
            # `cargo doc`, so they accumulate unnoticed unless denied here.
            $saved = $env:RUSTDOCFLAGS
            try {
                $env:RUSTDOCFLAGS = '-D warnings'
                Invoke-Native { cargo $tc doc --no-deps --workspace }
            } finally {
                $env:RUSTDOCFLAGS = $saved
            }
        }
        'unit' {
            Invoke-Native { cargo $tc test --workspace --lib }
        }
        'test' {
            # `--include-ignored` adds the tests tagged `#[ignore = "slow"]`; the
            # cheap Administrator tests run in the default pass.
            Invoke-Native { cargo $tc test --workspace --lib --tests -- --include-ignored }
            Invoke-Native { cargo $tc test --doc --workspace }
            Invoke-Native { cargo $tc bench --workspace --no-run }
        }
        'msrv' {
            # Compiling is the promise `rust-version` makes; running the ETW suite
            # on an old toolchain proves nothing extra.
            Invoke-Native { cargo $tc check --workspace --all-targets }
        }
        'miri' {
            # Miri aborts the whole test binary on the first Win32 call, so any
            # test reaching Win32 needs `#[cfg_attr(miri, ignore = "…")]`. On
            # "can't call foreign function", mark the named test rather than
            # weakening this step.
            # Permissive provenance: ETW hands some buffers over as integer
            # addresses (EVENT_HEADER_EXTENDED_DATA_ITEM.DataPtr), which only
            # `ptr::with_exposed_provenance` can turn back into a pointer.
            $saved = $env:MIRIFLAGS
            try {
                $env:MIRIFLAGS = '-Zmiri-permissive-provenance'
                Invoke-Native { cargo $tc miri test --workspace --lib --tests }
            } finally {
                $env:MIRIFLAGS = $saved
            }
        }
    }
}

if ($PSCmdlet.ParameterSetName -eq 'Toolchain') {
    Install-Toolchain $Toolchain
    return
}

# `unit` is a subset of `test`, so `all` leaves it out.
$steps = if ($Step -contains 'all') { @('fmt', 'lint', 'test', 'msrv', 'miri') } else { $Step }
Push-Location (Split-Path $PSScriptRoot -Parent)
try {
    foreach ($s in $steps) { Invoke-Step $s }
} finally {
    Pop-Location
}
