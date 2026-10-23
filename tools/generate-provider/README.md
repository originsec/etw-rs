# etw-rs-generate-provider

A CLI that generates [etw-rs](https://crates.io/crates/etw-rs) provider
definitions from the metadata registered on the local machine. It queries
TDH (manifest providers) or WMI (classic MOF providers) and prints a Rust module
to stdout: the provider's `NAME`, `GUID`, keywords, event IDs, and
`provider_schema!` static schemas.

Windows only.

## Install

```powershell
cargo install etw-rs-generate-provider
```

The installed binary is `generate-provider`.

## Usage

```powershell
generate-provider <provider_name> [options]
```

```powershell
# Full provider module
generate-provider Microsoft-Windows-Kernel-Process > kernel_process.rs

# Only the provider_schema! block, or only the metadata
generate-provider Microsoft-Windows-Kernel-File --schema-only
generate-provider Microsoft-Windows-Kernel-File --provider-only

# Only selected events
generate-provider Microsoft-Windows-Kernel-File --event-only 12

# Classic (MOF) provider, by WMI class name
generate-provider "Windows Kernel Trace" --mof

# Annotate event versions with the Windows release that introduced them
generate-provider Microsoft-Windows-Kernel-Process --query-release --schema-only
```

Run `generate-provider --help` for every option and its short alias. The output reflects the
metadata registered on the machine it runs on.
