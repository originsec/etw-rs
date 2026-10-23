//! CLI tool to generate ETW provider definitions from registered metadata.
//!
//! Queries Windows TDH/WMI APIs and generates a complete provider module with
//! NAME, GUID, keywords, event IDs, and `provider_schema!` static schemas.
//! Output is always printed to stdout.
//!
//! # Usage
//!
//! ```text
//! generate-provider <provider_name> [options]
//! ```
//!
//! # Options
//!
//! Use `generate-provider --help` for the full option list.
//!
//! Short aliases: `-s` (schema-only), `-p` (provider-only), `-e` (event-only),
//! `-E` (event-comment), `-m` (mof), `-q` (query-release)
//!
//! # Examples
//!
//! ```text
//! generate-provider Microsoft-Windows-Kernel-File
//! generate-provider Microsoft-Windows-Kernel-File -s
//! generate-provider Microsoft-Windows-Kernel-File -p
//! generate-provider Microsoft-Windows-Kernel-File -e 12
//! generate-provider Microsoft-Windows-Kernel-File -E 12
//! generate-provider "Windows Kernel Trace" -m
//! generate-provider "Thread Pool" -m -e 10
//! generate-provider Microsoft-Windows-Kernel-Process -q -s
//! generate-provider Microsoft-Windows-Kernel-Process -q --drop-old-versions
//! ```

#![expect(
    clippy::print_stderr,
    clippy::print_stdout,
    reason = "CLI tool — stdout/stderr are the primary output channels"
)]

use clap::Parser;
use etw::resolve::{provider_guid_from_name, provider_name_from_guid};
use generate_provider::{
    generate::{
        ReleaseMap, generate_comment_block, generate_full_file, generate_mof_comment_block,
        generate_mof_file, generate_mof_provider_only, generate_mof_schema, generate_provider_only,
        generate_schema_block,
    },
    manifest::{get_provider_events, get_provider_keywords, is_channel_keyword},
    mof,
    release::query_release_info,
};

/// Selects which output mode the CLI produces.
enum OutputMode {
    /// Full provider file with schema block.
    Full,
    /// Only the `provider_schema!` block.
    SchemaOnly,
    /// Only the provider metadata (NAME, GUID, keywords, events) — no schema block.
    ProviderOnly,
    /// Only the schema block for these events (by ID or opcode).
    EventOnly(Vec<u16>),
    /// Like `EventOnly`, but formatted as comments rather than Rust code.
    EventComment(u16),
}

/// Generate ETW provider definitions from registered metadata.
///
/// Queries Windows TDH/WMI APIs and generates a complete provider module with
/// NAME, GUID, keywords, event IDs, and `provider_schema!` static schemas.
/// Output is always printed to stdout.
#[derive(Parser)]
#[command(name = "generate-provider")]
#[expect(
    clippy::struct_excessive_bools,
    reason = "clap derive structs naturally accumulate bool flags; the state-machine refactor clippy suggests would fight the derive API"
)]
struct Args {
    /// ETW provider name (manifest) or WMI class name (MOF)
    provider_name: String,

    /// Only print the provider_schema! block
    #[arg(short, long, group = "mode")]
    schema_only: bool,

    /// Only print provider metadata (NAME, GUID, keywords, events)
    #[arg(short, long, group = "mode")]
    provider_only: bool,

    /// Only print the schema block for these event IDs (or opcodes for MOF)
    #[arg(short, long, value_name = "ID", group = "mode", num_args = 1..)]
    event_only: Vec<u16>,

    /// Like --event-only, but output as comments instead of Rust code
    #[arg(short = 'E', long, value_name = "ID", group = "mode")]
    event_comment: Option<u16>,

    /// Force MOF (classic/WMI) provider path
    #[arg(short, long)]
    mof: bool,

    /// Annotate event versions with the Windows release that introduced them
    #[arg(short, long)]
    query_release: bool,

    /// Drop event versions predating Windows 10 (requires --query-release)
    #[arg(long, requires = "query_release")]
    drop_old_versions: bool,
}

fn main() {
    let args = Args::parse();

    let mode = if args.schema_only {
        OutputMode::SchemaOnly
    } else if args.provider_only {
        OutputMode::ProviderOnly
    } else if !args.event_only.is_empty() {
        OutputMode::EventOnly(args.event_only.clone())
    } else if let Some(id) = args.event_comment {
        OutputMode::EventComment(id)
    } else {
        OutputMode::Full
    };

    // Build the flags string for "To regenerate" banners
    let mut extra_flags = String::new();
    if args.mof {
        extra_flags.push_str(" --mof");
    }
    if args.query_release {
        extra_flags.push_str(" --query-release");
    }
    if args.drop_old_versions {
        extra_flags.push_str(" --drop-old-versions");
    }
    let release_flag = extra_flags.as_str();

    if args.mof {
        generate_mof(
            &args.provider_name,
            &mode,
            args.query_release,
            release_flag,
            args.drop_old_versions,
        );
    } else {
        let releases = if args.query_release {
            query_release_info(&args.provider_name, false)
        } else {
            None
        };

        match try_manifest(
            &args.provider_name,
            &mode,
            releases.as_ref(),
            release_flag,
            args.drop_old_versions,
        ) {
            TryResult::Success => {}
            TryResult::NotFound => {
                eprintln!(
                    "No manifest events for '{}', trying MOF/WMI...",
                    args.provider_name
                );
                generate_mof(
                    &args.provider_name,
                    &mode,
                    args.query_release,
                    release_flag,
                    args.drop_old_versions,
                );
            }
            TryResult::Error(msg) => {
                eprintln!("{msg}");
                std::process::exit(1);
            }
        }
    }
}

enum TryResult {
    Success,
    NotFound,
    Error(String),
}

fn try_manifest(
    provider_name: &str,
    mode: &OutputMode,
    releases: Option<&ReleaseMap>,
    release_flag: &str,
    drop_old_versions: bool,
) -> TryResult {
    let Ok(guid) = provider_guid_from_name(provider_name) else {
        return TryResult::NotFound;
    };
    // The tool's TDH plumbing uses its own windows types; etw-rs keeps its
    // public boundary windows-free, so convert at the seam via u128.
    let guid = windows::core::GUID::from_u128(guid.to_u128());

    let events = match get_provider_events(&guid) {
        Ok(e) => e,
        Err(e) => return TryResult::Error(format!("Error enumerating events: {e}")),
    };

    if events.is_empty() {
        return TryResult::NotFound;
    }

    let keywords = get_provider_keywords(&guid).unwrap_or_default();
    let keywords: Vec<_> = keywords
        .into_iter()
        .filter(|k| !is_channel_keyword(&k.name))
        .collect();

    match mode {
        OutputMode::Full => {
            let content = generate_full_file(
                provider_name,
                &guid,
                &events,
                &keywords,
                releases,
                release_flag,
                drop_old_versions,
            );
            print!("{content}");
        }
        OutputMode::SchemaOnly => {
            let extra = format!(" --schema-only{release_flag}");
            let schema = generate_schema_block(
                provider_name,
                &guid,
                &events,
                &keywords,
                &extra,
                releases,
                drop_old_versions,
            );
            print!("{schema}");
        }
        OutputMode::ProviderOnly => {
            let content = generate_provider_only(provider_name, &guid, &events, &keywords);
            print!("{content}");
        }
        OutputMode::EventOnly(target_ids) => {
            let filtered: Vec<_> = events
                .iter()
                .filter(|e| target_ids.contains(&e.id))
                .cloned()
                .collect();
            let missing: Vec<String> = target_ids
                .iter()
                .filter(|id| !events.iter().any(|e| e.id == **id))
                .map(ToString::to_string)
                .collect();
            if !missing.is_empty() {
                return TryResult::Error(format!(
                    "No event with id {} found for '{provider_name}'",
                    missing.join(", ")
                ));
            }
            let ids = target_ids
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" ");
            let extra = format!(" --event-only {ids}{release_flag}");
            let schema = generate_schema_block(
                provider_name,
                &guid,
                &filtered,
                &keywords,
                &extra,
                releases,
                drop_old_versions,
            );
            print!("{schema}");
        }
        OutputMode::EventComment(target_id) => {
            let filtered: Vec<_> = events
                .iter()
                .filter(|e| e.id == *target_id)
                .cloned()
                .collect();
            if filtered.is_empty() {
                return TryResult::Error(format!(
                    "No event with id {target_id} found for '{provider_name}'"
                ));
            }
            let extra = format!(" --event-comment {target_id}{release_flag}");
            let block = generate_comment_block(
                provider_name,
                &guid,
                &filtered,
                &keywords,
                &extra,
                releases,
                drop_old_versions,
            );
            print!("{block}");
        }
    }

    TryResult::Success
}

fn generate_mof(
    provider_name: &str,
    mode: &OutputMode,
    query_release: bool,
    release_flag: &str,
    drop_old_versions: bool,
) {
    let provider = match mof::get_mof_provider(provider_name) {
        Ok(Some(p)) => p,
        Ok(None) => {
            eprintln!("MOF provider '{provider_name}' not found in WMI");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Error querying WMI for '{provider_name}': {e}");
            std::process::exit(1);
        }
    };

    if provider.events.is_empty() {
        eprintln!("MOF provider '{}' found but has no events", provider.name);
        std::process::exit(1);
    }

    // Query keywords from TDH using the provider registration GUID
    let keywords = get_provider_keywords(&provider.provider_guid).unwrap_or_default();
    let keywords: Vec<_> = keywords
        .into_iter()
        .filter(|k| !is_channel_keyword(&k.name))
        .collect();

    // Resolve a friendly display name: prefer user-provided name if it differs
    // from the WMI class, otherwise try TDH-registered name from the GUID.
    let display_name = if provider_name == provider.name {
        provider_name_from_guid(&etw::Guid::from_u128(provider.provider_guid.to_u128()))
    } else {
        Some(provider_name.to_owned())
    };

    // For MOF providers the TSV file in Windows10EtwEvents uses the TDH-registered
    // provider name (e.g. "Windows Kernel Trace"), not the user-provided WMI class
    // name (e.g. "FileIo"). Resolve the TDH name from the provider GUID.
    let releases = if query_release {
        let tsv_name =
            provider_name_from_guid(&etw::Guid::from_u128(provider.provider_guid.to_u128()))
                .unwrap_or_else(|| provider_name.to_owned());
        query_release_info(&tsv_name, true)
    } else {
        None
    };
    let releases = releases.as_ref();

    match mode {
        OutputMode::Full => {
            let content = generate_mof_file(
                &provider,
                display_name.as_deref(),
                &keywords,
                releases,
                release_flag,
                drop_old_versions,
            );
            print!("{content}");
        }
        OutputMode::SchemaOnly => {
            let extra = format!(" --schema-only{release_flag}");
            let schema = generate_mof_schema(
                &provider,
                display_name.as_deref(),
                &extra,
                releases,
                drop_old_versions,
            );
            print!("{schema}");
        }
        OutputMode::ProviderOnly => {
            let content = generate_mof_provider_only(&provider, display_name.as_deref(), &keywords);
            print!("{content}");
        }
        OutputMode::EventOnly(target_ids) => {
            let target_opcodes: Vec<u8> = target_ids
                .iter()
                .map(|id| {
                    u8::try_from(*id).unwrap_or_else(|_| {
                        eprintln!(
                            "Error: --event-only value {id} exceeds valid MOF opcode range (0-255)"
                        );
                        std::process::exit(1);
                    })
                })
                .collect();
            let mut filtered = provider;
            filtered
                .events
                .retain(|e| target_opcodes.contains(&e.opcode));
            if filtered.events.is_empty() {
                eprintln!(
                    "No event with opcode {target_opcodes:?} found for MOF provider '{provider_name}'"
                );
                std::process::exit(1);
            }
            let opcodes = target_opcodes
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" ");
            let extra = format!(" --event-only {opcodes}{release_flag}");
            let schema = generate_mof_schema(
                &filtered,
                display_name.as_deref(),
                &extra,
                releases,
                drop_old_versions,
            );
            print!("{schema}");
        }
        OutputMode::EventComment(target_id) => {
            let target_opcode = u8::try_from(*target_id).unwrap_or_else(|_| {
                eprintln!(
                    "Error: --event-comment value {target_id} exceeds valid MOF opcode range (0-255)"
                );
                std::process::exit(1);
            });
            let mut filtered = provider;
            filtered.events.retain(|e| e.opcode == target_opcode);
            if filtered.events.is_empty() {
                eprintln!(
                    "No event with opcode {target_opcode} found for MOF provider '{provider_name}'"
                );
                std::process::exit(1);
            }
            let extra = format!(" --event-comment {target_opcode}{release_flag}");
            let block = generate_mof_comment_block(
                &filtered,
                display_name.as_deref(),
                &extra,
                releases,
                drop_old_versions,
            );
            print!("{block}");
        }
    }
}
