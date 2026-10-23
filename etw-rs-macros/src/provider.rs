//! Provider schema macro implementation for defining multiple events under one provider.

use crate::{
    multi_version,
    schema::{EventSchema, FieldDef, FieldOffset, expand_event_schema_from_struct, to_snake_case},
};
use proc_macro::TokenStream;
use proc_macro2::{Ident, Span};
use quote::quote;
use syn::{
    LitInt, LitStr, Token, braced,
    parse::{Parse, ParseStream},
    parse_macro_input,
    token::Colon,
};

/// Parsed representation of a provider with multiple events.
pub(crate) struct ProviderSchema {
    guid: syn::Expr,
    /// Fallback name prefix when individual events lack a `name:` field.
    /// Optional if every event has `name:`.
    friendly_name: Option<String>,
    events: Vec<EventDef>,
}

/// A single event definition (one ID, one or more versions).
struct EventDef {
    /// Event ID (`EventDescriptor.Id`). `Some` for manifest events.
    id: Option<u16>,
    /// Event opcode (`EventDescriptor.Opcode`). `Some` for classic/MOF events.
    opcode: Option<u8>,
    /// Event name for parser struct naming (e.g., "FileCreate" → `FileCreateV1Parser`).
    name: Option<String>,
    /// Event class GUID for MOF/classic events. Forwarded to `EventSchema::class_guid`.
    class_guid: Option<syn::Expr>,
    versions: Vec<VersionDef>,
}

/// A single version within an event definition.
struct VersionDef {
    version: u8,
    extends_version: Option<u8>,
    /// When `true`, trailing unsupported fields were stripped from the schema.
    truncated: bool,
    fields: Vec<FieldDef>,
}

impl Parse for ProviderSchema {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut guid = None;
        let mut friendly_name = None;
        let mut events = None;

        // Parse provider-level key-value pairs
        while !input.is_empty() {
            let key: Ident = input.parse()?;
            input.parse::<Colon>()?;

            match key.to_string().as_str() {
                "guid" => {
                    guid = Some(input.parse::<syn::Expr>()?);
                }
                "friendly_name" => {
                    let lit: LitStr = input.parse()?;
                    friendly_name = Some(lit.value());
                }
                "events" => {
                    let content;
                    braced!(content in input);
                    events = Some(Self::parse_events(&content)?);
                    break; // events is last
                }
                _ => {
                    return Err(syn::Error::new(key.span(), format!("unknown key: {key}")));
                }
            }

            // Consume trailing comma if present
            let _ = input.parse::<Token![,]>();
        }

        Ok(Self {
            guid: guid.ok_or_else(|| {
                syn::Error::new(Span::call_site(), "missing required field: guid")
            })?,
            friendly_name,
            events: events.ok_or_else(|| {
                syn::Error::new(Span::call_site(), "missing required field: events")
            })?,
        })
    }
}

impl ProviderSchema {
    fn parse_events(input: ParseStream) -> syn::Result<Vec<EventDef>> {
        let mut events = Vec::new();

        while !input.is_empty() {
            let event_keyword: Ident = input.parse()?;
            if event_keyword != "event" {
                return Err(syn::Error::new(
                    event_keyword.span(),
                    "expected 'event' keyword",
                ));
            }

            let event_content;
            braced!(event_content in input);

            // Parse event-level key-value pairs (id, opcode, name, class_guid) before version
            // blocks
            let mut id: Option<u16> = None;
            let mut opcode: Option<u8> = None;
            let mut event_name: Option<String> = None;
            let mut class_guid: Option<syn::Expr> = None;

            // Key-value pairs: ident `:` value. Stops at `version {` (ident + brace).
            while event_content.peek(syn::Ident) && event_content.peek2(Colon) {
                let key: Ident = event_content.parse()?;
                event_content.parse::<Colon>()?;
                match key.to_string().as_str() {
                    "id" => {
                        let lit: LitInt = event_content.parse()?;
                        id = Some(lit.base10_parse()?);
                    }
                    "opcode" => {
                        let lit: LitInt = event_content.parse()?;
                        opcode = Some(lit.base10_parse()?);
                    }
                    "name" => {
                        let lit: LitStr = event_content.parse()?;
                        event_name = Some(lit.value());
                    }
                    "class_guid" => {
                        class_guid = Some(event_content.parse::<syn::Expr>()?);
                    }
                    _ => {
                        return Err(syn::Error::new(
                            key.span(),
                            format!(
                                "expected 'id', 'opcode', 'name', 'class_guid', or 'version'; got '{key}'"
                            ),
                        ));
                    }
                }
                let _ = event_content.parse::<Token![,]>();
            }

            if id.is_none() && opcode.is_none() {
                return Err(syn::Error::new(
                    Span::call_site(),
                    "event must have at least one of 'id' or 'opcode'",
                ));
            }

            // Parse version blocks
            let mut versions = Vec::new();
            while !event_content.is_empty() {
                // We may have already consumed 'version' above. Check if next token is
                // an ident — if not, we already consumed it and should proceed directly.
                if event_content.peek(syn::Ident) {
                    let ver_keyword: Ident = event_content.parse()?;
                    if ver_keyword != "version" {
                        return Err(syn::Error::new(
                            ver_keyword.span(),
                            "expected 'version' keyword",
                        ));
                    }
                }

                let ver_content;
                braced!(ver_content in event_content);

                // First element is the version number (positional)
                let ver_lit: LitInt = ver_content.parse()?;
                let version = ver_lit.base10_parse::<u8>()?;
                let _ = ver_content.parse::<Token![,]>();

                // Parse remaining key-value pairs
                let mut extends_version = None;
                let mut truncated = false;
                let mut fields = None;

                while !ver_content.is_empty() {
                    let key: Ident = ver_content.parse()?;
                    ver_content.parse::<Colon>()?;

                    match key.to_string().as_str() {
                        "extends_version" => {
                            let lit: LitInt = ver_content.parse()?;
                            extends_version = Some(lit.base10_parse::<u8>()?);
                        }
                        "truncated" => {
                            let lit: syn::LitBool = ver_content.parse()?;
                            truncated = lit.value();
                        }
                        "fields" => {
                            let fields_content;
                            braced!(fields_content in ver_content);
                            fields = Some(EventSchema::parse_fields(&fields_content)?);
                        }
                        _ => {
                            return Err(syn::Error::new(
                                key.span(),
                                format!("unknown version field: {key}"),
                            ));
                        }
                    }

                    let _ = ver_content.parse::<Token![,]>();
                }

                versions.push(VersionDef {
                    version,
                    extends_version,
                    truncated,
                    fields: fields.ok_or_else(|| {
                        syn::Error::new(Span::call_site(), "missing required field: fields")
                    })?,
                });
            }

            if versions.is_empty() {
                return Err(syn::Error::new(
                    Span::call_site(),
                    "event must have at least one version block",
                ));
            }

            events.push(EventDef {
                id,
                opcode,
                name: event_name,
                class_guid,
                versions,
            });
        }

        Ok(events)
    }
}

/// Resolves `extends_version` inheritance by prepending base version fields.
///
/// Within each event, versions are sorted so that bases are resolved before
/// their dependants. Chained inheritance (v2 extends v1 extends v0) is
/// handled naturally because each version's fields are expanded in-place.
fn resolve_extends(events: &mut [EventDef]) -> syn::Result<()> {
    use std::collections::HashMap;

    for event in events.iter_mut() {
        event.versions.sort_by_key(|v| v.version);

        // Reject duplicate version numbers — the second would silently
        // overwrite the first in the index, corrupting extends_version lookups.
        for pair in event.versions.windows(2) {
            if pair[0].version == pair[1].version {
                let ver = pair[0].version;
                return Err(syn::Error::new(
                    Span::call_site(),
                    format!(
                        "duplicate version {ver} in event {:?}",
                        event.id.or(event.opcode.map(|o| o as u16))
                    ),
                ));
            }
        }

        let index: HashMap<u8, usize> = event
            .versions
            .iter()
            .enumerate()
            .map(|(i, v)| (v.version, i))
            .collect();

        for i in 0..event.versions.len() {
            let Some(base_ver) = event.versions[i].extends_version else {
                continue;
            };

            let ver = event.versions[i].version;

            if base_ver >= ver {
                return Err(syn::Error::new(
                    Span::call_site(),
                    format!(
                        "event {:?}v{ver}: extends_version ({base_ver}) \
                         must be less than the version ({ver})",
                        event.id.or(event.opcode.map(|o| o as u16))
                    ),
                ));
            }

            let base_idx = *index.get(&base_ver).ok_or_else(|| {
                syn::Error::new(
                    Span::call_site(),
                    format!(
                        "event {:?}v{ver} extends version {base_ver}, \
                         but no version {base_ver} exists for this event",
                        event.id.or(event.opcode.map(|o| o as u16))
                    ),
                )
            })?;

            let base_fields = event.versions[base_idx].fields.clone();
            let suffix_fields = std::mem::take(&mut event.versions[i].fields);
            event.versions[i].fields = base_fields;
            event.versions[i].fields.extend(suffix_fields);
            event.versions[i].extends_version = None;
        }
    }

    Ok(())
}

/// Expands provider_schema! macro to multiple event_schema! invocations.
pub(crate) fn expand_provider_schema(input: TokenStream) -> TokenStream {
    let provider_schema = parse_macro_input!(input as ProviderSchema);

    let provider_guid = &provider_schema.guid;
    let friendly_name = &provider_schema.friendly_name;

    let mut events = provider_schema.events;
    if let Err(err) = resolve_extends(&mut events) {
        return err.to_compile_error().into();
    }

    // Resolve event names: event `name` takes priority, then `friendly_name + discriminator`
    // fallback
    let resolved_names: Vec<String> = match events
        .iter()
        .map(|event| {
            if let Some(ref name) = event.name {
                Ok(name.clone())
            } else if let Some(fn_name) = friendly_name {
                let mut fallback = fn_name.clone();
                if let Some(first) = fallback.get_mut(0..1) {
                    first.make_ascii_uppercase();
                }
                let discriminator = event.id.map(|id| id as u32)
                    .or(event.opcode.map(|op| op as u32))
                    .unwrap_or(0);
                Ok(format!("{fallback}{discriminator}"))
            } else {
                let discriminator = event.id.map(|id| id as u32)
                    .or(event.opcode.map(|op| op as u32))
                    .unwrap_or(0);
                Err(syn::Error::new(
                    Span::call_site(),
                    format!(
                        "event {discriminator} has no 'name' and no provider-level 'friendly_name' fallback"
                    ),
                ))
            }
        })
        .collect::<syn::Result<Vec<_>>>()
    {
        Ok(names) => names,
        Err(err) => return err.to_compile_error().into(),
    };

    // Generate an event_schema! token stream for each (event, version) pair
    let event_schemas: Vec<_> = events
        .iter()
        .zip(&resolved_names)
        .flat_map(|(event, event_name)| {
            let id = event.id;
            let opcode = event.opcode;
            let class_guid = &event.class_guid;
            event.versions.iter().map(move |ver| {
                let version = ver.version;
                let fields = &ver.fields;

                let field_defs: Vec<_> = fields
                    .iter()
                    .map(|field| {
                        let name = Ident::new(&field.name, Span::call_site());
                        let ty = &field.ty;
                        match &field.offset {
                            FieldOffset::Fixed(_) | FieldOffset::Auto => {
                                // Fixed offsets are auto-calculated; emit bare field.
                                quote! { #name: #ty, }
                            }
                            FieldOffset::LengthFrom(length_field) => {
                                quote! { #name: #ty @ length(#length_field), }
                            }
                            FieldOffset::FixedLength(len) => {
                                let len_lit = LitInt::new(&len.to_string(), Span::call_site());
                                quote! { #name: #ty @ fixed_length(#len_lit), }
                            }
                            FieldOffset::CountFrom(count_field) => {
                                quote! { #name: #ty @ count(#count_field), }
                            }
                            FieldOffset::BinaryCount(count_field, elem_size) => {
                                let elem_size_lit =
                                    LitInt::new(&elem_size.to_string(), Span::call_site());
                                quote! { #name: #ty @ count_bytes(#count_field, #elem_size_lit), }
                            }
                            _ => {
                                quote! { #name: #ty, }
                            }
                        }
                    })
                    .collect();

                let id_token = id.map(|id| quote! { id: #id, }).unwrap_or_default();
                let opcode_token = opcode.map(|op| quote! { opcode: #op, }).unwrap_or_default();
                let class_guid_token = class_guid
                    .as_ref()
                    .map(|cg| quote! { class_guid: #cg, })
                    .unwrap_or_default();
                let truncated_token = if ver.truncated {
                    quote! { truncated: true, }
                } else {
                    quote! {}
                };

                let tokens = quote! {
                    guid: #provider_guid,
                    #class_guid_token
                    name: #event_name,
                    #id_token
                    #opcode_token
                    version: #version,
                    #truncated_token
                    fields: {
                        #(#field_defs)*
                    }
                };

                match syn::parse2::<EventSchema>(tokens) {
                    Ok(mut event_schema) => {
                        // provider_schema! generates a unified check() method
                        // on the multi-version parser — suppress per-version
                        // validation test modules.
                        event_schema.skip_validation = true;
                        expand_event_schema_from_struct(&event_schema)
                    }
                    Err(e) => {
                        let err = e.to_string();
                        quote! {
                            compile_error!(#err);
                        }
                    }
                }
            })
        })
        .collect();

    // Generate multi-version parsers (trait, impls, dynamic wrapper, enum)
    // for each event that has at least one version declared.
    let multi_version_code: Vec<proc_macro2::TokenStream> = events
        .iter()
        .zip(&resolved_names)
        .map(|(event, event_name)| {
            let mv_event = multi_version::MultiVersionEvent {
                name: event_name.clone(),
                guid: provider_guid.clone(),
                event_id: event.id,
                opcode: event.opcode,
                class_guid: event.class_guid.clone(),
                versions: event
                    .versions
                    .iter()
                    .map(|v| multi_version::ResolvedVersion {
                        version: v.version,
                        truncated: v.truncated,
                        fields: v.fields.clone(),
                    })
                    .collect(),
            };

            let trait_def = multi_version::generate_trait(&mv_event)?;
            let trait_impls = multi_version::generate_trait_impls(&mv_event)?;
            let dynamic = multi_version::generate_dynamic_wrapper(&mv_event)?;
            let enum_parser = multi_version::generate_enum_parser(&mv_event)?;
            let check = multi_version::generate_validate_schema_method(&mv_event);

            Ok(quote! {
                #trait_def
                #trait_impls
                #dynamic
                #enum_parser
                #check
            })
        })
        .collect::<syn::Result<Vec<_>>>()
        .unwrap_or_else(|err| vec![err.to_compile_error()]);

    let validate_calls: Vec<proc_macro2::TokenStream> = resolved_names
        .iter()
        .map(|event_name| {
            let parser = Ident::new(&format!("{event_name}Parser"), Span::call_site());
            quote! { #parser::validate_schema()?; }
        })
        .collect();

    // Derive a unique static name from the first event name.
    // Two providers whose first event shares a name would also generate
    // duplicate parser type names (e.g. `FooParser`) causing an earlier,
    // clearer compile error — so this name is safe within a module.
    let ctor_ident = {
        let upper = to_snake_case(&resolved_names[0]).to_ascii_uppercase();
        Ident::new(&format!("__ETW_RS_CTOR_{upper}"), Span::call_site())
    };

    let expanded = quote! {
        #(#event_schemas)*
        #(#multi_version_code)*

        // Registers the schema validator via the Windows CRT constructor
        // mechanism (.CRT$XCU section). The function runs before main(),
        // so etw::validate_all_schemas() always finds every provider
        // registered by provider_schema! — no manual registration required.
        // No additional crate dependencies are needed in user code.
        #[cfg(windows)]
        #[allow(missing_docs, non_upper_case_globals)]
        #[used]
        #[unsafe(link_section = ".CRT$XCU")]
        static #ctor_ident: unsafe extern "C" fn() = {
            unsafe extern "C" fn __ctor() {
                ::etw::__register_schema_validator(|| {
                    #(#validate_calls)*
                    Ok(())
                });
            }
            __ctor
        };
    };

    expanded.into()
}
