//! Static schema parser macro implementation.
//!
//! Generates sequential parser structs for ETW event fields with compile-time
//! constant offsets and optional schema validation tests.

use proc_macro::TokenStream;
use proc_macro2::{Ident, Span, TokenStream as TokenStream2};
use quote::{ToTokens, quote};
use syn::{
    LitInt, LitStr, Token, Type,
    parse::{Parse, ParseStream},
    parse_macro_input,
    token::Colon,
};

/// Parsed representation of the event_schema! macro input.
pub(crate) struct EventSchema {
    /// Provider GUID expression (e.g., `GUID` or `etw::Guid::from_u128(0x...)`).
    /// When provided, a debug assertion checks the event's provider GUID in `Parser::new()`
    /// and a validation test is generated that checks the schema against Windows TDH.
    pub(crate) guid: Option<syn::Expr>,
    /// Event class GUID for MOF/classic events. When present, TDH validation uses this
    /// as `ProviderId` (with `EVENT_HEADER_FLAG_CLASSIC_HEADER`), and the debug assertion
    /// in `Parser::new()` checks against this instead of `guid`.
    pub(crate) class_guid: Option<syn::Expr>,
    /// Name used as the parser struct prefix (e.g., "FileCreate" → `FileCreateV1Parser`).
    /// Accepts either `name:` or `friendly_name:` (backwards-compatible alias).
    pub(crate) name: String,
    /// Event ID (`EventDescriptor.Id`). Checked in debug assert when `Some`.
    id: Option<u16>,
    /// Event opcode (`EventDescriptor.Opcode`). Checked in debug assert when `Some`.
    /// Classic/MOF events identify by opcode rather than event ID.
    opcode: Option<u8>,
    version: u8,
    /// When `true`, the schema is a valid prefix of the TDH schema — trailing
    /// unsupported fields were stripped by the generator.  The validation test
    /// uses `>=` instead of `==` for the field count assertion.
    pub(crate) truncated: bool,
    /// When `true`, suppress the per-version TDH validation test module.
    /// Set by `provider_schema!` which generates a unified `check()` method instead.
    pub(crate) skip_validation: bool,
    fields: Vec<FieldDef>,
}

/// A single field definition in the schema.
#[derive(Clone)]
pub(crate) struct FieldDef {
    pub(crate) name: String,
    pub(crate) ty: Type,
    pub(crate) offset: FieldOffset,
    /// TDH in-type from `@ tdh(...)`, when the Rust type does not determine it.
    ///
    /// `u64` is UInt64, FileTime or HexInt64; `usize` is Pointer or SizeT. The Rust
    /// type fixes the wire layout, not the meaning, so without this the crate has to
    /// guess a representative and `validate_schema` can only match by group.
    pub(crate) tdh: Option<String>,
}

/// Field offset strategy.
#[derive(Clone)]
pub(crate) enum FieldOffset {
    /// Fixed byte offset (explicitly specified or auto-calculated, before any variable fields)
    Fixed(usize),
    /// Explicitly-sized field at a compile-time offset, e.g. `u8 @ fixed_length(16)`
    /// appearing before any genuinely variable-length field.
    ///
    /// `@ fixed_length(N)` states the size at compile time, so the offset of
    /// every later field is still a constant. Treating such a field as the
    /// start of the variable region -- as it once was -- pushed all of them onto
    /// the cached sequential path for no reason: the IPv6 kernel network events
    /// declare two 16-byte addresses ahead of six plain integers.
    FixedBinary { offset: usize, len: usize },
    /// Inferred automatically for variable-length types (WideStrRef, AnsiStrRef, SidRef, etc.)
    Following,
    /// Length specified by another field (e.g., @ length("DataLength"))
    LengthFrom(String),
    /// Fixed byte length (e.g., @ fixed_length(128)). The field has a known compile-time
    /// byte size but follows variable fields. Accessor returns `&[u8]`.
    FixedLength(usize),
    /// Auto-calculate from previous fields
    Auto,
    /// Fixed field that comes after variable fields.
    /// Offset is computed at runtime via the sequential caching mechanism.
    FixedAfterVariable,
    /// Element count specified by another field (e.g., @ count("GuidCount")).
    /// Element size is derived from the field type at macro expansion time.
    /// Accessor returns `Vec<T>`.
    CountFrom(String),
    /// Byte count computed as `count_field_value * element_byte_size`.
    /// Used for struct property arrays where each element is a fixed-size binary blob.
    /// Syntax: `u8 @ count_bytes("CountField", 24)`.
    /// Accessor returns `&[u8]`.
    BinaryCount(String, usize),
}

impl Parse for EventSchema {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut guid = None;
        let mut class_guid = None;
        let mut name = None;
        let mut id = None;
        let mut opcode = None;
        let mut version = None;
        let mut truncated = false;
        let mut fields = None;

        // Parse key-value pairs
        while !input.is_empty() {
            let key: Ident = input.parse()?;
            input.parse::<Colon>()?;

            match key.to_string().as_str() {
                "guid" => {
                    guid = Some(input.parse::<syn::Expr>()?);
                }
                "class_guid" => {
                    class_guid = Some(input.parse::<syn::Expr>()?);
                }
                // Accept both "name" and "friendly_name" (backwards-compatible alias)
                "name" | "friendly_name" => {
                    let lit: LitStr = input.parse()?;
                    name = Some(lit.value());
                }
                "id" => {
                    let lit: LitInt = input.parse()?;
                    id = Some(lit.base10_parse::<u16>()?);
                }
                "opcode" => {
                    let lit: LitInt = input.parse()?;
                    opcode = Some(lit.base10_parse::<u8>()?);
                }
                "version" => {
                    let lit: LitInt = input.parse()?;
                    version = Some(lit.base10_parse::<u8>()?);
                }
                "truncated" => {
                    let lit: syn::LitBool = input.parse()?;
                    truncated = lit.value();
                }
                "fields" => {
                    let content;
                    syn::braced!(content in input);
                    fields = Some(Self::parse_fields(&content)?);
                }
                _ => {
                    return Err(syn::Error::new(key.span(), format!("unknown key: {key}")));
                }
            }

            // Consume trailing comma if present
            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            }
        }

        // Ensure all required fields are present
        let name = name.ok_or_else(|| input.error("missing 'name' (or 'friendly_name')"))?;
        if id.is_none() && opcode.is_none() {
            return Err(input.error("at least one of 'id' or 'opcode' must be specified"));
        }
        let version = version.ok_or_else(|| input.error("missing 'version'"))?;
        let mut fields = fields.ok_or_else(|| input.error("missing 'fields'"))?;

        // Calculate automatic offsets for fields marked Auto
        calculate_auto_offsets(&mut fields)?;

        Ok(Self {
            guid,
            class_guid,
            name,
            id,
            opcode,
            version,
            truncated,
            skip_validation: false,
            fields,
        })
    }
}

/// Every TDH in-type name `@ tdh(...)` accepts, mirroring `etw::TdhInType`.
const TDH_IN_TYPES: &[&str] = &[
    "Null",
    "UnicodeString",
    "AnsiString",
    "Int8",
    "UInt8",
    "Int16",
    "UInt16",
    "Int32",
    "UInt32",
    "Int64",
    "UInt64",
    "Float",
    "Double",
    "Boolean",
    "Binary",
    "Guid",
    "Pointer",
    "FileTime",
    "SystemTime",
    "Sid",
    "HexInt32",
    "HexInt64",
    "ManifestCountedString",
    "ManifestCountedAnsiString",
    "ManifestCountedBinary",
    "CountedString",
    "CountedAnsiString",
    "ReversedCountedString",
    "ReversedCountedAnsiString",
    "NonNullTerminatedString",
    "NonNullTerminatedAnsiString",
    "UnicodeChar",
    "AnsiChar",
    "SizeT",
    "HexDump",
    "WbemSid",
    "Struct",
];

impl EventSchema {
    /// Parse the fields section.
    pub(crate) fn parse_fields(input: ParseStream) -> syn::Result<Vec<FieldDef>> {
        let mut fields = Vec::new();

        while !input.is_empty() {
            // Parse: FieldName: Type [@ offset | @ following]
            let field_name: Ident = input.parse()?;
            input.parse::<Colon>()?;
            let field_type: Type = input.parse()?;

            // Any number of `@` annotations, in any order: at most one offset
            // specification, and at most one `@ tdh(...)`.
            let mut offset = None;
            let mut tdh = None;
            while input.peek(Token![@]) {
                input.parse::<Token![@]>()?;

                let is_tdh = input.fork().parse::<Ident>().is_ok_and(|i| i == "tdh");
                if is_tdh {
                    input.parse::<Ident>()?;
                    let content;
                    syn::parenthesized!(content in input);
                    let name: Ident = content.parse()?;
                    let name = name.to_string();
                    if !TDH_IN_TYPES.contains(&name.as_str()) {
                        return Err(syn::Error::new(
                            content.span(),
                            format!(
                                "unknown TDH in-type '{name}'; expected one of: {}",
                                TDH_IN_TYPES.join(", ")
                            ),
                        ));
                    }
                    if tdh.replace(name).is_some() {
                        return Err(syn::Error::new(
                            input.span(),
                            "duplicate @ tdh(...) annotation on one field",
                        ));
                    }
                    continue;
                }

                let parsed_offset = if input.peek(LitInt) {
                    // Explicit numeric offsets are not supported — offsets are
                    // auto-calculated from field sizes. Use auto (no annotation)
                    // for fixed fields.
                    let lit: LitInt = input.parse()?;
                    return Err(syn::Error::new(
                        lit.span(),
                        "explicit numeric offsets (@ N) are not supported; \
                         remove the @ annotation and let offsets be auto-calculated",
                    ));
                } else {
                    // Parse identifier for @ length("FieldName")
                    let ident: Ident = input.parse()?;

                    if ident == "length" {
                        // Parse: @ length("FieldName")
                        let content;
                        syn::parenthesized!(content in input);
                        let field_name: LitStr = content.parse()?;
                        FieldOffset::LengthFrom(field_name.value())
                    } else if ident == "fixed_length" {
                        // Parse: @ fixed_length(128)
                        let content;
                        syn::parenthesized!(content in input);
                        let size: LitInt = content.parse()?;
                        FieldOffset::FixedLength(size.base10_parse()?)
                    } else if ident == "count" {
                        // Parse: @ count("FieldName")
                        let content;
                        syn::parenthesized!(content in input);
                        let field_name: LitStr = content.parse()?;
                        FieldOffset::CountFrom(field_name.value())
                    } else if ident == "count_bytes" {
                        // Parse: @ count_bytes("FieldName", element_size)
                        let content;
                        syn::parenthesized!(content in input);
                        let field_name: LitStr = content.parse()?;
                        content.parse::<Token![,]>()?;
                        let size: LitInt = content.parse()?;
                        FieldOffset::BinaryCount(field_name.value(), size.base10_parse()?)
                    } else {
                        return Err(syn::Error::new(
                            ident.span(),
                            "expected 'length(\"FieldName\")', 'fixed_length(N)', 'count(\"FieldName\")', 'count_bytes(\"FieldName\", N)', or 'tdh(InType)'",
                        ));
                    }
                };

                if offset.replace(parsed_offset).is_some() {
                    return Err(syn::Error::new(
                        input.span(),
                        "more than one offset annotation on one field",
                    ));
                }
            }

            let offset = offset.unwrap_or_else(|| {
                // No offset specified - infer from type
                if is_variable_length_type(&field_type) {
                    FieldOffset::Following
                } else {
                    FieldOffset::Auto
                }
            });

            fields.push(FieldDef {
                name: field_name.to_string(),
                ty: field_type,
                offset,
                tdh,
            });

            // Consume trailing comma if present
            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            }
        }

        Ok(fields)
    }
}

/// Calculate automatic offsets for fields marked as Auto.
///
/// This walks through the field list and assigns offsets based on
/// the size of previous fields. Handles both fields before variable fields
/// and fixed fields that come after variable fields.
fn calculate_auto_offsets(fields: &mut [FieldDef]) -> syn::Result<()> {
    let mut current_offset = 0;
    let mut in_variable_region = false;

    for field in fields.iter_mut() {
        // Clone the offset to avoid borrowing issues
        let offset_type = field.offset.clone();

        match offset_type {
            FieldOffset::Auto => {
                if in_variable_region {
                    // We're after variable fields - use FixedAfterVariable
                    let size = type_to_size(&field.ty, 8);
                    if size == 0 {
                        return Err(syn::Error::new(
                            Span::call_site(),
                            format!(
                                "cannot auto-calculate offset for field '{}': unknown type size. \
                                 Use a variable-offset annotation: @ length(), @ count(), @ fixed_length(), or @ count_bytes()",
                                field.name
                            ),
                        ));
                    }
                    field.offset = FieldOffset::FixedAfterVariable;
                } else {
                    // Before any variable fields - use Fixed
                    let size = type_to_size(&field.ty, 8);
                    if size == 0 {
                        return Err(syn::Error::new(
                            Span::call_site(),
                            format!(
                                "cannot auto-calculate offset for field '{}': unknown type size. \
                                 Use a variable-offset annotation: @ length(), @ count(), @ fixed_length(), or @ count_bytes()",
                                field.name
                            ),
                        ));
                    }
                    field.offset = FieldOffset::Fixed(current_offset);
                    current_offset += size;
                }
            }
            FieldOffset::Fixed(_) => {
                // Fixed offsets are assigned internally by this function;
                // user-specified @ N is rejected at parse time.
                // If we encounter one here, it was already set — just
                // advance current_offset past it.
                let size = type_to_size(&field.ty, 8);
                current_offset += size;
            }
            FieldOffset::FixedLength(len) => {
                // Explicitly sized, so the offset of everything after it is
                // still a compile-time constant -- this does not start the
                // variable region. Once inside one, though, the offset is no
                // longer known and it stays a sequential read.
                if in_variable_region {
                    // Already sequential; leave the annotation as-is.
                } else {
                    field.offset = FieldOffset::FixedBinary {
                        offset: current_offset,
                        len,
                    };
                    current_offset += len;
                }
            }
            FieldOffset::Following
            | FieldOffset::LengthFrom(_)
            | FieldOffset::CountFrom(_)
            | FieldOffset::BinaryCount(_, _) => {
                // Genuinely variable-length — everything after needs scanning.
                if !in_variable_region {
                    in_variable_region = true;
                }
            }
            FieldOffset::FixedBinary { len, .. } => {
                // Already resolved by a previous pass.
                current_offset += len;
            }
            FieldOffset::FixedAfterVariable => {
                // Already marked — shouldn't happen during auto-calculation
                // but handle it gracefully
            }
        }
    }

    Ok(())
}

/// Generate a test module that validates the static schema against the registered Windows schema.
///
/// The generated test delegates to `etw::static_schema::validate_schema`,
/// which queries TDH and compares field count, names, types, and required
/// property flags. All TDH access happens inside etw-rs, so generated code
/// needs no `windows`(-sys) dependency of its own.
///
/// The test is only compiled in test/debug builds to avoid runtime overhead in release builds.
fn generate_validation_module(schema: &EventSchema) -> TokenStream2 {
    // provider_schema! generates a unified check() method — skip per-version modules.
    if schema.skip_validation {
        return quote! {};
    }

    // For TDH validation, use class_guid (MOF/classic) if available, otherwise guid
    let Some(tdh_guid_expr) = schema.class_guid.as_ref().or(schema.guid.as_ref()) else {
        return quote! {};
    };
    let is_classic = schema.class_guid.is_some();
    let id = schema.id.unwrap_or(0);
    let opcode = schema.opcode.unwrap_or(0);
    let version = schema.version;
    let truncated = schema.truncated;

    // Generate test module name from the schema name
    // Convert PascalCase to snake_case for idiomatic test module names
    let snake_name = to_snake_case(&schema.name);
    let test_module_name = Ident::new(
        &format!("validate_{snake_name}_{version}_schema"),
        Span::call_site(),
    );

    let field_entries: Vec<TokenStream2> = schema
        .fields
        .iter()
        .map(|field| {
            let name = &field.name;
            let tdh_type_token = if let Some(t) = field_tdh_intype(field) {
                quote! { Some(#t) }
            } else {
                quote! { None }
            };
            let required_flags = offset_required_flags(&field.offset);
            quote! {
                ::etw::static_schema::StaticFieldInfo {
                    name: #name,
                    expected_tdh_type: #tdh_type_token,
                    required_property_flags: #required_flags,
                }
            }
        })
        .collect();

    quote! {
        #[cfg(any(test, debug_assertions))]
        #[cfg(windows)]
        mod #test_module_name {
            use super::*;

            #[test]
            // Validates against the live Windows TDH registry, which Miri cannot
            // interpret. `ignore` rather than `cfg` keeps it enumerable via
            // `cargo miri test -- --list --ignored`.
            #[cfg_attr(miri, ignore = "calls TdhGetEventInformation (Win32)")]
            fn validate_schema_matches_windows() {
                // A provider that is not registered on this machine validates
                // as Ok(()) — the same skip semantics the previous inline
                // TdhGetEventInformation body had.
                ::etw::static_schema::validate_schema(
                    &#tdh_guid_expr,
                    #id,
                    #opcode,
                    #is_classic,
                    &[::etw::static_schema::StaticVersionInfo {
                        version: #version,
                        fields: &[#(#field_entries),*],
                        truncated: #truncated,
                    }],
                    &[],
                )
                .unwrap_or_else(|e| panic!("{e}"));
            }
        }
    }
}

/// TDH property flags a field's declared layout requires TDH to report:
/// `PropertyStruct` (0x1), `PropertyParamLength` (0x2), `PropertyParamCount`
/// (0x4). Zero when the layout implies none.
pub(crate) const fn offset_required_flags(offset: &FieldOffset) -> u32 {
    match offset {
        FieldOffset::BinaryCount(_, _) => 0x1 | 0x4,
        FieldOffset::CountFrom(_) => 0x4,
        FieldOffset::LengthFrom(_) => 0x2,
        _ => 0,
    }
}

/// Validates that `@ length("Field")` and `@ count("Field")` reference a preceding fixed field.
fn validate_field_references(fields: &[FieldDef]) -> std::result::Result<(), TokenStream2> {
    for (idx, field) in fields.iter().enumerate() {
        let (FieldOffset::LengthFrom(ref_name)
        | FieldOffset::CountFrom(ref_name)
        | FieldOffset::BinaryCount(ref_name, _)) = &field.offset
        else {
            continue;
        };

        // The referenced field must exist before this field and be fixed-offset.
        let found = fields[..idx]
            .iter()
            .any(|f| f.name == *ref_name && matches!(f.offset, FieldOffset::Fixed(_)));

        if !found {
            let kind = match &field.offset {
                FieldOffset::LengthFrom(_) => "length",
                FieldOffset::CountFrom(_) => "count",
                FieldOffset::BinaryCount(_, _) => "count_bytes",
                _ => unreachable!(),
            };
            let msg = format!(
                "field '{}': @ {}(\"{}\") references a field that is not a preceding \
                 fixed-offset field — the referenced field must appear earlier in the \
                 schema with a known offset",
                field.name, kind, ref_name,
            );
            return Err(quote::quote! { compile_error!(#msg); });
        }
    }
    Ok(())
}

/// Expands an EventSchema struct into generated code (internal helper).
pub(crate) fn expand_event_schema_from_struct(schema: &EventSchema) -> TokenStream2 {
    // Validate field references before code generation.
    if let Err(err) = validate_field_references(&schema.fields) {
        return err;
    }

    // Calculate fixed field end offset for variable fields
    let fixed_end_offset = calculate_fixed_end_offset(&schema.fields);

    // Detect pointer-sized fields (usize/isize) — these have event-dependent sizes
    // (4 bytes for 32-bit WOW64 processes, 8 bytes for 64-bit processes).
    let has_pointer_fields = schema.fields.iter().any(|f| is_pointer_type(&f.ty));

    // Compute per-field offsets for both pointer sizes when needed.
    // 64-bit offsets match the existing FieldOffset::Fixed values from calculate_auto_offsets.
    // 32-bit offsets are used to generate dual-offset accessors for correct WOW64 parsing.
    let (offsets_32, fixed_end_32) = if has_pointer_fields {
        compute_fixed_offsets(&schema.fields, 4)
    } else {
        (Vec::new(), fixed_end_offset)
    };
    let (offsets_64, fixed_end_64) = if has_pointer_fields {
        compute_fixed_offsets(&schema.fields, 8)
    } else {
        (Vec::new(), fixed_end_offset)
    };

    // Generate parser struct name: {Name}V{Version}Parser
    let parser_struct_name = Ident::new(
        &format!("{}V{}Parser", schema.name, schema.version),
        Span::call_site(),
    );

    // Calculate first variable field index for cache index arithmetic
    let first_variable_index = schema
        .fields
        .iter()
        .position(|f| {
            !matches!(
                f.offset,
                FieldOffset::Fixed(_) | FieldOffset::FixedBinary { .. }
            )
        })
        .unwrap_or(schema.fields.len());
    let first_variable_index_lit =
        syn::LitInt::new(&first_variable_index.to_string(), Span::call_site());

    // Find the last variable field (for eager caching optimization)
    let last_variable_field_index = schema
        .fields
        .iter()
        .enumerate()
        .rev()
        .find(|(_, f)| {
            !matches!(
                f.offset,
                FieldOffset::Fixed(_) | FieldOffset::FixedBinary { .. }
            )
        })
        .map(|(idx, _)| idx);

    // Pre-calculate literals needed in generated code
    let fixed_end_offset_lit = syn::LitInt::new(&fixed_end_offset.to_string(), Span::call_site());

    // Expression for the fixed-end offset in generated code. When pointer-sized fields
    // are present, this is a runtime selection; otherwise it's a compile-time constant.
    let fixed_end_expr: TokenStream2 = if has_pointer_fields {
        let fe32 = syn::LitInt::new(&fixed_end_32.to_string(), Span::call_site());
        let fe64 = syn::LitInt::new(&fixed_end_64.to_string(), Span::call_site());
        quote! { if self.pointer_size == 4 { #fe32 } else { #fe64 } }
    } else {
        let fe = syn::LitInt::new(&fixed_end_offset.to_string(), Span::call_site());
        quote! { #fe }
    };

    // Generate field accessor methods for the parser struct (eager caching approach)
    let mut parser_methods = Vec::new();
    let mut fixed_prefix_idx = 0usize; // Tracks index into offsets_32/offsets_64

    for (field_idx, field) in schema.fields.iter().enumerate() {
        let field_idx_lit = syn::LitInt::new(&field_idx.to_string(), Span::call_site());
        let field_name_snake = to_accessor_ident(&field.name);
        let field_type = &field.ty;

        // For ref-type fields, the raw accessor is named `{field}_ref()` and a thin
        // owned wrapper takes the bare `{field}()` name. Non-ref fields keep the bare name.
        let is_ref = is_ref_accessor(field);
        let accessor_name = if is_ref {
            Ident::new(&format!("{field_name_snake}_ref"), Span::call_site())
        } else {
            field_name_snake.clone()
        };

        let method = match &field.offset {
            FieldOffset::FixedBinary { offset, len } => {
                // Offset and length are both compile-time constants, so this
                // reads straight out of the event buffer -- no location cache
                // and no sequential scan, exactly as a fixed scalar field does.
                let fpi = fixed_prefix_idx;
                fixed_prefix_idx += 1;
                let len_lit = syn::LitInt::new(&len.to_string(), Span::call_site());
                let offset_lit = if has_pointer_fields {
                    syn::LitInt::new(&offsets_64[fpi].to_string(), Span::call_site())
                } else {
                    syn::LitInt::new(&offset.to_string(), Span::call_site())
                };
                quote! {
                    #[inline]
                    pub fn #accessor_name(&mut self) -> ::etw::Result<&'a [u8]> {
                        const OFFSET: usize = #offset_lit;
                        const LEN: usize = #len_lit;
                        ::etw::static_schema::parse_binary(self.data, OFFSET, LEN)
                    }
                }
            }
            FieldOffset::Fixed(offset) => {
                let qualified_type = qualify_crate_type(field_type);
                let fpi = fixed_prefix_idx;
                fixed_prefix_idx += 1;

                if !has_pointer_fields {
                    // No pointer fields — pure compile-time constants, no cache
                    let offset_lit = syn::LitInt::new(&offset.to_string(), Span::call_site());
                    let size = type_to_size_expr(field_type, false);
                    quote! {
                        #[inline]
                        pub fn #accessor_name(&self) -> ::etw::Result<#qualified_type> {
                            const OFFSET: usize = #offset_lit;
                            const SIZE: usize = #size;
                            ::etw::static_schema::parse_fixed(self.data, OFFSET, SIZE)
                        }
                    }
                } else if is_pointer_type(field_type) {
                    // Pointer-sized field — use parse_pointer/parse_signed_pointer
                    let o32 = offsets_32[fpi];
                    let o64 = offsets_64[fpi];
                    let o32_lit = syn::LitInt::new(&o32.to_string(), Span::call_site());
                    let o64_lit = syn::LitInt::new(&o64.to_string(), Span::call_site());
                    let is_signed =
                        matches!(field_type.to_token_stream().to_string().as_str(), "isize");

                    let parse_fn = if is_signed {
                        quote! { ::etw::static_schema::parse_signed_pointer }
                    } else {
                        quote! { ::etw::static_schema::parse_pointer }
                    };

                    if o32 == o64 {
                        // Offset is the same for both pointer sizes (field is before
                        // any other pointer field, or at position 0)
                        let offset_lit = syn::LitInt::new(&o64.to_string(), Span::call_site());
                        quote! {
                            #[inline]
                            pub fn #accessor_name(&self) -> ::etw::Result<#qualified_type> {
                                const OFFSET: usize = #offset_lit;
                                #parse_fn(self.data, OFFSET, self.pointer_size)
                            }
                        }
                    } else {
                        quote! {
                            #[inline]
                            pub fn #accessor_name(&self) -> ::etw::Result<#qualified_type> {
                                const OFFSET_32: usize = #o32_lit;
                                const OFFSET_64: usize = #o64_lit;
                                let offset = if self.pointer_size == 4 {
                                    OFFSET_32
                                } else {
                                    OFFSET_64
                                };
                                #parse_fn(self.data, offset, self.pointer_size)
                            }
                        }
                    }
                } else {
                    // Non-pointer field in a schema with pointer fields — may need
                    // dual offsets if preceded by pointer-sized fields
                    let o32 = offsets_32[fpi];
                    let o64 = offsets_64[fpi];
                    let size = type_to_size_expr(field_type, false);

                    if o32 == o64 {
                        // Offset is identical — no pointer fields precede this one
                        let offset_lit = syn::LitInt::new(&o64.to_string(), Span::call_site());
                        quote! {
                            #[inline]
                            pub fn #accessor_name(&self) -> ::etw::Result<#qualified_type> {
                                const OFFSET: usize = #offset_lit;
                                const SIZE: usize = #size;
                                ::etw::static_schema::parse_fixed(self.data, OFFSET, SIZE)
                            }
                        }
                    } else {
                        let o32_lit = syn::LitInt::new(&o32.to_string(), Span::call_site());
                        let o64_lit = syn::LitInt::new(&o64.to_string(), Span::call_site());
                        quote! {
                            #[inline]
                            pub fn #accessor_name(&self) -> ::etw::Result<#qualified_type> {
                                const OFFSET_32: usize = #o32_lit;
                                const OFFSET_64: usize = #o64_lit;
                                let offset = if self.pointer_size == 4 {
                                    OFFSET_32
                                } else {
                                    OFFSET_64
                                };
                                const SIZE: usize = #size;
                                ::etw::static_schema::parse_fixed(self.data, offset, SIZE)
                            }
                        }
                    }
                }
            }
            FieldOffset::Following
            | FieldOffset::LengthFrom(_)
            | FieldOffset::FixedLength(_)
            | FieldOffset::CountFrom(_)
            | FieldOffset::BinaryCount(_, _)
            | FieldOffset::FixedAfterVariable => {
                // All variable-offset fields use sequential caching
                // Simple: compute_locations_up_to(field_idx) then access cache[field_idx]

                // Generate method based on field type
                if is_counted_wide_string_type(field_type) {
                    // Counted types always read the size from the 2-byte prefix,
                    // even for the last field (unlike null-terminated strings that
                    // consume the rest of the buffer).
                    let is_last = last_variable_field_index == Some(field_idx);
                    if is_last {
                        let preamble = gen_last_field_preamble(
                            &field_idx_lit,
                            &first_variable_index_lit,
                            &fixed_end_expr,
                        );
                        quote! {
                            #[inline]
                            pub fn #accessor_name(
                                &mut self
                            ) -> ::etw::Result<::etw::WideStrRef<'a>> {
                                #preamble
                                let size_bytes = ::etw::static_schema::compute_counted_size(
                                    self.data,
                                    start_offset
                                )?;
                                ::etw::static_schema::parse_counted_wide_string_sized(
                                    self.data,
                                    start_offset,
                                    size_bytes
                                )
                            }
                        }
                    } else {
                        let preamble = gen_non_last_field_preamble(
                            &field_idx_lit,
                            &first_variable_index_lit,
                            &fixed_end_expr,
                            true,
                        );
                        quote! {
                            #[inline]
                            pub fn #accessor_name(
                                &mut self
                            ) -> ::etw::Result<::etw::WideStrRef<'a>> {
                                #preamble
                                ::etw::static_schema::parse_counted_wide_string_sized(
                                    self.data,
                                    start_offset,
                                    size_bytes
                                )
                            }
                        }
                    }
                } else if is_counted_ansi_string_type(field_type) {
                    let is_last = last_variable_field_index == Some(field_idx);
                    if is_last {
                        let preamble = gen_last_field_preamble(
                            &field_idx_lit,
                            &first_variable_index_lit,
                            &fixed_end_expr,
                        );
                        quote! {
                            #[inline]
                            pub fn #accessor_name(
                                &mut self
                            ) -> ::etw::Result<::etw::AnsiStrRef<'a>> {
                                #preamble
                                let size_bytes = ::etw::static_schema::compute_counted_size(
                                    self.data,
                                    start_offset
                                )?;
                                ::etw::static_schema::parse_counted_ansi_string_sized(
                                    self.data,
                                    start_offset,
                                    size_bytes
                                )
                            }
                        }
                    } else {
                        let preamble = gen_non_last_field_preamble(
                            &field_idx_lit,
                            &first_variable_index_lit,
                            &fixed_end_expr,
                            true,
                        );
                        quote! {
                            #[inline]
                            pub fn #accessor_name(
                                &mut self
                            ) -> ::etw::Result<::etw::AnsiStrRef<'a>> {
                                #preamble
                                ::etw::static_schema::parse_counted_ansi_string_sized(
                                    self.data,
                                    start_offset,
                                    size_bytes
                                )
                            }
                        }
                    }
                } else if is_counted_binary_type(field_type) {
                    let is_last = last_variable_field_index == Some(field_idx);
                    if is_last {
                        let preamble = gen_last_field_preamble(
                            &field_idx_lit,
                            &first_variable_index_lit,
                            &fixed_end_expr,
                        );
                        quote! {
                            #[inline]
                            pub fn #accessor_name(&mut self) -> ::etw::Result<&'a [u8]> {
                                #preamble
                                let size_bytes = ::etw::static_schema::compute_counted_size(
                                    self.data,
                                    start_offset
                                )?;
                                ::etw::static_schema::parse_counted_binary_sized(
                                    self.data,
                                    start_offset,
                                    size_bytes
                                )
                            }
                        }
                    } else {
                        let preamble = gen_non_last_field_preamble(
                            &field_idx_lit,
                            &first_variable_index_lit,
                            &fixed_end_expr,
                            true,
                        );
                        quote! {
                            #[inline]
                            pub fn #accessor_name(&mut self) -> ::etw::Result<&'a [u8]> {
                                #preamble
                                ::etw::static_schema::parse_counted_binary_sized(
                                    self.data,
                                    start_offset,
                                    size_bytes
                                )
                            }
                        }
                    }
                } else if is_wide_string_type(field_type) {
                    let is_last = last_variable_field_index == Some(field_idx);
                    let parse_fn = quote! { ::etw::static_schema::parse_wide_string_sized };

                    if is_last {
                        let preamble = gen_last_field_preamble(
                            &field_idx_lit,
                            &first_variable_index_lit,
                            &fixed_end_expr,
                        );
                        quote! {
                            #[inline]
                            pub fn #accessor_name(
                                &mut self
                            ) -> ::etw::Result<::etw::WideStrRef<'a>> {
                                #preamble
                                let size_bytes = self.data.len().saturating_sub(start_offset);
                                #parse_fn(self.data, start_offset, size_bytes)
                            }
                        }
                    } else {
                        let preamble = gen_non_last_field_preamble(
                            &field_idx_lit,
                            &first_variable_index_lit,
                            &fixed_end_expr,
                            true,
                        );
                        quote! {
                            #[inline]
                            pub fn #accessor_name(
                                &mut self
                            ) -> ::etw::Result<::etw::WideStrRef<'a>> {
                                #preamble
                                #parse_fn(self.data, start_offset, size_bytes)
                            }
                        }
                    }
                } else if is_ansi_string_type(field_type) {
                    let is_last = last_variable_field_index == Some(field_idx);
                    if is_last {
                        let preamble = gen_last_field_preamble(
                            &field_idx_lit,
                            &first_variable_index_lit,
                            &fixed_end_expr,
                        );
                        quote! {
                            #[inline]
                            pub fn #accessor_name(
                                &mut self
                            ) -> ::etw::Result<::etw::AnsiStrRef<'a>> {
                                #preamble
                                let size_bytes = self.data.len().saturating_sub(start_offset);
                                ::etw::static_schema::parse_ansi_string_sized(
                                    self.data,
                                    start_offset,
                                    size_bytes
                                )
                            }
                        }
                    } else {
                        let preamble = gen_non_last_field_preamble(
                            &field_idx_lit,
                            &first_variable_index_lit,
                            &fixed_end_expr,
                            true,
                        );
                        quote! {
                            #[inline]
                            pub fn #accessor_name(
                                &mut self
                            ) -> ::etw::Result<::etw::AnsiStrRef<'a>> {
                                #preamble
                                ::etw::static_schema::parse_ansi_string_sized(
                                    self.data,
                                    start_offset,
                                    size_bytes
                                )
                            }
                        }
                    }
                } else if is_sid_type(field_type) {
                    let is_last = last_variable_field_index == Some(field_idx);
                    if is_last {
                        let preamble = gen_last_field_preamble(
                            &field_idx_lit,
                            &first_variable_index_lit,
                            &fixed_end_expr,
                        );
                        quote! {
                            #[inline]
                            pub fn #accessor_name(&mut self) -> ::etw::Result<::etw::SidRef<'a>> {
                                #preamble
                                let size_bytes = self.data.len().saturating_sub(start_offset);
                                ::etw::static_schema::parse_sid_sized(
                                    self.data,
                                    start_offset,
                                    size_bytes
                                )
                            }
                        }
                    } else {
                        let preamble = gen_non_last_field_preamble(
                            &field_idx_lit,
                            &first_variable_index_lit,
                            &fixed_end_expr,
                            true,
                        );
                        quote! {
                            #[inline]
                            pub fn #accessor_name(&mut self) -> ::etw::Result<::etw::SidRef<'a>> {
                                #preamble
                                ::etw::static_schema::parse_sid_sized(
                                    self.data,
                                    start_offset,
                                    size_bytes
                                )
                            }
                        }
                    }
                } else if is_wbem_sid_type(field_type) {
                    // WbemSid: TOKEN_USER header + SID data, returns SidRef
                    let is_last = last_variable_field_index == Some(field_idx);
                    if is_last {
                        let preamble = gen_last_field_preamble(
                            &field_idx_lit,
                            &first_variable_index_lit,
                            &fixed_end_expr,
                        );
                        quote! {
                            #[inline]
                            pub fn #accessor_name(&mut self) -> ::etw::Result<::etw::SidRef<'a>> {
                                #preamble
                                ::etw::static_schema::parse_wbem_sid(self.data, start_offset)
                            }
                        }
                    } else {
                        let preamble = gen_non_last_field_preamble(
                            &field_idx_lit,
                            &first_variable_index_lit,
                            &fixed_end_expr,
                            true,
                        );
                        quote! {
                            #[inline]
                            pub fn #accessor_name(&mut self) -> ::etw::Result<::etw::SidRef<'a>> {
                                #preamble
                                ::etw::static_schema::parse_wbem_sid_sized(
                                    self.data,
                                    start_offset,
                                    size_bytes
                                )
                            }
                        }
                    }
                } else if matches!(&field.offset, FieldOffset::FixedLength(_)) {
                    // Fixed-length binary field — known compile-time byte size, returns &[u8]
                    let len = match &field.offset {
                        FieldOffset::FixedLength(n) => *n,
                        _ => unreachable!(),
                    };
                    let len_lit = syn::LitInt::new(&len.to_string(), Span::call_site());
                    let is_last = last_variable_field_index == Some(field_idx);
                    let preamble = if is_last {
                        gen_last_field_preamble(
                            &field_idx_lit,
                            &first_variable_index_lit,
                            &fixed_end_expr,
                        )
                    } else {
                        gen_non_last_field_preamble(
                            &field_idx_lit,
                            &first_variable_index_lit,
                            &fixed_end_expr,
                            false,
                        )
                    };
                    quote! {
                        #[inline]
                        pub fn #accessor_name(&mut self) -> ::etw::Result<&'a [u8]> {
                            #preamble
                            const LENGTH: usize = #len_lit;
                            ::etw::static_schema::parse_binary(self.data, start_offset, LENGTH)
                        }
                    }
                } else if let FieldOffset::LengthFrom(length_field_name) = &field.offset {
                    // Length-prefixed binary field — length read from another field
                    let length_field_snake = to_accessor_ident(length_field_name);
                    let is_last = last_variable_field_index == Some(field_idx);
                    let preamble = if is_last {
                        gen_last_field_preamble(
                            &field_idx_lit,
                            &first_variable_index_lit,
                            &fixed_end_expr,
                        )
                    } else {
                        gen_non_last_field_preamble(
                            &field_idx_lit,
                            &first_variable_index_lit,
                            &fixed_end_expr,
                            false,
                        )
                    };
                    quote! {
                        #[inline]
                        pub fn #accessor_name(&mut self) -> ::etw::Result<&'a [u8]> {
                            #preamble
                            let length = self.#length_field_snake()? as usize;
                            ::etw::static_schema::parse_binary(self.data, start_offset, length)
                        }
                    }
                } else if let FieldOffset::CountFrom(count_field_name) = &field.offset {
                    // Pointer-sized element types cannot use parse_array because
                    // FromBytes reads size_of::<usize>() bytes (host pointer size),
                    // which is wrong for 32-bit events on a 64-bit host.
                    if is_pointer_type(field_type) {
                        let msg = format!(
                            "field '{}': @ count() arrays of pointer-sized types \
                             (usize/isize) are not supported",
                            field.name
                        );
                        return quote! { compile_error!(#msg); };
                    }

                    // Count-from-field array — element count read from another field
                    let count_field_snake = to_accessor_ident(count_field_name);
                    let element_size = type_to_size_expr(field_type, has_pointer_fields);
                    let qualified_type = qualify_crate_type(field_type);
                    let is_last = last_variable_field_index == Some(field_idx);
                    let preamble = if is_last {
                        gen_last_field_preamble(
                            &field_idx_lit,
                            &first_variable_index_lit,
                            &fixed_end_expr,
                        )
                    } else {
                        gen_non_last_field_preamble(
                            &field_idx_lit,
                            &first_variable_index_lit,
                            &fixed_end_expr,
                            false,
                        )
                    };
                    quote! {
                        #[inline]
                        pub fn #accessor_name(&mut self) -> ::etw::Result<Vec<#qualified_type>> {
                            #preamble
                            let element_size: usize = #element_size;
                            let count = self.#count_field_snake()? as usize;
                            ::etw::static_schema::parse_array(
                                self.data,
                                start_offset,
                                count,
                                element_size
                            )
                        }
                    }
                } else if let FieldOffset::BinaryCount(count_field_name, element_byte_size) =
                    &field.offset
                {
                    // Binary count — total bytes = count_field * element_byte_size
                    let count_field_snake = to_accessor_ident(count_field_name);
                    let elem_size_lit =
                        syn::LitInt::new(&element_byte_size.to_string(), Span::call_site());
                    let is_last = last_variable_field_index == Some(field_idx);
                    let preamble = if is_last {
                        gen_last_field_preamble(
                            &field_idx_lit,
                            &first_variable_index_lit,
                            &fixed_end_expr,
                        )
                    } else {
                        gen_non_last_field_preamble(
                            &field_idx_lit,
                            &first_variable_index_lit,
                            &fixed_end_expr,
                            false,
                        )
                    };
                    quote! {
                        #[inline]
                        pub fn #accessor_name(&mut self) -> ::etw::Result<&'a [u8]> {
                            #preamble
                            const ELEMENT_BYTE_SIZE: usize = #elem_size_lit;
                            let count = self.#count_field_snake()? as usize;
                            let total_bytes = count.saturating_mul(ELEMENT_BYTE_SIZE);
                            ::etw::static_schema::parse_binary(
                                self.data,
                                start_offset,
                                total_bytes
                            )
                        }
                    }
                } else {
                    // FixedAfterVariable — fixed-size field but offset depends on variable fields
                    let qualified_type = qualify_crate_type(field_type);
                    let is_last = last_variable_field_index == Some(field_idx);

                    // For pointer-typed fields, use parse_pointer which handles
                    // 4-byte reads for 32-bit events. For non-pointer fields, use
                    // parse_fixed with a const or let size binding.
                    let is_ptr = is_pointer_type(field_type) && has_pointer_fields;
                    let parse_call = if is_ptr {
                        let is_signed =
                            matches!(field_type.to_token_stream().to_string().as_str(), "isize");
                        if is_signed {
                            quote! {
                                ::etw::static_schema::parse_signed_pointer(
                                    self.data,
                                    start_offset,
                                    self.pointer_size
                                )
                            }
                        } else {
                            quote! {
                                ::etw::static_schema::parse_pointer(
                                    self.data,
                                    start_offset,
                                    self.pointer_size
                                )
                            }
                        }
                    } else {
                        let size = type_to_size_expr(field_type, false);
                        quote! {
                            {
                                const SIZE: usize = #size;
                                ::etw::static_schema::parse_fixed(self.data, start_offset, SIZE)
                            }
                        }
                    };

                    let preamble = if is_last {
                        gen_last_field_preamble(
                            &field_idx_lit,
                            &first_variable_index_lit,
                            &fixed_end_expr,
                        )
                    } else {
                        gen_non_last_field_preamble(
                            &field_idx_lit,
                            &first_variable_index_lit,
                            &fixed_end_expr,
                            false,
                        )
                    };
                    quote! {
                        #[inline]
                        pub fn #accessor_name(&mut self) -> ::etw::Result<#qualified_type> {
                            #preamble
                            #parse_call
                        }
                    }
                }
            }
            FieldOffset::Auto => {
                quote! {
                    compile_error!("internal error: auto offset not resolved");
                }
            }
        };

        parser_methods.push(method);

        // For ref-type fields, also generate the owned convenience wrapper.
        if is_ref && let Some(owned) = gen_owned_wrapper(&field_name_snake, field) {
            parser_methods.push(owned);
        }
    }

    // first_variable_index and first_variable_index_lit already calculated above
    // fixed_end_offset_lit already calculated above (needed for parser methods)

    // No dummy entries needed - cache indices are offset from first_variable_index

    // Generate compute_size_match for compute_locations_up_to()
    let mut size_match_arms = Vec::new();
    for (field_idx, field) in schema.fields.iter().enumerate() {
        // Skip fixed fields (they're pre-populated)
        if matches!(field.offset, FieldOffset::Fixed(_)) {
            continue;
        }

        let field_idx_lit = syn::LitInt::new(&field_idx.to_string(), Span::call_site());
        let field_type = &field.ty;

        let size_computation = if let FieldOffset::FixedLength(len) = &field.offset {
            // Field has a compile-time known byte length
            let size_lit = syn::LitInt::new(&len.to_string(), Span::call_site());
            quote! { #size_lit }
        } else if let FieldOffset::LengthFrom(length_field_name) = &field.offset {
            // Length-from-field: read the length dynamically from another field.
            let length_field_snake = to_accessor_ident(length_field_name);
            quote! {
                self.#length_field_snake()? as usize
            }
        } else if let FieldOffset::CountFrom(count_field_name) = &field.offset {
            // Count-from-field: element count * element size (derived from field type)
            let count_field_snake = to_accessor_ident(count_field_name);
            let element_size = type_to_size_expr(field_type, has_pointer_fields);
            quote! {
                (self.#count_field_snake()? as usize).saturating_mul(#element_size)
            }
        } else if let FieldOffset::BinaryCount(count_field_name, element_byte_size) = &field.offset
        {
            // Binary count: count_field * explicit element byte size
            let count_field_snake = to_accessor_ident(count_field_name);
            let elem_size_lit = syn::LitInt::new(&element_byte_size.to_string(), Span::call_site());
            quote! {
                (self.#count_field_snake()? as usize).saturating_mul(#elem_size_lit)
            }
        } else if is_counted_wide_string_type(field_type)
            || is_counted_ansi_string_type(field_type)
            || is_counted_binary_type(field_type)
        {
            quote! {
                ::etw::static_schema::compute_counted_size(self.data, offset)?
            }
        } else if is_wide_string_type(field_type) {
            quote! {
                ::etw::static_schema::compute_wide_string_size(self.data, offset)?
            }
        } else if is_ansi_string_type(field_type) {
            quote! {
                ::etw::static_schema::compute_ansi_string_size(self.data, offset)?
            }
        } else if is_wbem_sid_type(field_type) {
            quote! {
                ::etw::static_schema::compute_wbem_sid_size(self.data, offset)?
            }
        } else if is_sid_type(field_type) {
            quote! {
                ::etw::static_schema::compute_sid_size(self.data, offset)?
            }
        } else if is_pointer_type(field_type) && has_pointer_fields {
            // Pointer-sized field after variable fields — size depends on event bitness
            quote! { self.pointer_size }
        } else {
            // Fixed-size field after variable fields
            let size = type_to_size(field_type, 8);
            let size_lit = syn::LitInt::new(&size.to_string(), Span::call_site());
            quote! { #size_lit }
        };

        size_match_arms.push(quote! {
            #field_idx_lit => { #size_computation }
        });
    }

    // size_match_arms are used directly in compute_locations_up_to() method
    let variable_field_count = schema.fields.len() - first_variable_index;
    let variable_field_count_lit =
        syn::LitInt::new(&variable_field_count.to_string(), Span::call_site());

    // Generate schema validation test module (only in test/debug builds)
    let validation_module = generate_validation_module(schema);

    // Generate debug assertions for Parser::new()
    let schema_version = schema.version;
    let debug_assertions = {
        // For classic/MOF events, provider_guid() returns the class GUID, not the
        // provider registration GUID — so check against class_guid when present.
        let guid_assert = if let Some(ref cg) = schema.class_guid {
            quote! {
                debug_assert_eq!(
                    event.provider_guid(), #cg,
                    "wrong class GUID for {}",
                    stringify!(#parser_struct_name)
                );
            }
        } else if let Some(ref guid_expr) = schema.guid {
            quote! {
                debug_assert_eq!(
                    event.provider_guid(),
                    #guid_expr,
                    "wrong provider GUID for {}",
                    stringify!(#parser_struct_name)
                );
            }
        } else {
            quote! {}
        };

        let id_assert = if let Some(id) = schema.id {
            quote! {
                debug_assert_eq!(
                    event.id(), #id,
                    "wrong event id for {} (expected {})",
                    stringify!(#parser_struct_name), #id
                );
            }
        } else {
            quote! {}
        };

        let opcode_assert = if let Some(opcode) = schema.opcode {
            quote! {
                debug_assert_eq!(
                    event.opcode(), #opcode,
                    "wrong event opcode for {} (expected {})",
                    stringify!(#parser_struct_name), #opcode
                );
            }
        } else {
            quote! {}
        };

        quote! {
            #id_assert
            #opcode_assert
            debug_assert_eq!(
                event.version(), #schema_version,
                "wrong event version for {} (expected {})",
                stringify!(#parser_struct_name), #schema_version
            );
            #guid_assert
        }
    };

    // Generate struct fields and constructors conditionally based on pointer field presence.
    let fe32_lit = syn::LitInt::new(&fixed_end_32.to_string(), Span::call_site());
    let fe64_lit = syn::LitInt::new(&fixed_end_64.to_string(), Span::call_site());

    let (struct_fields, new_constructor, from_bytes_methods) = if has_pointer_fields {
        (
            quote! {
                data: &'a [u8],
                cache: [::etw::static_schema::PropertyLocation; #variable_field_count_lit],
                cache_len: usize,
                current_offset: usize,
                /// Pointer size (4 or 8) derived from the event header flags.
                /// Controls how `usize`/`isize` (Pointer/SizeT) fields are parsed.
                pointer_size: usize,
            },
            quote! {
                /// Create a new parser for the given event.
                ///
                /// Initialises the cache for variable fields only.
                /// Fixed fields are accessed directly via compile-time constants.
                /// Pointer size is derived from the event header flags to correctly
                /// parse events from both 32-bit (WOW64) and 64-bit processes.
                ///
                /// # Panics (debug builds only)
                ///
                /// Panics if the event's ID, version, or provider GUID don't match
                /// the schema this parser was generated for.
                #[inline]
                pub fn new(event: &'a ::etw::RawEvent) -> Self {
                    #debug_assertions
                    let pointer_size = ::etw::static_schema::pointer_size_from_event(event);
                    Self::from_bytes_with_pointer_size(event.user_data(), pointer_size)
                }
            },
            quote! {
                /// Create a new parser from a raw byte slice, assuming 64-bit events.
                ///
                /// Prefer [`new`](Self::new) when you have a [`RawEvent`](etw::RawEvent).
                /// This constructor is useful for testing with synthetic 64-bit data.
                /// For 32-bit test data, use [`from_bytes_with_pointer_size`](Self::from_bytes_with_pointer_size).
                #[inline]
                pub fn from_bytes(data: &'a [u8]) -> Self {
                    Self::from_bytes_with_pointer_size(data, 8)
                }

                /// Create a new parser from a raw byte slice with an explicit pointer size.
                ///
                /// `pointer_size` must be 4 (32-bit) or 8 (64-bit). Controls how
                /// `usize`/`isize` (Pointer/SizeT) fields are parsed and how
                /// offsets are computed for fields following pointer-sized fields.
                #[inline]
                pub fn from_bytes_with_pointer_size(data: &'a [u8], pointer_size: usize) -> Self {
                    debug_assert!(
                        pointer_size == 4 || pointer_size == 8,
                        "pointer_size must be 4 or 8, got {pointer_size}"
                    );
                    let current_offset = if pointer_size == 4 { #fe32_lit } else { #fe64_lit };
                    Self {
                        data,
                        cache: [
                            ::etw::static_schema::PropertyLocation { offset: 0 };
                            #variable_field_count_lit
                        ],
                        cache_len: 0,
                        current_offset,
                        pointer_size,
                    }
                }
            },
        )
    } else {
        (
            quote! {
                data: &'a [u8],
                cache: [::etw::static_schema::PropertyLocation; #variable_field_count_lit],
                cache_len: usize,
                current_offset: usize,
            },
            quote! {
                /// Create a new parser for the given event.
                ///
                /// Initialises the cache for variable fields only.
                /// Fixed fields are accessed directly via compile-time constants.
                ///
                /// # Panics (debug builds only)
                ///
                /// Panics if the event's ID, version, or provider GUID don't match
                /// the schema this parser was generated for.
                #[inline]
                pub fn new(event: &'a ::etw::RawEvent) -> Self {
                    #debug_assertions
                    Self::from_bytes(event.user_data())
                }
            },
            quote! {
                /// Create a new parser from a raw byte slice.
                ///
                /// Prefer [`new`](Self::new) when you have a [`RawEvent`](etw::RawEvent).
                /// This constructor is useful for testing with synthetic data.
                #[inline]
                pub fn from_bytes(data: &'a [u8]) -> Self {
                    Self {
                        data,
                        cache: [
                            ::etw::static_schema::PropertyLocation { offset: 0 };
                            #variable_field_count_lit
                        ],
                        cache_len: 0,
                        current_offset: #fixed_end_offset_lit,
                    }
                }
            },
        )
    };

    let expanded = quote! {
        /// Sequential parser with incremental offset caching.
        ///
        /// Generated by `event_schema!` for efficient multi-field access.
        /// Uses sequential caching: accessing field N automatically caches all fields 0..N
        /// as a side effect, eliminating redundant scanning.
        ///
        /// This approach mirrors [`EventParser`](etw::EventParser)'s caching strategy,
        /// with the key difference being compile-time known field types vs runtime schema lookups.
        ///
        /// ETW callbacks are single-threaded, so this uses plain mutation without RefCell.
        #[allow(missing_docs, non_snake_case)]
        pub struct #parser_struct_name<'a> {
            #struct_fields
        }

        // The generated accessor methods have the same names as the superset
        // trait generated by `provider_schema!`. The duplication is intentional:
        // the inherent methods are the concrete implementations; the trait methods
        // delegate to them. Suppress same_name_method on this impl block.
        #[allow(missing_docs, clippy::same_name_method, non_snake_case)]
        impl<'a> #parser_struct_name<'a> {
            #new_constructor

            #from_bytes_methods

            /// Computes all property locations up to and including the target cache index.
            ///
            /// This function is the core of sequential caching. When accessing a variable field,
            /// it automatically computes and caches locations for all preceding variable fields
            /// that haven't been computed yet.
            ///
            /// This eliminates redundant scanning: accessing String3 after String1 and String2
            /// only scans String3 itself, not String1 and String2 again.
            ///
            /// **Stores END offsets**: cache[i] contains the end offset of field i (= start of field i+1).
            /// This allows computing field size by subtraction without re-scanning.
            ///
            /// # Arguments
            ///
            /// * `target_cache_index` - Cache index (0-based from first variable field)
            #[inline]
            #[allow(unreachable_code)] // Generated: default arm unreachable when no variable fields
            fn compute_locations_up_to(&mut self, target_cache_index: usize) -> ::etw::Result<()> {
                while self.cache_len <= target_cache_index {
                    let cache_idx = self.cache_len;
                    let field_idx = cache_idx + #first_variable_index_lit;
                    let offset = self.current_offset;

                    // Compute field size based on compile-time known field types
                    let size: usize = match field_idx {
                        #(#size_match_arms,)*
                        _ => return Err(::etw::Error::parse(
                            format!("unexpected field index {field_idx} in compute_locations_up_to")
                        )),
                    };

                    // Store END offset (start + size) to enable size computation by subtraction
                    let end_offset = offset.saturating_add(size);
                    debug_assert!(end_offset <= u16::MAX as usize, "end_offset {end_offset} exceeds u16::MAX");
                    self.cache[cache_idx] = ::etw::static_schema::PropertyLocation {
                        offset: end_offset as u16
                    };
                    self.cache_len += 1;
                    self.current_offset = end_offset;
                }

                Ok(())
            }

            #(#parser_methods)*
        }

        #validation_module
    };

    expanded
}

/// Generate the preamble for a last-field variable accessor body.
///
/// Defines compile-time constants and computes `start_offset` by caching
/// up to the preceding field. Callers append their type-specific parse call.
fn gen_last_field_preamble(
    field_idx_lit: &syn::LitInt,
    first_variable_index_lit: &syn::LitInt,
    fixed_end_expr: &TokenStream2,
) -> TokenStream2 {
    quote! {
        const FIELD_INDEX: usize = #field_idx_lit;
        const FIRST_VARIABLE_INDEX: usize = #first_variable_index_lit;
        const CACHE_INDEX: usize = FIELD_INDEX - FIRST_VARIABLE_INDEX;
        let fixed_end: usize = #fixed_end_expr;

        let start_offset = if CACHE_INDEX == 0 {
            fixed_end
        } else {
            self.compute_locations_up_to(CACHE_INDEX - 1)?;
            self.cache[CACHE_INDEX - 1].offset as usize
        };
    }
}

/// Generate the preamble for a non-last-field variable accessor body.
///
/// Defines compile-time constants, calls `compute_locations_up_to`, and
/// computes both `start_offset` and `size_bytes`. Callers append their
/// type-specific parse call (most can use `size_bytes` directly).
fn gen_non_last_field_preamble(
    field_idx_lit: &syn::LitInt,
    first_variable_index_lit: &syn::LitInt,
    fixed_end_expr: &TokenStream2,
    emit_size: bool,
) -> TokenStream2 {
    let size_bindings = if emit_size {
        quote! {
            let end_offset = self.cache[CACHE_INDEX].offset as usize;
            let size_bytes = end_offset.saturating_sub(start_offset);
        }
    } else {
        quote! {}
    };
    quote! {
        const FIELD_INDEX: usize = #field_idx_lit;
        const FIRST_VARIABLE_INDEX: usize = #first_variable_index_lit;
        const CACHE_INDEX: usize = FIELD_INDEX - FIRST_VARIABLE_INDEX;
        let fixed_end: usize = #fixed_end_expr;

        self.compute_locations_up_to(CACHE_INDEX)?;

        let start_offset = if CACHE_INDEX == 0 {
            fixed_end
        } else {
            self.cache[CACHE_INDEX - 1].offset as usize
        };
        #size_bindings
    }
}

/// Expands the event_schema! macro from a TokenStream.
pub(crate) fn expand_event_schema(input: TokenStream) -> TokenStream {
    let schema = parse_macro_input!(input as EventSchema);
    expand_event_schema_from_struct(&schema).into()
}

/// Calculate the end offset of all fixed fields.
///
/// This is where variable-length fields start.
fn calculate_fixed_end_offset(fields: &[FieldDef]) -> usize {
    let mut max_offset = 0;

    for field in fields {
        let end = match &field.offset {
            FieldOffset::Fixed(offset) => offset + type_to_size(&field.ty, 8),
            FieldOffset::FixedBinary { offset, len } => offset + len,
            // Stop at first variable field
            _ => break,
        };
        if end > max_offset {
            max_offset = end;
        }
    }

    max_offset
}

/// Convert a type to its size in bytes for a given pointer size.
///
/// `pointer_size` controls the size of `usize`/`isize` fields (4 or 8).
fn type_to_size(ty: &Type, pointer_size: usize) -> usize {
    if let Type::Path(type_path) = ty
        && let Some(ident) = type_path.path.get_ident()
    {
        return match ident.to_string().as_str() {
            "u8" | "i8" => 1,
            "u16" | "i16" => 2,
            "u32" | "i32" | "f32" | "bool" => 4, // bool = Win32 BOOL (4 bytes)
            "u64" | "i64" | "f64" => 8,
            "usize" | "isize" => pointer_size,
            "Guid" | "SystemTime" => 16,
            _ => 0, // Unknown type
        };
    }
    0
}

/// Convert a type to a size expression for generated code.
///
/// When `use_self_pointer` is true, `usize`/`isize` emit `self.pointer_size`
/// instead of `std::mem::size_of::<usize>()`, enabling correct parsing of
/// events from processes with a different pointer width (e.g., WOW64).
fn type_to_size_expr(ty: &Type, use_self_pointer: bool) -> TokenStream2 {
    if let Type::Path(type_path) = ty
        && let Some(ident) = type_path.path.get_ident()
    {
        match ident.to_string().as_str() {
            "u8" | "i8" => return quote! { 1 },
            "u16" | "i16" => return quote! { 2 },
            "u32" | "i32" | "f32" | "bool" => return quote! { 4 }, // bool = Win32 BOOL

            "u64" | "i64" | "f64" => return quote! { 8 },
            "usize" | "isize" => {
                if use_self_pointer {
                    return quote! { self.pointer_size };
                }
                return quote! { std::mem::size_of::<#ty>() };
            }
            "Guid" | "SystemTime" => return quote! { 16 },
            _ => {}
        }
    }

    // Default: use size_of for the type
    quote! { std::mem::size_of::<#ty>() }
}

/// Qualify non-primitive types with `etw::` so they resolve in any expansion context.
///
/// Primitives (`u8`, `u32`, `bool`, etc.) are always in scope. Types like `Guid` and
/// `SystemTime` live in the `etw` crate and must be path-qualified in generated code.
pub(crate) fn qualify_crate_type(ty: &Type) -> TokenStream2 {
    if let Type::Path(type_path) = ty
        && let Some(ident) = type_path.path.get_ident()
    {
        match ident.to_string().as_str() {
            "Guid" => return quote! { ::etw::Guid },
            "SystemTime" => return quote! { ::etw::SystemTime },
            _ => {}
        }
    }
    quote! { #ty }
}

/// Return the token stream for the actual accessor return type of a field.
///
/// The return type depends on both `field.ty` and `field.offset`:
/// - `FixedLength`, `LengthFrom`, `BinaryCount` → `&'a [u8]`
/// - `CountFrom` → `Vec<T>` where T is `qualify_crate_type(field.ty)`
/// - `Following` with a string/SID type → the qualified crate type (e.g., `etw::WideStrRef`)
/// - All other offsets → `qualify_crate_type(field.ty)` (the declared type)
///
/// This is used by multi-version trait generation to produce trait signatures
/// that match the inherent methods generated by `expand_event_schema_from_struct`.
pub(crate) fn accessor_return_type(field: &FieldDef) -> TokenStream2 {
    match &field.offset {
        FieldOffset::FixedLength(_)
        | FieldOffset::LengthFrom(_)
        | FieldOffset::BinaryCount(_, _) => {
            quote! { &'a [u8] }
        }
        FieldOffset::CountFrom(_) => {
            let qualified = qualify_crate_type(&field.ty);
            quote! { Vec<#qualified> }
        }
        _ => {
            // For Following (variable-length) types, match the exact return type
            // that the inherent accessor generates. CountedBinary returns &[u8],
            // Counted strings return their typed refs, WbemSidRef returns SidRef,
            // and string/SID ref types carry a lifetime.
            if is_counted_binary_type(&field.ty) {
                quote! { &'a [u8] }
            } else if is_wide_string_type(&field.ty) || is_counted_wide_string_type(&field.ty) {
                quote! { ::etw::WideStrRef<'a> }
            } else if is_ansi_string_type(&field.ty) || is_counted_ansi_string_type(&field.ty) {
                quote! { ::etw::AnsiStrRef<'a> }
            } else if is_sid_type(&field.ty) || is_wbem_sid_type(&field.ty) {
                // Both SidRef and WbemSidRef inherent accessors return SidRef<'a>
                quote! { ::etw::SidRef<'a> }
            } else {
                qualify_crate_type(&field.ty)
            }
        }
    }
}

/// Check if a type is a wide string type.
fn is_wide_string_type(ty: &Type) -> bool {
    if let Type::Path(type_path) = ty
        && let Some(ident) = type_path.path.get_ident()
    {
        let name = ident.to_string();
        return name == "WideString" || name == "WideStrRef";
    }
    false
}

/// Check if a type is an ANSI string type.
fn is_ansi_string_type(ty: &Type) -> bool {
    if let Type::Path(type_path) = ty
        && let Some(ident) = type_path.path.get_ident()
    {
        let name = ident.to_string();
        return name == "AnsiString" || name == "AnsiStrRef";
    }
    false
}

/// Check if a type is a SID type.
fn is_sid_type(ty: &Type) -> bool {
    if let Type::Path(type_path) = ty
        && let Some(ident) = type_path.path.get_ident()
    {
        let name = ident.to_string();
        return name == "Sid" || name == "SID" || name == "SidRef";
    }
    false
}

/// The accessor method name for a schema property.
///
/// The manifest's spelling is preserved verbatim, so one name covers the accessor,
/// the `get("...")` string API, the manifest and TDH output, with no mental
/// transformation between them. A property whose name is a Rust keyword becomes a
/// raw identifier.
/// Converts a PascalCase field name to a snake_case [`Ident`].
pub(crate) fn to_accessor_ident(name: &str) -> Ident {
    if syn::parse_str::<Ident>(name).is_err() {
        Ident::new_raw(name, Span::call_site())
    } else {
        Ident::new(name, Span::call_site())
    }
}

/// Check if a type is a WbemSid type (TOKEN_USER header + SID).
fn is_wbem_sid_type(ty: &Type) -> bool {
    if let Type::Path(type_path) = ty
        && let Some(ident) = type_path.path.get_ident()
    {
        return ident == "WbemSidRef";
    }
    false
}

/// Check if a type is a ManifestCounted wide string (InType 22).
fn is_counted_wide_string_type(ty: &Type) -> bool {
    if let Type::Path(type_path) = ty
        && let Some(ident) = type_path.path.get_ident()
    {
        return ident == "CountedWideStrRef";
    }
    false
}

/// Check if a type is a ManifestCounted ANSI string (InType 23).
fn is_counted_ansi_string_type(ty: &Type) -> bool {
    if let Type::Path(type_path) = ty
        && let Some(ident) = type_path.path.get_ident()
    {
        return ident == "CountedAnsiStrRef";
    }
    false
}

/// Check if a type is a ManifestCounted binary (InType 25).
fn is_counted_binary_type(ty: &Type) -> bool {
    if let Type::Path(type_path) = ty
        && let Some(ident) = type_path.path.get_ident()
    {
        return ident == "CountedBinaryRef";
    }
    false
}

/// Check if a type is a variable-length type (strings, SIDs, WbemSids, or ManifestCounted).
fn is_variable_length_type(ty: &Type) -> bool {
    is_wide_string_type(ty)
        || is_ansi_string_type(ty)
        || is_sid_type(ty)
        || is_wbem_sid_type(ty)
        || is_counted_wide_string_type(ty)
        || is_counted_ansi_string_type(ty)
        || is_counted_binary_type(ty)
}

/// Returns true if this field generates a ref-type accessor that needs an owned counterpart.
///
/// Ref-type accessors return borrowed types (`WideStrRef`, `AnsiStrRef`, `SidRef`, `&[u8]`).
/// The owned counterpart returns the owned type (`String`, `AnsiString`, `Sid`, `Vec<u8>`).
pub(crate) fn is_ref_accessor(field: &FieldDef) -> bool {
    // Binary fields accessed via length/fixed_length/count_bytes return &[u8]
    matches!(
        field.offset,
        FieldOffset::FixedLength(_)
            | FieldOffset::FixedBinary { .. }
            | FieldOffset::LengthFrom(_)
            | FieldOffset::BinaryCount(_, _)
    ) || is_wide_string_type(&field.ty)
        || is_ansi_string_type(&field.ty)
        || is_sid_type(&field.ty)
        || is_wbem_sid_type(&field.ty)
        || is_counted_wide_string_type(&field.ty)
        || is_counted_ansi_string_type(&field.ty)
        || is_counted_binary_type(&field.ty)
}

/// Generate the owned wrapper method for a ref-type field accessor.
///
/// The owned wrapper calls `self.{name}_ref()?` and converts to the owned type.
fn gen_owned_wrapper(owned_name: &Ident, field: &FieldDef) -> Option<TokenStream2> {
    let ref_name = Ident::new(&format!("{owned_name}_ref"), Span::call_site());

    if is_wide_string_type(&field.ty) || is_counted_wide_string_type(&field.ty) {
        Some(quote! {
            #[inline]
            pub fn #owned_name(&mut self) -> ::etw::Result<String> {
                self.#ref_name()?.decode_utf16()
            }
        })
    } else if is_ansi_string_type(&field.ty) || is_counted_ansi_string_type(&field.ty) {
        Some(quote! {
            #[inline]
            pub fn #owned_name(&mut self) -> ::etw::Result<String> {
                // Decode using the process active code page (CP_ACP).
                // Use the _ref() accessor and call .decode(codepage) explicitly
                // if the event source uses a different code page.
                self.#ref_name()?.decode(::etw::CP_ACP)
            }
        })
    } else if is_sid_type(&field.ty) || is_wbem_sid_type(&field.ty) {
        Some(quote! {
            #[inline]
            pub fn #owned_name(&mut self) -> ::etw::Result<::etw::Sid> {
                Ok(self.#ref_name()?.to_owned())
            }
        })
    } else if is_counted_binary_type(&field.ty)
        || matches!(
            field.offset,
            FieldOffset::FixedLength(_)
                | FieldOffset::FixedBinary { .. }
                | FieldOffset::LengthFrom(_)
                | FieldOffset::BinaryCount(_, _)
        )
    {
        Some(quote! {
            #[inline]
            pub fn #owned_name(&mut self) -> ::etw::Result<Vec<u8>> {
                Ok(self.#ref_name()?.to_vec())
            }
        })
    } else {
        None
    }
}

/// Returns the owned return type for a ref-type field accessor.
///
/// Used by multi-version trait generation to declare the owned method signature.
/// Returns `None` for non-ref fields.
pub(crate) fn owned_return_type(field: &FieldDef) -> Option<TokenStream2> {
    if is_wide_string_type(&field.ty)
        || is_counted_wide_string_type(&field.ty)
        || is_ansi_string_type(&field.ty)
        || is_counted_ansi_string_type(&field.ty)
    {
        Some(quote! { String })
    } else if is_sid_type(&field.ty) || is_wbem_sid_type(&field.ty) {
        Some(quote! { ::etw::Sid })
    } else if is_counted_binary_type(&field.ty)
        || matches!(
            field.offset,
            FieldOffset::FixedLength(_)
                | FieldOffset::FixedBinary { .. }
                | FieldOffset::LengthFrom(_)
                | FieldOffset::BinaryCount(_, _)
        )
    {
        Some(quote! { Vec<u8> })
    } else {
        None
    }
}

/// Whether the type is a pointer-sized field (`usize` or `isize`).
///
/// These fields have event-dependent sizes: 4 bytes for 32-bit processes,
/// 8 bytes for 64-bit processes.
fn is_pointer_type(ty: &Type) -> bool {
    if let Type::Path(type_path) = ty
        && let Some(ident) = type_path.path.get_ident()
    {
        return matches!(ident.to_string().as_str(), "usize" | "isize");
    }
    false
}

/// Recompute fixed-prefix byte offsets for a given pointer size.
///
/// Walks the fixed-prefix fields sequentially, accumulating offsets based on
/// each field's type size at the specified `pointer_size`. Returns a parallel
/// vector of per-field byte offsets and the total fixed-end offset.
///
/// This is used to compute 32-bit offsets when the schema contains
/// pointer-sized fields (`usize`/`isize`), enabling correct dual-offset
/// code generation for WOW64 event parsing.
fn compute_fixed_offsets(fields: &[FieldDef], pointer_size: usize) -> (Vec<usize>, usize) {
    let mut offsets = Vec::new();
    let mut current = 0;

    for field in fields {
        match field.offset {
            FieldOffset::Fixed(_) => {
                offsets.push(current);
                current += type_to_size(&field.ty, pointer_size);
            }
            FieldOffset::FixedBinary { len, .. } => {
                offsets.push(current);
                current += len;
            }
            _ => break,
        }
    }

    (offsets, current)
}

/// Converts a PascalCase or camelCase name to snake_case.
///
/// Handles consecutive uppercase runs (acronyms) by keeping them together:
/// e.g., `ProcessID` → `process_id`, `IOSize` → `io_size`, `FileIO` → `file_io`.
pub(crate) fn to_snake_case(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 4);
    for (i, ch) in s.chars().enumerate() {
        if ch.is_ascii_uppercase() && i > 0 {
            // Don't insert underscore between consecutive uppercase (e.g., "TCP" → "tcp")
            let prev_upper = s.as_bytes().get(i - 1).is_some_and(u8::is_ascii_uppercase);
            let next_lower = s.as_bytes().get(i + 1).is_some_and(u8::is_ascii_lowercase);
            if !prev_upper || next_lower {
                result.push('_');
            }
        }
        result.push(ch.to_ascii_lowercase());
    }
    result
}

/// Map a Rust type to its expected TDH InType name for validation.
///
/// Returns `None` for types that don't have a direct TDH mapping.
/// The TDH in-type for a field: the declared `@ tdh(...)` if there is one, else the
/// representative implied by the Rust type.
pub(crate) fn field_tdh_intype(field: &FieldDef) -> Option<String> {
    field
        .tdh
        .clone()
        .or_else(|| type_to_tdh_intype(&field.ty, &field.offset).map(ToOwned::to_owned))
}

pub(crate) fn type_to_tdh_intype(ty: &Type, offset: &FieldOffset) -> Option<&'static str> {
    if let Type::Path(type_path) = ty
        && let Some(ident) = type_path.path.get_ident()
    {
        return match ident.to_string().as_str() {
            // u8 with @ length/fixed_length/count_bytes annotations is Binary in TDH, not UInt8
            "u8" if matches!(
                offset,
                FieldOffset::LengthFrom(_)
                    | FieldOffset::FixedLength(_)
                    | FieldOffset::BinaryCount(_, _)
            ) =>
            {
                Some("Binary")
            }
            "u8" => Some("UInt8"),
            "u16" => Some("UInt16"),
            "u32" => Some("UInt32"),
            "u64" => Some("UInt64"),
            "i8" => Some("Int8"),
            "i16" => Some("Int16"),
            "i32" => Some("Int32"),
            "i64" => Some("Int64"),
            "usize" => Some("SizeT"),
            "isize" => Some("IntPtr"),
            "bool" => Some("Boolean"),
            "f32" => Some("Float"),
            "f64" => Some("Double"),
            "Guid" | "GUID" => Some("Guid"),
            "SystemTime" | "SYSTEMTIME" => Some("SystemTime"),
            "WideString" | "WideStrRef" => Some("UnicodeString"),
            "AnsiString" | "AnsiStrRef" => Some("AnsiString"),
            "Sid" | "SID" | "SidRef" => Some("Sid"),
            "WbemSidRef" => Some("WbemSid"),
            "CountedWideStrRef" => Some("ManifestCountedString"),
            "CountedAnsiStrRef" => Some("ManifestCountedAnsiString"),
            "CountedBinaryRef" => Some("ManifestCountedBinary"),
            _ => None,
        };
    }
    None
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "test-only assertions")]
mod tests {
    use super::{EventSchema, field_tdh_intype, to_snake_case};
    use syn::parse::Parser as _;

    fn parse(src: &str) -> Vec<super::FieldDef> {
        EventSchema::parse_fields
            .parse_str(src)
            .expect("fields should parse")
    }

    #[test]
    fn tdh_annotation_overrides_the_type_derived_from_rust() {
        // Without it, `u64` is indistinguishable from FileTime and HexInt64, so the
        // crate would report the group's representative and be wrong about this field.
        let fields = parse("CreateTime: u64 @ tdh(FileTime), Plain: u64,");
        assert_eq!(fields[0].tdh.as_deref(), Some("FileTime"));
        assert_eq!(field_tdh_intype(&fields[0]).as_deref(), Some("FileTime"));
        assert_eq!(fields[1].tdh, None);
        assert_eq!(field_tdh_intype(&fields[1]).as_deref(), Some("UInt64"));
    }

    #[test]
    fn tdh_annotation_composes_with_an_offset_annotation() {
        let fields = parse(r#"Blob: u8 @ length("Len") @ tdh(Binary),"#);
        assert_eq!(fields[0].tdh.as_deref(), Some("Binary"));
        assert!(matches!(fields[0].offset, super::FieldOffset::LengthFrom(ref f) if f == "Len"));
    }

    #[test]
    fn tdh_annotation_rejects_a_name_that_is_not_a_tdh_in_type() {
        // `FieldDef` has no Debug, so `expect_err` is unavailable.
        let msg = match EventSchema::parse_fields.parse_str("When: u64 @ tdh(FileTimeish),") {
            Ok(_) => panic!("an unknown in-type should not compile"),
            Err(e) => e.to_string(),
        };
        assert!(
            msg.contains("FileTimeish"),
            "error should name the offender: {msg}"
        );
        assert!(
            msg.contains("FileTime"),
            "error should list valid names: {msg}"
        );
    }

    #[test]
    fn duplicate_tdh_annotations_are_rejected() {
        assert!(
            EventSchema::parse_fields
                .parse_str("When: u64 @ tdh(FileTime) @ tdh(UInt64),")
                .is_err(),
            "two @ tdh(...) on one field should not compile"
        );
    }

    #[test]
    fn test_to_snake_case() {
        // Simple PascalCase
        assert_eq!(to_snake_case("ProcessId"), "process_id");
        // Trailing acronym
        assert_eq!(to_snake_case("ProcessID"), "process_id");
        // Leading acronym
        assert_eq!(to_snake_case("IOSize"), "io_size");
        // Leading acronym followed by more words
        assert_eq!(to_snake_case("HTTPSStatus"), "https_status");
        // All-caps acronym in the middle
        assert_eq!(to_snake_case("ImageNTHeaders"), "image_nt_headers");
        // Single word
        assert_eq!(to_snake_case("Filename"), "filename");
        // Already lowercase
        assert_eq!(to_snake_case("size"), "size");
    }
}
