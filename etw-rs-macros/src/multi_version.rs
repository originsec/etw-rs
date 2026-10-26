//! Multi-version parser generation for `provider_schema!`.
//!
//! Generates: superset accessor trait, trait impls on per-version parsers,
//! dynamic parser wrapper, and enum multi-version parser.
//!
//! # Dispatch: why the enum is the only API
//!
//! A second approach existed until it was removed: a `{name}_dispatch!` macro that
//! matched the version once and handed a named `#[inline(always)]` handler the
//! concrete parser type, so accessors carried no dispatch at all. The enum
//! (`{Name}Parser`) instead does one `match &mut self.inner` per accessor.
//!
//! Measured over five live-captured event types, median ns/event across three
//! passes, each arm written the way a user of that API would write it:
//!
//! | Event (fields)            | enum  | macro |
//! |---------------------------|-------|-------|
//! | ProcessStart (15, mixed)  | 221.5 | 224.2 |
//! | RpcClientCall (9, mixed)  | 127.0 | 133.8 |
//! | RegistryCreateKey (6)     |  68.7 |  66.5 |
//! | FileCreate (7, mixed)     |  82.7 |  79.6 |
//! | ThreadStart (10, fixed)   |   9.3 |   5.0 |
//!
//! Four of the five land within 5% of each other and fall on both sides of zero,
//! which is not a difference worth choosing between. The exception is ThreadStart,
//! whose fields are all fixed width: a field is then a load at a constant offset,
//! about 1.5 cycles, and the enum's per-accessor discriminant check costs roughly
//! the same again — so the macro ran at twice the speed. As soon as a field
//! involves decoding a wide string, that saving disappears into the noise.
//!
//! **Decision:** the enum is the only API. Its 2x case is confined to events whose
//! fields are all fixed width, consumed at volumes where ~5ns/event is material —
//! an atypical workload. Against that, the macro cost a second public API to
//! document and support, a `dispatch_module` key that existed in the schema DSL
//! solely so `#[macro_export]` could resolve type paths cross-crate, and handlers
//! that could not reach the event header at all without being written as a
//! closure. The per-version parsers (`{Name}V{N}Parser`) are public, so a caller
//! who genuinely needs zero dispatch can match the version and construct one.
//!
//! Also tested while both existed: replacing the enum match with a `u8` version
//! field + `unreachable_unchecked()` to skip discriminant checks. No measurable
//! improvement — LLVM already optimises the enum match similarly.

use crate::schema::{
    FieldDef, accessor_return_type, field_tdh_intype, is_ref_accessor, owned_return_type,
    to_snake_case,
};
use proc_macro2::{Ident, Span, TokenStream as TokenStream2};
use quote::{ToTokens, quote};
use std::collections::BTreeMap;

/// Information about a single event's versions, used for multi-version generation.
pub(crate) struct MultiVersionEvent {
    /// Event name (e.g., "FileCreate")
    pub name: String,
    /// Provider GUID expression for TDH validation.
    pub guid: syn::Expr,
    /// Event ID (manifest events).
    pub event_id: Option<u16>,
    /// Event opcode (classic/MOF events).
    pub opcode: Option<u8>,
    /// Class GUID for MOF/classic events. When present, TDH validation uses
    /// this as the provider GUID with the classic header flag.
    pub class_guid: Option<syn::Expr>,
    /// All versions, sorted ascending, fields already resolved (extends applied)
    pub versions: Vec<ResolvedVersion>,
}

pub(crate) struct ResolvedVersion {
    pub version: u8,
    /// When `true`, the schema is a valid prefix — trailing unsupported fields
    /// were stripped by the generator.
    pub truncated: bool,
    pub fields: Vec<FieldDef>,
}

/// A field in the superset, tracking which versions contain it and its index hint.
struct SupersetField {
    /// Field name (original casing, e.g., "IssuingThreadId")
    name: String,
    /// Actual return type (matching what the `_ref` accessor generates for
    /// ref-type fields, or the only accessor for non-ref fields).
    /// Stored as `syn::Type` so cross-version equality is structural, not textual.
    actual_ty: syn::Type,
    /// Owned return type for ref-type fields (e.g., `OsString` for `WideStrRef`).
    /// `None` for non-ref fields.
    owned_ty: Option<TokenStream2>,
    /// Which version numbers contain this field
    present_in: Vec<u8>,
    /// Index hint for dynamic parser (index in latest version that has this field)
    hint_index: u32,
    /// Whether this is a reference type (needs as_ref_hinted instead of get_hinted)
    is_ref_type: bool,
    /// TDH in-type name, for the accessor's doc comment. `None` when the Rust type
    /// has no TDH equivalent.
    tdh_type: Option<String>,
}

/// Build the superset of fields across all versions.
///
/// Fields with the same name and actual return type are unified. Fields with the
/// same name but different actual return types produce a compile error.
fn build_superset(versions: &[ResolvedVersion]) -> syn::Result<Vec<SupersetField>> {
    let mut seen: BTreeMap<String, SupersetField> = BTreeMap::new();

    for ver in versions {
        for (idx, field) in ver.fields.iter().enumerate() {
            let actual_ty: syn::Type = syn::parse2(accessor_return_type(field))?;
            let is_ref = is_ref_accessor(field);
            let owned = owned_return_type(field);

            if let Some(existing) = seen.get_mut(&field.name) {
                if existing.actual_ty != actual_ty {
                    return Err(syn::Error::new(
                        Span::call_site(),
                        format!(
                            "Field '{}' has return type '{}' in one version but '{}' in version {} — rename one",
                            field.name,
                            existing.actual_ty.to_token_stream(),
                            actual_ty.to_token_stream(),
                            ver.version,
                        ),
                    ));
                }
                existing.present_in.push(ver.version);
                existing.hint_index = idx as u32;
            } else {
                seen.insert(
                    field.name.clone(),
                    SupersetField {
                        name: field.name.clone(),
                        actual_ty,
                        owned_ty: owned,
                        present_in: vec![ver.version],
                        hint_index: idx as u32,
                        is_ref_type: is_ref,
                        tdh_type: field_tdh_intype(field),
                    },
                );
            }
        }
    }

    Ok(seen.into_values().collect())
}

/// Generate the superset accessor trait for an event.
pub(crate) fn generate_trait(event: &MultiVersionEvent) -> syn::Result<TokenStream2> {
    let superset = build_superset(&event.versions)?;
    let trait_name = Ident::new(&format!("{}Accessors", event.name), Span::call_site());

    let mut methods = Vec::new();
    for field in &superset {
        let method_name = crate::schema::to_accessor_ident(&field.name);
        let actual_ty = &field.actual_ty;

        let doc = match &field.tdh_type {
            Some(tdh) => format!("Property: `{}` \u{2014} {tdh}.", field.name),
            None => format!("Property: `{}`.", field.name),
        };

        if let Some(owned_ty) = &field.owned_ty {
            // Ref-type field: generate both owned and ref accessors
            let ref_name = Ident::new(&format!("{method_name}_ref"), Span::call_site());
            let ref_doc = format!("{doc} Borrowed.");
            methods.push(quote! {
                #[doc = #doc]
                fn #method_name(&mut self) -> ::etw::Result<#owned_ty>;
                #[doc = #ref_doc]
                fn #ref_name(&mut self) -> ::etw::Result<#actual_ty>;
            });
        } else {
            methods.push(quote! {
                #[doc = #doc]
                fn #method_name(&mut self) -> ::etw::Result<#actual_ty>;
            });
        }
    }

    Ok(quote! {
        /// Superset accessor trait for all versions of this event.
        ///
        /// Fields not present in the actual event version return
        /// [`etw::Error::PropertyNotFound`].
        // A crate may consume only a subset of the accessors.
        // Accessors carry the manifest's spelling, which is not snake_case.
        #[allow(dead_code, non_snake_case)]
        pub trait #trait_name<'a> {
            #(#methods)*
        }
    })
}

/// Generate trait impls on each per-version static parser.
///
/// Present fields delegate to the inherent method. Absent fields return
/// `Err(etw::Error::PropertyNotFound(...))`.
pub(crate) fn generate_trait_impls(event: &MultiVersionEvent) -> syn::Result<TokenStream2> {
    let superset = build_superset(&event.versions)?;
    let trait_name = Ident::new(&format!("{}Accessors", event.name), Span::call_site());

    let mut impls = Vec::new();

    for ver in &event.versions {
        let parser_name = Ident::new(
            &format!("{}V{}Parser", event.name, ver.version),
            Span::call_site(),
        );

        let version_fields: std::collections::HashSet<&str> =
            ver.fields.iter().map(|f| f.name.as_str()).collect();

        // This version's identity, built as a constant: the absent-field error
        // below is statically known, so it should not read the event at runtime.
        let guid_expr = &event.guid;
        let event_id = event.event_id.unwrap_or(0);
        let opcode = event.opcode.unwrap_or(0);
        let version_lit = ver.version;
        let context_expr = quote! {
            ::etw::processing_context::EventContext::new(
                #guid_expr, #event_id, #opcode, #version_lit,
            )
        };

        let mut methods = Vec::new();
        for field in &superset {
            let method_name = crate::schema::to_accessor_ident(&field.name);
            let actual_ty = &field.actual_ty;
            let field_name_str = &field.name;

            if let Some(owned_ty) = &field.owned_ty {
                // Ref-type field: delegate both owned and ref methods
                let ref_name = Ident::new(&format!("{method_name}_ref"), Span::call_site());

                if version_fields.contains(field.name.as_str()) {
                    methods.push(quote! {
                        #[inline]
                        fn #method_name(&mut self) -> ::etw::Result<#owned_ty> {
                            #parser_name::#method_name(self)
                        }
                        #[inline]
                        fn #ref_name(&mut self) -> ::etw::Result<#actual_ty> {
                            #parser_name::#ref_name(self)
                        }
                    });
                } else {
                    methods.push(quote! {
                        #[inline]
                        fn #method_name(&mut self) -> ::etw::Result<#owned_ty> {
                            Err(::etw::Error::PropertyNotFound {
                                name: #field_name_str.into(),
                                context: #context_expr,
                            })
                        }
                        #[inline]
                        fn #ref_name(&mut self) -> ::etw::Result<#actual_ty> {
                            Err(::etw::Error::PropertyNotFound {
                                name: #field_name_str.into(),
                                context: #context_expr,
                            })
                        }
                    });
                }
            } else {
                // Non-ref field: single method
                if version_fields.contains(field.name.as_str()) {
                    methods.push(quote! {
                        #[inline]
                        fn #method_name(&mut self) -> ::etw::Result<#actual_ty> {
                            #parser_name::#method_name(self)
                        }
                    });
                } else {
                    methods.push(quote! {
                        #[inline]
                        fn #method_name(&mut self) -> ::etw::Result<#actual_ty> {
                            Err(::etw::Error::PropertyNotFound {
                                name: #field_name_str.into(),
                                context: #context_expr,
                            })
                        }
                    });
                }
            }
        }

        impls.push(quote! {
            // The per-version parser has inherent methods with the same names
            // as these trait methods (generated by event_schema!). Clippy's
            // same_name_method lint flags this pattern, but the design is
            // intentional: the trait delegates to the inherent impl for present
            // fields, and returns PropertyNotFound for absent ones.
            #[allow(clippy::same_name_method, non_snake_case)]
            impl<'a> #trait_name<'a> for #parser_name<'a> {
                #(#methods)*
            }
        });
    }

    Ok(quote! { #(#impls)* })
}

/// Generate the dynamic parser wrapper struct and trait impl.
///
/// Uses `get_hinted`/`as_ref_hinted` with index hints from the latest
/// declared version for O(1) field lookup on unknown future versions.
pub(crate) fn generate_dynamic_wrapper(event: &MultiVersionEvent) -> syn::Result<TokenStream2> {
    let superset = build_superset(&event.versions)?;
    let trait_name = Ident::new(&format!("{}Accessors", event.name), Span::call_site());
    let wrapper_name = Ident::new(&format!("{}DynamicParser", event.name), Span::call_site());

    let mut methods = Vec::new();
    for field in &superset {
        let method_name = crate::schema::to_accessor_ident(&field.name);
        let actual_ty = &field.actual_ty;
        let field_name_str = &field.name;
        let hint_lit = syn::LitInt::new(
            &field.hint_index.to_string(),
            proc_macro2::Span::call_site(),
        );

        if let Some(owned_ty) = &field.owned_ty {
            // Ref-type field: owned uses get_hinted (FromProperty), ref uses as_ref_hinted
            let ref_name = Ident::new(&format!("{method_name}_ref"), Span::call_site());
            methods.push(quote! {
                #[inline]
                fn #method_name(&mut self) -> ::etw::Result<#owned_ty> {
                    self.inner.get_hinted(#field_name_str, #hint_lit)
                }
                #[inline]
                fn #ref_name(&mut self) -> ::etw::Result<#actual_ty> {
                    self.inner.as_ref_hinted(#field_name_str, #hint_lit)
                }
            });
        } else if field.is_ref_type {
            // Non-owned ref type (shouldn't happen if owned_ty is populated correctly,
            // but kept as fallback)
            methods.push(quote! {
                #[inline]
                fn #method_name(&mut self) -> ::etw::Result<#actual_ty> {
                    self.inner.as_ref_hinted(#field_name_str, #hint_lit)
                }
            });
        } else {
            methods.push(quote! {
                #[inline]
                fn #method_name(&mut self) -> ::etw::Result<#actual_ty> {
                    self.inner.get_hinted(#field_name_str, #hint_lit)
                }
            });
        }
    }

    Ok(quote! {
        /// Dynamic parser for unknown future versions of this event.
        ///
        /// Delegates to [`etw::EventParser`] with index hints from the
        /// latest known version for O(1) field lookup when field positions
        /// haven't changed.
        // A crate may use only the enum parser, leaving this wrapper type
        // unreferenced.
        #[allow(dead_code, non_snake_case)]
        pub struct #wrapper_name<'a> {
            inner: ::etw::EventParser<'a>,
        }

        impl<'a> #wrapper_name<'a> {
            /// Create from an event and schema cache.
            pub fn new(
                event: &'a ::etw::RawEvent,
                cache: &'a mut ::etw::processing_context::ProcessingContext,
            ) -> ::etw::Result<Self> {
                Ok(Self { inner: cache.parser(event)? })
            }
        }

        impl<'a> #trait_name<'a> for #wrapper_name<'a> {
            #(#methods)*
        }
    })
}

/// Generate the enum-based multi-version parser (Approach A).
///
/// Dispatches to the correct static parser variant at construction.
/// Each accessor has one match arm per variant — a single well-predicted
/// branch in practice since all events in a trace share the same version.
pub(crate) fn generate_enum_parser(event: &MultiVersionEvent) -> syn::Result<TokenStream2> {
    let superset = build_superset(&event.versions)?;
    let trait_name = Ident::new(&format!("{}Accessors", event.name), Span::call_site());
    let parser_name = Ident::new(&format!("{}Parser", event.name), Span::call_site());
    let inner_name = Ident::new(&format!("{}Inner", event.name), Span::call_site());
    let dynamic_name = Ident::new(&format!("{}DynamicParser", event.name), Span::call_site());

    #[expect(
        clippy::unwrap_used,
        reason = "provider_schema! rejects events with no version block"
    )]
    let (min_version, max_version) = (
        event.versions.first().unwrap().version,
        event.versions.last().unwrap().version,
    );
    let min_version_lit = syn::LitInt::new(&min_version.to_string(), Span::call_site());
    let max_version_lit = syn::LitInt::new(&max_version.to_string(), Span::call_site());

    // Enum variant definitions: V0(NameV0Parser<'a>), V1(NameV1Parser<'a>), ...
    let variant_defs: Vec<TokenStream2> = event
        .versions
        .iter()
        .map(|ver| {
            let variant = Ident::new(&format!("V{}", ver.version), Span::call_site());
            let vparser = Ident::new(
                &format!("{}V{}Parser", event.name, ver.version),
                Span::call_site(),
            );
            quote! { #variant(#vparser<'a>) }
        })
        .collect();

    // Constructor match arms: 0 => Inner::V0(V0Parser::new(event)), ...
    let construct_arms: Vec<TokenStream2> = event
        .versions
        .iter()
        .map(|ver| {
            let v = ver.version;
            let variant = Ident::new(&format!("V{}", ver.version), Span::call_site());
            let vparser = Ident::new(
                &format!("{}V{}Parser", event.name, ver.version),
                Span::call_site(),
            );
            quote! {
                #v => #inner_name::#variant(#vparser::new(event)),
            }
        })
        .collect();

    // Trait impl: each accessor matches on all variants + Dynamic
    let mut trait_methods = Vec::new();
    for field in &superset {
        let method_name = crate::schema::to_accessor_ident(&field.name);
        let actual_ty = &field.actual_ty;

        if let Some(owned_ty) = &field.owned_ty {
            // Ref-type field: generate both owned and ref dispatch methods
            let ref_name = Ident::new(&format!("{method_name}_ref"), Span::call_site());

            let owned_arms: Vec<TokenStream2> = event
                .versions
                .iter()
                .map(|ver| {
                    let variant = Ident::new(&format!("V{}", ver.version), Span::call_site());
                    quote! {
                        #inner_name::#variant(p) => p.#method_name(),
                    }
                })
                .collect();

            let ref_arms: Vec<TokenStream2> = event
                .versions
                .iter()
                .map(|ver| {
                    let variant = Ident::new(&format!("V{}", ver.version), Span::call_site());
                    quote! {
                        #inner_name::#variant(p) => p.#ref_name(),
                    }
                })
                .collect();

            trait_methods.push(quote! {
                #[inline]
                fn #method_name(&mut self) -> ::etw::Result<#owned_ty> {
                    match &mut self.inner {
                        #(#owned_arms)*
                        #inner_name::Dynamic(p) => p.#method_name(),
                    }
                }
                #[inline]
                fn #ref_name(&mut self) -> ::etw::Result<#actual_ty> {
                    match &mut self.inner {
                        #(#ref_arms)*
                        #inner_name::Dynamic(p) => p.#ref_name(),
                    }
                }
            });
        } else {
            let match_arms: Vec<TokenStream2> = event
                .versions
                .iter()
                .map(|ver| {
                    let variant = Ident::new(&format!("V{}", ver.version), Span::call_site());
                    quote! {
                        #inner_name::#variant(p) => p.#method_name(),
                    }
                })
                .collect();

            trait_methods.push(quote! {
                #[inline]
                fn #method_name(&mut self) -> ::etw::Result<#actual_ty> {
                    match &mut self.inner {
                        #(#match_arms)*
                        #inner_name::Dynamic(p) => p.#method_name(),
                    }
                }
            });
        }
    }

    // Only emit the below-min arm when min_version > 0: for u8, `v < 0`
    // is always false and clippy correctly rejects it as useless.
    let below_min_arm = if min_version > 0 {
        quote! {
            v if v < #min_version_lit => {
                return Err(::etw::Error::UnsupportedVersion {
                    version: event.version(),
                    minimum: #min_version_lit,
                });
            }
        }
    } else {
        quote! {}
    };

    Ok(quote! {
        /// Multi-version parser — handles all declared versions plus dynamic
        /// fallback for unknown future versions.
        ///
        /// Version dispatch happens once at construction. Each accessor has a
        /// single well-predicted branch.
        // A crate may reference neither the enum parser nor some of its inner
        // variants.
        #[allow(dead_code, non_snake_case)]
        pub struct #parser_name<'a> {
            inner: #inner_name<'a>,
        }

        #[allow(dead_code, non_snake_case)]
        enum #inner_name<'a> {
            #(#variant_defs,)*
            Dynamic(#dynamic_name<'a>),
        }

        impl<'a> #parser_name<'a> {
            /// Create a parser for the given event.
            ///
            /// Returns `Err(UnsupportedVersion)` if the event version is
            /// strictly below the minimum declared version. Falls back to
            /// dynamic parsing for versions above the maximum declared, or
            /// for versions within the declared range that were not explicitly
            /// declared (gaps between non-contiguous version numbers).
            pub fn new(
                event: &'a ::etw::RawEvent,
                cache: &'a mut ::etw::processing_context::ProcessingContext,
            ) -> ::etw::Result<Self> {
                let inner = match event.version() {
                    #(#construct_arms)*
                    v if v > #max_version_lit => {
                        #inner_name::Dynamic(#dynamic_name::new(event, cache)?)
                    }
                    #below_min_arm
                    _ => {
                        // Version is within [min, max] but not explicitly declared
                        // (gap in a non-contiguous range) — fall back to dynamic.
                        #inner_name::Dynamic(#dynamic_name::new(event, cache)?)
                    }
                };
                Ok(Self { inner })
            }
        }

        impl<'a> #trait_name<'a> for #parser_name<'a> {
            #(#trait_methods)*
        }
    })
}

/// Generate the `validate_schema()` static method and its test for runtime TDH validation.
///
/// The method validates all known versions plus an N+1 canary against
/// the Windows TDH registry. It delegates to `etw::static_schema::validate_schema()`.
pub(crate) fn generate_validate_schema_method(event: &MultiVersionEvent) -> TokenStream2 {
    let parser_name = Ident::new(&format!("{}Parser", event.name), Span::call_site());

    // Determine which GUID to use for TDH validation
    let (tdh_guid_expr, is_classic) = if let Some(ref class_guid) = event.class_guid {
        (class_guid.clone(), true)
    } else {
        (event.guid.clone(), false)
    };
    let id = event.event_id.unwrap_or(0);
    let opcode = event.opcode.unwrap_or(0);

    // Generate StaticVersionInfo entries for each known version
    let version_entries: Vec<TokenStream2> = event
        .versions
        .iter()
        .map(|ver| {
            let version_lit = ver.version;
            let truncated = ver.truncated;

            let field_entries: Vec<TokenStream2> = ver
                .fields
                .iter()
                .map(|field| {
                    let name = &field.name;
                    let tdh_type = field_tdh_intype(field);
                    let tdh_type_token = if let Some(t) = tdh_type {
                        quote! { Some(#t) }
                    } else {
                        quote! { None }
                    };
                    let required_flags = crate::schema::offset_required_flags(&field.offset);
                    let out_type_token = crate::schema::ansi_out_type(field)
                        .map_or_else(|| quote! { None }, |out_type| quote! { Some(#out_type) });
                    quote! {
                        ::etw::static_schema::StaticFieldInfo {
                            name: #name,
                            expected_tdh_type: #tdh_type_token,
                            expected_out_type: #out_type_token,
                            required_property_flags: #required_flags,
                        }
                    }
                })
                .collect();

            quote! {
                ::etw::static_schema::StaticVersionInfo {
                    version: #version_lit,
                    fields: &[
                        #(#field_entries),*
                    ],
                    truncated: #truncated,
                }
            }
        })
        .collect();

    // Generate N+1 hints from the latest version: (field_name, index) pairs
    let hint_entries: Vec<TokenStream2> = if let Some(last) = event.versions.last() {
        last.fields
            .iter()
            .enumerate()
            .map(|(idx, field)| {
                let name = &field.name;
                let idx_u32 = idx as u32;
                quote! { (#name, #idx_u32) }
            })
            .collect()
    } else {
        Vec::new()
    };

    // Generate test module name
    let snake_name = to_snake_case(&event.name);
    let test_module_name = Ident::new(&format!("validate_{snake_name}"), Span::call_site());

    quote! {
        #[cfg(windows)]
        impl #parser_name<'_> {
            /// Validate the static schema against the Windows TDH registry.
            ///
            /// Checks all known versions plus a canary for the next unknown version.
            /// Returns `Ok(())` if validation passes or if the provider is not
            /// registered on this machine.
            pub fn validate_schema() -> ::etw::Result<()> {
                ::etw::static_schema::validate_schema(
                    &#tdh_guid_expr,
                    #id,
                    #opcode,
                    #is_classic,
                    &[
                        #(#version_entries),*
                    ],
                    &[
                        #(#hint_entries),*
                    ],
                )
            }
        }

        #[cfg(test)]
        #[cfg(windows)]
        mod #test_module_name {
            use super::*;

            #[test]
            // Validates against the live Windows TDH registry, which Miri cannot
            // interpret. `ignore` rather than `cfg` keeps it enumerable via
            // `cargo miri test -- --list --ignored`.
            #[cfg_attr(miri, ignore = "calls TdhGetEventInformation (Win32)")]
            fn validate_schema() {
                #parser_name::validate_schema().unwrap();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_snake_case_simple() {
        assert_eq!(to_snake_case("ProcessStart"), "process_start");
        assert_eq!(to_snake_case("FileCreate"), "file_create");
    }

    #[test]
    fn to_snake_case_acronym_suffix() {
        assert_eq!(to_snake_case("ProcessID"), "process_id");
        assert_eq!(to_snake_case("SessionID"), "session_id");
    }

    #[test]
    fn to_snake_case_acronym_prefix() {
        assert_eq!(to_snake_case("CPUCycleCount"), "cpu_cycle_count");
        assert_eq!(to_snake_case("IOSize"), "io_size");
    }

    #[test]
    fn to_snake_case_acronym_mid() {
        // Regression: consecutive uppercase followed by lowercase must not
        // insert an underscore before every uppercase letter.
        assert_eq!(to_snake_case("LostWPPEvent"), "lost_wpp_event");
        assert_eq!(
            to_snake_case("LostTraceLoggingEvent"),
            "lost_trace_logging_event"
        );
    }
}
