/*
Copyright 2025 The Hyperlight Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
 */

//! # WIT World Macro
//!
//! This crate provides the [`wit_world!`] procedural macro that
//! generates shared Rust type definitions and interface traits from a
//! binary-encoded wasm component (compiled from a WIT file).
//!
//! Unlike [`hyperlight_component_macro::host_bindgen`] and
//! [`hyperlight_component_macro::guest_bindgen`], which generate
//! host-specific or guest-specific bindings respectively, `wit_world!`
//! generates **only** the shared type and trait definitions. This
//! allows users to define types once and use them on both the host and
//! guest sides.
//!
//! ## Prerequisites
//!
//! The macro takes a path to a binary-encoded wasm component file. To
//! produce such a file from a `.wit` text file, use:
//!
//! ```bash
//! wasm-tools component wit -w -o interface.wasm my_interface.wit
//! ```
//!
//! ## Usage
//!
//! ```rust,ignore
//! // Generate types from a WIT component file
//! hyperlight_wit::wit_world!("path/to/interface.wasm");
//!
//! // Or with an explicit world name
//! hyperlight_wit::wit_world!({
//!     path: "interface.wasm",
//!     world_name: "my-world"
//! });
//! ```
//!
//! If no path is provided, the macro falls back to the `$WIT_WORLD`
//! environment variable. Relative paths are resolved from
//! `$CARGO_MANIFEST_DIR`.
//!
//! ## What Gets Generated
//!
//! Given a WIT file like:
//!
//! ```wit
//! package my:api;
//!
//! interface types {
//!     record user {
//!         name: string,
//!         age: u32,
//!     }
//!
//!     enum status {
//!         active,
//!         inactive,
//!     }
//!
//!     do-something: func(u: user) -> status;
//! }
//! ```
//!
//! The macro generates:
//! - Rust structs for WIT records (e.g., `pub struct User { pub name: String, pub age: u32 }`)
//! - Rust enums for WIT enums and variants
//! - Rust structs with `bool` fields for WIT flags
//! - Rust traits for WIT interfaces with function signatures
//! - A module hierarchy matching the WIT package namespace
//!
//! ## Debugging
//!
//! Set `$HYPERLIGHT_COMPONENT_MACRO_DEBUG=/path/to/file.rs` to write
//! the generated code to a file for inspection. Set `RUST_LOG=debug`
//! for detailed internal logging.

extern crate proc_macro;

use hyperlight_component_util::*;
use syn::parse::{Parse, ParseStream};
use syn::{Ident, LitStr, Result, Token};

/// Generate shared Rust type definitions and interface traits from a
/// WIT component file.
///
/// This macro produces type and trait definitions that are usable on
/// **both** the Hyperlight host and guest. It does **not** generate
/// host-specific binding code (like `instantiate()` or
/// `register_host_functions`) or guest-specific binding code (like
/// `hyperlight_guest_init()`).
///
/// # Parameters
///
/// The macro accepts either a simple string literal path or a
/// brace-delimited set of key-value options:
///
/// - **Simple:** `wit_world!("path/to/interface.wasm")`
/// - **Options:** `wit_world!({ path: "interface.wasm", world_name: "my-world" })`
///
/// If no path is given, the macro reads from the `$WIT_WORLD`
/// environment variable.
///
/// # Panics
///
/// Panics at compile time if the provided file cannot be read or does
/// not contain a valid binary-encoded WIT component type.
#[proc_macro]
pub fn wit_world(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let _ = env_logger::try_init();
    let parsed = syn::parse_macro_input!(input as WitWorldInput);
    let path = match parsed.path {
        Some(path_buf) => path_buf.into_os_string(),
        None => std::env::var_os("WIT_WORLD").expect("No path provided and $WIT_WORLD is not set"),
    };
    let world_name = parsed.world_name;

    util::read_wit_type_from_file(path, world_name, |kebab_name, ct| {
        // Generate only the shared type definitions and interface
        // traits. Deliberately omit host::emit_toplevel and
        // guest::emit_toplevel so that no side-specific binding code
        // is produced.
        let decls = emit::run_state(false, false, |s| {
            rtypes::emit_toplevel(s, &kebab_name, ct);
        });
        util::emit_decls(decls).into()
    })
}

/// Parsed input for the `wit_world!` macro.
#[derive(Debug)]
struct WitWorldInput {
    world_name: Option<String>,
    path: Option<std::path::PathBuf>,
}

impl Parse for WitWorldInput {
    fn parse(input: ParseStream) -> Result<Self> {
        let mut path = None;
        let mut world_name = None;

        if input.peek(syn::token::Brace) {
            let content;
            syn::braced!(content in input);

            while !content.is_empty() {
                let key: Ident = content.parse()?;
                content.parse::<Token![:]>()?;

                match key.to_string().as_str() {
                    "world_name" => {
                        let value: LitStr = content.parse()?;
                        world_name = Some(value.value());
                    }
                    "path" => {
                        let value: LitStr = content.parse()?;
                        path = Some(std::path::PathBuf::from(value.value()));
                    }
                    _ => {
                        return Err(syn::Error::new(
                            key.span(),
                            format!(
                                "unknown parameter '{}'; expected 'path' or 'world_name'",
                                key
                            ),
                        ));
                    }
                }
                if content.peek(Token![,]) {
                    content.parse::<Token![,]>()?;
                }
            }
        } else {
            let option_path_litstr = input.parse::<Option<syn::LitStr>>()?;
            if let Some(concrete_path) = option_path_litstr {
                path = Some(std::path::PathBuf::from(concrete_path.value()));
            }
        }
        Ok(Self { world_name, path })
    }
}
