#[cfg(feature = "std")]
use std::collections::HashMap;
#[cfg(feature = "std")]
use syn::{Lit, Meta, MetaNameValue, NestedMeta};

#[cfg(feature = "std")]
use crate::constants::DEFAULT_MAX_TRACE_LENGTH;

pub struct Attributes {
    pub wasm: bool,
    pub nightly: bool,
    pub guest_only: bool,
    pub max_trace_length: u64,
}

#[cfg(feature = "std")]
pub fn parse_attributes(attr: &Vec<NestedMeta>) -> Attributes {
    let mut attributes = HashMap::<_, u64>::new();
    let mut wasm = false;
    let mut guest_only = false;
    let mut nightly = false;

    for attr in attr {
        match attr {
            NestedMeta::Meta(Meta::NameValue(MetaNameValue { path, lit, .. })) => {
                let value: u64 = match lit {
                    Lit::Int(lit) => lit.base10_parse().unwrap(),
                    _ => panic!("expected integer literal"),
                };
                let ident = &path.get_ident().expect("Expected identifier");
                match ident.to_string().as_str() {
                    "max_trace_length" => attributes.insert("max_trace_length", value),
                    _ => panic!("invalid attribute"),
                };
            }
            NestedMeta::Meta(Meta::Path(path)) if path.is_ident("wasm") => {
                wasm = true;
            }
            NestedMeta::Meta(Meta::Path(path)) if path.is_ident("guest_only") => {
                guest_only = true;
            }
            NestedMeta::Meta(Meta::Path(path)) if path.is_ident("nightly") => {
                nightly = true;
            }
            _ => panic!("expected integer literal"),
        }
    }

    let max_trace_length = attributes
        .get("max_trace_length")
        .cloned()
        .unwrap_or(DEFAULT_MAX_TRACE_LENGTH);

    Attributes {
        wasm,
        nightly,
        guest_only,
        max_trace_length,
    }
}
