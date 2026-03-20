extern crate proc_macro;

use proc_macro::TokenStream;
use proc_macro2::Ident;
use quote::quote;

#[proc_macro_attribute]
pub fn compatible_component(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let _struct = syn::parse::<syn::ItemStruct>(item).unwrap();

    let (_enum, enum_ident) = _enum(_struct.clone());
    let ctor = ctor(_struct.clone(), enum_ident.clone());
    let accessors = accessors(_struct.clone(), enum_ident);
    let debug = debug(_struct.clone());

    let vis = _struct.vis;
    let ident = _struct.ident;
    let attrs = _struct.attrs;

    quote! {
        #[derive(
            Clone,
            Eq,
            PartialEq,
            Ord,
            PartialOrd,
            mimi_protocol_mls::reexports::tls_codec::TlsSize,
            mimi_protocol_mls::reexports::tls_codec::TlsSerialize,
            mimi_protocol_mls::reexports::tls_codec::TlsDeserialize,
        )]
        #(#attrs)*
        #vis struct #ident(crate::compatible_component::CompatibleComponent);

        impl std::ops::Deref for #ident {
            type Target = crate::compatible_component::CompatibleComponent;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl std::ops::DerefMut for #ident {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }

        #_enum
        #ctor
        #accessors
        #debug
    }
    .into()
}

fn _enum(_struct: syn::ItemStruct) -> (proc_macro2::TokenStream, Ident) {
    let ident = _struct.ident;
    let ident = Ident::new(&format!("{ident}Enum"), ident.span());

    let fields = _struct
        .fields
        .iter()
        .map(|f| {
            let ident = f.ident.clone().expect("Tuple structs are not supported");
            let ident_str = format!("{}", ident);
            let ident = Ident::new(&capitalize(ident_str), ident.span());
            quote! { #ident }
        })
        .collect::<Vec<_>>();

    let q = quote! {
        #[derive(Debug, Copy, Clone)]
        #[repr(u8)]
        enum #ident {
            #(#fields),*
        }
    };
    (q, ident)
}

fn accessors(_struct: syn::ItemStruct, enum_ident: Ident) -> proc_macro2::TokenStream {
    let ident = _struct.ident;

    let accessors = _struct
        .fields
        .iter()
        .map(|f| {
            let vis = f.vis.clone();
            let typ = f.ty.clone();
            let ident = f.ident.clone().expect("Tuple structs are not supported");
            let get_ident = Ident::new(&format!("get_{ident}"), ident.span());
            let try_get_ident = Ident::new(&format!("try_get_{ident}"), ident.span());
            let set_ident = Ident::new(&format!("set_{ident}"), ident.span());
            let try_set_ident = Ident::new(&format!("try_set_{ident}"), ident.span());
            let enum_variant = Ident::new(&capitalize(ident.to_string()), ident.span());
            quote! {
                #vis fn #get_ident(&self) -> Option<#typ> {
                    self.get_field::<#typ>(#enum_ident::#enum_variant as u8).ok().flatten()
                }

                #vis fn #try_get_ident(&self) -> Result<Option<#typ>, mimi_protocol_mls::reexports::tls_codec::Error> {
                    self.get_field::<#typ>(#enum_ident::#enum_variant as u8)
                }

                #vis fn #set_ident(&mut self, value: #typ) -> Option<#typ> {
                    self.set_field::<#typ>(#enum_ident::#enum_variant as u8, value).ok().flatten()
                }

                #vis fn #try_set_ident(&mut self, value: #typ) -> Result<Option<#typ>, mimi_protocol_mls::reexports::tls_codec::Error> {
                    self.set_field::<#typ>(#enum_ident::#enum_variant as u8, value)
                }
            }
        })
        .collect::<Vec<_>>();

    quote! {
        impl #ident {
            #(#accessors)*
        }
    }
}

fn debug(_struct: syn::ItemStruct) -> proc_macro2::TokenStream {
    let ident = _struct.ident;
    let ident_str = format!("{ident}");

    let debug_fields = _struct
        .fields
        .iter()
        .map(|f| {
            let ident = f.ident.clone().expect("Tuple structs are not supported");
            let ident_str = format!("{ident}");
            let get_ident = Ident::new(&format!("get_{ident}"), ident.span());
            quote! {
                if let Some(it) = &self.#get_ident() {
                    b.field(#ident_str, it);
                }
            }
        })
        .collect::<Vec<_>>();

    quote! {
        impl std::fmt::Debug for #ident {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let mut b = f.debug_struct(#ident_str);
                #(#debug_fields)*
                b.finish()
            }
        }
    }
}

fn ctor(_struct: syn::ItemStruct, enum_ident: Ident) -> proc_macro2::TokenStream {
    let ident = _struct.ident;
    let fields = _struct.fields;

    let ctor_arg = fields
        .iter()
        .map(|f| {
            let ident = f.ident.clone().expect("Tuple structs are not supported");
            let typ = f.ty.clone();
            quote! { #ident : #typ }
        })
        .collect::<Vec<_>>();

    let set_field = fields
        .iter()
        .map(|f| {
            let ident = f.ident.clone().expect("Tuple structs are not supported");
            let enum_variant = Ident::new(&capitalize(ident.to_string()), ident.span());
            quote! { c.set_field(#enum_ident::#enum_variant as u8, #ident)?; }
        })
        .collect::<Vec<_>>();

    quote! {
        impl #ident {
            pub fn try_new(#(#ctor_arg),*) -> Result<Self, mimi_protocol_mls::reexports::tls_codec::Error> {
                let mut c = crate::compatible_component::CompatibleComponent::empty();
                #(#set_field)*
                Ok(Self(c))
            }
        }
    }
}

fn capitalize(s: String) -> String {
    let chars = s.chars().filter(|c| *c != '_').collect::<Vec<_>>();
    let first = chars.first().unwrap().to_uppercase().to_string();
    let rest = chars.get(1..).unwrap_or_default().iter().collect::<String>();
    first + &rest
}
