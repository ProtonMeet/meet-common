//! This attempts at solving the issue with MLS components and versioning.
//!
//! Since different versions
//! of a MLS client could have different versions of the component hence different deserialization
//! of it they might produce a different TLSPL serialization of it, which leads to a different hash,
//! which is included in the MLS transcript hash which ultimately leads to a different KeySchedule
//! (leading to an `invalid confirmation tag` error).
//!
//! This aims at fixing this by using a Map to store the content of the Component (and it's Update
//! version which is the one creating an `invalid membership tag` error). This way, even though an
//! old client might not understand a new field introduced by a new client (or an updated version
//! of an existing field), he will still be able to process the same hash input (forward
//! compatibility) and derive the same KeySchedule. Likewise, when this old client will update the
//! component, a new client will be able to merge it (backward compatibility).

use mimi_protocol_mls::reexports::tls_codec;
use std::{
    collections::BTreeMap,
    io::{Read, Write},
};

/// Use via the `#[meet_app_components_macros::compatible_component]` proc-macro.
///
/// We use a BTreeMap here for deterministic serialization of the Map.
/// We assume a Component with not hold more than 256 fields, otherwise create a new component !
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct CompatibleComponent(BTreeMap<u8, Vec<u8>>);

impl CompatibleComponent {
    pub(crate) fn empty() -> Self {
        Self(Default::default())
    }

    /// Read a value in the Map and deserializes it
    #[allow(dead_code)]
    pub(crate) fn get_field<T: tls_codec::Deserialize>(&self, key: u8) -> Result<Option<T>, tls_codec::Error> {
        self.0
            .get(&key)
            .map(|v| T::tls_deserialize(&mut v.as_slice()))
            .transpose()
    }

    /// Sets a (serialized) value in the Map and returns the old value if any.
    pub(crate) fn set_field<T: tls_codec::Serialize + tls_codec::Deserialize>(
        &mut self,
        key: u8,
        value: T,
    ) -> Result<Option<T>, tls_codec::Error> {
        self.0
            .insert(key, value.tls_serialize_detached()?)
            .map(|v| T::tls_deserialize(&mut v.as_slice()))
            .transpose()
    }
}

impl tls_codec::Size for CompatibleComponent {
    fn tls_serialized_len(&self) -> usize {
        self.0
            .iter()
            .map(|(k, v)| (*k, &v[..]))
            .collect::<Vec<_>>()
            .tls_serialized_len()
    }
}

impl tls_codec::Serialize for CompatibleComponent {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        self.0
            .iter()
            .map(|(k, v)| (*k, &v[..]))
            .collect::<Vec<_>>()
            .tls_serialize(writer)
    }
}

impl tls_codec::Deserialize for CompatibleComponent {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        Ok(Vec::<(u8, Vec<u8>)>::tls_deserialize(bytes)?
            .into_iter()
            .fold(Self::empty(), |mut acc, (k, v)| {
                acc.0.insert(k, v);
                acc
            }))
    }
}

