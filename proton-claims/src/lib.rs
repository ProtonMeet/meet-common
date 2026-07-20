use enum_variants_strings::EnumVariantsStrings;
use esdicawt::{
    EsdicawtReadResult, SdCwtRead,
    spec::{ClaimName, REDACTED_CLAIM_ELEMENT_TAG, Select, Value, reexports::ciborium},
};
use meet_identifiers::OrgId;
use serde::ser::SerializeMap;
use spice_oidc_cwt::SpiceOidcClaims;
use std::{collections::HashMap, sync::LazyLock};

mod about;
mod blanket;
mod client_type;
mod error;
mod provider;
mod role;
mod user_asserted;

pub use {
    about::About,
    client_type::ClientType,
    error::ProtonClaimsError,
    provider::MimiProvider,
    role::Role,
    user_asserted::{KbtProtonLabel, UserAsserted},
};

pub mod reexports {
    pub use esdicawt::cose_key;
    pub use esdicawt::cose_key_confirmation;
    pub use esdicawt::cose_key_set;
    pub use esdicawt::coset;
    pub use esdicawt::spec::reexports::ciborium;
    pub use esdicawt::spec::*;
    pub use esdicawt::*;
    pub use spice_oidc_cwt::*;
    #[cfg(feature = "status-list")]
    pub use status_list;
}

#[derive(Debug, Copy, Clone, serde_repr::Serialize_repr, serde_repr::Deserialize_repr, EnumVariantsStrings)]
#[enum_variants_strings_transform(transform = "snake_case")]
#[repr(i64)]
pub enum CwtProtonMeetLabel {
    MeetingId = -67550,
    TokenUuid = -67551,
    PolicyEnforcer = -67552,
    Host = -67553,
    ClientType = -67554,
}
esdicawt::cwt_label!(CwtProtonMeetLabel);

/// ProtonMeetClaims contains only meeting_id for meeting-specific tokens
/// Uses standard serde serialization with string keys for simplicity
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, derive_builder::Builder)]
#[builder(pattern = "mutable", setter(into, strip_option))]
pub struct ProtonMeetClaims {
    pub meeting_id: String,
    pub uuid: [u8; 16],
    pub oidc_claims: SpiceOidcClaims,
    pub role: Role,
    pub mimi_provider: MimiProvider,
    #[builder(default = "false")]
    pub is_from_server: bool,
    #[builder(default = "false")]
    pub is_host: bool,
    #[builder(default = "ClientType::None")]
    pub client_type: ClientType,
}

impl serde::Serialize for ProtonMeetClaims {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as _;

        let mut map = serializer.serialize_map(None)?;

        let oidc_claims = Value::serialized(&self.oidc_claims).map_err(S::Error::custom)?;
        let oidc_claims = oidc_claims
            .into_map()
            .map_err(|_| S::Error::custom("should have been a mapping"))?;
        for (k, v) in oidc_claims {
            map.serialize_entry(&k, &v)?;
        }

        map.serialize_entry(&CwtProtonLabel::Role, &self.role)?;
        map.serialize_entry(&CwtProtonLabel::MimiProvider, &self.mimi_provider)?;
        map.serialize_entry(&CwtProtonMeetLabel::MeetingId, &self.meeting_id)?;
        map.serialize_entry(&CwtProtonMeetLabel::TokenUuid, &Value::Bytes(self.uuid.to_vec()))?;
        map.serialize_entry(&CwtProtonMeetLabel::PolicyEnforcer, &self.is_from_server)?;
        map.serialize_entry(&CwtProtonMeetLabel::Host, &self.is_host)?;
        map.serialize_entry(&CwtProtonMeetLabel::ClientType, &self.client_type)?;
        map.end()
    }
}

impl<'de> serde::Deserialize<'de> for ProtonMeetClaims {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ProtonClaimsVisitor;

        impl<'de> serde::de::Visitor<'de> for ProtonClaimsVisitor {
            type Value = ProtonMeetClaims;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "a ProtonMeetClaims")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                use serde::de::Error as _;

                let mut extra = vec![];
                let mut builder = ProtonMeetClaimsBuilder::create_empty();
                while let Some((k, v)) = map.next_entry::<Value, Value>()? {
                    let mut handled = false;
                    if let Value::Integer(i) = &k {
                        // TODO: Remove the back compatibility with the old labels later
                        let i_val_opt = i64::try_from(*i).ok();
                        let is_meeting_id = *i == CwtProtonMeetLabel::MeetingId || i_val_opt == Some(-66550);
                        let is_token_uuid = *i == CwtProtonMeetLabel::TokenUuid || i_val_opt == Some(-66551);
                        let is_policy_enforcer = *i == CwtProtonMeetLabel::PolicyEnforcer || i_val_opt == Some(-66552);
                        let is_host_label = *i == CwtProtonMeetLabel::Host;
                        let is_client_type = *i == CwtProtonMeetLabel::ClientType;

                        match (&k, &v) {
                            (Value::Integer(i), Value::Integer(j)) if *i == CwtProtonLabel::Role => {
                                let nb = u16::try_from(*j).map_err(A::Error::custom)?;
                                builder.role(Role::try_from(nb).map_err(A::Error::custom)?);
                                handled = true;
                            }
                            (Value::Integer(i), Value::Integer(j)) if *i == CwtProtonLabel::MimiProvider => {
                                builder.mimi_provider(MimiProvider::from(u16::try_from(*j).map_err(A::Error::custom)?));
                                handled = true;
                            }
                            (_, meeting_id) if is_meeting_id => {
                                let meeting_id = meeting_id.deserialized::<String>().map_err(A::Error::custom)?;
                                builder.meeting_id(meeting_id);
                                handled = true;
                            }
                            (_, Value::Bytes(uuid_bytes)) if is_token_uuid => {
                                let uuid: [u8; 16] = uuid_bytes
                                    .clone()
                                    .try_into()
                                    .map_err(|_| A::Error::custom("UUID must be exactly 16 bytes"))?;
                                builder.uuid(uuid);
                                handled = true;
                            }
                            (_, Value::Bool(is_from_server)) if is_policy_enforcer => {
                                builder.is_from_server(*is_from_server);
                                handled = true;
                            }
                            (_, Value::Bool(is_host)) if is_host_label => {
                                builder.is_host(*is_host);
                                handled = true;
                            }
                            (_, Value::Integer(j)) if is_client_type => {
                                builder.client_type(ClientType::from(u16::try_from(*j).map_err(A::Error::custom)?));
                                handled = true;
                            }
                            _ => {}
                        }
                    }
                    if !handled {
                        extra.push((k, v));
                    }
                }

                let oidc_claims = Value::Map(extra)
                    .deserialized::<SpiceOidcClaims>()
                    .map_err(A::Error::custom)?;

                builder.oidc_claims(oidc_claims).build().map_err(A::Error::custom)
            }
        }

        deserializer.deserialize_map(ProtonClaimsVisitor)
    }
}

impl Select for ProtonMeetClaims {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reexports::ciborium;

    #[test]
    fn forward_compat_meet_labels_accept_new_ids() {
        let mut map = Vec::new();
        map.push((
            ciborium::value::Value::Integer((CwtProtonLabel::Role as i64).into()),
            ciborium::value::Value::Integer(0i64.into()),
        ));
        map.push((
            ciborium::value::Value::Integer((CwtProtonLabel::MimiProvider as i64).into()),
            ciborium::value::Value::Integer(56809i64.into()),
        ));
        map.push((
            ciborium::value::Value::Integer((-67550i64).into()),
            ciborium::value::Value::Text("meeting-123".to_string()),
        ));
        map.push((
            ciborium::value::Value::Integer((-67551i64).into()),
            ciborium::value::Value::Bytes(vec![1u8; 16]),
        ));
        map.push((
            ciborium::value::Value::Integer((-67552i64).into()),
            ciborium::value::Value::Bool(true),
        ));

        let value = ciborium::value::Value::Map(map);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&value, &mut bytes).unwrap();

        let claims: ProtonMeetClaims = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(claims.meeting_id, "meeting-123");
        assert_eq!(claims.uuid, [1u8; 16]);
        assert_eq!(claims.role, Role::User);
        assert_eq!(claims.mimi_provider, MimiProvider::ProtonAg);
        assert!(claims.is_from_server);
        assert!(!claims.is_host); // Default to false if not set
        assert_eq!(claims.client_type, ClientType::None); // Default when claim is absent
    }

    #[test]
    fn client_type_round_trip() {
        let claims = ProtonMeetClaimsBuilder::create_empty()
            .meeting_id("meeting-123")
            .uuid([1u8; 16])
            .oidc_claims(SpiceOidcClaims::default())
            .role(Role::User)
            .mimi_provider(MimiProvider::ProtonAg)
            .client_type(ClientType::Guest)
            .build()
            .unwrap();

        let value = Value::serialized(&claims).unwrap();
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&value, &mut bytes).unwrap();

        let decoded: ProtonMeetClaims = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(decoded.client_type, ClientType::Guest);
    }
}

// Used to allow using [spice_oidc_cwt::SpiceOidcSdCwtRead] trait
impl<'a> From<&'a ProtonMeetClaims> for &'a SpiceOidcClaims {
    fn from(c: &'a ProtonMeetClaims) -> Self {
        &c.oidc_claims
    }
}

#[derive(
    Debug,
    Copy,
    Clone,
    serde_repr::Serialize_repr,
    serde_repr::Deserialize_repr,
    enum_variants_strings::EnumVariantsStrings,
)]
#[enum_variants_strings_transform(transform = "snake_case")]
#[repr(i64)]
pub enum CwtProtonLabel {
    Aliases = -66538,
    OrgIds = -66539,
    Role = -66541,
    // Private Enterprise Number
    // see https://www.iana.org/assignments/enterprise-numbers
    MimiProvider = -66542,
}
esdicawt::cwt_label!(CwtProtonLabel);

/// All the custom claims we'll add to our SD-CWT
#[derive(Debug, Clone, PartialEq, Eq, derive_builder::Builder)]
#[builder(pattern = "mutable", setter(into, strip_option))]
pub struct ProtonClaims {
    #[builder(default)]
    pub aliases: Option<Vec<EmailAlias>>,
    /// Proton organization ID. Should have at most one entry for now, might be
    /// more in the future if we support a user joining multiple organizations
    /// in the Proton API
    #[builder(default)]
    pub organization_ids: Option<Vec<OrgId>>,
    pub oidc_claims: SpiceOidcClaims,
    /// User role in the organization. 0 is a user not member of any organization,
    /// 1 is an organization member, 2 is an organization admin
    #[builder(default)]
    pub role: Role,
    pub mimi_provider: MimiProvider,
}

impl serde::Serialize for ProtonClaims {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as _;

        let mut map = serializer.serialize_map(None)?;
        if let Some(aliases) = &self.aliases {
            map.serialize_entry(&CwtProtonLabel::Aliases, aliases)?;
        }
        if let Some(organization_ids) = &self.organization_ids {
            map.serialize_entry(&CwtProtonLabel::OrgIds, organization_ids)?;
        }

        let oidc_claims = Value::serialized(&self.oidc_claims).map_err(S::Error::custom)?;
        let oidc_claims = oidc_claims
            .into_map()
            .map_err(|_| S::Error::custom("should have been a mapping"))?;
        for (k, v) in oidc_claims {
            map.serialize_entry(&k, &v)?;
        }

        map.serialize_entry(&CwtProtonLabel::Role, &self.role)?;
        map.serialize_entry(&CwtProtonLabel::MimiProvider, &self.mimi_provider)?;

        map.end()
    }
}

impl<'de> serde::Deserialize<'de> for ProtonClaims {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ProtonClaimsVisitor;

        impl<'de> serde::de::Visitor<'de> for ProtonClaimsVisitor {
            type Value = ProtonClaims;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "an Proton claims payload")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                use serde::de::Error as _;

                let mut extra = vec![];
                let mut builder = ProtonClaimsBuilder::create_empty();
                while let Some((k, v)) = map.next_entry::<Value, Value>()? {
                    match (k, v) {
                        (Value::Integer(i), Value::Array(org_ids)) if i == CwtProtonLabel::OrgIds => {
                            builder.organization_ids(
                                org_ids
                                .into_iter()
                                    // filter out redacted elements
                                    .filter(|v| !matches!(v, Value::Tag(t, _) if *t == REDACTED_CLAIM_ELEMENT_TAG))
                                .map(|v| {
                                    v.into_bytes()
                                        .map_err(|_| A::Error::custom("expected bstr for organisation ids"))
                                })
                                .map(|v| v.and_then(|b| OrgId::try_from(&b[..]).map_err(A::Error::custom)))
                                .collect::<Result<Vec<_>, _>>()?,
                            );
                        }
                        (Value::Integer(i), Value::Array(aliases)) if i == CwtProtonLabel::Aliases => {
                            builder.aliases(
                                aliases
                                    .iter()
                                    // filter out redacted elements
                                    .filter(|v| !matches!(v, Value::Tag(t, _) if *t == REDACTED_CLAIM_ELEMENT_TAG))
                                    .map(|v| v.deserialized::<EmailAlias>())
                                    .collect::<Result<Vec<_>, _>>()
                                    .map_err(A::Error::custom)?,
                            );
                        }
                        (Value::Integer(i), Value::Integer(j)) if i == CwtProtonLabel::Role => {
                            builder.role(Role::from(u16::try_from(j).map_err(A::Error::custom)?));
                        }
                        (Value::Integer(i), Value::Integer(j)) if i == CwtProtonLabel::MimiProvider => {
                            builder.mimi_provider(MimiProvider::from(u16::try_from(j).map_err(A::Error::custom)?));
                        }
                        (k, v) => {
                            extra.push((k, v));
                        }
                    }
                }

                let oidc_claims = Value::Map(extra)
                    .deserialized::<SpiceOidcClaims>()
                    .map_err(A::Error::custom)?;

                builder.oidc_claims(oidc_claims).build().map_err(A::Error::custom)
            }
        }

        deserializer.deserialize_map(ProtonClaimsVisitor)
    }
}

impl Select for ProtonClaims {}

impl ProtonClaims {
    pub fn claim_name(name: &str) -> Option<&ClaimName> {
        (*CLAIM_MAP).get(name).or_else(|| SpiceOidcClaims::claim_name(name))
    }
}

// Used to allow using [spice_oidc_cwt::SpiceOidcSdCwtRead] trait
impl<'a> From<&'a ProtonClaims> for &'a SpiceOidcClaims {
    fn from(c: &'a ProtonClaims) -> Self {
        &c.oidc_claims
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct EmailAlias {
    #[serde(rename = "e")]
    pub email: String,
    #[serde(rename = "v")]
    pub verified: bool,
}

pub(crate) static CLAIM_MAP: LazyLock<HashMap<&'static str, ClaimName>> = LazyLock::new(|| {
    [
        (CwtProtonLabel::Aliases.to_str(), CwtProtonLabel::Aliases.into()),
        (CwtProtonLabel::OrgIds.to_str(), CwtProtonLabel::OrgIds.into()),
        (CwtProtonLabel::Role.to_str(), CwtProtonLabel::Role.into()),
    ]
    .into_iter()
    .collect()
});

pub trait ProtonSdCwtRead: SdCwtRead<PayloadClaims = ProtonClaims> {
    fn aliases(&mut self) -> EsdicawtReadResult<Option<Vec<EmailAlias>>> {
        Ok(self
            .query(vec![CwtProtonLabel::Aliases.into()].into())?
            .as_ref()
            .map(Value::deserialized)
            .transpose()?)
    }

    fn organization_ids(&mut self) -> EsdicawtReadResult<Option<Vec<OrgId>>> {
        Ok(self
            .query(vec![CwtProtonLabel::OrgIds.into()].into())?
            .as_ref()
            .map(Value::deserialized)
            .transpose()?)
    }

    fn role(&mut self) -> EsdicawtReadResult<Role> {
        Ok(self
            .query(vec![CwtProtonLabel::Role.into()].into())?
            .as_ref()
            .map(Value::deserialized)
            .transpose()?
            .unwrap_or_default())
    }

    fn provider(&mut self) -> EsdicawtReadResult<MimiProvider> {
        Ok(self
            .query(vec![CwtProtonLabel::MimiProvider.into()].into())?
            .as_ref()
            .map(Value::deserialized)
            .transpose()?
            .unwrap_or(MimiProvider::Unknown(0)))
    }
}
