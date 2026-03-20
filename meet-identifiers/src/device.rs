use crate::{
    AsOwned, ByRef, Domain, Id, Identifier, ProtonMeetIdError, UserId, domain::DomainRef, id::IdRef, user::UserIdRef,
};
use std::borrow::Cow;

/// Device and account hosting the MLS client and its associated secrets
#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct DeviceId {
    domain: Domain,
    owning_identity_id: Id,
    id: Id,
}

impl DeviceId {
    /// Generates a new user identifier given an existing [Domain]
    pub fn new(owning_identity_id: &UserId) -> Self {
        Self {
            domain: owning_identity_id.domain.clone(),
            owning_identity_id: owning_identity_id.id.clone(),
            id: Id::new(),
        }
    }

    /// Generates a new user identifier given an existing [Domain]
    pub fn new_random(rng: &mut impl rand::Rng, owning_identiy_id: &UserId) -> Self {
        Self {
            domain: owning_identiy_id.domain.clone(),
            owning_identity_id: owning_identiy_id.id.clone(),
            id: Id::new_random(rng),
        }
    }

    pub fn new_deterministic(owning_identity_id: &UserId, id: Id) -> Self {
        Self {
            domain: owning_identity_id.domain.clone(),
            owning_identity_id: owning_identity_id.id.clone(),
            id,
        }
    }

    pub fn owning_identity_id(&self) -> UserIdRef<'_> {
        UserIdRef {
            domain: self.domain.as_ref(),
            id: self.owning_identity_id.as_ref(),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }
}

impl serde::Serialize for DeviceId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.as_ref().serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for DeviceId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let uri: Cow<str> = serde::Deserialize::deserialize(deserializer)?;
        uri.parse::<Self>().map_err(serde::de::Error::custom)
    }
}

impl std::fmt::Display for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}

impl std::fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.as_ref())
    }
}

impl std::str::FromStr for DeviceId {
    type Err = ProtonMeetIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(DeviceIdRef::try_from(s)?.as_owned())
    }
}

impl TryFrom<&[u8]> for DeviceId {
    type Error = ProtonMeetIdError;

    fn try_from(b: &[u8]) -> Result<Self, Self::Error> {
        std::str::from_utf8(b)?.parse()
    }
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct DeviceIdRef<'a> {
    /// A device using its public identity
    domain: DomainRef<'a>,
    owning_identity_id: IdRef<'a>,
    id: IdRef<'a>,
}

impl DeviceIdRef<'_> {
    pub fn owning_identity_id(&self) -> UserIdRef<'_> {
        UserIdRef {
            domain: self.domain,
            id: self.owning_identity_id,
        }
    }
}

impl ByRef for DeviceId {
    type Target<'a> = DeviceIdRef<'a>;

    fn as_ref(&self) -> Self::Target<'_> {
        DeviceIdRef {
            domain: self.domain.as_ref(),
            owning_identity_id: self.owning_identity_id.as_ref(),
            id: self.id.as_ref(),
        }
    }
}

impl AsOwned for DeviceIdRef<'_> {
    type Target = DeviceId;

    fn as_owned(&self) -> Self::Target {
        DeviceId {
            domain: self.domain.as_owned(),
            owning_identity_id: self.owning_identity_id.as_owned(),
            id: self.id.as_owned(),
        }
    }
}

impl Identifier for DeviceIdRef<'_> {
    const URI_PATH_SHORT: &'static str = "d";
}

impl serde::Serialize for DeviceIdRef<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let s = self.to_string();
        s.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for DeviceIdRef<'de> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        <&str as serde::Deserialize>::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

impl<'a> TryFrom<&'a str> for DeviceIdRef<'a> {
    type Error = ProtonMeetIdError;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        let uri = fluent_uri::UriRef::parse(s)?;

        let domain = uri
            .authority()
            .ok_or(ProtonMeetIdError::InvalidDeviceId("authority is missing"))?
            .host()
            .try_into()?;

        let Some(mut path) = uri.path().segments_if_absolute() else {
            return Err(ProtonMeetIdError::InvalidDeviceId("invalid URI"));
        };

        let d = path
            .next()
            .ok_or(ProtonMeetIdError::InvalidDeviceId("device code is missing"))?;
        if d.is_empty() {
            return Err(ProtonMeetIdError::InvalidDeviceId("device code is missing"));
        }
        if d != Self::URI_PATH_SHORT {
            return Err(ProtonMeetIdError::InvalidDeviceId("device code must be 'd'"));
        }

        let first_part = path
            .next()
            .ok_or(ProtonMeetIdError::InvalidDeviceId("missing identifier"))?
            .as_str();

        if first_part.is_empty() {
            return Err(ProtonMeetIdError::InvalidDeviceId("empty identifier"));
        }

        let device_part = if let Some(second_part) = path.next() {
            if !second_part.is_empty() {
                // URI:s starting with ".../d/{owning_identity_id}/{device_id}"
                if let Some(third_part) = path.next()
                    && !third_part.is_empty()
                {
                    // Disallow URI:s on the format ".../d/{owning_identity_id}/{device_id}/foo"
                    // but allow ".../d/{owning_identity_id}/{device_id}/"
                    return Err(ProtonMeetIdError::InvalidDeviceId("too many path parts"));
                }
                second_part.as_str()
            } else {
                if path.next().is_some() {
                    // Disallow URI:s on the format ".../d/{id}//" and ".../d/{id}//foo"
                    return Err(ProtonMeetIdError::InvalidDeviceId("empty identifier"));
                }
                // TODO: Allow URI:s on the format  ".../d/{device_id}/" by returning:
                // first_part
                return Err(ProtonMeetIdError::UnimplementedError(
                    "device URI:s without user part is currently not supported",
                ));
            }
        } else {
            // TODO: allow URI:s on the format ".../d/{device_id}" by returning:
            // first_part
            return Err(ProtonMeetIdError::UnimplementedError(
                "device URI:s without user part is currently not supported",
            ));
        };

        let owning_identity_id = first_part.into();
        let device_id = device_part.into();

        Ok(Self {
            domain,
            owning_identity_id,
            id: device_id,
        })
    }
}

impl<'a> TryFrom<&'a [u8]> for DeviceIdRef<'a> {
    type Error = ProtonMeetIdError;

    fn try_from(b: &'a [u8]) -> Result<Self, Self::Error> {
        std::str::from_utf8(b)?.try_into()
    }
}

impl std::fmt::Display for DeviceIdRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (scheme, device_code) = (crate::MIMI_SCHEME, Self::URI_PATH_SHORT);
        let (domain, owning_identity_id, id) = (self.domain, self.owning_identity_id, self.id);
        write!(f, "{scheme}://{domain}/{device_code}/{owning_identity_id}/{id}")
    }
}

impl std::fmt::Debug for DeviceIdRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (scheme, device_code) = (crate::MIMI_SCHEME, Self::URI_PATH_SHORT);
        let (domain, owning_identity_id, id) = (self.domain, self.owning_identity_id, self.id);
        write!(f, "{scheme}://{domain}/{device_code}/{owning_identity_id:?}/{id}")
    }
}
