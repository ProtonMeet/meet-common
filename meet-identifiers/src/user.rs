use std::borrow::Cow;

use crate::{
    AsOwned, ByRef, Domain, Id, Identifier, ProtonMeetIdError, ProtonMeetIdResult, domain::DomainRef, id::IdRef,
};

/// Human user holding an account and having one or many devices
/// In the format of a MIMI URI identifier
#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct UserId {
    pub domain: Domain,
    pub id: Id,
}

impl UserId {
    /// Generates a new user identifier given an existing [Domain]
    pub fn new(domain: &Domain) -> Self {
        Self {
            domain: domain.clone(),
            id: Id::new(),
        }
    }

    /// Generates a new user identifier given a raw [Domain]
    pub fn try_new_random(
        rng: &mut impl rand::Rng,
        domain: impl TryInto<Domain, Error = ProtonMeetIdError>,
    ) -> ProtonMeetIdResult<Self> {
        Ok(Self::new_random(rng, &domain.try_into()?))
    }

    /// Generates a new user identifier given an existing [Domain]
    pub fn new_random(rng: &mut impl rand::Rng, domain: &Domain) -> Self {
        Self {
            domain: domain.clone(),
            id: Id::new_random(rng),
        }
    }

    pub fn id(&self) -> &Id {
        &self.id
    }

    pub fn domain(&self) -> &Domain {
        &self.domain
    }

    pub fn to_self_room_id(&self) -> crate::RoomId {
        use base64::prelude::Engine as _;
        use sha2::Digest as _;

        #[allow(clippy::indexing_slicing)] // SAFETY: SHA-256 output is always 32 bytes so slicing is safe
        let digest = &sha2::Sha256::digest(&*self.id)[..16];
        let id = Id(base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(digest));
        let domain = self.domain().clone();
        crate::RoomId { id, domain }
    }
}

impl serde::Serialize for UserId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl std::fmt::Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (scheme, user_code) = (crate::MIMI_SCHEME, UserIdRef::URI_PATH_SHORT);
        let (domain, id) = (self.domain(), self.id());
        write!(f, "{scheme}://{domain}/{user_code}/{id}")
    }
}

impl std::fmt::Debug for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (scheme, user_code) = (crate::MIMI_SCHEME, UserIdRef::URI_PATH_SHORT);
        let (domain, id) = (self.domain(), self.id());
        write!(f, "{scheme}://{domain:?}/{user_code}/{id:?}")?;
        Ok(())
    }
}

impl<'de> serde::Deserialize<'de> for UserId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let id: Cow<str> = serde::Deserialize::deserialize(deserializer)?;
        id.parse::<Self>().map_err(serde::de::Error::custom)
    }
}

impl std::str::FromStr for UserId {
    type Err = ProtonMeetIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(UserIdRef::try_from(s)?.as_owned())
    }
}

impl TryFrom<&[u8]> for UserId {
    type Error = ProtonMeetIdError;

    fn try_from(b: &[u8]) -> Result<Self, Self::Error> {
        std::str::from_utf8(b)?.parse()
    }
}

#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct UserIdRef<'a> {
    pub domain: DomainRef<'a>,
    pub id: IdRef<'a>,
}

impl Identifier for UserIdRef<'_> {
    const URI_PATH_SHORT: &'static str = "u";
}

impl std::fmt::Display for UserIdRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (scheme, user_code) = (crate::MIMI_SCHEME, Self::URI_PATH_SHORT);
        let (domain, id) = (&self.domain, &self.id);
        write!(f, "{scheme}://{domain}/{user_code}/{id}")
    }
}

impl std::fmt::Debug for UserIdRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (scheme, user_code) = (crate::MIMI_SCHEME, Self::URI_PATH_SHORT);
        let (domain, id) = (&self.domain, &self.id);
        write!(f, "{scheme}://{domain:?}/{user_code}/{id:?}")
    }
}

impl ByRef for UserId {
    type Target<'a> = UserIdRef<'a>;

    fn as_ref(&self) -> Self::Target<'_> {
        UserIdRef {
            id: self.id.as_ref(),
            domain: self.domain.as_ref(),
        }
    }
}

impl AsOwned for UserIdRef<'_> {
    type Target = UserId;

    fn as_owned(&self) -> Self::Target {
        UserId {
            id: self.id.as_owned(),
            domain: self.domain.as_owned(),
        }
    }
}

impl<'a> TryFrom<&'a str> for UserIdRef<'a> {
    type Error = ProtonMeetIdError;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        let uri = fluent_uri::UriRef::parse(s)?;

        let domain: DomainRef = uri
            .authority()
            .ok_or(ProtonMeetIdError::InvalidUserId("authority is missing"))?
            .host()
            .try_into()?;

        let mut path = uri
            .path()
            .segments_if_absolute()
            .ok_or(ProtonMeetIdError::InvalidUserId("invalid URI"))?;

        let separator = path.next().ok_or(ProtonMeetIdError::InvalidUserId(
            "path component of MIMI URI is missing",
        ))?;
        let id = match separator.as_str() {
            "u" => {
                let id = path
                    .next()
                    .ok_or(ProtonMeetIdError::InvalidUserId("missing unique identifier"))?
                    .as_str();
                if id.is_empty() {
                    return Err(ProtonMeetIdError::InvalidUserId("missing unique identifier"));
                }
                if path.next().is_some() {
                    return Err(ProtonMeetIdError::InvalidUserId("multiple user parts in MIMI user ID"));
                }
                id
            }
            "d" => {
                let id = path
                    .next()
                    .ok_or(ProtonMeetIdError::InvalidUserId("missing unique identifier"))?
                    .as_str();
                if id.is_empty() {
                    return Err(ProtonMeetIdError::InvalidUserId("missing unique identifier"));
                }
                if path.next().is_none() {
                    return Err(ProtonMeetIdError::InvalidUserId(
                        "tried to deserialize a device ID into a user ID",
                    ));
                }
                id
            }
            "" => {
                return Err(ProtonMeetIdError::InvalidUserId(
                    "path component of MIMI URI is missing",
                ));
            }
            _ => {
                return Err(ProtonMeetIdError::InvalidUserId(
                    "'u' or 'd' must directly precede identity part",
                ));
            }
        };

        Ok(Self { domain, id: id.into() })
    }
}

impl<'a> TryFrom<&'a [u8]> for UserIdRef<'a> {
    type Error = ProtonMeetIdError;

    fn try_from(b: &'a [u8]) -> Result<Self, Self::Error> {
        std::str::from_utf8(b)?.try_into()
    }
}

impl serde::Serialize for UserIdRef<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_string().serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for UserIdRef<'de> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let id = <&str as serde::Deserialize>::deserialize(deserializer)?;
        id.try_into().map_err(serde::de::Error::custom)
    }
}
