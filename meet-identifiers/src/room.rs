use std::borrow::Cow;

use crate::{AsOwned, ByRef, Domain, Id, Identifier, ProtonMeetIdError, ProtonMeetIdResult, domain::DomainRef};

/// Identifier for a Room
#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct RoomId {
    pub id: Id,
    pub domain: Domain,
}

impl RoomId {
    /// Generates a new room identifier given an existing [Domain]
    pub fn new(domain: &Domain) -> Self {
        Self {
            domain: domain.clone(),
            id: Id::new(),
        }
    }

    /// Generates a new room identifier given a raw [Domain]
    pub fn try_new_random(
        rng: &mut impl rand::Rng,
        domain: impl TryInto<Domain, Error = ProtonMeetIdError>,
    ) -> ProtonMeetIdResult<Self> {
        Ok(Self::new_random(rng, &domain.try_into()?))
    }

    /// Generates a new room identifier given an existing [Domain]
    pub fn new_random(rng: &mut impl rand::Rng, domain: &Domain) -> Self {
        Self {
            domain: domain.clone(),
            id: Id::new_random(rng),
        }
    }
}

impl std::fmt::Debug for RoomId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.as_ref())
    }
}

impl std::fmt::Display for RoomId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}

impl serde::Serialize for RoomId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.as_ref().serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for RoomId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let uri: Cow<str> = serde::Deserialize::deserialize(deserializer)?;
        uri.parse::<Self>().map_err(serde::de::Error::custom)
    }
}

impl std::str::FromStr for RoomId {
    type Err = ProtonMeetIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(RoomIdRef::try_from(s)?.as_owned())
    }
}

impl TryFrom<&[u8]> for RoomId {
    type Error = ProtonMeetIdError;

    fn try_from(b: &[u8]) -> Result<Self, Self::Error> {
        std::str::from_utf8(b)?.parse()
    }
}

#[cfg(any(test, feature = "test-util"))]
impl RoomId {
    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        Self::new_random(&mut rng, &Domain::default())
    }
}

#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct RoomIdRef<'a> {
    pub id: Id,
    pub domain: DomainRef<'a>,
}

impl Identifier for RoomIdRef<'_> {
    const URI_PATH_SHORT: &'static str = "r";
}

impl std::fmt::Debug for RoomIdRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (scheme, domain, room_code, room_id) = (crate::MIMI_SCHEME, &self.domain, Self::URI_PATH_SHORT, &self.id);
        write!(f, "{scheme}://{domain:?}/{room_code}/{room_id:?}")
    }
}

impl std::fmt::Display for RoomIdRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (scheme, domain, room_code, room_id) = (crate::MIMI_SCHEME, &self.domain, Self::URI_PATH_SHORT, &self.id);
        write!(f, "{scheme}://{domain}/{room_code}/{room_id}")
    }
}

impl ByRef for RoomId {
    type Target<'a> = RoomIdRef<'a>;

    fn as_ref(&self) -> Self::Target<'_> {
        RoomIdRef {
            id: self.id.clone(),
            domain: self.domain.as_ref(),
        }
    }
}

impl AsOwned for RoomIdRef<'_> {
    type Target = RoomId;

    fn as_owned(&self) -> Self::Target {
        RoomId {
            id: self.id.clone(),
            domain: self.domain.as_owned(),
        }
    }
}

impl<'a> TryFrom<&'a str> for RoomIdRef<'a> {
    type Error = ProtonMeetIdError;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        let uri = fluent_uri::UriRef::parse(s)?;

        let domain = uri
            .authority()
            .ok_or(ProtonMeetIdError::InvalidRoomId("authority is missing"))?
            .host()
            .try_into()?;

        let Some(mut path) = uri.path().segments_if_absolute() else {
            return Err(ProtonMeetIdError::InvalidRoomId("invalid URI"));
        };
        // parse '/r/{room-id}'
        let r = path
            .next()
            .ok_or(ProtonMeetIdError::InvalidRoomId("room code is missing"))?;
        if r != Self::URI_PATH_SHORT {
            return Err(ProtonMeetIdError::InvalidRoomId("room code must be 'r'"));
        }

        let id = path
            .next()
            .ok_or(ProtonMeetIdError::InvalidRoomId("missing unique identifier"))?
            .as_str()
            .parse::<Id>()
            .map_err(|_| ProtonMeetIdError::InvalidRoomId("the identifier is invalid"))?;

        Ok(Self { domain, id })
    }
}

impl<'a> TryFrom<&'a [u8]> for RoomIdRef<'a> {
    type Error = ProtonMeetIdError;

    fn try_from(b: &'a [u8]) -> Result<Self, Self::Error> {
        std::str::from_utf8(b)?.try_into()
    }
}

impl serde::Serialize for RoomIdRef<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_string().serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for RoomIdRef<'de> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let uri = <&str as serde::Deserialize>::deserialize(deserializer)?;
        uri.try_into().map_err(serde::de::Error::custom)
    }
}
