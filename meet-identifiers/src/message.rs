use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use mimi_content::MimiContent;
use std::borrow::Cow;

/// Unique message identifier
/// See https://www.ietf.org/archive/id/draft-ietf-mimi-content-04.html#name-message-id-and-accepted-tim
#[derive(Copy, Clone, Eq, PartialEq)]
#[repr(transparent)]
pub struct MessageId(mimi_content::MessageId);

impl std::hash::Hash for MessageId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state)
    }
}

impl std::fmt::Debug for MessageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", BASE64_URL_SAFE_NO_PAD.encode(&self.0[..]))
    }
}

impl std::fmt::Display for MessageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", BASE64_URL_SAFE_NO_PAD.encode(&self.0[..]))
    }
}

impl std::str::FromStr for MessageId {
    type Err = crate::ProtonMeetIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = BASE64_URL_SAFE_NO_PAD.decode(s)?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| crate::ProtonMeetIdError::InvalidMessageId("Expected 32 bytes"))?;
        Ok(bytes.into())
    }
}

impl From<[u8; 32]> for MessageId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(mimi_content::MessageId::from_raw_unchecked(bytes))
    }
}

impl<'a> From<&'a MessageId> for &'a [u8; 32] {
    fn from(id: &'a MessageId) -> Self {
        std::ops::Deref::deref(&id.0)
    }
}

impl From<MessageId> for [u8; 32] {
    fn from(value: MessageId) -> Self {
        *value.0
    }
}

impl From<MessageId> for mimi_content::MessageId {
    fn from(value: MessageId) -> Self {
        value.0
    }
}

impl From<mimi_content::MessageId> for MessageId {
    fn from(value: mimi_content::MessageId) -> Self {
        Self(value)
    }
}

impl serde::Serialize for MessageId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_string().serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for MessageId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <Cow<str> as serde::Deserialize>::deserialize(deserializer)?;

        #[cfg(feature = "crux-typegen")]
        if s.is_empty() {
            return Ok(Self(mimi_content::MessageId::from_raw_unchecked(Default::default())));
        }
        s.parse::<Self>().map_err(serde::de::Error::custom)
    }
}

impl MessageId {
    #[inline]
    pub fn construct_sha256(
        sender_uri: &str,
        room_uri: &str,
        mimi_content: &MimiContent,
    ) -> Result<Self, crate::ProtonMeetIdError> {
        Ok(Self(mimi_content::MessageId::construct::<sha2::Sha256>(
            sender_uri.into(),
            room_uri.into(),
            mimi_content,
        )?))
    }

    #[inline]
    pub fn compute_sha256_from_parts(
        sender_uri: &str,
        room_uri: &str,
        raw_mimi_content: &[u8],
        salt: &[u8],
    ) -> Result<Self, crate::ProtonMeetIdError> {
        Ok(Self(mimi_content::MessageId::compute_from_parts::<sha2::Sha256>(
            sender_uri.into(),
            room_uri.into(),
            raw_mimi_content,
            salt,
        )?))
    }
}

