use crate::ProtonMeetIdError;

/// We got from Proton Account. It is unique and assigned to every account
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize, facet::Facet)]
#[serde(untagged)]
#[repr(C)]
pub enum ProtonUserId {
    Legacy(
        #[serde(with = "serde_bytes")]
        #[facet(bytes)]
        [u8; 64],
    ),
}

impl ProtonUserId {
    #[inline]
    pub const fn empty() -> Self {
        Self::Legacy([0; 64])
    }

    #[cfg(any(test, feature = "test-util"))]
    pub fn random() -> Self {
        use rand::Rng as _;
        let mut buf = [0; 64];
        rand::thread_rng().fill(&mut buf);
        Self::Legacy(buf)
    }
}

impl ProtonUserId {
    // This is how it's represented externally
    const B64: base64::engine::GeneralPurpose = base64::prelude::BASE64_URL_SAFE;
}

impl std::str::FromStr for ProtonUserId {
    type Err = ProtonMeetIdError;

    fn from_str(v: &str) -> Result<Self, Self::Err> {
        use base64::Engine as _;
        let id = Self::B64
            .decode(v)
            .map_err(|_| ProtonMeetIdError::InvalidProtonUserId("Failed to decode from base 64"))?;
        let id = id
            .try_into()
            .map_err(|_| ProtonMeetIdError::InvalidProtonUserId("Should be 512 bits long"));
        Ok(Self::Legacy(id?))
    }
}

impl From<ProtonUserId> for String {
    fn from(id: ProtonUserId) -> Self {
        use base64::Engine as _;
        match id {
            ProtonUserId::Legacy(id) => ProtonUserId::B64.encode(id),
        }
    }
}

impl std::fmt::Display for ProtonUserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use base64::Engine as _;
        match self {
            Self::Legacy(id) => write!(f, "{}", Self::B64.encode(id)),
        }
    }
}

impl std::fmt::Debug for ProtonUserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use base64::Engine as _;
        match self {
            Self::Legacy(id) => write!(f, "{}", Self::B64.encode(id)),
        }
    }
}
