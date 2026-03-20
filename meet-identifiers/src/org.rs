use crate::ProtonMeetIdError;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize, facet::Facet)]
pub struct OrgId(
    #[serde(with = "serde_bytes")]
    #[facet(bytes)]
    [u8; 64],
);

impl OrgId {
    // This is how it's represented externally
    const B64: base64::engine::GeneralPurpose = base64::prelude::BASE64_URL_SAFE;

    #[cfg(any(test, feature = "test-util"))]
    pub fn random() -> Self {
        use rand::Rng as _;
        let mut buf = [0; 64];
        rand::thread_rng().fill(&mut buf);
        Self(buf)
    }
}

impl std::str::FromStr for OrgId {
    type Err = ProtonMeetIdError;

    fn from_str(v: &str) -> Result<Self, Self::Err> {
        use base64::Engine as _;
        let id = Self::B64
            .decode(v)
            .map_err(|_| ProtonMeetIdError::InvalidOrgId("Failed to decode from base 64"))?;
        let id = id
            .try_into()
            .map_err(|_| ProtonMeetIdError::InvalidOrgId("Should be 512 bits long"))?;
        Ok(Self(id))
    }
}

impl TryFrom<&[u8]> for OrgId {
    type Error = ProtonMeetIdError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let id = bytes
            .try_into()
            .map_err(|_| ProtonMeetIdError::InvalidOrgId("Should be 512 bits long"))?;
        Ok(Self(id))
    }
}

impl std::fmt::Display for OrgId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use base64::Engine as _;
        write!(f, "{}", Self::B64.encode(self.0))
    }
}

impl std::fmt::Debug for OrgId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use base64::Engine as _;
        write!(f, "{}", Self::B64.encode(self.0))
    }
}

