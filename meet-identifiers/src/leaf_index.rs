use crate::{ProtonMeetIdError, ProtonMeetIdResult};

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, serde::Serialize, serde::Deserialize, facet::Facet)]
#[repr(transparent)]
#[serde(transparent)]
#[facet(transparent)]
pub struct LeafIndex(u32);

impl LeafIndex {
    // ((2^32) / 2) - 1
    pub const MAX: Self = Self((u32::MAX >> 1) - 1);
}

impl TryFrom<u32> for LeafIndex {
    type Error = ProtonMeetIdError;

    fn try_from(i: u32) -> ProtonMeetIdResult<Self> {
        if i > Self::MAX.0 {
            return Err(ProtonMeetIdError::InvalidLeafIndex("LeafIndex too large"));
        }
        Ok(Self(i))
    }
}

impl std::str::FromStr for LeafIndex {
    type Err = ProtonMeetIdError;

    fn from_str(s: &str) -> ProtonMeetIdResult<Self> {
        s.parse::<u32>()
            .map_err(|_| ProtonMeetIdError::InvalidLeafIndex("Epoch must be a 'uint32'"))
            .and_then(TryInto::try_into)
    }
}

impl std::fmt::Display for LeafIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::fmt::Debug for LeafIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::ops::Deref for LeafIndex {
    type Target = u32;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(any(test, feature = "test-util"))]
impl LeafIndex {
    pub fn random() -> Self {
        use rand::Rng as _;
        let mut rng = rand::thread_rng();
        rng.gen_range(0..Self::MAX.0).try_into().unwrap()
    }
}
