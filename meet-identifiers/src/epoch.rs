use crate::{ProtonMeetIdError, ProtonMeetIdResult};

/// A MLS epoch
#[derive(
    Default, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, serde::Serialize, serde::Deserialize, facet::Facet,
)]
#[serde(transparent)]
#[facet(transparent)]
pub struct Epoch(u64);

impl std::ops::Deref for Epoch {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<u64> for Epoch {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl std::fmt::Debug for Epoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::fmt::Display for Epoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for Epoch {
    type Err = ProtonMeetIdError;

    fn from_str(s: &str) -> ProtonMeetIdResult<Self> {
        s.parse::<u64>()
            .map_err(|_| ProtonMeetIdError::InvalidEpoch("Epoch must be a 'uint64'"))
            .map(Into::into)
    }
}

#[cfg(any(test, feature = "test-util"))]
impl Epoch {
    pub fn random() -> Self {
        use rand::Rng as _;
        let mut rng = rand::thread_rng();
        rng.r#gen::<u64>().into()
    }
}
