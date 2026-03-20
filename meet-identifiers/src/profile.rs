use crate::{Id, ProtonMeetIdError};

#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize, facet::Facet)]
pub struct ProfileId(Id);

impl ProfileId {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self(Id::new())
    }

    pub fn new_random(rng: &mut impl rand::Rng) -> Self {
        Self(Id::new_random(rng))
    }
}

impl std::fmt::Display for ProfileId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for ProfileId {
    type Err = ProtonMeetIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.parse::<Id>()?))
    }
}
