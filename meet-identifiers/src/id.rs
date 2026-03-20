use crate::{AsOwned, ByRef};

#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize, facet::Facet)]
#[repr(transparent)]
#[serde(transparent)]
#[facet(transparent)]
pub struct Id(pub(crate) String);

impl Id {
    /// Generates a new random base64url identifier
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let mut rng = rand::rngs::OsRng;
        Self::new_random(&mut rng)
    }

    /// Generates a new random base64url identifier
    pub fn new_random(rng: &mut impl rand::Rng) -> Self {
        use base64::prelude::*;
        let mut bytes = [0u8; 16];
        rng.fill_bytes(&mut bytes);
        let id = BASE64_URL_SAFE_NO_PAD.encode(bytes);
        Self(id)
    }
}

#[cfg(any(test, feature = "test-util"))]
impl Default for Id {
    fn default() -> Self {
        Self::new()
    }
}

impl std::ops::Deref for Id {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::str::FromStr for Id {
    type Err = crate::ProtonMeetIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_owned()))
    }
}

impl std::fmt::Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::fmt::Debug for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let min_hidden_chars = 5;
        let max_displayed_chars = 10;
        crate::obfuscate(&self.0, f, min_hidden_chars, max_displayed_chars)
    }
}

#[cfg(any(test, feature = "test-util"))]
impl Id {
    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        Self::new_random(&mut rng)
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct IdRef<'a>(&'a str);

impl ByRef for Id {
    type Target<'a> = IdRef<'a>;

    fn as_ref(&self) -> Self::Target<'_> {
        IdRef(self.0.as_str())
    }
}

impl AsOwned for IdRef<'_> {
    type Target = Id;

    fn as_owned(&self) -> Self::Target {
        Id(self.0.to_owned())
    }
}

impl std::fmt::Display for IdRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_owned())
    }
}

impl std::fmt::Debug for IdRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.as_owned())
    }
}

impl<'a> From<&'a str> for IdRef<'a> {
    fn from(s: &'a str) -> Self {
        Self(s)
    }
}
