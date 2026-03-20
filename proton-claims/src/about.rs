/// A User's about section describing himself
#[derive(Default, Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
#[repr(transparent)]
pub struct About(String);

impl About {
    pub const MAX_SIZE: usize = 200;
}

impl TryFrom<String> for About {
    type Error = crate::error::ProtonClaimsError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.chars().count() > Self::MAX_SIZE {
            return Err(crate::error::ProtonClaimsError::AboutTooLong(Self::MAX_SIZE));
        }
        Ok(Self(value))
    }
}

impl std::ops::Deref for About {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
