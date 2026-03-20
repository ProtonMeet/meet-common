use crate::{AsOwned, ProtonMeetIdError};
use fluent_uri::{
    component::Host,
    encoding::{EStr, encoder::RegName},
};

#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize, facet::Facet)]
#[repr(transparent)]
#[facet(transparent)]
#[serde(transparent)]
pub struct Domain(String);

impl std::str::FromStr for Domain {
    type Err = ProtonMeetIdError;

    fn from_str(host: &str) -> Result<Self, Self::Err> {
        Ok(Self(DomainRef::try_from(host)?.to_string()))
    }
}

impl TryFrom<&[u8]> for Domain {
    type Error = ProtonMeetIdError;

    fn try_from(b: &[u8]) -> Result<Self, Self::Error> {
        std::str::from_utf8(b)?.parse()
    }
}

impl<'a> TryFrom<&Host<'a>> for Domain {
    type Error = ProtonMeetIdError;

    fn try_from(host: &Host<'a>) -> Result<Self, Self::Error> {
        Ok(DomainRef::try_from(host)?.as_owned())
    }
}

impl std::fmt::Display for Domain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::fmt::Debug for Domain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::ops::Deref for Domain {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

#[cfg(any(test, feature = "test-util"))]
impl Domain {
    const DEFAULT: &'static str = "proton.me";

    /// Generates a semi-random domain for test purposes
    pub fn new_random() -> Self {
        use rand::distributions::{Alphanumeric, DistString};

        let subdomain = Alphanumeric.sample_string(&mut rand::thread_rng(), 5);
        Self(format!("{subdomain}.{}", Self::DEFAULT))
    }

    pub fn new_unchecked(s: &'static str) -> Self {
        Self(s.to_owned())
    }
}

#[cfg(any(test, feature = "test-util"))]
impl Default for Domain {
    fn default() -> Self {
        Self(Self::DEFAULT.to_owned())
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct DomainRef<'a>(&'a str);

impl crate::ByRef for Domain {
    type Target<'a> = DomainRef<'a>;

    fn as_ref(&self) -> Self::Target<'_> {
        DomainRef(self.0.as_str())
    }
}

impl AsOwned for DomainRef<'_> {
    type Target = Domain;

    fn as_owned(&self) -> Self::Target {
        Domain(self.0.to_owned())
    }
}

impl std::fmt::Display for DomainRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::fmt::Debug for DomainRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::ops::Deref for DomainRef<'_> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<'a> TryFrom<&'a String> for DomainRef<'a> {
    type Error = ProtonMeetIdError;

    fn try_from(s: &'a String) -> Result<Self, Self::Error> {
        s.as_str().try_into()
    }
}

impl<'a> TryFrom<&'a str> for DomainRef<'a> {
    type Error = ProtonMeetIdError;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        let s = EStr::<RegName>::new(s).ok_or(ProtonMeetIdError::ImplementationError("Invalid domain name"))?;
        Ok(Self(s.as_str()))
    }
}

impl<'a> TryFrom<&'a Host<'a>> for DomainRef<'a> {
    type Error = ProtonMeetIdError;

    fn try_from(host: &'a Host<'a>) -> Result<Self, Self::Error> {
        match host {
            Host::RegName(name) => Ok(Self(name.as_str())),
            _ => Err(ProtonMeetIdError::ImplementationError("Invalid hostname")),
        }
    }
}

#[cfg(any(test, feature = "test-util"))]
impl Default for DomainRef<'_> {
    fn default() -> Self {
        Domain::DEFAULT.try_into().unwrap()
    }
}
