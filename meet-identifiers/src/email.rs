use crate::ProtonMeetIdError;
use std::borrow::Cow;

#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash, serde::Serialize, facet::Facet)]
#[repr(transparent)]
#[serde(transparent)]
#[facet(transparent)]
pub struct ProtonEmail(String);

impl std::str::FromStr for ProtonEmail {
    type Err = ProtonMeetIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        email_address::EmailAddress::parse_with_options(s, Self::EMAIL_OPTIONS)?;
        Ok(Self(s.to_owned()))
    }
}

impl std::ops::Deref for ProtonEmail {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ProtonEmail {
    const EMAIL_OPTIONS: email_address::Options = email_address::Options {
        minimum_sub_domains: 2, // same as 'with_required_tld()'
        allow_domain_literal: false,
        allow_display_text: false,
    };

    pub fn new_unchecked(email: String) -> Self {
        Self(email)
    }

    #[deprecated(note = "Use 'handle()' instead")]
    pub fn name(&self) -> String {
        self.0.split("@").next().unwrap().replace('.', " ")
    }
}

impl<'de> serde::Deserialize<'de> for ProtonEmail {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s: Cow<str> = serde::Deserialize::deserialize(deserializer)?;
        s.parse::<Self>().map_err(serde::de::Error::custom)
    }
}

#[derive(Copy, Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash, serde::Serialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct ProtonEmailRef<'a>(&'a str);

impl crate::ByRef for ProtonEmail {
    type Target<'a> = ProtonEmailRef<'a>;

    fn as_ref(&self) -> Self::Target<'_> {
        ProtonEmailRef(self.0.as_str())
    }
}

impl crate::AsOwned for ProtonEmailRef<'_> {
    type Target = ProtonEmail;

    fn as_owned(&self) -> Self::Target {
        ProtonEmail(self.0.to_owned())
    }
}

impl std::ops::Deref for ProtonEmailRef<'_> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[allow(clippy::infallible_try_from)]
impl<'a> TryFrom<&'a String> for ProtonEmailRef<'a> {
    type Error = ProtonMeetIdError;

    fn try_from(s: &'a String) -> Result<Self, Self::Error> {
        s.as_str().try_into()
    }
}

#[allow(clippy::infallible_try_from)]
impl<'a> TryFrom<&'a str> for ProtonEmailRef<'a> {
    type Error = ProtonMeetIdError;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        email_address::EmailAddress::parse_with_options(s, ProtonEmail::EMAIL_OPTIONS)?;
        Ok(Self(s))
    }
}

impl<'de> serde::Deserialize<'de> for ProtonEmailRef<'de> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s: &str = serde::Deserialize::deserialize(deserializer)?;
        email_address::EmailAddress::parse_with_options(s, ProtonEmail::EMAIL_OPTIONS)
            .map_err(serde::de::Error::custom)?;
        Ok(Self(s))
    }
}
