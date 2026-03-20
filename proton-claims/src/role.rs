#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum Role {
    #[default]
    User = 0,
    OrganizationMember = 1,
    OrganizationAdmin = 2,
    ProtonAdmin = 3,
    Unknown(u16),
}

impl serde::Serialize for Role {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let v = match self {
            Self::User => 0,
            Self::OrganizationMember => 1,
            Self::OrganizationAdmin => 2,
            Self::ProtonAdmin => 3,
            Self::Unknown(v) => *v,
        };
        serializer.serialize_u16(v)
    }
}

impl<'de> serde::Deserialize<'de> for Role {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let v = <u16 as serde::Deserialize>::deserialize(deserializer)?;
        Ok(match v {
            0 => Self::User,
            1 => Self::OrganizationMember,
            2 => Self::OrganizationAdmin,
            3 => Self::ProtonAdmin,
            _ => Self::Unknown(v),
        })
    }
}

impl From<u16> for Role {
    fn from(value: u16) -> Self {
        match value {
            0 => Self::User,
            1 => Self::OrganizationMember,
            2 => Self::OrganizationAdmin,
            3 => Self::ProtonAdmin,
            i => Self::Unknown(i),
        }
    }
}
