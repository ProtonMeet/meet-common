// see https://www.iana.org/assignments/enterprise-numbers/
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(u16)]
pub enum MimiProvider {
    ProtonAg = 56809,
    Unknown(u16),
}

impl PartialOrd for MimiProvider {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MimiProvider {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let self_val = match self {
            Self::ProtonAg => 56809,
            Self::Unknown(v) => *v,
        };
        let other_val = match other {
            Self::ProtonAg => 56809,
            Self::Unknown(v) => *v,
        };
        self_val.cmp(&other_val)
    }
}

impl serde::Serialize for MimiProvider {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let v = match self {
            Self::ProtonAg => 56809,
            Self::Unknown(v) => *v,
        };
        serializer.serialize_u16(v)
    }
}

impl<'de> serde::Deserialize<'de> for MimiProvider {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let v = <u16 as serde::Deserialize>::deserialize(deserializer)?;
        Ok(match v {
            56809 => Self::ProtonAg,
            _ => Self::Unknown(v),
        })
    }
}

impl From<u16> for MimiProvider {
    fn from(value: u16) -> Self {
        match value {
            56809 => Self::ProtonAg,
            i => Self::Unknown(i),
        }
    }
}
