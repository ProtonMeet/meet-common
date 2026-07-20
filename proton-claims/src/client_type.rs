#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(u16)]
pub enum ClientType {
    None = 0,
    Proton,
    Guest,
    Agent,
}

impl Default for ClientType {
    fn default() -> Self {
        Self::None
    }
}

impl PartialOrd for ClientType {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ClientType {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let self_val = match self {
            Self::None => 0,
            Self::Proton => 1,
            Self::Guest => 2,
            Self::Agent => 3,
        };
        let other_val = match other {
            Self::None => 0,
            Self::Proton => 1,
            Self::Guest => 2,
            Self::Agent => 3,
        };
        self_val.cmp(&other_val)
    }
}

impl serde::Serialize for ClientType {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let v = match self {
            Self::None => 0,
            Self::Proton => 1,
            Self::Guest => 2,
            Self::Agent => 3,
        };
        serializer.serialize_u16(v)
    }
}

impl<'de> serde::Deserialize<'de> for ClientType {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let v = <u16 as serde::Deserialize>::deserialize(deserializer)?;
        Ok(Self::from(v))
    }
}

impl From<u16> for ClientType {
    fn from(value: u16) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Proton,
            2 => Self::Guest,
            3 => Self::Agent,
            _ => Self::None,
        }
    }
}
