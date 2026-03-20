use mimi_room_policy::spec::rbac::Role;

#[derive(
    Debug,
    Copy,
    Clone,
    Default,
    PartialEq,
    Eq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    strum::EnumIter,
    strum::Display,
)]
#[repr(u8)]
pub enum UserRole {
    /// User is not a member of the room
    NoRole = 0x00,
    /// User is not a member of the room anymore, but was banned
    Banned = 0x01,
    #[default]
    /// A regular member of a room with basic privileges
    Member = 0x03,
    /// Also known as a room admin, he is almighty on the room
    RoomAdmin = 0x04,
    /// In charge of...
    PolicyEnforcer = 0xF0,
    /// unknown role, when a room has a role_index that we do not know about
    Unknown = 0xFF,
}

impl UserRole {
    pub fn from_index(index: u32) -> Self {
        match index {
            0 => Self::NoRole,
            1 => Self::Banned,
            3 => Self::Member,
            4 => Self::RoomAdmin,
            0xF0 => Self::PolicyEnforcer,
            _ => Self::Unknown,
        }
    }

    pub fn builder(self) -> Role {
        match self {
            Self::NoRole => Role::new(self as u32, "no role", "no role"),
            Self::Banned => Role::new(self as u32, "banned", "banned"),
            Self::Member => Role::new(self as u32, "member", "member"),
            Self::RoomAdmin => Role::new(self as u32, "room admin", "room admin"),
            Self::PolicyEnforcer => Role::new(self as u32, "policy enforcer", "policy enforcer"),
            Self::Unknown => Role::new(self as u32, "unknown", "unknown"),
        }
    }
}

impl From<UserRole> for u32 {
    #[inline(always)]
    fn from(value: UserRole) -> Self {
        value as Self
    }
}
