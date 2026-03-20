#[doc = include_str!("../README.md")]
pub(crate) mod device;
pub(crate) mod domain;
pub(crate) mod email;
pub(crate) mod epoch;
pub(crate) mod error;
pub(crate) mod group;
pub(crate) mod id;
pub(crate) mod leaf_index;
pub(crate) mod org;
pub(crate) mod profile;
pub(crate) mod proton_user;
pub(crate) mod room;
pub(crate) mod time;
pub(crate) mod user;

const MIMI_SCHEME: &str = "mimi";
pub use {
    device::{DeviceId, DeviceIdRef},
    domain::{Domain, DomainRef},
    email::{ProtonEmail, ProtonEmailRef},
    epoch::Epoch,
    error::{ProtonMeetIdError, ProtonMeetIdResult},
    group::{GroupId, GroupIdRef},
    id::Id,
    leaf_index::LeafIndex,
    org::OrgId,
    profile::ProfileId,
    proton_user::ProtonUserId,
    room::{RoomId, RoomIdRef},
    time::TimeArg,
    user::{UserId, UserIdRef},
};

pub trait Identifier: std::fmt::Display + std::fmt::Debug {
    const URI_PATH_SHORT: &'static str;

    #[allow(dead_code)]
    fn to_bytes(&self) -> Vec<u8> {
        self.to_string().into_bytes()
    }
}

impl<T> Identifier for T
where
    T: ByRef + std::fmt::Display + std::fmt::Debug,
{
    const URI_PATH_SHORT: &'static str = T::URI_PATH_SHORT;
}

pub trait ByRef {
    type Target<'a>
    where
        Self: 'a;

    fn as_ref(&self) -> Self::Target<'_>;
}

pub trait AsOwned {
    type Target;

    fn as_owned(&self) -> Self::Target;
}

pub(crate) fn obfuscate(
    s: &str,
    f: &mut std::fmt::Formatter<'_>,
    min_hidden_chars: usize,
    max_displayed_chars: usize,
) -> std::fmt::Result {
    let len = s.len();
    let hidden_chars = usize::min(
        usize::max(len.saturating_sub(max_displayed_chars), min_hidden_chars),
        len,
    );
    let hidden_index_start = (len - hidden_chars) / 2;
    let hidden_index_end = hidden_index_start + hidden_chars;
    let mut obfuscated = s.to_owned();
    obfuscated.replace_range(hidden_index_start..hidden_index_end, "*".repeat(hidden_chars).as_str());

    write!(f, "{obfuscated}")
}
