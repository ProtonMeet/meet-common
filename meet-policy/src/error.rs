use crate::{RoomKind, UserRole};

pub type PolicyResult<T> = Result<T, PolicyError>;

#[derive(thiserror::Error, Debug)]
pub enum PolicyError {
    #[error(transparent)]
    SdCwtSpecError(#[from] proton_claims::reexports::EsdicawtSpecError),
    #[error("No UserRole {0} is defined for room kind {1:?}")]
    MissingRole(UserRole, RoomKind),
    #[error("{0}")]
    ImplementationError(&'static str),
}
