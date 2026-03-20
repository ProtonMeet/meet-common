use crate::reexports::ciborium;

#[derive(Debug, thiserror::Error)]
pub enum ProtonClaimsError {
    #[error("Missing required field: {0}")]
    MissingField(&'static str),
    #[error("More than one space is disclosed")]
    InvalidSpacePresentation,
    #[error("About is too long, it must go beyond {0} characters")]
    AboutTooLong(usize),
    #[error(transparent)]
    CborValueError(#[from] ciborium::value::Error),
}
