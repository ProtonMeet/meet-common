pub type ProtonMeetIdResult<T> = Result<T, ProtonMeetIdError>;

#[derive(Debug, thiserror::Error)]
pub enum ProtonMeetIdError {
    #[error("{0}")]
    RandError(String),
    #[error(transparent)]
    Utf8Error(#[from] std::str::Utf8Error),
    #[error(transparent)]
    UlidDecodeError(#[from] ulid::DecodeError),
    #[error(transparent)]
    Base64DecodeError(#[from] base64::DecodeError),
    #[error("{0}")]
    InvalidUri(String),
    #[error("Invalid ProtonUserId because {0}")]
    InvalidProtonUserId(&'static str),
    #[error("Invalid OrgId because {0}")]
    InvalidOrgId(&'static str),
    #[error("Invalid SpaceId because {0}")]
    InvalidSpaceId(&'static str),
    #[error("Invalid UserId because {0}")]
    InvalidUserId(&'static str),
    #[error("Invalid DeviceId because {0}")]
    InvalidDeviceId(&'static str),
    #[error("Invalid ProviderId because {0}")]
    InvalidProviderId(&'static str),
    #[error("Invalid CommitId because {0}")]
    InvalidCommitId(&'static str),
    #[error("Invalid ApplicationMessageId because {0}")]
    InvalidAppMsgId(&'static str),
    #[error("Invalid RoomId because {0}")]
    InvalidRoomId(&'static str),
    #[error("Invalid MessageId because {0}")]
    InvalidMessageId(&'static str),
    #[error("Invalid Topic Id because {0}")]
    InvalidTopicId(&'static str),
    #[error("{0}")]
    InvalidEpoch(&'static str),
    #[error("{0}")]
    InvalidGeneration(&'static str),
    #[error("{0}")]
    InvalidLeafIndex(&'static str),
    #[error("Invalid email address '{0}'")]
    InvalidEmail(String),
    #[error(transparent)]
    EmailAddressError(#[from] email_address::Error),
    #[error("{0}")]
    ImplementationError(&'static str),
    #[error("{0}")]
    UnimplementedError(&'static str),
}

impl From<rand::Error> for ProtonMeetIdError {
    fn from(e: rand::Error) -> Self {
        Self::RandError(format!("{e}"))
    }
}

impl From<fluent_uri::error::ParseError> for ProtonMeetIdError {
    fn from(e: fluent_uri::error::ParseError) -> Self {
        Self::InvalidUri(format!("{e}"))
    }
}
