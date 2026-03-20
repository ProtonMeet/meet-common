use crate::mls_spec;
use mls_spec::defs::CredentialType;

pub type MeetMlsResult<T> = Result<T, MeetMlsError>;

#[derive(thiserror::Error, Debug)]
pub enum MeetMlsError {
    #[error(transparent)]
    SdCwtSpecError(#[from] proton_claims::reexports::EsdicawtSpecError),
    #[error(transparent)]
    EsdicawtReadError(#[from] proton_claims::reexports::EsdicawtReadError),
    #[error(transparent)]
    MimiPolicyError(#[from] mimi_room_policy::MimiPolicyError),
    #[error(transparent)]
    MlsSpecError(#[from] crate::mls_spec::MlsSpecError),
    #[error(transparent)]
    IdentifierError(#[from] meet_identifiers::ProtonMeetIdError),
    #[cfg(feature = "server")]
    #[error(transparent)]
    SystemTimeError(#[from] std::time::SystemTimeError),
    #[error("Unknown member leaf")]
    InvalidLeaf,
    #[error("A GroupContextExtension has modified the ApplicationDataDictionary extension")]
    GceModifiedApplicationDataDictionary,
    #[error(
        "A role transition requested by {sender_role_index} is not authorized from {target_from_role_index} to {target_to_role_index}"
    )]
    UnauthorizedRoleChange {
        sender_role_index: u32,
        target_from_role_index: u32,
        target_to_role_index: u32,
    },
    #[error("The message that was sent was malformed")]
    MalformedMessage,
    #[error("No token was provided or the user isn't allowed to perform this action")]
    Unauthorized,
    #[error("Unexpected proposal")]
    UnexpectedProposal,
    #[error("Unknown external sender")]
    UnknownExternalSender,
    #[error("Credential type '{0}' not supported")]
    UnsupportedCredential(CredentialType),
    #[error("Invalid SD-CWT credential")]
    InvalidSdCwtCredential,
    #[error("The commit sent was rejected because it {0}")]
    RejectedCommit(#[from] CommitRejectionReason),
    #[error("{0}")]
    ImplementationError(&'static str),
}

#[derive(Debug, thiserror::Error)]
pub enum CommitRejectionReason {
    #[error("it contains an invalid proposal")]
    InvalidProposal,
    #[error("references unknown proposals")]
    UnknownProposalsReferenced,
    #[error("violates permissions or policies")]
    PolicyViolation,
    #[error("removes an unknown LeafIndex")]
    RemovedUnknownLeafNode,
    #[error("removes its own LeafIndex in a Commit")]
    RemovedSelf,
    #[error("references a keypackage twice")]
    DuplicateKeyPackageRef,
    #[error("only the same device can replace itself in a group")]
    InvalidReplace,
    #[error("its `confirmed_transcript_hash` is invalid")]
    InvalidConfirmedTranscriptHash,
    #[error("is missing the epoch 0 GroupInfo in the SafeAAD")]
    MissingAadEpoch0GroupInfo,
}
