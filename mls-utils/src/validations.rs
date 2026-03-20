use mimi_protocol_mls::reexports::mls_spec::defs::ProposalType;

use crate::tree::TreeNodeIndex;

#[derive(Debug, thiserror::Error)]
pub enum InvalidSignatureItem {
    #[error("GroupInfo")]
    GroupInfo,
    #[error("LeafNode")]
    LeafNode,
    #[error("KeyPackage")]
    KeyPackage,
    #[error("AuthenticatedContent")]
    AuthenticatedContent,
    #[error("MIMI GroupInfoRequest")]
    GroupInfoRequest,
    #[error("MIMI KeyMaterialRequest")]
    KeyMaterialRequest,
}

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("The AuthenticationServiceDelegate determined the credential to be invalid")]
    InvalidCredential,
    #[error("Structural validation failed")]
    Structural,
    #[error("The KeyPackage Lifetime is expired")]
    ExpiredKeyPackage,
    #[error("The encryption_key of the updated LeafNode is the same as the previous one")]
    StaleEncryptionKey,
    #[error("The LeafNode has extensions that it doesn't declare as supported")]
    InsufficientCapabilities,
    #[error("Mismatching ciphersuites")]
    CiphersuiteMismatch,
    #[error("No ciphersuite has been set for validation")]
    NoCiphersuite,
    #[error("There's no root in the RatchetTree. This is an invalid MLS state")]
    NoRootInTree,
    #[error("Protocol is not Mls 1.0")]
    WtfIsThisProtocol,
    #[error("The LeafNode's encryption key is the same as the KeyPackage's init_key")]
    LeafNodeEncryptionKeyIsKeyPackageInitKey,
    #[error("The proposal list contains multiple ExternalInit proposals")]
    MultipleExternalInit,
    #[error("The client is already a member of the group")]
    DuplicateClient,
    #[error("It is forbidden to commit your own Update proposal")]
    CannotApplySelfUpdate,
    #[error("It is forbidden to commit your own Remove proposal")]
    CannotApplySelfRemoval,
    #[error("Mutiple Update and/or Remove proposals apply to the same LeafNode")]
    MultipleUpdateOrRemoveOnLeaf,
    #[error("The same PreSharedKey has been added multiple times")]
    PreSharedKeyMultipleAdd,
    #[error("This External Join Proposal is invalid")]
    InvalidExternalJoinProposal,
    #[error("Cannot target this LeafNode in this context")]
    IncorrectTargetLeaf,
    #[error("The leaf node at leaf index {0} doesn't exist")]
    NoSuchLeafNode(u32),
    #[error("The ExternalSender at index {0} does not exist")]
    NoSuchExternalSender(u32),
    #[error("There's no update path while there must be")]
    NoUpdatePath,
    #[error("The provided UpdatePath is invalid")]
    InvalidUpdatePath,
    #[error("The proposal list contains more than 1 GroupContextExtensions Proposal")]
    MultipleGroupContextExtensions,
    #[error("It is forbidden to update AppDataDictionary through a GroupContextExtensions Proposal")]
    ForbiddenGceAppDataDictUpdate,
    #[error("Not all members of the group support the non-standard proposal type set: {0:?}")]
    NotAllMembersSupportProposalTypes(Vec<ProposalType>),
    #[error(
        "The target LeafNode for the External Commit Remove mismatches the \
        UpdatePath's LeafNode contained in the External Commit"
    )]
    ExternalCommitRemovesUnownedNode,
    #[error("The external commit contains no ExternalInit proposal. It needs exactly one.")]
    NoExternalInit,
    #[error(
        "Removing a LeafNode multiple times in a single \
        commit is not allowed by the specification"
    )]
    MutipleSelfRemove,
    #[error(
        "The proposal list contains proposals other than the ReInit alone. \
        You should remove the ReInit proposal and renew it for a later epoch."
    )]
    ReInitWithOtherProposals,
    #[error("There's a Proposal ({0}) that is invalid in the current context")]
    InvalidProposal(ProposalType),
    #[error("The `parent_hash` of the node at index {idx} is invalid")]
    InvalidParentHash { idx: TreeNodeIndex },
    #[error("The GroupContext's `tree_hash` mismatches the RatchetTree's Hash")]
    InvalidTreeHash,
    #[error("The signature held on the {0} is invalid")]
    InvalidSignature(InvalidSignatureItem),
    #[error("This Update proposal tries to change the Signature key, which is forbidden")]
    UpdateWithDifferentSignatureKeys,
    #[error("The API has been misused. This is an implementation error and must not happen: {0}")]
    ApiMisuse(&'static str),
}

pub mod content;
pub mod group_info;
pub mod key_package;
pub mod leaf_node;
pub mod parent_hashes;
pub mod proposals;
pub mod tree_hashes;
