use crate::mls_spec;

pub trait SenderExt {
    fn is_external(&self) -> bool;
    fn is_external_proposal(&self) -> bool;
    fn is_external_commit(&self) -> bool;
}

impl SenderExt for mls_spec::messages::Sender {
    fn is_external(&self) -> bool {
        match self {
            Self::Member(_) => false,
            Self::External(_) | Self::NewMemberCommit | Self::NewMemberProposal => true,
        }
    }

    fn is_external_proposal(&self) -> bool {
        match self {
            Self::External(_) | Self::NewMemberProposal => true,
            Self::Member(_) | Self::NewMemberCommit => false,
        }
    }

    fn is_external_commit(&self) -> bool {
        match self {
            Self::NewMemberCommit => true,
            Self::Member(_) | Self::External(_) | Self::NewMemberProposal => false,
        }
    }
}
