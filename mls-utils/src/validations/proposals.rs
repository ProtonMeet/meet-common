use std::collections::BTreeMap;

use mimi_protocol_mls::reexports::mls_spec::{
    AuthenticationServiceDelegate,
    defs::{ExtensionType, LeafIndex, ProposalType},
    group::proposals::Proposal,
    key_schedule::{GroupContext, PreSharedKeyId},
    messages::Sender,
    tree::{RatchetTree, UpdatePath},
};

use crate::{
    tree::{RatchetTreeLeafIterator, RatchetTreeReader, TreeLeafIndex, TreeNodeIndex},
    validations::{
        key_package::KeyPackageValidationContext,
        leaf_node::{GroupMemberValidationContext, LeafNodeValidationContext},
    },
};

use super::ValidationError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProposalSenderPair<'a> {
    pub proposal: &'a Proposal,
    pub sender: &'a Sender,
}

pub struct ProposalListValidationContext<'a> {
    pub ratchet_tree: &'a RatchetTree,
    pub group_context: &'a GroupContext,
    pub sender: &'a Sender,
    pub update_path: Option<&'a UpdatePath>,
    pub own_leaf_index: Option<&'a LeafIndex>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum MutationSource {
    Proposal(ProposalType),
    UpdatePath,
}

impl From<ProposalType> for MutationSource {
    fn from(value: ProposalType) -> Self {
        Self::Proposal(value)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CommitSummary {
    pub mutated_leaves: BTreeMap<TreeLeafIndex, Vec<MutationSource>>,
    pub needs_update_path: bool,
    pub reinit_pending: bool,
}

impl ProposalListValidationContext<'_> {
    /// https://www.rfc-editor.org/rfc/rfc9420.html#section-12.2-5
    fn validate_external_commit(&self, proposals: &[ProposalSenderPair]) -> Result<CommitSummary, ValidationError> {
        if !matches!(self.sender, Sender::NewMemberCommit) {
            return Err(ValidationError::ApiMisuse(
                "Not an external commit in `validate_external_commit()`",
            ));
        }

        if self.update_path.is_none() {
            return Err(ValidationError::NoUpdatePath);
        }

        let mut summary = CommitSummary {
            needs_update_path: true,
            ..Default::default()
        };

        let mut has_self_remove = false;
        let mut has_external_init = false;

        for ProposalSenderPair { proposal, sender } in proposals {
            if *sender != self.sender {
                return Err(ValidationError::Structural);
            }

            match proposal {
                Proposal::ExternalInit(_) => {
                    if has_external_init {
                        return Err(ValidationError::MultipleExternalInit);
                    }

                    has_external_init = true;
                }
                Proposal::SelfRemove(_) => {
                    if has_self_remove {
                        return Err(ValidationError::MutipleSelfRemove);
                    }

                    let Some(own_leaf_index) = self.own_leaf_index else {
                        return Err(ValidationError::ExternalCommitRemovesUnownedNode);
                    };

                    summary
                        .mutated_leaves
                        .entry((*own_leaf_index).into())
                        .or_default()
                        .push(ProposalType::new_unchecked(ProposalType::REMOVE).into());

                    has_self_remove = true;
                }
                Proposal::Remove(remove_proposal) => {
                    if has_self_remove {
                        return Err(ValidationError::MutipleSelfRemove);
                    }

                    let removed_index: usize = *TreeNodeIndex::from(TreeLeafIndex(remove_proposal.removed));
                    let Some(removed_leaf_node) = self
                        .ratchet_tree
                        .get(removed_index)
                        .and_then(|tn| tn.as_ref())
                        .and_then(|tn| tn.as_leaf_node())
                    else {
                        return Err(ValidationError::NoSuchLeafNode(remove_proposal.removed));
                    };

                    let Some(update_path) = self.update_path else {
                        return Err(ValidationError::NoUpdatePath);
                    };

                    if update_path.leaf_node.signature_key != removed_leaf_node.signature_key {
                        return Err(ValidationError::ExternalCommitRemovesUnownedNode);
                    }

                    summary
                        .mutated_leaves
                        .entry(remove_proposal.removed.into())
                        .or_default()
                        .push(ProposalType::new_unchecked(ProposalType::REMOVE).into());

                    has_self_remove = true;
                }
                Proposal::PreSharedKey(_) | Proposal::AppDataUpdate(_) => {}
                _ => return Err(ValidationError::InvalidProposal(proposal.proposal_type())),
            }
        }

        if !has_external_init {
            return Err(ValidationError::NoExternalInit);
        }

        Ok(summary)
    }

    //// https://www.rfc-editor.org/rfc/rfc9420.html#section-12.2-2
    fn validate_regular_commit(&self, proposals: &[ProposalSenderPair]) -> Result<CommitSummary, ValidationError> {
        let mut gce_proposal_count = 0usize;
        let mut seen_psks: Vec<&PreSharedKeyId> = vec![];
        let mut added_clients = vec![]; // No clue what's the actual type
        let mut has_others_than_reinit = false;

        let mut summary = CommitSummary::default();

        let Some(own_leaf_index) = self.own_leaf_index else {
            return Err(ValidationError::ApiMisuse(
                "Not a regular commit in `validate_regular_commit()`",
            ));
        };
        let is_commit_sender_self = matches!(self.sender, Sender::Member(idx) if idx == own_leaf_index);

        // Check if all the group members support the set of proposals contained in the Commit
        let non_default_proposal_types = proposals
            .iter()
            .filter_map(|ProposalSenderPair { proposal, .. }| {
                let pt = proposal.proposal_type();
                (!pt.is_spec_default()).then_some(pt)
            })
            .collect::<Vec<_>>();

        if non_default_proposal_types.is_empty() {
            let all_members_support_proposals = RatchetTreeLeafIterator::from(self.ratchet_tree)
                .filter_map(|(_, ln)| ln)
                .all(|ln| {
                    non_default_proposal_types
                        .iter()
                        .all(|pt| ln.capabilities.proposals.contains(pt))
                });

            if !all_members_support_proposals {
                return Err(ValidationError::NotAllMembersSupportProposalTypes(
                    non_default_proposal_types,
                ));
            }
        }

        for ProposalSenderPair { proposal, sender } in proposals {
            let is_proposal_sender_self = sender == &self.sender;
            let proposal_type = proposal.proposal_type();
            summary.needs_update_path |= proposal_type.needs_update_path();
            match proposal {
                Proposal::Add(add_proposal) => {
                    has_others_than_reinit = true;

                    // Double add in tree check
                    if RatchetTreeLeafIterator::from(self.ratchet_tree).any(|(_, ln)| {
                        ln.map(|ln| ln.signature_key == add_proposal.key_package.leaf_node.signature_key)
                            .unwrap_or_default()
                    }) {
                        return Err(ValidationError::DuplicateClient);
                    }

                    // Double add in the same commit check
                    if added_clients.contains(&&add_proposal.key_package.leaf_node.signature_key) {
                        return Err(ValidationError::DuplicateClient);
                    }

                    added_clients.push(&add_proposal.key_package.leaf_node.signature_key);
                }
                Proposal::Update(_) => {
                    has_others_than_reinit = true;

                    if is_commit_sender_self && is_proposal_sender_self {
                        return Err(ValidationError::CannotApplySelfUpdate);
                    }

                    let Sender::Member(leaf_idx) = sender else {
                        return Err(ValidationError::IncorrectTargetLeaf);
                    };

                    summary
                        .mutated_leaves
                        .entry((*leaf_idx).into())
                        .or_default()
                        .push(proposal_type.into());
                }
                Proposal::SelfRemove(_) => {
                    has_others_than_reinit = true;
                    let concrete_proposal_type = ProposalType::new_unchecked(ProposalType::REMOVE);
                    let mutation_source = concrete_proposal_type.into();

                    if is_commit_sender_self {
                        return Err(ValidationError::CannotApplySelfRemoval);
                    }
                    let mutated_leaf_history = summary.mutated_leaves.entry((*own_leaf_index).into()).or_default();

                    if mutated_leaf_history.contains(&mutation_source) {
                        return Err(ValidationError::MultipleUpdateOrRemoveOnLeaf);
                    }

                    mutated_leaf_history.push(mutation_source);
                }
                Proposal::Remove(remove_proposal) => {
                    has_others_than_reinit = true;

                    if is_commit_sender_self && &remove_proposal.removed == own_leaf_index {
                        return Err(ValidationError::CannotApplySelfRemoval);
                    }
                    let mutated_leaf_history = summary
                        .mutated_leaves
                        .entry(remove_proposal.removed.into())
                        .or_default();

                    let mutation_source = proposal_type.into();

                    if mutated_leaf_history.contains(&mutation_source) {
                        return Err(ValidationError::MultipleUpdateOrRemoveOnLeaf);
                    }

                    mutated_leaf_history.push(mutation_source);
                }
                Proposal::PreSharedKey(pre_shared_key_proposal) => {
                    has_others_than_reinit = true;
                    if seen_psks.contains(&&pre_shared_key_proposal.psk) {
                        return Err(ValidationError::PreSharedKeyMultipleAdd);
                    }

                    seen_psks.push(&pre_shared_key_proposal.psk);
                }
                Proposal::ReInit(_) => {
                    if has_others_than_reinit {
                        return Err(ValidationError::ReInitWithOtherProposals);
                    }

                    summary.reinit_pending = true;
                }
                Proposal::ExternalInit(_) => return Err(ValidationError::InvalidProposal(proposal_type)),
                Proposal::GroupContextExtensions(gce_proposal) => {
                    has_others_than_reinit = true;
                    gce_proposal_count += 1;
                    if gce_proposal_count > 1 {
                        return Err(ValidationError::MultipleGroupContextExtensions);
                    }

                    // If the group is ApplicationDataDictionary-enabled, then deny
                    // modifications to the AppDD through GCE
                    let has_app_data_dict = self
                        .group_context
                        .extensions
                        .iter()
                        .any(|extension| *extension.ext_type() == ExtensionType::APPLICATION_DATA_DICTIONARY);

                    if has_app_data_dict
                        && gce_proposal
                            .extensions
                            .iter()
                            .any(|extension| *extension.ext_type() == ExtensionType::APPLICATION_DATA_DICTIONARY)
                    {
                        return Err(ValidationError::ForbiddenGceAppDataDictUpdate);
                    }
                }
                Proposal::AppDataUpdate(_app_data_update) => {}
                Proposal::AppEphemeral(_application_data) => {}
            }
        }

        if summary.needs_update_path && self.update_path.is_none() {
            return Err(ValidationError::NoUpdatePath);
        }

        Ok(summary)
    }

    /// https://www.rfc-editor.org/rfc/rfc9420.html#name-proposal-list-validation
    pub fn validate_commit(&self, proposals: &[ProposalSenderPair]) -> Result<CommitSummary, ValidationError> {
        match self.sender {
            Sender::Member(_) => self.validate_regular_commit(proposals),
            Sender::NewMemberCommit => self.validate_external_commit(proposals),
            _ => Err(ValidationError::ApiMisuse("`validate_commit` called on...not a Commit")),
        }
    }

    pub async fn validate_standalone_proposals(
        &self,
        proposals: impl Iterator<Item = &Proposal>,
        credential_validator: &dyn AuthenticationServiceDelegate,
    ) -> Result<(), ValidationError> {
        match self.sender {
            Sender::Member(leaf_index) => {
                for proposal in proposals {
                    match proposal {
                        Proposal::Add(add_proposal) => {
                            KeyPackageValidationContext::default()
                                .with_ciphersuite(self.group_context.cipher_suite)
                                .validate(&add_proposal.key_package, credential_validator)
                                .await
                                .map_err(|_| ValidationError::InvalidProposal(proposal.proposal_type()))?;
                        }
                        Proposal::Update(update_proposal) => {
                            let leaf_idx = TreeLeafIndex(*leaf_index);
                            let finder = RatchetTreeReader::from(self.ratchet_tree);
                            let Some(leaf_node) = finder.find_leafnode_at_idx(leaf_idx) else {
                                return Err(ValidationError::InvalidProposal(proposal.proposal_type()));
                            };
                            let ctx = LeafNodeValidationContext::Update {
                                ctx: GroupMemberValidationContext {
                                    group_context: self.group_context,
                                    leaf_index,
                                },
                                previous_encryption_key: &leaf_node.encryption_key,
                                previous_signature_key: &leaf_node.signature_key,
                            };

                            ctx.validate_leaf_node(&update_proposal.leaf_node, credential_validator)
                                .await
                                .map_err(|_| ValidationError::InvalidProposal(proposal.proposal_type()))?;
                        }
                        Proposal::Remove(remove_proposal) => {
                            let leaf_idx = TreeLeafIndex(remove_proposal.removed);
                            if RatchetTreeReader::from(self.ratchet_tree)
                                .find_leafnode_at_idx(leaf_idx)
                                .is_none()
                            {
                                return Err(ValidationError::InvalidProposal(proposal.proposal_type()));
                            }
                        }
                        Proposal::ReInit(_) | Proposal::AppEphemeral(_) => {
                            return Err(ValidationError::InvalidProposal(proposal.proposal_type()));
                        }
                        _ => {}
                    }
                }
            }
            Sender::External(_) => {
                for proposal in proposals {
                    match proposal {
                        Proposal::Add(add_proposal) => {
                            KeyPackageValidationContext::default()
                                .with_ciphersuite(self.group_context.cipher_suite)
                                .validate(&add_proposal.key_package, credential_validator)
                                .await
                                .map_err(|_| ValidationError::InvalidProposal(proposal.proposal_type()))?;
                        }
                        Proposal::Remove(remove_proposal) => {
                            let leaf_idx = TreeLeafIndex(remove_proposal.removed);
                            if RatchetTreeReader::from(self.ratchet_tree)
                                .find_leafnode_at_idx(leaf_idx)
                                .is_none()
                            {
                                return Err(ValidationError::InvalidProposal(proposal.proposal_type()));
                            }
                        }
                        Proposal::PreSharedKey(_) | Proposal::ReInit(_) => {}
                        Proposal::GroupContextExtensions(_group_context_extensions_proposal) => {}
                        _ => return Err(ValidationError::InvalidProposal(proposal.proposal_type())),
                    }
                }
            }
            Sender::NewMemberProposal => {
                let proposal_set = proposals.collect::<Vec<&Proposal>>();
                if proposal_set.len() != 1 {
                    return Err(ValidationError::InvalidExternalJoinProposal);
                }

                let Proposal::Add(add_proposal) = &proposal_set[0] else {
                    return Err(ValidationError::InvalidExternalJoinProposal);
                };

                KeyPackageValidationContext::default()
                    .with_ciphersuite(self.group_context.cipher_suite)
                    .validate(&add_proposal.key_package, credential_validator)
                    .await
                    .map_err(|_| ValidationError::InvalidExternalJoinProposal)?;
            }
            _ => {
                return Err(ValidationError::ApiMisuse(
                    "`validate_standalone_proposals` called on a Commit",
                ));
            }
        }

        Ok(())
    }

    /// <https://www.rfc-editor.org/rfc/rfc9420.html#section-12.3-1>
    pub fn sorting_order_for_proposal_type(pt: ProposalType) -> usize {
        match *pt {
            ProposalType::GROUP_CONTEXT_EXTENSIONS => 0usize,
            ProposalType::UPDATE => 1,
            ProposalType::SELF_REMOVE => 2,
            ProposalType::REMOVE => 3,
            ProposalType::ADD => 4,
            ProposalType::PSK => 5,
            ProposalType::EXTERNAL_INIT => 6,
            ProposalType::REINIT => 7,
            ProposalType::APP_EPHEMERAL => 8,
            ProposalType::APP_DATA_UPDATE => 9,
            _ => usize::MAX,
        }
    }
}
