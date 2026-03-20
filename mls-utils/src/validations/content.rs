use mimi_protocol_mls::reexports::mls_spec::{
    Serializable, ToPrefixedLabel,
    defs::labels::SignatureLabel,
    group::{
        commits::{Commit, ProposalOrRef},
        proposals::{AddProposal, Proposal},
    },
    key_schedule::GroupContext,
    messages::{AuthenticatedContentRef, ContentTypeInner, Sender},
    tree::{RatchetTree, TreeNode, UpdatePath},
};

use crate::{
    UtilError,
    tree::{TreeLeafIndex, TreeNodeIndex},
    validations::{
        InvalidSignatureItem, ValidationError,
        proposals::{ProposalListValidationContext, ProposalSenderPair},
    },
};

#[derive(Clone, Copy)]
pub struct ContentValidationContext<'a> {
    pub group_context: &'a GroupContext,
    pub ratchet_tree: &'a RatchetTree,
}

impl ContentValidationContext<'_> {
    fn proposal_validation_ctx_for_ext_commit<'a>(
        &'a self,
        update_path: Option<&'a UpdatePath>,
    ) -> ProposalListValidationContext<'a> {
        ProposalListValidationContext {
            ratchet_tree: self.ratchet_tree,
            group_context: self.group_context,
            sender: &Sender::NewMemberCommit,
            update_path,
            own_leaf_index: None,
        }
    }

    pub fn validate_authenticated_content(
        &self,
        authenticated_content: AuthenticatedContentRef,
    ) -> Result<(), UtilError> {
        let signature_public_key = match authenticated_content.content.sender {
            // member: The signature key contained in the LeafNode at the index indicated by leaf_index in the ratchet tree.
            Sender::Member(leaf_index) => {
                let leaf_array_idx: usize = *TreeNodeIndex::from(TreeLeafIndex(leaf_index));

                self.ratchet_tree
                    .get(leaf_array_idx)
                    .and_then(|tn| {
                        let Some(TreeNode::LeafNode(ln)) = tn else {
                            return None;
                        };

                        Some(&ln.signature_key)
                    })
                    .ok_or_else(|| UtilError::ValidationError(ValidationError::NoSuchLeafNode(leaf_index)))?
            }
            // The signature key at the index indicated by sender_index in the external_senders group context extension (see Section 12.1.8.1).
            // The content_type of the message MUST be proposal and the proposal_type MUST be a value that is allowed for external senders.
            Sender::External(ext_sender_index) => {
                // Check if proposal is allowed
                let ContentTypeInner::Proposal { proposal } = &authenticated_content.content.content else {
                    return Err(ValidationError::Structural.into());
                };

                if !proposal.proposal_type().is_allowed_in_external_proposals() {
                    return Err(ValidationError::Structural.into());
                }

                self.group_context
                    .external_senders()
                    .get(ext_sender_index as usize)
                    .map(|ext_sender| &ext_sender.signature_key)
                    .ok_or_else(|| {
                        UtilError::ValidationError(ValidationError::NoSuchExternalSender(ext_sender_index))
                    })?
            }
            // new_member_commit: The signature key in the LeafNode in the Commit's path (see Section 12.4.3.2).
            // The content_type of the message MUST be commit.
            Sender::NewMemberCommit => {
                let ContentTypeInner::Commit {
                    commit: Commit { proposals, path },
                } = &authenticated_content.content.content
                else {
                    return Err(ValidationError::Structural.into());
                };
                // TODO: Validate the structure of proposals listed
                let proposals: Vec<ProposalSenderPair> = proposals
                    .iter()
                    .map(|proposal_or_ref| {
                        let ProposalOrRef::Proposal(proposal) = proposal_or_ref else {
                            return Err(ValidationError::Structural.into());
                        };

                        Ok(ProposalSenderPair {
                            proposal,
                            sender: &authenticated_content.content.sender,
                        })
                    })
                    .collect::<Result<_, UtilError>>()?;

                self.proposal_validation_ctx_for_ext_commit(path.as_ref())
                    .validate_commit(proposals.as_slice())?;

                // NOTE: `validate_commit` above will catch if the path is `None` and error out before we
                // reach this line.
                let Some(UpdatePath { leaf_node, .. }) = &path else {
                    unreachable!();
                };

                &leaf_node.signature_key
            }
            // new_member_proposal: The signature key in the LeafNode in the KeyPackage embedded in an external Add proposal.
            // The content_type of the message MUST be proposal and the proposal_type of the Proposal MUST be add.
            Sender::NewMemberProposal => {
                let ContentTypeInner::Proposal {
                    proposal: Proposal::Add(AddProposal { key_package }),
                } = &authenticated_content.content.content
                else {
                    return Err(ValidationError::Structural.into());
                };

                &key_package.leaf_node.signature_key
            }
        };

        let framed_tbs = authenticated_content
            .content
            .to_tbs(authenticated_content.wire_format, self.group_context)?;

        crate::crypto::signatures::verify_with_label(
            signature_public_key,
            self.group_context.cipher_suite,
            &framed_tbs.to_tls_bytes()?,
            &SignatureLabel::FramedContentTBS.to_prefixed_string(self.group_context.version),
            &authenticated_content.auth.signature,
        )
        .map_err(|_| ValidationError::InvalidSignature(InvalidSignatureItem::AuthenticatedContent))?;

        Ok(())
    }
}
