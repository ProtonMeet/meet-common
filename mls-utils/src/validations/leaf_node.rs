use mimi_protocol_mls::reexports::mls_spec::{
    AuthenticationServiceDelegate, Serializable, ToPrefixedLabel,
    defs::{CiphersuiteId, LeafIndex, labels::SignatureLabel},
    key_schedule::GroupContext,
    tree::leaf_node::{LeafNode, LeafNodeMemberInfo, LeafNodeSource},
};

use crate::{
    UtilError,
    validations::{InvalidSignatureItem, ValidationError},
};

use super::key_package::KeyPackageValidationContext;

#[derive(Debug, Clone, Copy)]
pub struct GroupMemberValidationContext<'a> {
    pub group_context: &'a GroupContext,
    pub leaf_index: &'a LeafIndex,
}

#[derive(Debug, Clone, Copy)]
pub enum LeafNodeValidationContext<'a> {
    KeyPackage(&'a KeyPackageValidationContext),
    Commit(GroupMemberValidationContext<'a>),
    Update {
        ctx: GroupMemberValidationContext<'a>,
        previous_encryption_key: &'a [u8],
        previous_signature_key: &'a [u8],
    },
}

impl LeafNodeValidationContext<'_> {
    fn member_info(&self) -> Option<LeafNodeMemberInfo<'_>> {
        let ctx = match self {
            LeafNodeValidationContext::Commit(ctx) => ctx,
            LeafNodeValidationContext::Update { ctx, .. } => ctx,
            LeafNodeValidationContext::KeyPackage(_) => return None,
        };

        Some(LeafNodeMemberInfo {
            group_id: ctx.group_context.group_id(),
            leaf_index: *ctx.leaf_index,
        })
    }

    fn ciphersuite(&self) -> Option<&CiphersuiteId> {
        match self {
            LeafNodeValidationContext::KeyPackage(ctx) => ctx.cipher_suite.as_ref(),
            LeafNodeValidationContext::Commit(ctx) => Some(&ctx.group_context.cipher_suite),
            LeafNodeValidationContext::Update { ctx, .. } => Some(&ctx.group_context.cipher_suite),
        }
    }

    fn group_context(&self) -> Option<&GroupContext> {
        match self {
            LeafNodeValidationContext::KeyPackage(_) => None,
            LeafNodeValidationContext::Commit(ctx) => Some(ctx.group_context),
            LeafNodeValidationContext::Update { ctx, .. } => Some(ctx.group_context),
        }
    }

    fn check_required_caps(&self, leaf_node: &LeafNode) -> Result<(), ValidationError> {
        let Some(group_context) = self.group_context() else {
            return Ok(());
        };

        let Some(required_caps) = group_context.required_capabilities() else {
            return Ok(());
        };

        if !required_caps.extension_types.iter().all(|req_ext| {
            req_ext.is_grease_value()
                || req_ext.is_spec_default()
                || leaf_node.capabilities.extensions.contains(req_ext)
        }) {
            return Err(ValidationError::InsufficientCapabilities);
        }

        if !required_caps.proposal_types.iter().all(|req_prop| {
            req_prop.is_grease_value()
                || req_prop.is_spec_default()
                || leaf_node.capabilities.proposals.contains(req_prop)
        }) {
            return Err(ValidationError::InsufficientCapabilities);
        }

        if !required_caps
            .credential_types
            .iter()
            .all(|req_cred| req_cred.is_grease_value() || leaf_node.capabilities.credentials.contains(req_cred))
        {
            return Err(ValidationError::InsufficientCapabilities);
        }

        Ok(())
    }

    /// Validate a LeafNode respecting the rules from RFC9420
    /// https://www.rfc-editor.org/rfc/rfc9420.html#name-leaf-node-validation
    pub async fn validate_leaf_node(
        &self,
        leaf_node: &LeafNode,
        credential_validator: &dyn AuthenticationServiceDelegate,
    ) -> Result<(), UtilError> {
        self.validate_leaf_node_internal(leaf_node, credential_validator, false)
            .await
    }

    /// https://www.rfc-editor.org/rfc/rfc9420.html#name-leaf-node-validation
    async fn validate_leaf_node_internal(
        &self,
        leaf_node: &LeafNode,
        credential_validator: &dyn AuthenticationServiceDelegate,
        skip_signature_check: bool,
    ) -> Result<(), UtilError> {
        // Verify that the credential in the LeafNode is valid as described in Section 5.3.1.
        if !credential_validator.validate_credential(&leaf_node.credential).await {
            return Err(ValidationError::InvalidCredential.into());
        }

        let Some(ciphersuite) = self.ciphersuite().copied() else {
            return Err(ValidationError::NoCiphersuite.into());
        };

        // Verify that the signature on the LeafNode is valid using signature_key.
        if !skip_signature_check {
            let version = self.group_context().map(|gc| gc.version).unwrap_or_default();
            crate::crypto::signatures::verify_with_label(
                &leaf_node.signature_key,
                ciphersuite,
                &leaf_node
                    .to_tbs(leaf_node.requires_member_info().then(|| self.member_info()).flatten())
                    .ok_or(ValidationError::Structural)?
                    .to_tls_bytes()?,
                &SignatureLabel::LeafNodeTBS.to_prefixed_string(version),
                &leaf_node.signature,
            )
            .map_err(|_| ValidationError::InvalidSignature(InvalidSignatureItem::LeafNode))?;
        }

        // Verify that the extensions in the LeafNode are supported by checking that
        // - the ID for each extension in the extensions field is listed in the capabilities.
        // - extensions field of the LeafNode.
        if !leaf_node.extensions.iter().all(|extension| {
            let extension_type = extension.ext_type();
            extension_type.is_grease_value()
                || extension_type.is_spec_default()
                || leaf_node.capabilities.extensions.contains(&extension_type)
        }) {
            return Err(ValidationError::InsufficientCapabilities.into());
        }

        // Verify that the LeafNode is compatible with the group's parameters.
        // - If the GroupContext has a required_capabilities extension, then the required
        // - extensions, proposals, and credential types MUST be listed in the LeafNode's capabilities field.
        self.check_required_caps(leaf_node)?;

        // Verify the leaf_node_source field:
        match self {
            // - * If the LeafNode appears in a KeyPackage, verify that leaf_node_source is set to key_package.
            LeafNodeValidationContext::KeyPackage(kp_ctx) => {
                if !kp_ctx.validate_keypackage_lifetime(&leaf_node.source) {
                    return Err(ValidationError::ExpiredKeyPackage.into());
                }
            }
            LeafNodeValidationContext::Commit(_) => {
                // - * If the LeafNode appears in the leaf_node value of the UpdatePath in a Commit, verify that leaf_node_source is set to commit.
                if !matches!(leaf_node.source, LeafNodeSource::Commit { .. }) {
                    return Err(ValidationError::Structural.into());
                }
            }
            LeafNodeValidationContext::Update {
                previous_encryption_key,
                previous_signature_key,
                ..
            } => {
                // - * If the LeafNode appears in an Update proposal, verify that leaf_node_source is set to update.
                if leaf_node.source != LeafNodeSource::Update {
                    return Err(ValidationError::Structural.into());
                }

                // CUSTOM VALIDATION
                // Enforce that signature keys are identical since we don't do signature key rotation
                if leaf_node.signature_key.as_slice() != *previous_signature_key {
                    return Err(ValidationError::UpdateWithDifferentSignatureKeys.into());
                }

                // - * Check that `encryption_key` represents a different public key than the `encryption_key`
                // in the leaf node being replaced by the Update proposal.
                if leaf_node.encryption_key.as_slice() == *previous_encryption_key {
                    return Err(ValidationError::StaleEncryptionKey.into());
                }
            }
        };

        Ok(())
    }
}
