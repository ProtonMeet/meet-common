use mimi_protocol_mls::reexports::mls_spec::{
    Serializable, ToPrefixedLabel, defs::labels::SignatureLabel, group::group_info::GroupInfo, tree::RatchetTree,
};

use crate::{
    UtilError,
    crypto::signatures::verify_with_label,
    tree::{RatchetTreeReader, TreeLeafIndex},
    validations::ValidationError,
};

use super::InvalidSignatureItem;

pub fn verify_group_info(rt: &RatchetTree, group_info: &GroupInfo) -> Result<(), UtilError> {
    let signer_idx = TreeLeafIndex(group_info.signer);
    let finder = RatchetTreeReader::from(rt);
    let Some(signer_leaf_node) = finder.find_leafnode_at_idx(signer_idx) else {
        return Err(ValidationError::InvalidSignature(InvalidSignatureItem::GroupInfo).into());
    };

    verify_with_label(
        &signer_leaf_node.signature_key,
        group_info.group_context.cipher_suite,
        &group_info.to_tbs().to_tls_bytes()?,
        &SignatureLabel::GroupInfoTBS.to_prefixed_string(group_info.group_context.version),
        &group_info.signature,
    )
    .map_err(|_| UtilError::from(ValidationError::InvalidSignature(InvalidSignatureItem::GroupInfo)))?;

    Ok(())
}
