use mimi_protocol_mls::reexports::mls_spec::{
    SensitiveBytes, Serializable,
    key_schedule::GroupContext,
    tree::{ParentNode, RatchetTree, hashes::ParentHashInput},
};

use crate::{
    HashAlg, NamedCiphersuite, UtilError,
    tree::{RatchetTreeReader, TreeLeafIndex, TreeNodeIndex},
    validations::{ValidationError, tree_hashes::compute_tree_hash_at_idx_with_alg},
};

#[inline]
fn compute_parent_hash_for_parent_node(
    parent_node: &ParentNode,
    original_sibling_tree_hash: &[u8],
    hash_alg: &HashAlg,
) -> Result<SensitiveBytes, UtilError> {
    Ok(hash_alg
        .digest(
            &ParentHashInput {
                encryption_key: &parent_node.encryption_key,
                parent_hash: &parent_node.parent_hash,
                original_sibling_tree_hash,
            }
            .to_tls_bytes()?,
        )
        .into())
}

pub fn verify_parent_hashes(rt: &RatchetTree, ctx: &GroupContext) -> Result<(), UtilError> {
    let hash_alg = NamedCiphersuite::from(ctx.cipher_suite).hash_alg()?;

    fn verify_parent_hash_internal_dig(
        finder: &RatchetTreeReader,
        subroot_idx: TreeNodeIndex,
        hash_alg: &HashAlg,
    ) -> Result<(), UtilError> {
        // If the node is blank or a leaf (which we shouldn't reach), assume valid
        let Some(node) = finder.find_parent_node_at_idx(subroot_idx) else {
            return Ok(());
        };

        let excluded_leaves = node
            .unmerged_leaves
            .iter()
            .map(|li| TreeLeafIndex(*li))
            .collect::<Vec<_>>();

        let Some((left_idx, right_idx)) = subroot_idx.children() else {
            unreachable!()
        };

        let left_oth = compute_tree_hash_at_idx_with_alg(finder, left_idx, &excluded_leaves, hash_alg)?;
        let right_oth = compute_tree_hash_at_idx_with_alg(finder, right_idx, &excluded_leaves, hash_alg)?;
        let left_ph = compute_parent_hash_for_parent_node(node, &right_oth, hash_alg)?;
        let right_ph = compute_parent_hash_for_parent_node(node, &left_oth, hash_alg)?;

        let left_ph_valid = finder.find_parent_hash_in_resolution(left_idx, &left_ph, &excluded_leaves);
        let right_ph_valid = finder.find_parent_hash_in_resolution(right_idx, &right_ph, &excluded_leaves);

        // Stop digging if we're on the level above leaves
        if left_idx.is_leaf() {
            return if left_ph_valid ^ right_ph_valid {
                Ok(())
            } else {
                Err(ValidationError::InvalidParentHash { idx: subroot_idx }.into())
            };
        }

        let left_is_ph_valid = left_ph_valid && verify_parent_hash_internal_dig(finder, left_idx, hash_alg).is_ok();
        let right_is_ph_valid = right_ph_valid && verify_parent_hash_internal_dig(finder, right_idx, hash_alg).is_ok();

        if left_is_ph_valid ^ right_is_ph_valid {
            Ok(())
        } else {
            Err(ValidationError::InvalidParentHash { idx: subroot_idx }.into())
        }
    }

    let finder = RatchetTreeReader::from(rt).with_computed_leaf_count();
    verify_parent_hash_internal_dig(&finder, finder.root_idx(), &hash_alg)
}
