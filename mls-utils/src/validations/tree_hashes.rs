use mimi_protocol_mls::reexports::mls_spec::{
    SensitiveBytes, Serializable,
    key_schedule::GroupContext,
    tree::{
        RatchetTree,
        hashes::{LeafNodeHashInput, ParentNodeHashInput, TreeHashInput},
    },
};

use crate::{
    HashAlg, NamedCiphersuite, UtilError,
    tree::{RatchetTreeReader, TreeLeafIndex, TreeNodeIndex},
    validations::ValidationError,
};

#[inline]
pub(crate) fn compute_tree_hash_at_idx(
    finder: &RatchetTreeReader,
    idx: TreeNodeIndex,
    excluded_leaves: &[TreeLeafIndex],
    ctx: &GroupContext,
) -> Result<SensitiveBytes, UtilError> {
    let hash_alg = NamedCiphersuite::from(ctx.cipher_suite).hash_alg()?;
    compute_tree_hash_at_idx_with_alg(finder, idx, excluded_leaves, &hash_alg)
}

pub fn compute_tree_hash_at_idx_with_alg(
    finder: &RatchetTreeReader,
    idx: TreeNodeIndex,
    excluded_leaves: &[TreeLeafIndex],
    hash_alg: &HashAlg,
) -> Result<SensitiveBytes, UtilError> {
    let hash_input = if let Some(leaf_idx) = idx.to_tree_leaf_idx() {
        TreeHashInput::Leaf(LeafNodeHashInput {
            leaf_index: &leaf_idx.0,
            leaf_node: (!excluded_leaves.contains(&leaf_idx))
                .then(|| finder.find_leafnode_at_idx(leaf_idx))
                .flatten(),
        })
        .to_tls_bytes()?
    } else {
        let Some((left_idx, right_idx)) = idx.children() else {
            unreachable!()
        };

        let left_hash = compute_tree_hash_at_idx_with_alg(finder, left_idx, excluded_leaves, hash_alg)?;
        let right_hash = compute_tree_hash_at_idx_with_alg(finder, right_idx, excluded_leaves, hash_alg)?;

        let input = TreeHashInput::Parent(ParentNodeHashInput {
            parent_node: finder.find_parent_node_at_idx(idx),
            left_hash: &left_hash,
            right_hash: &right_hash,
        });

        input.to_tls_bytes()?
    };

    Ok(hash_alg.digest(&hash_input).into())
}

#[inline]
pub fn compute_tree_hash(rt: &RatchetTree, ctx: &GroupContext) -> Result<SensitiveBytes, UtilError> {
    let finder = RatchetTreeReader::from(rt).with_computed_leaf_count();
    compute_tree_hash_at_idx(&finder, finder.root_idx(), &[], ctx)
}

pub fn verify_tree_hash(rt: &RatchetTree, ctx: &GroupContext) -> Result<(), UtilError> {
    let computed_tree_hash = compute_tree_hash(rt, ctx)?;
    if computed_tree_hash != ctx.tree_hash {
        return Err(ValidationError::InvalidTreeHash.into());
    }

    Ok(())
}
