use mimi_protocol_mls::reexports::mls_spec::{
    SensitiveBytes,
    credential::Credential,
    tree::{
        ParentNode, RatchetTree, TreeNode,
        leaf_node::{LeafNode, LeafNodeSource},
    },
};

use crate::tree::{FilteredDirectPathItem, RatchetTreeLeafIterator, TreeLeafIndex, TreeNodeIndex};

pub type IndexNodePair<'a> = (TreeNodeIndex, Option<&'a TreeNode>);

pub(crate) fn leaf_count(rt: &[Option<TreeNode>]) -> usize {
    if rt.is_empty() {
        return 0;
    }

    let leaf_idx = rightmost_nonblank_leafnode_idx(rt).unwrap_or_default();
    ((*leaf_idx) as usize).saturating_add(1)
}

pub(crate) fn rightmost_nonblank_leafnode_idx(rt: &[Option<TreeNode>]) -> Option<TreeLeafIndex> {
    rt.iter()
        .enumerate()
        .rev()
        .find_map(|(idx, n)| n.is_some().then(|| TreeNodeIndex(idx).to_tree_leaf_idx()).flatten())
}

pub(crate) fn compute_nw(lc: usize) -> usize {
    if lc == 0 {
        return 0;
    }

    lc.saturating_sub(1).saturating_mul(2).saturating_add(1)
}

pub(crate) fn root_idx_from_nw(nw: usize) -> TreeNodeIndex {
    TreeNodeIndex((1usize << (nw.ilog2() as usize)).saturating_sub(1))
}

#[derive(Debug, Clone, Copy)]
pub struct RatchetTreeReader<'a> {
    pub(crate) rt: &'a RatchetTree,
    pub(crate) leaf_count: usize,
}

impl<'a> From<&'a RatchetTree> for RatchetTreeReader<'a> {
    fn from(rt: &'a RatchetTree) -> Self {
        Self { rt, leaf_count: 0 }
    }
}

impl RatchetTreeReader<'_> {
    pub fn with_computed_leaf_count(mut self) -> Self {
        self.leaf_count = self.compute_leaf_count();
        self
    }

    #[inline]
    fn compute_leaf_count(&self) -> usize {
        leaf_count(&self.rt[..])
    }

    pub fn leaf_count(&self) -> usize {
        if !self.rt.is_empty() && self.leaf_count == 0 {
            panic!("MISUSE: You forgot to call `.with_computed_leaf_count()` on the `RatchetTreeFinder`!!!");
        }

        self.leaf_count
    }

    #[inline]
    pub fn node_width(&self) -> usize {
        compute_nw(self.leaf_count())
    }

    pub fn iter_leafnodes(&self) -> RatchetTreeLeafIterator<'_> {
        RatchetTreeLeafIterator::from(self.rt)
    }

    pub fn ratchet_tree(&self) -> &RatchetTree {
        self.rt
    }

    fn find_treenode_at_idx(&self, node_idx: TreeNodeIndex) -> Option<&TreeNode> {
        self.rt.get(*node_idx).and_then(Option::as_ref)
    }

    pub fn find_leafnode_by_credential(&self, credential: &Credential) -> Option<(TreeLeafIndex, &LeafNode)> {
        self.iter_leafnodes()
            .find_map(|(idx, ln)| ln.and_then(|ln| (&ln.credential == credential).then_some((idx, ln))))
    }

    pub fn find_leafnode_at_idx(&self, leaf_idx: TreeLeafIndex) -> Option<&LeafNode> {
        self.find_treenode_at_idx(TreeNodeIndex::from(leaf_idx))
            .and_then(|tn| tn.as_leaf_node())
    }

    pub fn find_parent_node_at_idx(&self, node_idx: TreeNodeIndex) -> Option<&ParentNode> {
        self.find_treenode_at_idx(node_idx).and_then(|tn| tn.as_parent_node())
    }

    pub fn find_idx_for_leafnode(&self, leaf_node: &LeafNode) -> Option<TreeLeafIndex> {
        self.iter_leafnodes()
            .find_map(|(idx, ln)| (ln? == leaf_node).then_some(idx))
    }

    pub fn parent_hash_at_idx(&self, node_idx: TreeNodeIndex) -> Option<&SensitiveBytes> {
        self.find_treenode_at_idx(node_idx).and_then(|tn| match tn {
            TreeNode::LeafNode(LeafNode {
                source:
                    LeafNodeSource::Commit {
                        parent_hash: leaf_node_parent_hash,
                    },
                ..
            }) => Some(leaf_node_parent_hash),
            TreeNode::ParentNode(parent_node) => Some(&parent_node.parent_hash),
            _ => None,
        })
    }

    pub fn next_non_blank_parent(&self, mut node_idx: TreeNodeIndex, root_idx: TreeNodeIndex) -> TreeNodeIndex {
        if node_idx == root_idx {
            return node_idx;
        }

        loop {
            let Some(parent_idx) = node_idx.parent(&root_idx) else {
                // It means the node_idx is the root already so return itself
                return node_idx;
            };
            if self.find_treenode_at_idx(parent_idx).is_some() {
                return parent_idx;
            }
            node_idx = parent_idx;
        }
    }

    #[inline]
    pub fn root_idx(&self) -> TreeNodeIndex {
        root_idx_from_nw(self.node_width())
    }

    pub fn root_node(&self) -> Option<&TreeNode> {
        self.find_treenode_at_idx(self.root_idx())
    }

    #[inline]
    pub fn rightmost_non_blank_leafnode_idx(&self) -> Option<TreeLeafIndex> {
        rightmost_nonblank_leafnode_idx(&self.rt[..])
    }

    pub fn leftmost_blank_leafnode_idx(&self) -> TreeLeafIndex {
        self.rt
            .iter()
            .enumerate()
            .find_map(|(idx, n)| {
                TreeNodeIndex(idx)
                    .to_tree_leaf_idx()
                    .and_then(|leaf_idx| n.is_none().then_some(leaf_idx))
            })
            .unwrap_or_else(|| {
                // The index of the root node after expanding the tree is the node width before expanding the tree
                let expanded_tree_root_idx = self.node_width();
                // Skip over the hypothetical new root node (at idx = tree.node_width()) to the new leaf index
                let leaf_node_idx = TreeNodeIndex(expanded_tree_root_idx.saturating_add(1));
                debug_assert!(leaf_node_idx.is_leaf());
                // SAFETY: Debug assertion above. There's no way this lands on *not* a LeafNode tree index
                leaf_node_idx.to_tree_leaf_idx().unwrap()
            })
    }

    #[inline]
    pub fn direct_path(&self, idx: TreeLeafIndex) -> Option<impl Iterator<Item = (TreeNodeIndex, Option<&TreeNode>)>> {
        self.direct_path_to_subroot(idx, self.root_idx())
    }

    fn direct_path_to_subroot(
        &self,
        idx: TreeLeafIndex,
        subroot_idx: TreeNodeIndex,
    ) -> Option<impl Iterator<Item = (TreeNodeIndex, Option<&TreeNode>)>> {
        let mut current_idx = TreeNodeIndex::from(idx);
        if subroot_idx == current_idx {
            return None;
        }

        Some(std::iter::from_fn(move || {
            current_idx = current_idx.parent(&subroot_idx)?;
            Some((current_idx, self.find_treenode_at_idx(current_idx)))
        }))
    }

    pub fn copath(&self, idx: TreeLeafIndex) -> Option<impl Iterator<Item = (TreeNodeIndex, Option<&TreeNode>)>> {
        self.direct_path(idx).map(|dp_iter| {
            std::iter::once((TreeNodeIndex::from(idx), None))
                .chain(dp_iter)
                .filter_map(|(idx, _)| {
                    let sibling_idx = idx.sibling()?;
                    Some((sibling_idx, self.find_treenode_at_idx(sibling_idx)))
                })
        })
    }

    pub fn node_resolution(
        &self,
        idx: TreeNodeIndex,
        excluded_leaves: &[TreeLeafIndex],
    ) -> Option<Vec<(TreeNodeIndex, Option<&TreeNode>)>> {
        let node = self.find_treenode_at_idx(idx);
        let is_leaf = idx.is_leaf();
        let is_blank = node.is_none();
        if is_leaf {
            let leaf_idx = idx.to_tree_leaf_idx()?;
            return Some(if is_blank || excluded_leaves.contains(&leaf_idx) {
                vec![]
            } else {
                vec![(idx, node)]
            });
        }

        let mut resolution = vec![];
        if is_blank {
            if let Some(mut left_resolution) = idx
                .left()
                .and_then(|left_idx| self.node_resolution(left_idx, excluded_leaves))
            {
                resolution.append(&mut left_resolution);
            }
            if let Some(mut right_resolution) = idx
                .right()
                .and_then(|right_idx| self.node_resolution(right_idx, excluded_leaves))
            {
                resolution.append(&mut right_resolution);
            }
        } else {
            resolution.push((idx, node));
            let Some(TreeNode::ParentNode(ParentNode { unmerged_leaves, .. })) = &node else {
                unreachable!()
            };

            resolution.extend(unmerged_leaves.iter().filter_map(|&idx| {
                let leaf_idx = TreeLeafIndex(idx);
                if excluded_leaves.contains(&leaf_idx) {
                    return None;
                }
                let leaf_node_idx = TreeNodeIndex::from(leaf_idx);
                let node_ref = self.find_treenode_at_idx(leaf_node_idx);
                Some((leaf_node_idx, node_ref))
            }));
        }

        Some(resolution)
    }

    pub fn copath_resolutions(
        &self,
        idx: TreeLeafIndex,
    ) -> Option<impl Iterator<Item = (TreeNodeIndex, Vec<IndexNodePair<'_>>)>> {
        if self.leaf_count() <= 1 {
            return None;
        }

        self.copath(idx).map(|copath_iter| {
            copath_iter.filter_map(|(copath_idx, _)| {
                self.node_resolution(copath_idx, &[])
                    .map(|resolution| (copath_idx, resolution))
            })
        })
    }

    pub fn filtered_direct_path(&self, idx: TreeLeafIndex) -> Option<impl Iterator<Item = FilteredDirectPathItem<'_>>> {
        Some(self.direct_path(idx)?.zip(self.copath_resolutions(idx)?).filter_map(
            |((node_idx, _), (sibling_idx, copath_resolution))| {
                (!copath_resolution.is_empty()).then_some(FilteredDirectPathItem {
                    node_idx,
                    sibling_idx,
                    copath_resolution,
                })
            },
        ))
    }

    pub fn find_parent_hash_in_resolution(
        &self,
        node_idx: TreeNodeIndex,
        parent_hash: &SensitiveBytes,
        excluded_leaves: &[TreeLeafIndex],
    ) -> bool {
        self.node_resolution(node_idx, excluded_leaves)
            .map(|resolution| {
                resolution.into_iter().any(|(_, node)| {
                    node.map(|tn| match tn {
                        TreeNode::LeafNode(LeafNode {
                            source:
                                LeafNodeSource::Commit {
                                    parent_hash: leaf_node_parent_hash,
                                },
                            ..
                        }) => leaf_node_parent_hash == parent_hash,
                        TreeNode::ParentNode(parent_node) => &parent_node.parent_hash == parent_hash,
                        _ => false,
                    })
                    .unwrap_or_default()
                })
            })
            .unwrap_or_default()
    }
}
