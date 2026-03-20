use mimi_protocol_mls::reexports::mls_spec::tree::{RatchetTree, TreeNode, leaf_node::LeafNode};

use crate::tree::{
    RatchetTreeReader, TreeLeafIndex, TreeNodeIndex,
    reader::{compute_nw, leaf_count, rightmost_nonblank_leafnode_idx, root_idx_from_nw},
};

#[derive(Debug)]
pub struct RatchetTreeContainer(pub Vec<Option<TreeNode>>);

impl RatchetTreeContainer {
    fn needs_to_grow(&self, target_idx: TreeNodeIndex) -> bool {
        self.0.len() <= *target_idx
    }

    fn needs_to_shrink(&self) -> bool {
        if self.0.len() <= 1 {
            return false;
        }

        if let Some(idx) = rightmost_nonblank_leafnode_idx(&self.0).map(TreeNodeIndex::from) {
            let root_idx = root_idx_from_nw(compute_nw(leaf_count(&self.0)));
            if idx >= root_idx {
                return false;
            }
        }

        true
    }

    pub fn grow_if_needed(&mut self, target_idx: TreeNodeIndex) {
        if self.needs_to_grow(target_idx) {
            let new_len = compute_nw(leaf_count(&self.0)).saturating_mul(2).saturating_add(1);
            self.0.resize_with(new_len, Default::default);
        }
    }

    pub fn shrink_if_needed(&mut self) {
        while self.needs_to_shrink() {
            let target_len = self.0.len().saturating_add(1).div_ceil(2).saturating_sub(1);
            self.0.truncate(target_len);
            self.0.shrink_to_fit();
        }
    }
}

#[derive(Debug)]
pub struct RatchetTreeWriter<'a> {
    rt: &'a mut RatchetTree,
    leaf_count: usize,
}

impl<'a> From<&'a mut RatchetTree> for RatchetTreeWriter<'a> {
    fn from(rt: &'a mut RatchetTree) -> Self {
        let leaf_count = RatchetTreeReader::from(&*rt).with_computed_leaf_count().leaf_count();
        Self { rt, leaf_count }
    }
}

impl RatchetTreeWriter<'_> {
    fn modify_raw_rt<T>(&mut self, mut f: impl FnMut(&mut RatchetTreeContainer) -> T) -> T {
        let mut raw_rt = RatchetTreeContainer(std::mem::take(self.rt).into_inner());
        let ret = f(&mut raw_rt);
        *self.rt = raw_rt.0.into();
        ret
    }

    pub fn reader(&self) -> RatchetTreeReader<'_> {
        RatchetTreeReader {
            rt: &*self.rt,
            leaf_count: self.leaf_count,
        }
    }

    pub fn add_member(&mut self, ln: &LeafNode) -> Option<LeafNode> {
        let target_idx = TreeNodeIndex::from(self.reader().leftmost_blank_leafnode_idx());
        self.modify_raw_rt(move |rt: &mut RatchetTreeContainer| {
            rt.grow_if_needed(target_idx);
            let old = rt.0[*target_idx].replace(TreeNode::LeafNode(ln.clone()));
            old.map(|tn| match tn {
                TreeNode::LeafNode(leaf_node) => leaf_node,
                _ => unreachable!(),
            })
        })
    }

    pub fn remove_member(&mut self, idx: TreeLeafIndex) -> bool {
        let target_idx = TreeNodeIndex::from(idx);
        self.modify_raw_rt(|rt| {
            let removed = rt.0[*target_idx].take().is_some();
            rt.shrink_if_needed();
            removed
        })
    }
}
