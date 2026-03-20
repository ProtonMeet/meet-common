use crate::mls_spec;
use mls_spec::{credential::Credential, tree::RatchetTree};
use mls_utils::tree::{TreeLeafIndex, TreeNodeIndex};

pub trait RatchetTreeExt {
    fn credential_at_index(&self, idx: TreeLeafIndex) -> Option<&Credential>;
}

impl RatchetTreeExt for RatchetTree {
    fn credential_at_index(&self, idx: TreeLeafIndex) -> Option<&Credential> {
        let node_idx = TreeNodeIndex::from(idx);
        self.get(*node_idx)
            .and_then(Option::as_ref)
            .and_then(|tn| tn.as_leaf_node().map(|ln| &ln.credential))
    }
}
