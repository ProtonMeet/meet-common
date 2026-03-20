use mimi_protocol_mls::reexports::mls_spec::{
    defs::LeafIndex,
    tree::{RatchetTree, TreeNode, leaf_node::LeafNode},
};
use num_traits::{One, PrimInt, WrappingSub};

mod reader;
pub use reader::RatchetTreeReader;

mod writer;
pub use writer::{RatchetTreeContainer, RatchetTreeWriter};

#[inline]
fn last_set_bit<T: WrappingSub + PrimInt + One>(n: T) -> T {
    n.wrapping_sub(&(n.wrapping_sub(&T::one()) & n))
}

#[inline]
fn last_zero_bit<T: WrappingSub + PrimInt + One>(n: T) -> T {
    last_set_bit(n + T::one())
}

#[inline]
fn range_from_leafcount(leaf_count: usize) -> std::ops::RangeInclusive<u32> {
    0..=(leaf_count as u32 - 1)
}

pub struct RatchetTreeLeafIterator<'a> {
    idx_range: std::ops::RangeInclusive<LeafIndex>,
    rt: &'a RatchetTree,
}

impl<'a, 'b> From<&'b RatchetTreeReader<'a>> for RatchetTreeLeafIterator<'a> {
    fn from(value: &'b RatchetTreeReader<'a>) -> Self {
        let reader = (*value).with_computed_leaf_count();
        let leaf_count = reader.leaf_count();
        let idx_range = range_from_leafcount(leaf_count);

        Self {
            idx_range,
            rt: reader.rt,
        }
    }
}

impl<'a> From<&'a RatchetTree> for RatchetTreeLeafIterator<'a> {
    fn from(rt: &'a RatchetTree) -> Self {
        (&RatchetTreeReader::from(rt)).into()
    }
}

impl RatchetTreeLeafIterator<'_> {
    fn get_value(&self, index: TreeLeafIndex) -> Option<<Self as Iterator>::Item> {
        self.rt
            .get(*TreeNodeIndex::from(index))
            .map(|maybe_tree_node| (index, maybe_tree_node.as_ref().and_then(|tn| tn.as_leaf_node())))
    }
}

impl<'a> Iterator for RatchetTreeLeafIterator<'a> {
    type Item = (TreeLeafIndex, Option<&'a LeafNode>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx_range.is_empty() {
            return None;
        }
        let value = self
            .get_value(TreeLeafIndex(*self.idx_range.start()))
            .expect("RatchetTreeLeafIterator::next(): idx_range is always valid; QED");
        self.idx_range = self.idx_range.start() + 1..=*self.idx_range.end();
        Some(value)
    }
}

impl<'a> DoubleEndedIterator for RatchetTreeLeafIterator<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.idx_range.is_empty() {
            return None;
        }
        let value = self
            .get_value(TreeLeafIndex(*self.idx_range.end()))
            .expect("RatchetTreeLeafIterator::next_back(): idx_range is always valid; QED");
        self.idx_range = *self.idx_range.start()..=self.idx_range.end() - 1;
        Some(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilteredDirectPathItem<'a> {
    pub node_idx: TreeNodeIndex,
    pub sibling_idx: TreeNodeIndex,
    pub copath_resolution: Vec<(TreeNodeIndex, Option<&'a TreeNode>)>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct TreeLeafIndex(pub u32);

impl std::fmt::Display for TreeLeafIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::ops::Deref for TreeLeafIndex {
    type Target = u32;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<u32> for TreeLeafIndex {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct TreeNodeIndex(pub usize);

impl std::fmt::Display for TreeNodeIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TreeNodeIndex {
    pub const fn is_leaf(&self) -> bool {
        self.0.is_multiple_of(2)
    }

    pub const fn to_tree_leaf_idx(&self) -> Option<TreeLeafIndex> {
        if !self.is_leaf() {
            return None;
        }

        Some(TreeLeafIndex((self.0 / 2) as u32))
    }

    pub fn left(&self) -> Option<Self> {
        if self.is_leaf() {
            return None;
        }

        let lzb = last_zero_bit(self.0);
        let left = self.0 & !lzb.wrapping_shr(1);
        Some(Self(left))
    }

    pub fn right(&self) -> Option<Self> {
        if self.is_leaf() {
            return None;
        }

        let lzb = last_zero_bit(self.0);
        let right = (self.0 | lzb) & !lzb.wrapping_shr(1);
        Some(Self(right))
    }

    /// Returns (Left, Right)
    pub fn children(&self) -> Option<(Self, Self)> {
        if self.is_leaf() {
            return None;
        }

        let lzb = last_zero_bit(self.0);
        let lzb_shr = !lzb.wrapping_shr(1);
        let left = self.0 & lzb_shr;
        let right = (self.0 | lzb) & lzb_shr;
        Some((Self(left), Self(right)))
    }

    pub fn sibling(&self) -> Option<Self> {
        let parent = self.parent_naive();
        if self < &parent { parent.right() } else { parent.left() }
    }

    fn parent_naive(&self) -> Self {
        let lzb = last_zero_bit(self.0);
        Self((lzb | self.0) & !lzb.wrapping_shl(1))
    }

    pub fn level(&self) -> u32 {
        self.0.trailing_ones()
    }

    pub fn parent(&self, root_idx: &TreeNodeIndex) -> Option<Self> {
        (self != root_idx).then(|| self.parent_naive())
    }
}

impl std::ops::Deref for TreeNodeIndex {
    type Target = usize;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<usize> for TreeNodeIndex {
    fn from(value: usize) -> Self {
        Self(value)
    }
}

impl From<TreeLeafIndex> for TreeNodeIndex {
    fn from(value: TreeLeafIndex) -> Self {
        Self((value.0 as usize) * 2)
    }
}

