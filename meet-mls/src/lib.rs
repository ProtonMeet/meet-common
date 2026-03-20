pub use {
    claim_extractor::AnySdKbt,
    error::{CommitRejectionReason, MeetMlsError, MeetMlsResult},
    extensions::ExtensionsExt,
    preauth::PreAuthExt,
    ratchet_tree::RatchetTreeExt,
    sender::SenderExt,
};

use proton_claims::{
    ProtonMeetClaims, UserAsserted,
    reexports::{key_binding::KbtCwtTagged, verified::KbtCwtVerified},
};

pub(crate) mod claim_extractor;
mod error;
mod extensions;
mod preauth;
mod ratchet_tree;
mod sender;
pub(crate) use mimi_protocol_mls::reexports::mls_spec;

pub mod reexports {
    pub use meet_policy;
    pub use mimi_content;
    pub use mimi_protocol_mls;
    pub use mimi_room_policy;
}

pub type SdKbt = KbtCwtTagged<ProtonMeetClaims, sha2::Sha256, UserAsserted>;
pub type SdKbtVerified = KbtCwtVerified<ProtonMeetClaims, UserAsserted>;
