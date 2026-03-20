#![allow(deprecated)]

pub(crate) use mimi_protocol_mls::reexports::{mls_spec, tls_codec};

pub mod compatible_component;
pub mod error;

/// Enumerates ALL the ComponentId we are using within the app, even those defined in another crate or in an RFC.
/// This has the benefit of preventing conflicts and provides const access to those numbers.
#[repr(u16)]
#[fwd_comp::fwd]
#[derive(strum::EnumIter, strum::Display)]
pub enum MeetComponentId {
    // mls-extensions
    // see https://messaginglayersecurity.rocks/mls-extensions/draft-ietf-mls-extensions.html#name-iana-considerations
    AppComponents = mls_spec::drafts::mls_extensions::APP_COMPONENTS_ID,
    SafeAad = mls_spec::drafts::mls_extensions::SAFE_AAD_ID,
    ContentMediaTypes = mls_spec::drafts::mls_extensions::CONTENT_MEDIA_TYPES_ID,
    LastResortKeyPackage = mls_spec::drafts::mls_extensions::LAST_RESORT_KEY_PACKAGE_ID,
    AppAck = mls_spec::drafts::mls_extensions::APP_ACK_ID,

    // draft pq-combiner
    // see https://messaginglayersecurity.rocks/mls-combiner/draft-ietf-mls-combiner.html#name-iana-considerations
    HpqMlsInfo = 0x0006,
    // draft associated parties
    AssociatedParties = 0x0007,
    // draft semi-private message
    ExternalReceivers = 0x0008,

    // mimi-protocol
    // see https://ietf-wg-mimi.github.io/mimi-protocol/draft-ietf-mimi-protocol.html#name-iana-considerations
    FrankAad = 0x0020,
    FrankingSignatureKey = 0x0021,
    ParticipantList = 0x0022,
    RoomMetadata = 0x0023,

    // draft mimi-room-policy
    // see https://ietf-wg-mimi.github.io/mimi-room-policy/draft-ietf-mimi-room-policy.html#name-iana-considerations
    MlsOperationalPolicy = 0x0024,
    RoleList = 0x0025,
    #[deprecated]
    PreAuthList = 0x0026,
    PreAuthListTmp = 0xFE26,
    BaseRoomPolicy = 0x0027,
    StatusNotificationPolicy = 0x0028,
    LinkPreviewPolicy = 0x002B,
    AssetPolicy = 0x002C,
    LoggingPolicy = 0x002D,
    MeetHistoryPolicy = 0x002E,
    BotPolicy = 0x002F,
    MessageExpirationPolicy = 0x0030,

    //draft msgid-aad
    MessageIdAad = 0x0040,
}
