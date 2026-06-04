mod claim_name;
mod error;
mod hosted;
mod user_role;

pub use {
    claim_name::{ClaimNameExt, SD_CWT_CREDENTIAL_TYPE},
    error::{PolicyError, PolicyResult},
    user_role::UserRole,
};

use mimi_protocol_mls::{ParticipantListData, UserIdentifier, UserRolePair, reexports::tls_codec};

use hosted::{
    admin_can_accept_knock, admin_can_change_role_definitions, is_waiting_room, member_can_add_participant,
    no_role_has_lobby_access,
};
use meet_identifiers::UserId;
use mimi_room_policy::spec::{
    preauth::{PreAuthData, PreAuthRoleEntry},
    rbac::{Capability, CapabilityType, Role, RoleData, StdCapability},
};
use proton_claims::{CwtProtonLabel, CwtProtonMeetLabel};
use strum::IntoEnumIterator;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RoomPolicies {
    pub roles: RoleData,
    pub participant_list: ParticipantListData,
    pub pre_auth: PreAuthData,
}

impl RoomPolicies {
    pub fn new(creator: &UserId, kind: &RoomKind, is_host: bool) -> PolicyResult<Self> {
        let roles: RoleData = UserRole::iter()
            .filter_map(|r| Self::roles(kind, r))
            .collect::<Vec<_>>()
            .into();
        let participant_list = ParticipantListData {
            participants: Self::participant_list(creator, kind, is_host),
        };
        let pre_auth = PreAuthData {
            preauthorized_entries: Self::preauth(kind)?,
        };
        Ok(Self {
            roles,
            participant_list,
            pre_auth,
        })
    }

    /// Policy snapshot when waiting room is enabled (strict lobby).
    pub fn waiting_room(creator: &UserId, other_users: &[UserId], is_host: bool) -> PolicyResult<Self> {
        Self::new(
            creator,
            &RoomKind::BasicRoomWithWaiting {
                other_users: other_users.to_vec(),
            },
            is_host,
        )
    }

    /// Policy snapshot when waiting room is disabled — identical to an open hosted room.
    pub fn open_lobby(creator: &UserId, other_users: &[UserId], is_host: bool) -> PolicyResult<Self> {
        Self::new(
            creator,
            &RoomKind::BasicHostedRoom {
                is_open: true,
                other_users: other_users.to_vec(),
            },
            is_host,
        )
    }

    fn participant_list(creator: &UserId, kind: &RoomKind, is_host: bool) -> Vec<UserRolePair> {
        let creator = UserIdentifier::from(creator.to_string());
        let role_index = match kind {
            RoomKind::SelfRoom => UserRole::RoomAdmin as u32,
            RoomKind::Dm { .. } => UserRole::RoomAdmin as u32,
            RoomKind::BasicHostedRoom { .. } | RoomKind::BasicRoomWithWaiting { .. } => {
                if is_host {
                    UserRole::RoomAdmin as u32
                } else {
                    UserRole::Member as u32
                }
            }
        };
        let admin_creator = UserRolePair {
            user: creator,
            role_index,
        };
        match kind {
            RoomKind::SelfRoom => {
                vec![admin_creator]
            }
            RoomKind::Dm { other_users } => {
                // everyone is an admin in a DM
                let mut other_members = other_users
                    .iter()
                    .map(ToString::to_string)
                    .map(UserIdentifier::from)
                    .map(|user| UserRolePair {
                        user,
                        role_index: UserRole::RoomAdmin as u32,
                    })
                    .collect::<Vec<_>>();
                other_members.push(admin_creator);
                other_members
            }
            RoomKind::BasicHostedRoom { other_users, .. } | RoomKind::BasicRoomWithWaiting { other_users } => {
                let mut other_members = other_users
                    .iter()
                    .map(ToString::to_string)
                    .map(UserIdentifier::from)
                    .map(|user| UserRolePair {
                        user,
                        role_index: UserRole::Member as u32,
                    })
                    .collect::<Vec<_>>();
                other_members.push(admin_creator);
                other_members
            }
        }
    }

    fn preauth(kind: &RoomKind) -> PolicyResult<Vec<PreAuthRoleEntry>> {
        let policy_enforcer_preauth = PreAuthRoleEntry {
            claimset: vec![CwtProtonLabel::Role.preauth_claim_condition(&proton_claims::Role::ProtonAdmin)?],
            target_role: Self::roles(kind, UserRole::PolicyEnforcer)
                .ok_or_else(|| PolicyError::MissingRole(UserRole::PolicyEnforcer, kind.clone()))?,
        };
        // always first to have the highest precedence
        let mut preauth = vec![policy_enforcer_preauth];

        match kind {
            RoomKind::BasicRoomWithWaiting { .. } => {
                // the meeting host becomes admin of the room
                preauth.push(PreAuthRoleEntry {
                    claimset: vec![CwtProtonMeetLabel::Host.preauth_claim_condition(&true)?],
                    target_role: Self::roles(kind, UserRole::RoomAdmin)
                        .ok_or_else(|| PolicyError::MissingRole(UserRole::RoomAdmin, kind.clone()))?,
                });
                // the org admin becomes admin of any public room in the space he joins
                preauth.push(PreAuthRoleEntry {
                    claimset: vec![
                        CwtProtonLabel::Role.preauth_claim_condition(&proton_claims::Role::OrganizationAdmin)?,
                    ],
                    target_role: Self::roles(kind, UserRole::RoomAdmin)
                        .ok_or_else(|| PolicyError::MissingRole(UserRole::RoomAdmin, kind.clone()))?,
                });
            }
            RoomKind::BasicHostedRoom { is_open: true, .. } => {
                // the meeting host becomes admin of the room
                preauth.push(PreAuthRoleEntry {
                    claimset: vec![CwtProtonMeetLabel::Host.preauth_claim_condition(&true)?],
                    target_role: Self::roles(kind, UserRole::RoomAdmin)
                        .ok_or_else(|| PolicyError::MissingRole(UserRole::RoomAdmin, kind.clone()))?,
                });
                // the org admin becomes admin of any public room in the space he joins
                preauth.push(PreAuthRoleEntry {
                    claimset: vec![
                        CwtProtonLabel::Role.preauth_claim_condition(&proton_claims::Role::OrganizationAdmin)?,
                    ],
                    target_role: Self::roles(kind, UserRole::RoomAdmin)
                        .ok_or_else(|| PolicyError::MissingRole(UserRole::RoomAdmin, kind.clone()))?,
                });
                // anyone in a space can join any public room of this space
                preauth.push(PreAuthRoleEntry {
                    claimset: vec![],
                    target_role: Self::roles(kind, UserRole::Member)
                        .ok_or_else(|| PolicyError::MissingRole(UserRole::Member, kind.clone()))?,
                });
            }
            _ => {}
        }

        Ok(preauth)
    }

    fn roles(kind: &RoomKind, user_role: UserRole) -> Option<Role> {
        let mut r = user_role.builder();
        #[allow(clippy::match_same_arms)]
        match user_role {
            UserRole::NoRole => {
                r = r
                    .with_capabilities([
                        // used when room is destroyed and the last members sends a remove proposal to leave
                        StdCapability::CanRemoveSelf,
                        StdCapability::CanChangeOwnRole,
                    ])
                    .with_maximum_active_participants_constraint(0)
                    .with_authorized_role_change(UserRole::NoRole, vec![UserRole::Member]);
                if is_waiting_room(kind) {
                    Some(r)
                } else {
                    r = r.with_capabilities([StdCapability::CanOpenJoin, StdCapability::CanSendMlsExternalCommit]);
                    if no_role_has_lobby_access(kind) {
                        Some(r.with_capabilities([StdCapability::CanUseJoinCode, StdCapability::CanKnock]))
                    } else {
                        Some(r)
                    }
                }
            }
            UserRole::Banned => Some(r.with_maximum_active_participants_constraint(0)),
            UserRole::Member => {
                r = r
                    .with_capabilities([
                        StdCapability::CanAddOwnClient,
                        StdCapability::CanChangeOwnName,
                        StdCapability::CanChangeOwnPresence,
                        StdCapability::CanChangeOwnMood,
                        StdCapability::CanChangeOwnAvatar,
                        StdCapability::CanSendMlsPSKProposal,
                        StdCapability::CanSendMlsReinitProposal,
                        StdCapability::CanSendMlsExternalCommit,
                        StdCapability::CanSendMlsExternalProposal,
                        StdCapability::CanSendMessage,
                        StdCapability::CanSendDirectMessage,
                        StdCapability::CanTargetMessage,
                        StdCapability::CanJoinIfPreauthorized,
                        StdCapability::CanChangeUserRole,
                        StdCapability::CanRemoveSelf,
                        StdCapability::CanChangePreauthorizedUserList,
                    ])
                    .with_authorized_role_change(UserRole::Member, vec![UserRole::NoRole])
                    .with_authorized_role_change(UserRole::NoRole, vec![UserRole::Member]);
                match kind {
                    RoomKind::BasicHostedRoom { .. } | RoomKind::BasicRoomWithWaiting { .. } | RoomKind::Dm { .. } => {
                        if member_can_add_participant(kind) {
                            r = r.with_capabilities([StdCapability::CanAddParticipant]);
                        }
                        Some(r.with_capabilities([
                            StdCapability::CanRemoveOwnClient,
                            StdCapability::CanRemoveSelf,
                            StdCapability::CanSendMessage,
                            StdCapability::CanTargetMessage,
                            StdCapability::CanReceiveMessage,
                            StdCapability::CanCopyMessage,
                            StdCapability::CanReplyToMessage,
                            StdCapability::CanReactToMessage,
                            StdCapability::CanEditReaction,
                            StdCapability::CanDeleteOwnReaction,
                            StdCapability::CanEditOwnMessage,
                            StdCapability::CanReplyInTopic,
                            StdCapability::CanEditOwnTopic,
                            StdCapability::CanUploadImage,
                            StdCapability::CanUploadVideo,
                            StdCapability::CanUploadAudio,
                            StdCapability::CanUploadAttachment,
                            StdCapability::CanDownloadImage,
                            StdCapability::CanDownloadAudio,
                            StdCapability::CanDownloadVideo,
                            StdCapability::CanDownloadAttachment,
                            StdCapability::CanSendLink,
                            StdCapability::CanSendLinkPreview,
                            StdCapability::CanFollowLink,
                            StdCapability::CanCopyLink,
                            StdCapability::CanJoinCall,
                            StdCapability::CanSendAudio,
                            StdCapability::CanReceiveAudio,
                            StdCapability::CanSendVideo,
                            StdCapability::CanReceiveVideo,
                            StdCapability::CanShareScreen,
                            StdCapability::CanViewSharedScreen,
                            StdCapability::CanDeleteOwnMessage,
                            StdCapability::CanSendMlsUpdateProposal,
                            StdCapability::CanChangeOwnRole,
                            StdCapability::CanSendMlsExternalCommit,
                            StdCapability::CanSendMlsExternalProposal,
                            StdCapability::CanChangePreauthorizedUserList,
                            StdCapability::CanUseJoinCode,
                            StdCapability::CanJoinIfPreauthorized,
                            StdCapability::CanReportAbuse,
                            StdCapability::CanStartTopic,
                            StdCapability::CanStartCall,
                        ]))
                    }
                    // everyone is admin in this room
                    RoomKind::SelfRoom => None,
                }
            }
            UserRole::RoomAdmin => {
                r = r.with_capabilities([
                    StdCapability::CanRemoveSelf,
                    StdCapability::CanSendMlsExternalCommit,
                    StdCapability::CanRemoveParticipant,
                    StdCapability::CanBan,
                    StdCapability::CanUnBan,
                    StdCapability::CanKick,
                ]);
                Some(match kind {
                    RoomKind::BasicHostedRoom { .. } | RoomKind::BasicRoomWithWaiting { .. } | RoomKind::Dm { .. } => {
                        if !matches!(kind, RoomKind::Dm { .. }) {
                            r = r.with_capabilities([StdCapability::CanAddParticipant]);
                        }

                        let mut admin = r
                            .inherit_capabilities(&Self::roles(kind, UserRole::Member)?)
                            .with_capabilities([
                                StdCapability::CanChangeRoomName,
                                StdCapability::CanChangeRoomDescription,
                                StdCapability::CanChangeRoomAvatar,
                                StdCapability::CanChangeRoomSubject,
                                StdCapability::CanChangeRoomMood,
                                StdCapability::CanDestroyRoom,
                                StdCapability::CanChangeUserRole,
                                StdCapability::CanChangePreauthorizedUserList,
                                // FIXME: admin act as a moderator until the appropriate role is defined
                                StdCapability::CanDeleteOtherMessage,
                            ]);
                        if admin_can_accept_knock(kind) {
                            admin = admin.with_capabilities([StdCapability::CanAcceptKnock]);
                        }
                        if admin_can_change_role_definitions(kind) {
                            admin = admin.with_capabilities([StdCapability::CanChangeRoleDefinitions]);
                        }
                        admin
                            .with_authorized_role_change(
                                UserRole::NoRole,
                                vec![UserRole::Banned, UserRole::Member, UserRole::RoomAdmin],
                            )
                            .with_authorized_role_change(
                                UserRole::Banned,
                                vec![UserRole::NoRole, UserRole::Member, UserRole::RoomAdmin],
                            )
                            .with_authorized_role_change(
                                UserRole::Member,
                                vec![UserRole::NoRole, UserRole::Banned, UserRole::RoomAdmin],
                            )
                            .with_authorized_role_change(
                                UserRole::RoomAdmin,
                                vec![UserRole::NoRole, UserRole::Banned, UserRole::Member],
                            )
                            .with_minimum_participants_constraint(1)
                    }
                    RoomKind::SelfRoom => r
                        .with_capabilities([
                            StdCapability::CanAddOwnClient,
                            StdCapability::CanRemoveOwnClient,
                            StdCapability::CanSendMessage,
                            StdCapability::CanReceiveMessage,
                            StdCapability::CanUploadAttachment,
                            StdCapability::CanDownloadAttachment,
                            StdCapability::CanSendMlsReinitProposal,
                            StdCapability::CanSendMlsPSKProposal,
                        ])
                        .with_authorized_role_change(UserRole::NoRole, vec![UserRole::RoomAdmin])
                        .with_authorized_role_change(UserRole::RoomAdmin, vec![UserRole::NoRole]),
                })
            }
            UserRole::PolicyEnforcer => {
                r = r
                    .with_capabilities([
                        StdCapability::CanBan,
                        StdCapability::CanUnBan,
                        StdCapability::CanKick,
                        StdCapability::CanDestroyRoom,
                        StdCapability::CanChangeRoleDefinitions,
                        StdCapability::CanChangePreauthorizedUserList,
                        StdCapability::CanChangeOtherPolicyAttribute,
                        StdCapability::CanChangeMlsOperationalPolicies,
                        StdCapability::CanSendMlsReinitProposal,
                        StdCapability::CanSendMlsExternalProposal,
                    ])
                    .with_minimum_participants_constraint(1)
                    .with_maximum_participants_constraint(1)
                    .with_maximum_active_participants_constraint(0)
                    .with_authorized_role_change(UserRole::NoRole, vec![UserRole::Banned]);
                Some(match kind {
                    RoomKind::BasicHostedRoom { .. } | RoomKind::BasicRoomWithWaiting { .. } | RoomKind::Dm { .. } => r
                        .with_capabilities([
                            StdCapability::CanRemoveParticipant,
                            StdCapability::CanChangeUserRole,
                            StdCapability::CanChangeRoomMembershipStyle,
                        ])
                        .with_authorized_role_change(UserRole::Banned, vec![UserRole::NoRole])
                        .with_authorized_role_change(UserRole::Member, vec![UserRole::NoRole, UserRole::Banned])
                        .with_authorized_role_change(
                            UserRole::RoomAdmin,
                            vec![UserRole::NoRole, UserRole::Banned, UserRole::Member],
                        )
                        .with_authorized_role_change(
                            UserRole::PolicyEnforcer,
                            vec![
                                UserRole::NoRole,
                                UserRole::Banned,
                                UserRole::Member,
                                UserRole::RoomAdmin,
                            ],
                        ),
                    RoomKind::SelfRoom => r
                        .with_authorized_role_change(UserRole::Banned, vec![UserRole::NoRole, UserRole::RoomAdmin])
                        .with_authorized_role_change(UserRole::RoomAdmin, vec![UserRole::NoRole, UserRole::Banned]),
                })
            }
            UserRole::Unknown => None,
        }
    }
}

#[repr(u16)]
#[derive(strum::EnumIter, strum::FromRepr)]
#[fwd_comp::fwd]
pub enum PrivateCapability {
    CanUpdateSpaceMetadata = 0x8001,
}

impl Capability for PrivateCapability {
    fn as_capability_type(&self) -> CapabilityType {
        **self
    }

    fn from_capability_type(ct: CapabilityType) -> Option<Self> {
        Self::from_repr(ct)
    }
}

#[derive(Clone)]
#[cfg_attr(test, derive(strum::EnumIter))]
pub enum RoomKind {
    BasicHostedRoom {
        is_open: bool,
        other_users: Vec<UserId>,
    },
    BasicRoomWithWaiting {
        other_users: Vec<UserId>,
    },
    Dm {
        other_users: Vec<UserId>,
    },
    /// The hidden room of a user
    SelfRoom,
}

impl std::fmt::Debug for RoomKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BasicHostedRoom { is_open, .. } => {
                let room_privacy = match *is_open {
                    true => "Open",
                    false => "Private",
                };
                write!(f, "{room_privacy} room")
            }
            Self::BasicRoomWithWaiting { .. } => write!(f, "Waiting room"),
            Self::Dm { other_users } => write!(f, "DM with {other_users:?}"),
            Self::SelfRoom => write!(f, "Self room"),
        }
    }
}
