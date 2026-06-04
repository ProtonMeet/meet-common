use meet_identifiers::{Domain, UserId};
use meet_policy::{RoomKind, RoomPolicies, UserRole};
use mimi_room_policy::spec::rbac::{Capability, StdCapability};

fn role_has_capability(policy: &RoomPolicies, role: UserRole, capability: StdCapability) -> bool {
    policy
        .roles
        .get_role(&u32::from(role))
        .is_some_and(|r| r.role_capabilities.contains(&capability.as_capability_type()))
}

fn creator() -> UserId {
    UserId::new(&Domain::default())
}

#[test]
fn waiting_room_member_cannot_add_participants() {
    let policy = RoomPolicies::waiting_room(&creator(), &[], true).unwrap();
    assert!(!role_has_capability(&policy, UserRole::Member, StdCapability::CanAddParticipant));
}

#[test]
fn waiting_room_admin_can_add_participants() {
    let policy = RoomPolicies::waiting_room(&creator(), &[], true).unwrap();
    assert!(role_has_capability(&policy, UserRole::RoomAdmin, StdCapability::CanAddParticipant));
}

#[test]
fn waiting_room_no_role_has_no_lobby_access() {
    let policy = RoomPolicies::waiting_room(&creator(), &[], true).unwrap();
    assert!(!role_has_capability(&policy, UserRole::NoRole, StdCapability::CanKnock));
    assert!(!role_has_capability(&policy, UserRole::NoRole, StdCapability::CanUseJoinCode));
    assert!(!role_has_capability(&policy, UserRole::NoRole, StdCapability::CanOpenJoin));
    assert!(!role_has_capability(
        &policy,
        UserRole::NoRole,
        StdCapability::CanSendMlsExternalCommit
    ));
}

#[test]
fn waiting_room_admin_cannot_accept_knocks() {
    let policy = RoomPolicies::waiting_room(&creator(), &[], true).unwrap();
    assert!(!role_has_capability(&policy, UserRole::RoomAdmin, StdCapability::CanAcceptKnock));
}

#[test]
fn waiting_room_admin_can_change_role_definitions() {
    let policy = RoomPolicies::waiting_room(&creator(), &[], true).unwrap();
    assert!(role_has_capability(
        &policy,
        UserRole::RoomAdmin,
        StdCapability::CanChangeRoleDefinitions
    ));
}

#[test]
fn waiting_room_policy_enforcer_cannot_add_participants() {
    let policy = RoomPolicies::waiting_room(&creator(), &[], true).unwrap();
    assert!(!role_has_capability(
        &policy,
        UserRole::PolicyEnforcer,
        StdCapability::CanAddParticipant
    ));
}

#[test]
fn waiting_room_preauth_targets_admin_only_with_non_empty_claimset() {
    let policy = RoomPolicies::waiting_room(&creator(), &[], true).unwrap();
    let role_indices = policy
        .pre_auth
        .preauthorized_entries
        .iter()
        .map(|entry| entry.target_role.role_index)
        .collect::<Vec<_>>();

    assert!(role_indices.contains(&u32::from(UserRole::PolicyEnforcer)));
    assert_eq!(
        role_indices
            .iter()
            .filter(|&&role_index| role_index == u32::from(UserRole::RoomAdmin))
            .count(),
        2
    );
    assert!(!role_indices.contains(&u32::from(UserRole::Member)));
    assert!(policy
        .pre_auth
        .preauthorized_entries
        .iter()
        .all(|entry| !entry.claimset.is_empty()));
}

#[test]
fn open_lobby_matches_open_hosted_room() {
    let creator = creator();
    let other_users = vec![UserId::new(&Domain::default())];
    let open_lobby = RoomPolicies::open_lobby(&creator, &other_users, true).unwrap();
    let open_hosted = RoomPolicies::new(
        &creator,
        &RoomKind::BasicHostedRoom {
            is_open: true,
            other_users: other_users.clone(),
        },
        true,
    )
    .unwrap();
    assert_eq!(open_lobby.roles, open_hosted.roles);
    assert_eq!(open_lobby.participant_list, open_hosted.participant_list);
    assert_eq!(open_lobby.pre_auth, open_hosted.pre_auth);
}

#[test]
fn open_lobby_member_can_add_participants() {
    let policy = RoomPolicies::open_lobby(&creator(), &[], true).unwrap();
    assert!(role_has_capability(&policy, UserRole::Member, StdCapability::CanAddParticipant));
}

#[test]
fn open_lobby_no_role_has_lobby_access() {
    let policy = RoomPolicies::open_lobby(&creator(), &[], true).unwrap();
    assert!(role_has_capability(&policy, UserRole::NoRole, StdCapability::CanKnock));
    assert!(role_has_capability(&policy, UserRole::NoRole, StdCapability::CanUseJoinCode));
}

#[test]
fn open_lobby_admin_can_change_role_definitions() {
    let policy = RoomPolicies::open_lobby(&creator(), &[], true).unwrap();
    assert!(role_has_capability(
        &policy,
        UserRole::RoomAdmin,
        StdCapability::CanChangeRoleDefinitions
    ));
}

#[test]
fn private_hosted_admin_cannot_change_role_definitions() {
    let policy = RoomPolicies::new(
        &creator(),
        &RoomKind::BasicHostedRoom {
            is_open: false,
            other_users: vec![],
        },
        true,
    )
    .unwrap();
    assert!(!role_has_capability(
        &policy,
        UserRole::RoomAdmin,
        StdCapability::CanChangeRoleDefinitions
    ));
}
