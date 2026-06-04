use crate::RoomKind;

/// Returns true for hosted room kinds (excluding DMs and self rooms).
pub(crate) fn is_basic_hosted(kind: &RoomKind) -> bool {
    matches!(
        kind,
        RoomKind::BasicHostedRoom { .. } | RoomKind::BasicRoomWithWaiting { .. }
    )
}

pub(crate) fn is_waiting_room(kind: &RoomKind) -> bool {
    matches!(kind, RoomKind::BasicRoomWithWaiting { .. })
}

/// Members may add participants in standard hosted rooms, but not in waiting rooms or DMs.
pub(crate) fn member_can_add_participant(kind: &RoomKind) -> bool {
    matches!(kind, RoomKind::BasicHostedRoom { .. })
}

/// NoRole users get knock/join-code capabilities in hosted rooms and DMs, but not waiting rooms.
pub(crate) fn no_role_has_lobby_access(kind: &RoomKind) -> bool {
    matches!(kind, RoomKind::BasicHostedRoom { .. } | RoomKind::Dm { .. })
}

/// RoomAdmin may swap role definitions when toggling waiting room mode.
pub(crate) fn admin_can_change_role_definitions(kind: &RoomKind) -> bool {
    matches!(
        kind,
        RoomKind::BasicRoomWithWaiting { .. }
            | RoomKind::BasicHostedRoom {
                is_open: true,
                ..
            }
    )
}

/// RoomAdmin gets knock acceptance in hosted rooms except waiting rooms.
pub(crate) fn admin_can_accept_knock(kind: &RoomKind) -> bool {
    is_basic_hosted(kind) && !is_waiting_room(kind)
}
