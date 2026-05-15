// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use newtype_uuid::TypedUuid;
use std::collections::BTreeSet;
use uuid::Uuid;
use v_api::permissions::VPermission;
use v_api_permission_derive::v_api;
use v_model::UserId;
use v_model::permissions::PermissionStorage;

struct ItemWrapper {
    id: Uuid,
}

#[v_api(From(VPermission))]
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
enum AppPermissions {
    #[v_api(contract(kind = append, variant = CreateItems))]
    CreateItem(Uuid),
    #[v_api(contract(kind = extend, variant = CreateItems), expand(kind = iter, variant = CreateItem))]
    CreateItems(BTreeSet<Uuid>),
    #[v_api(scope(to = "write", from = "write"))]
    CreateItemsAssigned,
    #[v_api(expand(kind = replace, variant = CreateItem, source = ext, ext = ItemWrapper, field = id))]
    CreateItemsSelf,
    #[v_api(
        implies(variant = CreateItem),
        implies(variant = CreateItems),
        implies(variant = CreateItemsAssigned),
        implies(variant = CreateItemsSelf),
    )]
    CreateItemsAll,
    #[v_api(contract(kind = append, variant = ReadItems))]
    ReadItem(Uuid),
    #[v_api(expand(kind = iter, variant = ReadItem))]
    ReadItems(BTreeSet<Uuid>),
    #[v_api(expand(kind = alias, variant = ReadItem, source = actor), scope(to = "read read2 read3", from = "read read2 read3"))]
    ReadItemsAssigned,
    #[v_api(
        implies(variant = ReadItem),
        implies(variant = ReadItems),
        implies(variant = ReadItemsAssigned),
    )]
    ReadItemsAll,
    #[v_api(contract(kind = replace, variant = Flop))]
    Flip(TypedUuid<UserId>),
    #[v_api(expand(kind = replace, variant = Flip, source = actor, field = id))]
    Flop,
}

#[test]
fn test_derive() {
    let _ = ItemWrapper { id: Uuid::new_v4() };
    let _ = AppPermissions::Flop;
}

#[test]
fn test_implies_identity_unit_variant() {
    assert!(AppPermissions::implies(
        &AppPermissions::CreateItemsAssigned,
        &AppPermissions::CreateItemsAssigned,
    ));
    assert!(AppPermissions::implies(
        &AppPermissions::CreateItemsAll,
        &AppPermissions::CreateItemsAll,
    ));
    assert!(AppPermissions::implies(
        &AppPermissions::ReadItemsAssigned,
        &AppPermissions::ReadItemsAssigned,
    ));
    assert!(AppPermissions::implies(
        &AppPermissions::Flop,
        &AppPermissions::Flop,
    ));
}

#[test]
fn test_implies_identity_data_variant() {
    let id = Uuid::new_v4();
    assert!(AppPermissions::implies(
        &AppPermissions::CreateItem(id),
        &AppPermissions::CreateItem(id),
    ));
    assert!(AppPermissions::implies(
        &AppPermissions::ReadItem(id),
        &AppPermissions::ReadItem(id),
    ));

    let set: BTreeSet<Uuid> = [Uuid::new_v4(), Uuid::new_v4()].into();
    assert!(AppPermissions::implies(
        &AppPermissions::CreateItems(set.clone()),
        &AppPermissions::CreateItems(set),
    ));
}

#[test]
fn test_implies_all_implies_specific() {
    let id = Uuid::new_v4();
    assert!(AppPermissions::implies(
        &AppPermissions::CreateItemsAll,
        &AppPermissions::CreateItem(id),
    ));
    assert!(AppPermissions::implies(
        &AppPermissions::ReadItemsAll,
        &AppPermissions::ReadItem(id),
    ));
}

#[test]
fn test_implies_all_implies_set() {
    let set: BTreeSet<Uuid> = [Uuid::new_v4(), Uuid::new_v4()].into();
    assert!(AppPermissions::implies(
        &AppPermissions::CreateItemsAll,
        &AppPermissions::CreateItems(set.clone()),
    ));
    assert!(AppPermissions::implies(
        &AppPermissions::ReadItemsAll,
        &AppPermissions::ReadItems(set),
    ));
}

#[test]
fn test_implies_all_implies_assigned() {
    assert!(AppPermissions::implies(
        &AppPermissions::CreateItemsAll,
        &AppPermissions::CreateItemsAssigned,
    ));
    assert!(AppPermissions::implies(
        &AppPermissions::ReadItemsAll,
        &AppPermissions::ReadItemsAssigned,
    ));
}

#[test]
fn test_implies_all_implies_self() {
    assert!(AppPermissions::implies(
        &AppPermissions::CreateItemsAll,
        &AppPermissions::CreateItemsSelf,
    ));
}

#[test]
fn test_implies_set_contains_specific() {
    let id_a = Uuid::new_v4();
    let id_b = Uuid::new_v4();
    let set: BTreeSet<Uuid> = [id_a, id_b].into();

    // Contained id — should imply
    assert!(AppPermissions::implies(
        &AppPermissions::CreateItems(set.clone()),
        &AppPermissions::CreateItem(id_a),
    ));
    assert!(AppPermissions::implies(
        &AppPermissions::CreateItems(set.clone()),
        &AppPermissions::CreateItem(id_b),
    ));

    // Id NOT in the set — should NOT imply
    let id_c = Uuid::new_v4();
    assert!(!AppPermissions::implies(
        &AppPermissions::CreateItems(set),
        &AppPermissions::CreateItem(id_c),
    ));
}

#[test]
fn test_implies_set_contains_specific_read() {
    let id = Uuid::new_v4();
    let set: BTreeSet<Uuid> = [id].into();

    assert!(AppPermissions::implies(
        &AppPermissions::ReadItems(set.clone()),
        &AppPermissions::ReadItem(id),
    ));

    let other = Uuid::new_v4();
    assert!(!AppPermissions::implies(
        &AppPermissions::ReadItems(set),
        &AppPermissions::ReadItem(other),
    ));
}

#[test]
fn test_implies_set_subset() {
    let id_a = Uuid::new_v4();
    let id_b = Uuid::new_v4();
    let id_c = Uuid::new_v4();
    let superset: BTreeSet<Uuid> = [id_a, id_b, id_c].into();
    let subset: BTreeSet<Uuid> = [id_a, id_c].into();
    let disjoint: BTreeSet<Uuid> = [Uuid::new_v4()].into();

    // Proper subset — should imply
    assert!(AppPermissions::implies(
        &AppPermissions::CreateItems(superset.clone()),
        &AppPermissions::CreateItems(subset),
    ));

    // Equal sets — handled by identity check
    assert!(AppPermissions::implies(
        &AppPermissions::CreateItems(superset.clone()),
        &AppPermissions::CreateItems(superset.clone()),
    ));

    // Disjoint set — should NOT imply
    assert!(!AppPermissions::implies(
        &AppPermissions::CreateItems(superset.clone()),
        &AppPermissions::CreateItems(disjoint),
    ));

    // Superset target — should NOT imply (you can't grant more than you have)
    let smaller: BTreeSet<Uuid> = [id_a].into();
    assert!(!AppPermissions::implies(
        &AppPermissions::CreateItems(smaller),
        &AppPermissions::CreateItems(superset),
    ));
}

#[test]
fn test_implies_specific_does_not_imply_different_id() {
    let id_a = Uuid::new_v4();
    let id_b = Uuid::new_v4();
    assert!(!AppPermissions::implies(
        &AppPermissions::CreateItem(id_a),
        &AppPermissions::CreateItem(id_b),
    ));
}

#[test]
fn test_implies_specific_does_not_imply_all() {
    let id = Uuid::new_v4();
    // A specific permission must never imply the All variant
    assert!(!AppPermissions::implies(
        &AppPermissions::CreateItem(id),
        &AppPermissions::CreateItemsAll,
    ));
    assert!(!AppPermissions::implies(
        &AppPermissions::ReadItem(id),
        &AppPermissions::ReadItemsAll,
    ));
}

#[test]
fn test_implies_assigned_does_not_imply_all() {
    assert!(!AppPermissions::implies(
        &AppPermissions::CreateItemsAssigned,
        &AppPermissions::CreateItemsAll,
    ));
}

#[test]
fn test_implies_cross_family_never_holds() {
    let id = Uuid::new_v4();
    // CreateItemsAll must NOT imply ReadItem or ReadItemsAll
    assert!(!AppPermissions::implies(
        &AppPermissions::CreateItemsAll,
        &AppPermissions::ReadItem(id),
    ));
    assert!(!AppPermissions::implies(
        &AppPermissions::CreateItemsAll,
        &AppPermissions::ReadItemsAll,
    ));
    // ReadItemsAll must NOT imply CreateItem or CreateItemsAll
    assert!(!AppPermissions::implies(
        &AppPermissions::ReadItemsAll,
        &AppPermissions::CreateItem(id),
    ));
    assert!(!AppPermissions::implies(
        &AppPermissions::ReadItemsAll,
        &AppPermissions::CreateItemsAll,
    ));
}

#[test]
fn test_implies_set_does_not_imply_assigned_or_all() {
    let set: BTreeSet<Uuid> = [Uuid::new_v4()].into();
    assert!(!AppPermissions::implies(
        &AppPermissions::CreateItems(set.clone()),
        &AppPermissions::CreateItemsAssigned,
    ));
    assert!(!AppPermissions::implies(
        &AppPermissions::CreateItems(set),
        &AppPermissions::CreateItemsAll,
    ));
}

#[test]
fn test_implies_system_manage_groups_all() {
    use v_model::AccessGroupId;

    let group_id = TypedUuid::<AccessGroupId>::new_v4();

    // ManageGroupsAll implies ManageGroup(any)
    assert!(VPermission::implies(
        &VPermission::ManageGroupsAll,
        &VPermission::ManageGroup(group_id),
    ));

    // ManageGroupsAll implies ManageGroups(any set)
    let set: BTreeSet<TypedUuid<AccessGroupId>> = [group_id].into();
    assert!(VPermission::implies(
        &VPermission::ManageGroupsAll,
        &VPermission::ManageGroups(set),
    ));

    // ManageGroupsAll implies ManageGroupsAssigned
    assert!(VPermission::implies(
        &VPermission::ManageGroupsAll,
        &VPermission::ManageGroupsAssigned,
    ));

    // But NOT the reverse
    assert!(!VPermission::implies(
        &VPermission::ManageGroupsAssigned,
        &VPermission::ManageGroupsAll,
    ));
    assert!(!VPermission::implies(
        &VPermission::ManageGroup(group_id),
        &VPermission::ManageGroupsAll,
    ));
}

#[test]
fn test_implies_system_manage_group_membership_all() {
    use v_model::AccessGroupId;

    let group_id = TypedUuid::<AccessGroupId>::new_v4();

    assert!(VPermission::implies(
        &VPermission::ManageGroupMembershipsAll,
        &VPermission::ManageGroupMembership(group_id),
    ));
    assert!(VPermission::implies(
        &VPermission::ManageGroupMembershipsAll,
        &VPermission::ManageGroupMembershipsAssigned,
    ));
    assert!(!VPermission::implies(
        &VPermission::ManageGroupMembership(group_id),
        &VPermission::ManageGroupMembershipsAll,
    ));
}

#[test]
fn test_implies_system_create_oauth_client_does_not_imply_manage() {
    use v_model::OAuthClientId;

    let client_id = TypedUuid::<OAuthClientId>::new_v4();

    // CreateOAuthClient must NOT imply Get/Manage on arbitrary clients.
    // Auto-granting after creation uses an internal system caller.
    assert!(!VPermission::implies(
        &VPermission::CreateOAuthClient,
        &VPermission::GetOAuthClient(client_id),
    ));
    assert!(!VPermission::implies(
        &VPermission::CreateOAuthClient,
        &VPermission::ManageOAuthClient(client_id),
    ));
    assert!(!VPermission::implies(
        &VPermission::CreateOAuthClient,
        &VPermission::GetOAuthClientsAll,
    ));
    assert!(!VPermission::implies(
        &VPermission::CreateOAuthClient,
        &VPermission::ManageOAuthClientsAll,
    ));
}

#[test]
fn test_implies_system_create_magic_link_client_does_not_imply_manage() {
    use v_model::MagicLinkId;

    let client_id = TypedUuid::<MagicLinkId>::new_v4();

    assert!(!VPermission::implies(
        &VPermission::CreateMagicLinkClient,
        &VPermission::GetMagicLinkClient(client_id),
    ));
    assert!(!VPermission::implies(
        &VPermission::CreateMagicLinkClient,
        &VPermission::ManageMagicLinkClient(client_id),
    ));
}

#[test]
fn test_implies_system_manage_api_users_all() {
    let user_id = TypedUuid::<UserId>::new_v4();

    assert!(VPermission::implies(
        &VPermission::ManageApiUsersAll,
        &VPermission::ManageApiUser(user_id),
    ));
    assert!(VPermission::implies(
        &VPermission::ManageApiUsersAll,
        &VPermission::ManageApiUsersAssigned,
    ));
    assert!(!VPermission::implies(
        &VPermission::ManageApiUser(user_id),
        &VPermission::ManageApiUsersAll,
    ));
}

#[test]
fn test_implies_system_set_containment() {
    use v_model::AccessGroupId;

    let g1 = TypedUuid::<AccessGroupId>::new_v4();
    let g2 = TypedUuid::<AccessGroupId>::new_v4();
    let g3 = TypedUuid::<AccessGroupId>::new_v4();

    let full: BTreeSet<_> = [g1, g2, g3].into();
    let partial: BTreeSet<_> = [g1, g3].into();

    // ManageGroups(full) implies ManageGroup(g1)
    assert!(VPermission::implies(
        &VPermission::ManageGroups(full.clone()),
        &VPermission::ManageGroup(g1),
    ));

    // ManageGroups(full) implies ManageGroups(partial) — subset
    assert!(VPermission::implies(
        &VPermission::ManageGroups(full.clone()),
        &VPermission::ManageGroups(partial.clone()),
    ));

    // ManageGroups(partial) does NOT imply ManageGroups(full) — superset
    assert!(!VPermission::implies(
        &VPermission::ManageGroups(partial),
        &VPermission::ManageGroups(full),
    ));
}

#[test]
fn test_can_grant_via_all() {
    use v_model::Permissions;

    let caller: Permissions<AppPermissions> = vec![AppPermissions::CreateItemsAll].into();
    let id = Uuid::new_v4();

    assert!(caller.can_grant(&AppPermissions::CreateItem(id)));
    assert!(caller.can_grant(&AppPermissions::CreateItemsAssigned));
    assert!(caller.can_grant(&AppPermissions::CreateItemsSelf));
    assert!(caller.can_grant(&AppPermissions::CreateItemsAll));

    // Cannot grant permissions from a different family
    assert!(!caller.can_grant(&AppPermissions::ReadItem(id)));
    assert!(!caller.can_grant(&AppPermissions::ReadItemsAll));
}

#[test]
fn test_can_grant_via_set() {
    use v_model::Permissions;

    let id_a = Uuid::new_v4();
    let id_b = Uuid::new_v4();
    let id_c = Uuid::new_v4();
    let held_set: BTreeSet<Uuid> = [id_a, id_b].into();

    let caller: Permissions<AppPermissions> = vec![AppPermissions::CreateItems(held_set)].into();

    assert!(caller.can_grant(&AppPermissions::CreateItem(id_a)));
    assert!(caller.can_grant(&AppPermissions::CreateItem(id_b)));
    assert!(!caller.can_grant(&AppPermissions::CreateItem(id_c)));
    assert!(!caller.can_grant(&AppPermissions::CreateItemsAll));
}

#[test]
fn test_can_grant_all_succeeds() {
    use v_model::Permissions;

    let caller: Permissions<AppPermissions> =
        vec![AppPermissions::CreateItemsAll, AppPermissions::ReadItemsAll].into();

    let id = Uuid::new_v4();
    let targets: Permissions<AppPermissions> = vec![
        AppPermissions::CreateItem(id),
        AppPermissions::ReadItem(id),
        AppPermissions::ReadItemsAssigned,
    ]
    .into();

    assert!(caller.can_grant_all(&targets));
}

#[test]
fn test_can_grant_all_fails_when_missing() {
    use v_model::Permissions;

    let caller: Permissions<AppPermissions> = vec![AppPermissions::CreateItemsAll].into();

    let id = Uuid::new_v4();
    let targets: Permissions<AppPermissions> = vec![
        AppPermissions::CreateItem(id),
        AppPermissions::ReadItem(id), // caller cannot grant this
    ]
    .into();

    assert!(!caller.can_grant_all(&targets));
}

#[test]
fn test_can_grant_all_empty_targets() {
    use v_model::Permissions;

    // Granting nothing is always allowed
    let caller: Permissions<AppPermissions> = Permissions::new();
    let targets: Permissions<AppPermissions> = Permissions::new();
    assert!(caller.can_grant_all(&targets));
}
