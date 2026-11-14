// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use partial_struct::partial;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use v_api_permission_derive::v_api;
use v_model::permissions::{AsScope, Permission, PermissionStorage};

pub trait VAppPermission: Permission + From<VPermission> + AsScope + PermissionStorage {}
impl<T> VAppPermission for T where T: Permission + From<VPermission> + AsScope + PermissionStorage {}

pub trait VAppPermissionResponse: Permission {}
impl<T> VAppPermissionResponse for T where T: Permission {}

// TODO: Split permissions into expanded and contracted permission sets. Contracted permissions
// are stored in the database as such

#[v_api(From(VPermission))]
#[partial(VPermissionResponse, attributes(#[serde(tag = "kind", content = "value")]))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum VPermission {}

#[cfg(test)]
mod tests {
    use newtype_uuid::TypedUuid;
    use std::collections::{BTreeSet, HashSet};
    use v_model::permissions::{PermissionStorage, Permissions};

    use super::VPermission;

    /// Only permissions whose own field carries a set of values are split. Permissions that are
    /// relative to their holder stay whole.
    #[test]
    fn only_value_sets_are_expanded() {
        let (a, b) = (TypedUuid::new_v4(), TypedUuid::new_v4());

        let expanded = VPermission::ManageGroups(BTreeSet::from([a, b]))
            .expand_value()
            .unwrap();
        assert_eq!(2, expanded.len());
        assert!(expanded.contains(&VPermission::ManageGroup(a)));
        assert!(expanded.contains(&VPermission::ManageGroup(b)));

        for relative in [
            VPermission::GetApiUserSelf,
            VPermission::ManageApiUsersAssigned,
            VPermission::GetGroupsJoined,
            VPermission::ManageGroupsAll,
            VPermission::ManageGroup(a),
        ] {
            assert_eq!(None, relative.expand_value(), "{relative:?} was expanded");
        }
    }

    /// A set is granted value by value, so it can be assembled from separate holdings but not
    /// from holdings that miss any value
    #[test]
    fn value_sets_are_granted_per_value() {
        let (a, b, c) = (
            TypedUuid::new_v4(),
            TypedUuid::new_v4(),
            TypedUuid::new_v4(),
        );
        let held: Permissions<VPermission> = vec![
            VPermission::ManageGroup(a),
            VPermission::ManageGroups(BTreeSet::from([b])),
        ]
        .into();

        assert!(held.can_grant(&VPermission::ManageGroups(BTreeSet::from([a, b]))));
        assert!(!held.can_grant(&VPermission::ManageGroups(BTreeSet::from([a, c]))));

        let all: Permissions<VPermission> = vec![VPermission::ManageGroupsAll].into();
        assert!(all.can_grant(&VPermission::ManageGroups(BTreeSet::from([a, c]))));
    }

    /// Removing one value from a stored set keeps the other values of that set
    #[test]
    fn removing_a_value_keeps_the_rest_of_its_set() {
        let (a, b) = (TypedUuid::new_v4(), TypedUuid::new_v4());
        let stored: Permissions<VPermission> = vec![
            VPermission::ManageGroups(BTreeSet::from([a, b])),
            VPermission::CreateGroup,
        ]
        .into();

        let remaining = VPermission::contract(&stored.without(&VPermission::ManageGroup(a)));

        assert!(remaining.can(&VPermission::ManageGroup(b)));
        assert!(!remaining.can(&VPermission::ManageGroup(a)));
        assert!(remaining.can(&VPermission::CreateGroup));
    }

    /// Permissions relative to their holder are stored and removed as written, never turned into
    /// the specific values they would resolve to
    #[test]
    fn relative_permissions_are_kept_as_written() {
        let stored: Permissions<VPermission> =
            vec![VPermission::GetApiUserSelf, VPermission::GetGroupsJoined].into();

        let remaining = VPermission::contract(&stored.without(&VPermission::CreateGroup));
        assert!(remaining.iter().any(|p| p == &VPermission::GetApiUserSelf));
        assert!(remaining.iter().any(|p| p == &VPermission::GetGroupsJoined));

        let remaining = VPermission::contract(&stored.without(&VPermission::GetApiUserSelf));
        assert!(!remaining.iter().any(|p| p == &VPermission::GetApiUserSelf));
        assert!(remaining.iter().any(|p| p == &VPermission::GetGroupsJoined));
    }

    /// Without an actor the permissions that need one resolve to nothing, while value sets and
    /// aliases of the given permissions still resolve
    #[test]
    fn expanding_without_an_actor() {
        let client = TypedUuid::new_v4();
        let group = TypedUuid::new_v4();
        let held: Permissions<VPermission> = vec![
            VPermission::GetApiUserSelf,
            VPermission::GetGroupsJoined,
            VPermission::ManageGroups(BTreeSet::from([group])),
            VPermission::GetOAuthClientsAssigned,
            VPermission::GetOAuthClient(client),
        ]
        .into();

        let expanded = VPermission::expand(&held, None, Some(&held), &Default::default());

        assert_eq!(
            HashSet::from([
                VPermission::ManageGroup(group),
                VPermission::GetOAuthClient(client),
            ]),
            expanded.into_iter().collect::<HashSet<_>>()
        );
    }

    /// A permission over one specific group is stored as it was granted. It is never widened
    /// into the permission over every group the holder has joined.
    #[test]
    fn a_single_group_grant_is_kept_as_written() {
        let group = TypedUuid::new_v4();
        let stored = VPermission::contract(&vec![VPermission::GetGroup(group)].into());

        assert!(stored.can(&VPermission::GetGroup(group)));
        assert!(!stored.iter().any(|p| p == &VPermission::GetGroupsJoined));
    }
}
