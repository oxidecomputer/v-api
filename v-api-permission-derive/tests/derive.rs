use std::collections::BTreeSet;
use uuid::Uuid;
use v_api::permissions::VPermission;
use v_api_permission_derive::v_api;

#[test]
fn test_derive() {
    // let x = VPermission::CreateApiUser;
    // match x {
    // }
    #[v_api(From(VPermission))]
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        Hash,
        serde::Serialize,
        serde::Deserialize,
        schemars::JsonSchema,
        PartialOrd,
        Ord,
    )]
    enum AppPermissions {
        #[v_api(contract(kind = append, variant = CreateItems))]
        CreateItem(Uuid),
        #[v_api(contract(kind = extend, variant = CreateItems), expand(kind = iter, variant = CreateItem))]
        CreateItems(BTreeSet<Uuid>),
        #[v_api(scope(to = "write", from = "write"))]
        CreateItemsAssigned,
        #[v_api(contract(kind = append, variant = ReadItems))]
        ReadItem(Uuid),
        #[v_api(expand(kind = iter, variant = ReadItem))]
        ReadItems(BTreeSet<Uuid>),
        #[v_api(expand(kind = alias, variant = ReadItem, source = actor), scope(to = "read", from = "read"))]
        ReadItemsAssigned,
    }
}
