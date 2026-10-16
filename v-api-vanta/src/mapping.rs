// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Turns v-model records into the resources Vanta accepts.

use chrono::{DateTime, Utc};
use v_model::{AccessGroup, ApiKey, ApiUserInfo, ApiUserProvider};

use crate::resource::{
    AccountStatus, ApiKeyProperties, CustomResource, GroupProperties, UserAccount,
};

/// Report a user as a `user_account`.
///
/// `public_url` is the service's public address, used to point Vanta at the user's API resource.
pub fn user_account<T>(info: &ApiUserInfo<T>, public_url: &str) -> UserAccount {
    let unique_id = info.user.id.to_string();
    let provider_name = provider_display_name(&info.providers);
    let email = info
        .contact_email()
        .map(str::to_string)
        .or_else(|| provider_email(&info.providers));

    UserAccount {
        // Vanta requires a display name, so fall back through everything that could stand in for
        // one before resorting to the id.
        display_name: provider_name
            .clone()
            .or_else(|| email.clone())
            .unwrap_or_else(|| unique_id.clone()),
        full_name: provider_name,
        email,
        status: if info.user.deleted_at.is_some() {
            AccountStatus::Deactivated
        } else {
            AccountStatus::Active
        },
        auth_method: auth_method(&info.providers),
        external_url: Some(format!(
            "{}/api-user/{unique_id}",
            public_url.trim_end_matches('/')
        )),
        created_timestamp: info.user.created_at,
        updated_timestamp: info.user.updated_at,
        unique_id,
    }
}

/// Report an access group and its membership as a custom resource.
pub fn group_resource<T>(
    group: &AccessGroup<T>,
    member_unique_ids: Vec<String>,
) -> CustomResource<GroupProperties> {
    CustomResource {
        unique_id: group.id.to_string(),
        display_name: group.name.clone(),
        external_url: None,
        custom_properties: GroupProperties {
            name: group.name.clone(),
            source: group.source.to_string(),
            active: group.deleted_at.is_none(),
            member_count: member_unique_ids.len().try_into().unwrap_or(i32::MAX),
            member_unique_ids,
            created_at: group.created_at,
        },
    }
}

/// Report an API key as a custom resource. `now` decides whether the key has expired.
pub fn api_key_resource<T>(
    key: &ApiKey<T>,
    owner_email: Option<&str>,
    now: DateTime<Utc>,
) -> CustomResource<ApiKeyProperties> {
    let unique_id = key.id.to_string();

    CustomResource {
        // Named for the owner rather than the key, since that is what a reviewer is deciding
        // about. The key signature is never reported.
        display_name: match owner_email {
            Some(email) => format!("API key for {email}"),
            None => format!("API key {unique_id}"),
        },
        external_url: None,
        custom_properties: ApiKeyProperties {
            user_unique_id: key.user_id.to_string(),
            user_email: owner_email.map(str::to_string),
            active: key.deleted_at.is_none() && key.expires_at > now,
            has_permission_boundary: key.permission_boundary.is_some(),
            expires_at: key.expires_at,
            created_at: key.created_at,
        },
        unique_id,
    }
}

/// The first display name any linked provider reports for the user
fn provider_display_name(providers: &[ApiUserProvider]) -> Option<String> {
    providers
        .iter()
        .flat_map(|provider| provider.display_names.iter())
        .find(|name| !name.trim().is_empty())
        .cloned()
}

/// The first email any linked provider reports, used only when the user has not set a contact
/// email of their own
fn provider_email(providers: &[ApiUserProvider]) -> Option<String> {
    providers
        .iter()
        .flat_map(|provider| provider.emails.iter())
        .find(|email| !email.trim().is_empty())
        .cloned()
}

/// Every provider the user can log in through, deduplicated and ordered so that the value does
/// not churn between syncs. All of them are reported because all of them are a way in.
fn auth_method(providers: &[ApiUserProvider]) -> Option<String> {
    let mut names = providers
        .iter()
        .map(|provider| provider.provider.as_str())
        .filter(|name| !name.trim().is_empty())
        .collect::<Vec<_>>();
    names.sort_unstable();
    names.dedup();

    if names.is_empty() {
        None
    } else {
        Some(names.join(","))
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeDelta, Utc};
    use newtype_uuid::TypedUuid;
    use v_model::{
        AccessGroup, AccessGroupSource, ApiKey, ApiUser, ApiUserContactEmail, ApiUserInfo,
        ApiUserProvider, permissions::Permissions,
    };

    use super::{api_key_resource, group_resource, user_account};
    use crate::resource::AccountStatus;

    /// The mapping does not read permissions, so the permission type is irrelevant here
    type Info = ApiUserInfo<()>;

    fn user() -> ApiUser<()> {
        let now = Utc::now();
        ApiUser {
            id: TypedUuid::new_v4(),
            permissions: Permissions::default(),
            groups: Default::default(),
            created_at: now,
            updated_at: now,
            deleted_at: None,
        }
    }

    fn provider(name: &str, emails: &[&str], display_names: &[&str]) -> ApiUserProvider {
        let now = Utc::now();
        ApiUserProvider {
            id: TypedUuid::new_v4(),
            user_id: TypedUuid::new_v4(),
            provider: name.to_string(),
            provider_id: "remote-id".to_string(),
            emails: emails.iter().map(|e| e.to_string()).collect(),
            display_names: display_names.iter().map(|n| n.to_string()).collect(),
            created_at: now,
            updated_at: now,
            deleted_at: None,
        }
    }

    fn contact_email(email: &str) -> ApiUserContactEmail {
        let now = Utc::now();
        ApiUserContactEmail {
            id: TypedUuid::new_v4(),
            user_id: TypedUuid::new_v4(),
            email: email.to_string(),
            created_at: now,
            updated_at: now,
            deleted_at: None,
        }
    }

    #[test]
    fn contact_email_is_preferred_over_a_provider_email() {
        let info = Info {
            user: user(),
            email: Some(contact_email("contact@example.com")),
            providers: vec![provider("google", &["provider@example.com"], &["Ada"])],
        };

        let account = user_account(&info, "https://api.example.com");

        assert_eq!(Some("contact@example.com".to_string()), account.email);
    }

    #[test]
    fn a_provider_email_stands_in_when_no_contact_email_is_set() {
        let info = Info {
            user: user(),
            email: None,
            providers: vec![provider("google", &["provider@example.com"], &[])],
        };

        let account = user_account(&info, "https://api.example.com");

        assert_eq!(Some("provider@example.com".to_string()), account.email);
    }

    /// Vanta requires a display name, so one is always produced
    #[test]
    fn display_name_falls_back_through_email_to_the_user_id() {
        let info = Info {
            user: user(),
            email: None,
            providers: vec![provider("google", &[], &["  "])],
        };

        let account = user_account(&info, "https://api.example.com");

        assert_eq!(info.user.id.to_string(), account.display_name);
        assert_eq!(None, account.full_name);

        let named = Info {
            providers: vec![provider("google", &[], &["Ada Lovelace"])],
            ..info
        };
        let account = user_account(&named, "https://api.example.com");

        assert_eq!("Ada Lovelace", account.display_name);
        assert_eq!(Some("Ada Lovelace".to_string()), account.full_name);
    }

    /// A deleted user is reported as deactivated rather than dropped, so that Vanta keeps the
    /// record of the account having been deprovisioned
    #[test]
    fn a_deleted_user_is_reported_as_deactivated() {
        let mut info = Info {
            user: user(),
            email: None,
            providers: vec![],
        };
        assert_eq!(AccountStatus::Active, user_account(&info, "").status);

        info.user.deleted_at = Some(Utc::now());

        assert_eq!(AccountStatus::Deactivated, user_account(&info, "").status);
    }

    /// Every linked provider is a way into the account, so every one is reported
    #[test]
    fn all_login_providers_are_reported_in_a_stable_order() {
        let info = Info {
            user: user(),
            email: None,
            providers: vec![
                provider("google", &[], &[]),
                provider("github", &[], &[]),
                provider("google", &[], &[]),
            ],
        };

        let account = user_account(&info, "https://api.example.com");

        assert_eq!(Some("github,google".to_string()), account.auth_method);
    }

    #[test]
    fn a_user_with_no_provider_reports_no_auth_method() {
        let info = Info {
            user: user(),
            email: None,
            providers: vec![],
        };

        assert_eq!(
            None,
            user_account(&info, "https://api.example.com").auth_method
        );
    }

    #[test]
    fn the_external_url_points_at_the_user_resource() {
        let info = Info {
            user: user(),
            email: None,
            providers: vec![],
        };

        // The trailing slash of the configured public url is not doubled up
        let account = user_account(&info, "https://api.example.com/");

        assert_eq!(
            Some(format!("https://api.example.com/api-user/{}", info.user.id)),
            account.external_url
        );
    }

    #[test]
    fn a_group_reports_its_membership() {
        let now = Utc::now();
        let group = AccessGroup::<()> {
            id: TypedUuid::new_v4(),
            name: "engineering".to_string(),
            permissions: Permissions::default(),
            source: AccessGroupSource::Dynamic,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };

        let members = vec!["user-a".to_string(), "user-b".to_string()];
        let resource = group_resource(&group, members.clone());

        assert_eq!(group.id.to_string(), resource.unique_id);
        assert_eq!("engineering", resource.display_name);
        assert_eq!("dynamic", resource.custom_properties.source);
        assert!(resource.custom_properties.active);
        assert_eq!(2, resource.custom_properties.member_count);
        assert_eq!(members, resource.custom_properties.member_unique_ids);
    }

    #[test]
    fn a_preset_group_reports_its_source() {
        let now = Utc::now();
        let group = AccessGroup::<()> {
            id: TypedUuid::new_v4(),
            name: "admins".to_string(),
            permissions: Permissions::default(),
            source: AccessGroupSource::Preset,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };

        assert_eq!(
            "preset",
            group_resource(&group, vec![]).custom_properties.source
        );
    }

    fn api_key(expires_in: TimeDelta) -> ApiKey<()> {
        let now = Utc::now();
        ApiKey {
            id: TypedUuid::new_v4(),
            user_id: TypedUuid::new_v4(),
            key_signature: "signature".to_string(),
            permission_boundary: None,
            expires_at: now + expires_in,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        }
    }

    #[test]
    fn an_api_key_is_linked_to_its_owner() {
        let key = api_key(TimeDelta::days(30));
        let resource = api_key_resource(&key, Some("ada@example.com"), Utc::now());

        assert_eq!(key.id.to_string(), resource.unique_id);
        assert_eq!("API key for ada@example.com", resource.display_name);
        assert_eq!(
            key.user_id.to_string(),
            resource.custom_properties.user_unique_id
        );
        assert!(resource.custom_properties.active);
        // An unbounded key can do anything its user can, which is the point of reporting it
        assert!(!resource.custom_properties.has_permission_boundary);
    }

    /// The key signature is a credential detail and has no place in a compliance report
    #[test]
    fn an_api_key_never_reports_its_signature() {
        let key = api_key(TimeDelta::days(30));
        let resource = api_key_resource(&key, None, Utc::now());
        let json = serde_json::to_string(&resource).expect("serialize");

        assert!(
            !json.contains(&key.key_signature),
            "the key signature was reported: {json}"
        );
    }

    #[test]
    fn expired_and_revoked_keys_are_inactive() {
        let now = Utc::now();

        let expired = api_key(TimeDelta::days(-1));
        assert!(
            !api_key_resource(&expired, None, now)
                .custom_properties
                .active
        );

        let mut revoked = api_key(TimeDelta::days(30));
        revoked.deleted_at = Some(now);
        assert!(
            !api_key_resource(&revoked, None, now)
                .custom_properties
                .active
        );
    }
}
