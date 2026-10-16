// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use chrono::{DateTime, Utc};
use serde::Serialize;

/// The envelope that Vanta's resource endpoints take. `resources` is the complete set of
/// resources this integration owns, not a delta.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SyncRequest<R> {
    pub resource_id: String,
    pub resources: Vec<R>,
}

/// Whether Vanta should treat an account as live.
///
/// v-api deletes users by setting `deleted_at`, and deprovisioned accounts are reported as
/// deactivated rather than dropped from the sync. Dropping them would tell Vanta the account
/// never existed, which discards the evidence that access was removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AccountStatus {
    Active,
    Deactivated,
}

/// A user, as Vanta's built in `user_account` resource.
///
/// Two fields Vanta offers are left off deliberately:
///
/// - `mfaEnabled` and `mfaMethods`, because v-api federates every login to an upstream provider
///   or a magic link and so never observes whether a second factor was used. The provider's own
///   Vanta integration is the accurate source for that.
/// - `permissionLevel`, because it is a single string and v-api permissions are an application
///   defined set. A consuming service will need to supply the mapping if it wants this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserAccount {
    /// The v-api user id, which is stable and never reused
    pub unique_id: String,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub status: AccountStatus,
    /// The login providers linked to the user, comma separated. A user may have more than one
    /// linked, and all of them are a way in, so all of them are reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_url: Option<String>,
    pub created_timestamp: DateTime<Utc>,
    pub updated_timestamp: DateTime<Utc>,
}

/// A resource whose shape is defined by a schema authored in the Vanta dashboard. The base fields
/// are fixed by Vanta and the schema only describes `customProperties`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomResource<P> {
    pub unique_id: String,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_url: Option<String>,
    pub custom_properties: P,
}

/// The custom properties of an access group.
///
/// The matching JSON Type Definition schema to create in the dashboard:
///
/// ```json
/// {
///   "properties": {
///     "name": { "type": "string" },
///     "source": { "type": "string" },
///     "active": { "type": "boolean" },
///     "memberCount": { "type": "int32" },
///     "memberUniqueIds": { "elements": { "type": "string" } },
///     "createdAt": { "type": "timestamp" }
///   }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupProperties {
    pub name: String,
    /// `dynamic` for a group in the database, `preset` for one fixed by service configuration
    pub source: String,
    pub active: bool,
    /// Reported alongside the ids so that a custom test can assert on the size of a group without
    /// having to reason about a list
    pub member_count: i32,
    /// The `uniqueId` of each member, matching the user accounts synced from the same service
    pub member_unique_ids: Vec<String>,
    pub created_at: DateTime<Utc>,
}

/// The custom properties of an API key.
///
/// API keys are non human access to the same permissions a user holds, which is what makes them
/// worth reviewing. The key material is never reported, only the fact of the key.
///
/// The matching JSON Type Definition schema to create in the dashboard:
///
/// ```json
/// {
///   "properties": {
///     "userUniqueId": { "type": "string" },
///     "active": { "type": "boolean" },
///     "hasPermissionBoundary": { "type": "boolean" },
///     "expiresAt": { "type": "timestamp" },
///     "createdAt": { "type": "timestamp" }
///   },
///   "optionalProperties": {
///     "userEmail": { "type": "string" }
///   }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyProperties {
    /// The `uniqueId` of the user the key acts as
    pub user_unique_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_email: Option<String>,
    /// Neither expired nor revoked
    pub active: bool,
    /// Whether the key is restricted to a subset of the user's permissions. A key without a
    /// boundary can do anything its user can.
    pub has_permission_boundary: bool,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}
