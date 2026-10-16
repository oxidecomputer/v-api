// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Pushes the access control inventory of a v-api service into Vanta as a private integration.
//!
//! Each consuming service registers its own private integration, so one instance of this client
//! owns one Vanta account's view of one service. Vanta's resource API is a full-state push: every
//! `PUT` carries the complete set of resources the integration owns, and any `uniqueId` that was
//! previously synced but is absent from the new request is marked as no longer existing. There is
//! no incremental mode, so a sync always sends everything.
//!
//! Three things are reported:
//!
//! - Users, as Vanta's built in `user_account` resource.
//! - Access groups and their membership, as a custom resource.
//! - API keys, as a custom resource, since they are non human access to the same permissions.
//!
//! Custom resources have to be created in the Vanta dashboard before they can be pushed to, which
//! is also where their schema and their tests are authored. The schema each of these expects is
//! documented on [`GroupProperties`] and [`ApiKeyProperties`]. A service that has not created them
//! yet can leave their ids unset and sync only users.
//!
//! Permission data is deliberately not reported. Vanta models a single `permissionLevel` string
//! per account, while v-api permissions are an application defined set, so there is nothing this
//! crate can map without knowing what a level means for the consuming service.

mod client;
mod config;
mod error;
mod mapping;
mod resource;

pub use client::VantaClient;
pub use config::VantaConfig;
pub use error::VantaError;
pub use mapping::{api_key_resource, group_resource, user_account};
pub use resource::{AccountStatus, ApiKeyProperties, CustomResource, GroupProperties, UserAccount};
