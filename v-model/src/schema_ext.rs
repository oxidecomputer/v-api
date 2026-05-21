// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use diesel::{
    AsExpression, FromSqlRow,
    backend::Backend,
    deserialize::{self, FromSql},
    pg::Pg,
    query_builder::QueryId,
    serialize::{self, IsNull, Output, ToSql},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    fmt::{Debug, Display},
    io::Write,
};

use crate::schema::sql_types::{AttemptState, MlinkAttemptState};

macro_rules! sql_conversion {
    (
        $sql_t:ident => $model_t:ident,
        $($to_matcher:tt => $to_result:tt),*,
    ) => {
        impl ToSql<$sql_t, Pg> for $model_t {
            fn to_sql(&self, out: &mut Output<Pg>) -> serialize::Result {
                match *self {
                    $($model_t::$to_matcher => out.write_all($to_result)?),*
                };

                Ok(IsNull::No)
            }
        }

        impl FromSql<$sql_t, Pg> for $model_t {
            fn from_sql(bytes: <Pg as Backend>::RawValue<'_>) -> deserialize::Result<Self> {
                match bytes.as_bytes() {
                    $($to_result => Ok($model_t::$to_matcher)),*,
                    x => Err(format!("Unrecognized {} variant {:?}", stringify!($sql_t), x).into()),
                }
            }
        }

        impl QueryId for $sql_t {
            type QueryId = $sql_t;
            const HAS_STATIC_QUERY_ID: bool = true;
        }
    };
}

#[derive(
    Copy,
    Debug,
    PartialEq,
    Clone,
    FromSqlRow,
    AsExpression,
    Serialize,
    Deserialize,
    JsonSchema,
    Default,
)]
#[diesel(sql_type = AttemptState)]
#[serde(rename_all = "lowercase")]
pub enum LoginAttemptState {
    Complete,
    Failed,
    #[default]
    New,
    RemoteAuthenticated,
}

sql_conversion! {
    AttemptState => LoginAttemptState,
    Complete => b"complete",
    Failed => b"failed",
    New => b"new",
    RemoteAuthenticated => b"remote_authenticated",
}

impl Display for LoginAttemptState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoginAttemptState::Complete => write!(f, "complete"),
            LoginAttemptState::Failed => write!(f, "failed"),
            LoginAttemptState::New => write!(f, "new"),
            LoginAttemptState::RemoteAuthenticated => write!(f, "remote_authenticated"),
        }
    }
}

// #[derive(Debug, PartialEq, Clone, FromSqlRow, AsExpression, Serialize, Deserialize, JsonSchema)]
#[derive(Debug, PartialEq, Clone, Copy, Serialize, Deserialize, JsonSchema, Hash, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MagicLinkMedium {
    Email,
}

impl Display for MagicLinkMedium {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MagicLinkMedium::Email => write!(f, "email"),
        }
    }
}

#[derive(Debug, PartialEq, Clone, FromSqlRow, AsExpression, Serialize, Deserialize, JsonSchema)]
#[diesel(sql_type = MlinkAttemptState)]
#[serde(rename_all = "lowercase")]
pub enum MagicLinkAttemptState {
    Complete,
    Failed,
    Sent,
}

sql_conversion! {
    MlinkAttemptState => MagicLinkAttemptState,
    Complete => b"complete",
    Failed => b"failed",
    Sent => b"sent",
}

impl Display for MagicLinkAttemptState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MagicLinkAttemptState::Complete => write!(f, "complete"),
            MagicLinkAttemptState::Failed => write!(f, "failed"),
            MagicLinkAttemptState::Sent => write!(f, "sent"),
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromSqlRow, AsExpression, Serialize, Deserialize, JsonSchema,
)]
#[diesel(sql_type = diesel::sql_types::Varchar)]
#[serde(rename_all = "snake_case")]
pub enum MapperSource {
    /// Created via the API, persisted in the database, supports activation limits
    Dynamic,
    /// Loaded from service configuration, in-memory only, no activation limits
    Preset,
}

impl ToSql<diesel::sql_types::Varchar, Pg> for MapperSource {
    fn to_sql(&self, out: &mut Output<Pg>) -> serialize::Result {
        match *self {
            MapperSource::Dynamic => out.write_all(b"dynamic")?,
            MapperSource::Preset => out.write_all(b"preset")?,
        }
        Ok(IsNull::No)
    }
}

impl FromSql<diesel::sql_types::Varchar, Pg> for MapperSource {
    fn from_sql(bytes: <Pg as Backend>::RawValue<'_>) -> deserialize::Result<Self> {
        match bytes.as_bytes() {
            b"dynamic" => Ok(MapperSource::Dynamic),
            b"preset" => Ok(MapperSource::Preset),
            x => Err(format!("Unrecognized MapperSource variant {:?}", x).into()),
        }
    }
}

impl Display for MapperSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MapperSource::Dynamic => write!(f, "dynamic"),
            MapperSource::Preset => write!(f, "preset"),
        }
    }
}
