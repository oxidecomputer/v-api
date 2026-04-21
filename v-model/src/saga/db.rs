// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use chrono::{DateTime, Utc};
use diesel::backend::Backend;
use diesel::deserialize::{self, FromSql};
use diesel::pg::Pg;
use diesel::prelude::Queryable;
use diesel::serialize::{self, IsNull, Output, ToSql};
use diesel::sql_types::Text;
use diesel::{AsExpression, FromSqlRow};
use partial_struct::partial;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::Write;
use uuid::Uuid;

#[derive(Debug, Copy, Clone, Deserialize, Serialize, FromSqlRow, AsExpression)]
#[diesel(sql_type = Text)]
pub enum ModelSagaCachedState {
    Done,
    Running,
    Unwinding,
}

impl ToSql<Text, Pg> for ModelSagaCachedState {
    fn to_sql(&self, out: &mut Output<Pg>) -> serialize::Result {
        match *self {
            ModelSagaCachedState::Done => out.write_all(b"done")?,
            ModelSagaCachedState::Running => out.write_all(b"running")?,
            ModelSagaCachedState::Unwinding => out.write_all(b"unwinding")?,
        };
        Ok(IsNull::No)
    }
}

impl FromSql<Text, Pg> for ModelSagaCachedState {
    fn from_sql(bytes: <Pg as Backend>::RawValue<'_>) -> deserialize::Result<Self> {
        match bytes.as_bytes() {
            b"done" => Ok(ModelSagaCachedState::Done),
            b"running" => Ok(ModelSagaCachedState::Running),
            b"unwinding" => Ok(ModelSagaCachedState::Unwinding),
            x => Err(format!("Unrecognized ModelSagaCachedState variant: {:?}", x).into()),
        }
    }
}

/// Model for a saga stored in the database.
#[partial(NewSagaModel)]
#[derive(Debug, Deserialize, Serialize, Queryable)]
pub struct SagaModel {
    /// Unique identifier for this saga
    pub saga_id: Uuid,
    /// Human-readable name of the saga type (e.g., "batch-processing")
    pub name: String,
    /// The saga DAG definition as JSON
    pub dag: Value,
    /// Current cached state of the saga
    pub state: ModelSagaCachedState,
    /// ID of the node currently processing this saga (None if unclaimed)
    pub current_node_id: Option<Uuid>,
    /// When the current node claimed this saga
    pub node_claimed_at: Option<DateTime<Utc>>,
    #[partial(NewSagaModel(skip))]
    pub created_at: DateTime<Utc>,
    #[partial(NewSagaModel(skip))]
    pub updated_at: DateTime<Utc>,
}

/// Model for a saga event stored in the database.
#[partial(NewSagaEventModel)]
#[derive(Debug, Deserialize, Serialize, Queryable)]
pub struct SagaEventModel {
    #[partial(NewSagaEventModel(skip))]
    pub id: i64,
    /// The saga this event belongs to
    pub saga_id: Uuid,
    /// The node within the saga DAG (action index)
    pub node_id: i64,
    /// Type of event (e.g., "Started", "Succeeded", "Failed")
    pub event_type: String,
    /// Full event data as JSON
    pub event_data: Value,
    #[partial(NewSagaEventModel(skip))]
    pub created_at: DateTime<Utc>,
}
