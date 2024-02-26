// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{collections::BTreeSet, fmt::Debug};

use diesel::{
    backend::Backend,
    deserialize::{self, FromSql},
    pg::Pg,
    serialize::{self, Output, ToSql},
    sql_types::Jsonb,
    AsExpression, FromSqlRow,
};
use schemars::JsonSchema;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use uuid::Uuid;

pub trait Permission:
    Clone + Debug + Serialize + DeserializeOwned + PartialEq + Send + Sync + 'static
{
}
impl<T> Permission for T where
    T: Clone + Debug + Serialize + DeserializeOwned + PartialEq + Send + Sync + 'static
{
}

#[derive(Debug, Clone)]
pub struct Caller<T> {
    pub id: Uuid,
    pub permissions: Permissions<T>,
}

impl<T> Caller<T>
where
    T: Permission,
{
    pub fn is(&self, id: &Uuid) -> bool {
        &self.id == id
    }

    pub fn all(&self, permissions: &[&T]) -> bool {
        self.permissions.all(permissions)
    }

    pub fn any(&self, permissions: &[&T]) -> bool {
        self.permissions.any(permissions)
    }

    pub fn can(&self, permission: &T) -> bool {
        let result = self.permissions.can(permission);
        tracing::trace!(?permission, ?result, "Test if caller can");
        result
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, FromSqlRow, AsExpression, JsonSchema)]
#[diesel(sql_type = Jsonb)]
pub struct Permissions<T>(Vec<T>);

impl<T> Default for Permissions<T> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<T> Permissions<T>
where
    T: Permission,
{
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn all(&self, permissions: &[&T]) -> bool {
        permissions.iter().all(|p| self.can(p))
    }

    pub fn any(&self, permissions: &[&T]) -> bool {
        permissions.iter().any(|p| self.can(p))
    }

    pub fn can(&self, permission: &T) -> bool {
        let res = self.0.contains(permission);
        tracing::trace!(available = ?self.0, requested = ?permission, result = ?res, "Permissions existence check");
        res
    }

    pub fn intersect(&self, other: &Permissions<T>) -> Permissions<T> {
        let mut new_permissions = vec![];
        for perm in &self.0 {
            if other.iter().any(|other_perm| perm == other_perm) {
                new_permissions.push(perm.clone());
            }
        }

        Permissions(new_permissions)
    }

    pub fn insert(&mut self, item: T) -> bool {
        if !self.can(&item) {
            self.0.push(item);
            true
        } else {
            false
        }
    }

    pub fn append(&mut self, other: &mut Self) {
        self.0.append(&mut other.0)
    }

    pub fn remove(&mut self, item: &T) -> bool {
        let mut removed = false;
        self.0.retain(|perm| {
            if perm == item {
                removed = true;
            }

            perm == item
        });

        removed
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.0.iter()
    }

    pub fn into_iter(self) -> impl Iterator<Item = T> {
        self.0.into_iter()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<T> From<BTreeSet<T>> for Permissions<T>
where
    T: Permission,
{
    fn from(value: BTreeSet<T>) -> Self {
        Self(value.into_iter().collect::<Vec<_>>())
    }
}

impl<T, U> From<Vec<T>> for Permissions<U>
where
    T: Permission,
    U: Permission + From<T>,
{
    fn from(value: Vec<T>) -> Self {
        Self::from_iter(value.into_iter().map(|v| v.into()))
    }
}

impl<T> FromIterator<T> for Permissions<T>
where
    T: Permission,
{
    fn from_iter<Iter: IntoIterator<Item = T>>(iter: Iter) -> Self {
        let mut v = Vec::new();
        v.extend::<Iter>(iter);
        Self(v)
    }
}

impl<T> ToSql<Jsonb, Pg> for Permissions<T>
where
    T: Serialize + Debug,
{
    fn to_sql(&self, out: &mut Output<Pg>) -> serialize::Result {
        let value = serde_json::to_value(self)?;
        <serde_json::Value as ToSql<Jsonb, Pg>>::to_sql(&value, &mut out.reborrow())
    }
}

impl<T> FromSql<Jsonb, Pg> for Permissions<T>
where
    T: DeserializeOwned + Debug,
{
    fn from_sql(bytes: <Pg as Backend>::RawValue<'_>) -> deserialize::Result<Self> {
        let value = <serde_json::Value as FromSql<Jsonb, Pg>>::from_sql(bytes)?;
        Ok(serde_json::from_value(value)?)
    }
}
