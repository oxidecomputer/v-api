// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{
    any::{Any, TypeId},
    borrow::Borrow,
    collections::{BTreeSet, HashMap},
    fmt::Debug,
    sync::Arc,
};

use diesel::{
    backend::Backend,
    deserialize::{self, FromSql},
    pg::Pg,
    serialize::{self, Output, ToSql},
    sql_types::Jsonb,
    AsExpression, FromSqlRow,
};
use newtype_uuid::TypedUuid;
use schemars::JsonSchema;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;

use crate::{ApiUser, UserId};

pub trait Permission:
    Clone + Debug + Serialize + DeserializeOwned + PartialEq + Send + Sync + 'static
{
}
impl<T> Permission for T where
    T: Clone + Debug + Serialize + DeserializeOwned + PartialEq + Send + Sync + 'static
{
}

pub type ArcMap = HashMap<TypeId, Arc<dyn Any + Send + Sync>>;

#[derive(Debug, Clone)]
pub struct Caller<T> {
    pub id: TypedUuid<UserId>,
    pub permissions: Permissions<T>,
    pub extensions: ArcMap,
}

impl<T> Caller<T>
where
    T: Permission,
{
    pub fn is(&self, id: &TypedUuid<UserId>) -> bool {
        &self.id == id
    }

    pub fn all<U, V>(&self, permissions: U) -> bool
    where
        U: Iterator<Item = V>,
        V: Borrow<T>,
    {
        self.permissions.all(permissions)
    }

    pub fn any<U, V>(&self, permissions: U) -> bool
    where
        U: Iterator<Item = V>,
        V: Borrow<T>,
    {
        self.permissions.any(permissions)
    }

    pub fn can(&self, permission: &T) -> bool {
        let result = self.permissions.can(permission);
        tracing::trace!(?permission, ?result, "Test if caller can");
        result
    }

    pub fn insert<U>(&mut self, value: U) -> Option<Arc<U>>
    where
        U: Send + Sync + 'static,
    {
        self.extensions
            .insert(TypeId::of::<U>(), Arc::new(value))
            .and_then(|arc| arc.downcast().ok())
    }

    pub fn get<U>(&self) -> Option<Arc<U>>
    where
        U: Send + Sync + 'static,
    {
        self.extensions
            .get(&TypeId::of::<U>())
            .and_then(|arc| arc.clone().downcast().ok())
    }

    pub fn remove<U>(&mut self) -> Option<Arc<U>>
    where
        U: Send + Sync + 'static,
    {
        self.extensions
            .remove(&TypeId::of::<U>())
            .and_then(|arc| arc.downcast().ok())
    }
}

impl<T> From<Permissions<T>> for Caller<T> {
    fn from(value: Permissions<T>) -> Self {
        Self {
            id: TypedUuid::new_v4(),
            permissions: value,
            extensions: HashMap::new(),
        }
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

    pub fn all<U, V>(&self, mut permissions: U) -> bool
    where
        U: Iterator<Item = V>,
        V: Borrow<T>,
    {
        permissions.all(|p| self.can(p.borrow()))
    }

    pub fn any<U, V>(&self, mut permissions: U) -> bool
    where
        U: Iterator<Item = V>,
        V: Borrow<T>,
    {
        permissions.any(|p| self.can(p.borrow()))
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

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<T> IntoIterator for Permissions<T>
where
    T: Permission,
{
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
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

impl<T, U, const N: usize> From<[T; N]> for Permissions<U>
where
    T: Permission,
    U: Permission + From<T>,
{
    fn from(value: [T; N]) -> Self {
        Self::from_iter(value.into_iter().map(|v| v.into()))
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

#[derive(Debug, Error)]
pub enum PermissionError {
    #[error("Scope is invalid: {0}")]
    InvalidScope(String),
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

pub trait AsScope: Sized {
    fn as_scope(&self) -> &str;
    fn from_scope_arg(scope_arg: &str) -> Result<Permissions<Self>, PermissionError> {
        Self::from_scope(scope_arg.split(' '))
    }
    fn from_scope<S>(scope: impl Iterator<Item = S>) -> Result<Permissions<Self>, PermissionError>
    where
        S: AsRef<str>;
}

pub trait PermissionStorage {
    fn contract(_collection: &Permissions<Self>) -> Permissions<Self>
    where
        Self: Sized;
    fn expand(
        collection: &Permissions<Self>,
        actor: &ApiUser<Self>,
        actor_permissions: Option<&Permissions<Self>>,
        extensions: &ArcMap,
    ) -> Permissions<Self>
    where
        Self: Sized;
}
