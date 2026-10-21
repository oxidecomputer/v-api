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
    AsExpression, FromSqlRow,
    backend::Backend,
    deserialize::{self, FromSql},
    pg::Pg,
    serialize::{self, Output, ToSql},
    sql_types::Jsonb,
};
use newtype_uuid::TypedUuid;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
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

impl<T> Caller<T>
where
    T: Permission + PermissionStorage,
{
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

    /// Returns true if the caller holds the given permission, either directly or via a
    /// permission that implies it (e.g., an "All" variant implies specific instances).
    pub fn can(&self, permission: &T) -> bool {
        let result = self.permissions.can(permission);
        tracing::trace!(?permission, ?result, "Test if caller can");
        result
    }

    /// Returns true if the caller could grant the target. See [`Permissions::can_grant`].
    pub fn can_grant(&self, target: &T) -> bool {
        self.permissions.can_grant(target)
    }

    /// Returns true if the caller could grant every permission in the targets
    pub fn can_grant_all(&self, targets: &Permissions<T>) -> bool {
        self.permissions.can_grant_all(targets)
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

    pub fn intersect(&self, other: &Permissions<T>) -> Permissions<T> {
        let mut new_permissions = vec![];
        for perm in &self.0 {
            if other.iter().any(|other_perm| perm == other_perm) {
                new_permissions.push(perm.clone());
            }
        }

        Permissions(new_permissions)
    }

    /// Inserts a permission into the set if it is not already present (exact match).
    pub fn insert(&mut self, item: T) -> bool {
        if !self.0.contains(&item) {
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
            let matches = perm == item;
            if matches {
                removed = true;
            }

            !matches
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

impl<T> Permissions<T>
where
    T: Permission + PermissionStorage,
{
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

    /// Returns true if any held permission implies the target, either by exact match
    /// or through a permission definition.
    pub fn can(&self, permission: &T) -> bool {
        let res = self.iter().any(|held| T::implies(held, permission));
        tracing::trace!(available = ?self.0, requested = ?permission, result = ?res, "Permissions existence check");
        res
    }

    /// Returns true if this set could grant the target to someone else.
    pub fn can_grant(&self, target: &T) -> bool {
        // We need to expand the target to verify that every permission it expresses is covered by
        // this permission set. We can not use equality as this permission set may contain supersets
        // for value carrying permissions compared to the target permission.
        match target.expand_value() {
            Some(values) => values.iter().all(|value| self.can(value)),
            None => self.can(target),
        }
    }

    /// Returns true if this set could grant every permission in the targets
    pub fn can_grant_all(&self, targets: &Permissions<T>) -> bool {
        targets.iter().all(|target| self.can_grant(target))
    }

    /// Splits every permission that carries a set of values into one permission per value.
    pub fn expand_values(&self) -> Permissions<T> {
        let mut expanded = Permissions::new();
        for permission in self.iter() {
            match permission.expand_value() {
                Some(values) => values.into_iter().for_each(|value| {
                    expanded.insert(value);
                }),
                None => {
                    expanded.insert(permission.clone());
                }
            }
        }

        expanded
    }

    /// Returns this set with the target removed.
    pub fn without(&self, target: &T) -> Permissions<T> {
        let removed = target
            .expand_value()
            .unwrap_or_else(|| vec![target.clone()]);
        let mut remaining = self.expand_values();
        removed.iter().for_each(|value| {
            remaining.remove(value);
        });

        remaining
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
    #[error("\"full\" scope cannot be combined with other scopes")]
    FullScopeMustBeExclusive,
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

    /// Validate that scope entries do not violate combination rules.
    /// The "full" scope must be the only entry when present.
    fn validate_scope<S: AsRef<str>>(entries: &[S]) -> Result<(), PermissionError> {
        if entries.len() > 1 && entries.iter().any(|s| s.as_ref() == "full") {
            return Err(PermissionError::FullScopeMustBeExclusive);
        }
        Ok(())
    }

    fn from_scope_arg(scope_arg: &str) -> Result<Permissions<Self>, PermissionError> {
        Self::from_scope(scope_arg.split(' ').filter(|s| !s.is_empty()))
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

    /// Returns true if holding permission `held` implies that you effectively also have `target`.
    /// This is used for privilege escalation checks: a caller can only grant permissions that
    /// are implied by permissions they already hold.
    fn implies(held: &Self, target: &Self) -> bool
    where
        Self: Sized;

    /// Splits a permission that carries a set of values into one permission per value. Returns
    /// `None` for any permission that does not carry a set of values, which includes permissions
    /// whose meaning is relative to whoever holds them.
    fn expand_value(&self) -> Option<Vec<Self>>
    where
        Self: Sized,
    {
        None
    }
}
