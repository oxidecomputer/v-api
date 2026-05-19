// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use diesel::{
    PgConnection,
    r2d2::{ConnectionManager, ManageConnection},
};
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};

/// Core v-model migrations that are always applied.
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

/// Saga-specific migrations, only available when the `sagas` feature is enabled.
#[cfg(feature = "sagas")]
pub const SAGA_MIGRATIONS: EmbeddedMigrations = embed_migrations!("src/saga/migrations");

/// Returns all embedded migration sets that should be applied based on the
/// currently enabled features.
fn all_migrations() -> Vec<EmbeddedMigrations> {
    let mut migrations = vec![MIGRATIONS];

    #[cfg(feature = "sagas")]
    migrations.push(SAGA_MIGRATIONS);

    migrations
}

/// Runs all pending migrations for each enabled feature against the database
/// at the provided connection string. Migration sets are applied in dependency
/// order (core first, then feature-specific).
pub fn run_migrations(url: &str) {
    let conn: ConnectionManager<PgConnection> = ConnectionManager::new(url);
    let mut conn = conn.connect().unwrap();

    for migrations in all_migrations() {
        conn.run_pending_migrations(migrations).unwrap();
    }
}
