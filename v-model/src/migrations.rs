// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::HashSet;

use diesel::{
    PgConnection,
    migration::MigrationSource,
    pg::Pg,
    r2d2::{ConnectionManager, ManageConnection},
};
use diesel_migrations::{
    EmbeddedMigrations, HarnessWithOutput, MigrationHarness, embed_migrations,
};

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

/// Panics if any enabled embedded migrations share a version.
pub fn assert_unique_migration_versions() {
    let mut seen = HashSet::new();

    for migration_set in all_migrations() {
        let migrations = <EmbeddedMigrations as MigrationSource<Pg>>::migrations(&migration_set)
            .expect("failed to read embedded migrations");

        for migration in &migrations {
            let name = migration.name();
            let version = name.version().to_string();
            assert!(
                seen.insert(version.clone()),
                "migration {name} reuses datestamp {version}; each needs a unique one"
            );
        }
    }
}

/// Runs all pending migrations for each enabled feature against the database
/// at the provided connection string. Migration sets are applied in dependency
/// order (core first, then feature-specific), naming each migration on stdout
/// as it is applied.
pub fn run_migrations(url: &str) {
    migrate(url, true);
}

/// Runs all pending migrations without per-migration output.
pub fn run_migrations_quiet(url: &str) {
    migrate(url, false);
}

fn migrate(url: &str, verbose: bool) {
    assert_unique_migration_versions();

    let conn: ConnectionManager<PgConnection> = ConnectionManager::new(url);
    let mut conn = conn.connect().unwrap();

    for migrations in all_migrations() {
        if verbose {
            HarnessWithOutput::write_to_stdout(&mut conn)
                .run_pending_migrations(migrations)
                .unwrap();
        } else {
            conn.run_pending_migrations(migrations).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::assert_unique_migration_versions;

    #[test]
    fn migration_versions_are_unique() {
        assert_unique_migration_versions();
    }
}
