// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use diesel::{
    migration::{Migration, MigrationSource},
    pg::Pg,
    r2d2::{ConnectionManager, ManageConnection},
    PgConnection,
};
use diesel_migrations::{embed_migrations, EmbeddedMigrations};

const MIGRATIONS: EmbeddedMigrations = embed_migrations!("../v-model/migrations");

pub fn migrations() -> Vec<Box<dyn Migration<Pg>>> {
    MIGRATIONS.migrations().unwrap()
}

pub fn run_migrations(url: &str) {
    let mut conn = db_conn(&url);
    run_migrations_on_conn(&mut conn);
}

pub fn run_migrations_on_conn(conn: &mut PgConnection) {
    for migration in migrations() {
        migration.run(conn).unwrap();
    }
}

fn db_conn(url: &str) -> PgConnection {
    let conn: ConnectionManager<PgConnection> = ConnectionManager::new(url);
    conn.connect().unwrap()
}
