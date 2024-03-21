// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use diesel::{migration::{Migration, MigrationSource}, pg::Pg, r2d2::{ConnectionManager, ManageConnection}, PgConnection};
use diesel_migrations::{embed_migrations, EmbeddedMigrations};

const MIGRATIONS: EmbeddedMigrations = embed_migrations!("../v-model/migrations");

fn main() {
    if let Ok(url) = std::env::var("DATABASE_URL") {
        let mut conn = db_conn(&url);

        let migrations: Vec<Box<dyn Migration<Pg>>> = MIGRATIONS.migrations().unwrap();

        for migration in migrations {
            migration.run(&mut conn).unwrap();
        }
    } else {
        println!("DATABASE_URL environment variable must be specified to run migrations and must be in the form of a connection string")
    }
}

fn db_conn(url: &str) -> PgConnection {
    let conn: ConnectionManager<PgConnection> = ConnectionManager::new(url);
    conn.connect().unwrap()
}