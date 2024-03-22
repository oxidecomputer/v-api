use diesel::{
    migration::{Migration, MigrationSource},
    pg::Pg,
    r2d2::{ConnectionManager, ManageConnection},
    PgConnection,
};
use diesel_migrations::{embed_migrations, EmbeddedMigrations};

const MIGRATIONS: EmbeddedMigrations = embed_migrations!("../v-model/migrations");

pub fn run_migrations(url: &str) {
    let mut conn = db_conn(&url);

    let migrations: Vec<Box<dyn Migration<Pg>>> = MIGRATIONS.migrations().unwrap();

    for migration in migrations {
        migration.run(&mut conn).unwrap();
    }
}

fn db_conn(url: &str) -> PgConnection {
    let conn: ConnectionManager<PgConnection> = ConnectionManager::new(url);
    conn.connect().unwrap()
}
