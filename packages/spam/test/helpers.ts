import { allMigrations, migrate, openSqlite, type DbDriver } from "@ionosphere/db";

export async function freshDb(): Promise<DbDriver> {
  const db = await openSqlite();
  await migrate(db, allMigrations);
  return db;
}
