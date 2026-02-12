import "dotenv/config";
import { PrismaClient } from "@prisma/client";
import { PrismaPg } from "@prisma/adapter-pg";
import pg from "pg";

/**
 * Commandments:
 * - Secret management: use DATABASE_URL from env, never hardcode.
 * - Dependency hygiene: adapter-based Prisma v7 setup.
 * - Careful error handling: fail fast if DATABASE_URL missing.
 * - Safe logging: only warn/error.
 *
 * Notes:
 * - We use `pg` default import for best ESM/CJS compatibility under NodeNext/tsx.
 * - Install types: `pnpm add -D @types/pg`
 * - Generate Prisma client: `pnpm exec prisma generate`
 */

const { Pool } = pg;

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  throw new Error("Missing DATABASE_URL in environment (.env).");
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  // Sensible defaults for a small API; tune later for production.
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000
});

const adapter = new PrismaPg(pool);

export const db = new PrismaClient({
  adapter,
  log: ["warn", "error"]
});

/**
 * Optional: graceful shutdown helper (nice for production & tests)
 * Easy to remove later if you don’t need it.
 */
export async function closeDb(): Promise<void> {
  await db.$disconnect();
  await pool.end();
}
