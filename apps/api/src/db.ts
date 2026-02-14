import "dotenv/config";
import { PrismaClient } from "@prisma/client";
import { PrismaPg } from "@prisma/adapter-pg";
import pg from "pg";

/**
 * db.ts
 * - Prisma + @prisma/adapter-pg for Postgres
 * - Works in Node ESM ("type":"module")
 * - Avoids multiple clients in dev/watch
 */

const { Pool } = pg;

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) {
  // Commandment: validation at boundary
  throw new Error("DATABASE_URL is required");
}

const pool = new Pool({ connectionString: databaseUrl });
const adapter = new PrismaPg(pool);

const globalForPrisma = globalThis as unknown as { prisma?: PrismaClient };

// Reuse client in dev to prevent too many connections during tsx watch.
export const db =
  globalForPrisma.prisma ??
  new PrismaClient({
    adapter,
    log: process.env.NODE_ENV === "development" ? ["error", "warn"] : ["error"]
  });

if (process.env.NODE_ENV !== "production") {
  globalForPrisma.prisma = db;
}
