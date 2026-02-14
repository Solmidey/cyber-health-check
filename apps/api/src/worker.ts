import "dotenv/config";
import { runDigestOnce, runRetryOnce } from "./alertsEngine.js";

/**
 * Worker:
 * - runs digest + retry ticks on intervals
 * - ensures no overlapping runs
 * - never crashes the process on transient failures
 */

function alertsEnabled(): boolean {
  return process.env.ALERTS_ENABLED === "true" || process.env.NOTIFICATIONS_ENABLED === "true";
}

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

async function guardedTick(name: string, fn: () => Promise<void>, lock: { running: boolean }) {
  if (!alertsEnabled()) return;
  if (lock.running) return;

  lock.running = true;
  try {
    await fn();
  } catch (err) {
    // keep worker alive; errors are already DB-safe inside alertsEngine
    // eslint-disable-next-line no-console
    console.warn(`${name}_tick_failed`, err);
  } finally {
    lock.running = false;
  }
}

async function main() {
  // eslint-disable-next-line no-console
  console.log("alerts worker started");

  const digestLock = { running: false };
  const retryLock = { running: false };

  // small boot delay so DB/docker can settle (top-tier dev experience)
  await sleep(750);

  // Digest: every 5 minutes
  setInterval(() => guardedTick("digest", () => runDigestOnce(new Date()), digestLock), 5 * 60_000);

  // Retry: every 1 minute
  setInterval(() => guardedTick("retry", () => runRetryOnce(new Date()), retryLock), 60_000);

  // First run quickly after boot
  void guardedTick("retry", () => runRetryOnce(new Date()), retryLock);
  void guardedTick("digest", () => runDigestOnce(new Date()), digestLock);

  // graceful shutdown
  const shutdown = () => {
    // eslint-disable-next-line no-console
    console.log("alerts worker shutting down");
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

void main();
