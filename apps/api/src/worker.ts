import "dotenv/config";
import { runDigestOnce, runRetryOnce } from "./alertsEngine.js";

/**
 * Dev worker.
 * In production, you'd run this as a separate process (container/service)
 * or trigger via a scheduler/cron.
 */

const DIGEST_INTERVAL_MS = 5 * 60_000; // every 5 minutes
const RETRY_INTERVAL_MS = 60_000;      // every 1 minute

async function tickDigest() {
  try {
    await runDigestOnce(new Date());
  } catch (err) {
    console.warn("digest_tick_failed", err);
  }
}

async function tickRetry() {
  try {
    await runRetryOnce(new Date());
  } catch (err) {
    console.warn("retry_tick_failed", err);
  }
}

console.log("alerts worker started");

await tickDigest();
await tickRetry();

setInterval(() => void tickDigest(), DIGEST_INTERVAL_MS);
setInterval(() => void tickRetry(), RETRY_INTERVAL_MS);
