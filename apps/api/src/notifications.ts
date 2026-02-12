import "dotenv/config";
import crypto from "node:crypto";
import { z } from "zod";
import { db } from "./db.js";

/**
 * =========================
 * Notifications module
 * =========================
 * Supports:
 *  - Slack webhook
 *  - Email (Resend)
 *  - Generic webhook (HMAC signed)
 *
 * Commandments applied:
 * - Secret management: keys from env only; never log them.
 * - Safe logging: never include tokens; no full URLs with queries.
 * - Careful error handling: never break ingestion if notify fails.
 * - Dependency hygiene: schema-validated configs.
 */

const ALERTS_ENABLED = process.env.ALERTS_ENABLED === "true";

// Operator-friendly startup signal (no secrets)
console.log(`[notifications] enabled=${ALERTS_ENABLED}`);

const channelFiltersSchema = z
  .object({
    minRisk: z.number().int().min(0).max(100).optional(),
    verdicts: z.array(z.enum(["warn", "block"])).optional(),
    eventTypes: z.array(z.enum(["NAVIGATE", "DOWNLOAD"])).optional()
  })
  .optional();

const slackConfigSchema = z.object({
  webhookUrl: z.string().url()
});

const emailConfigSchema = z.object({
  to: z.string().email(),
  from: z.string().email().optional()
});

const webhookConfigSchema = z.object({
  url: z.string().url(),
  secret: z.string().min(16).optional()
});

export type IncidentNotifyPayload = {
  tenantId: string;
  hostname: string;
  verdict: "warn" | "block";
  maxRisk: number;
  reasons: string[];
  firstSeenAt: Date;
  eventType: "NAVIGATE" | "DOWNLOAD";
};

export type NotifyOptions = {
  /**
   * If provided, send only to this channelId (used by /v1/notifications/test).
   */
  onlyChannelId?: string;
};

function channelMatchesFilters(payload: IncidentNotifyPayload, filtersRaw: unknown): boolean {
  const parsed = channelFiltersSchema.safeParse(filtersRaw);
  if (!parsed.success) return true; // ignore invalid filters rather than suppress alerts

  const f = parsed.data;
  if (!f) return true;

  if (typeof f.minRisk === "number" && payload.maxRisk < f.minRisk) return false;
  if (Array.isArray(f.verdicts) && f.verdicts.length > 0 && !f.verdicts.includes(payload.verdict))
    return false;
  if (Array.isArray(f.eventTypes) && f.eventTypes.length > 0 && !f.eventTypes.includes(payload.eventType))
    return false;

  return true;
}

function safeHostOnly(hostname: string): string {
  return hostname.toLowerCase();
}

function hmacBase64Url(secret: string, body: string) {
  return crypto.createHmac("sha256", secret).update(body).digest("base64url");
}

async function fetchWithTimeout(url: string, init: RequestInit, ms: number) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), ms);
  try {
    return await fetch(url, { ...init, signal: ac.signal });
  } finally {
    clearTimeout(t);
  }
}

async function sendSlack(webhookUrl: string, text: string) {
  const res = await fetchWithTimeout(
    webhookUrl,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ text })
    },
    8_000
  );

  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`slack_failed status=${res.status} body=${body.slice(0, 180)}`);
  }
}

async function sendWebhook(url: string, payloadObj: unknown, secret?: string) {
  const body = JSON.stringify(payloadObj);
  const headers: Record<string, string> = { "content-type": "application/json" };

  // Optional signature for authenticity
  if (secret) headers["x-threatpulse-signature"] = hmacBase64Url(secret, body);

  const res = await fetchWithTimeout(url, { method: "POST", headers, body }, 8_000);

  if (!res.ok) {
    const txt = await res.text().catch(() => "");
    throw new Error(`webhook_failed status=${res.status} body=${txt.slice(0, 180)}`);
  }
}

async function sendEmailResend(to: string, from: string, subject: string, text: string) {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) throw new Error("missing_RESEND_API_KEY");

  const res = await fetchWithTimeout(
    "https://api.resend.com/emails",
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${apiKey}`,
        "content-type": "application/json"
      },
      body: JSON.stringify({ from, to, subject, text })
    },
    10_000
  );

  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`email_failed status=${res.status} body=${body.slice(0, 180)}`);
  }
}

/**
 * Notify tenant about a NEW incident.
 * Called from server.ts only after incident creation (after commit).
 */
export async function notifyIncidentCreated(
  payload: IncidentNotifyPayload,
  options?: NotifyOptions
): Promise<void> {
  if (!ALERTS_ENABLED) return;

  const hostname = safeHostOnly(payload.hostname);

  // Load enabled channels for tenant (optionally only one channel)
  const channels = await db.notificationChannel.findMany({
    where: {
      tenantId: payload.tenantId,
      enabled: true,
      ...(options?.onlyChannelId ? { id: options.onlyChannelId } : {})
    }
  });

  if (channels.length === 0) return;

  // Safe, minimal payload (no URLs, no tokens)
  const safePayload = {
    kind: "incident_created",
    tenantId: payload.tenantId,
    hostname,
    verdict: payload.verdict,
    maxRisk: payload.maxRisk,
    reasons: payload.reasons.slice(0, 12),
    firstSeenAt: payload.firstSeenAt.toISOString(),
    eventType: payload.eventType
  };

  // Slack-friendly text
  const text = [
    `*ThreatPulse Incident*`,
    `• Tenant: ${payload.tenantId}`,
    `• Host: ${hostname}`,
    `• Verdict: ${payload.verdict.toUpperCase()}`,
    `• Risk: ${payload.maxRisk}/100`,
    `• Event: ${payload.eventType}`,
    `• Reasons: ${payload.reasons.slice(0, 6).join(", ")}`
  ].join("\n");

  await Promise.allSettled(
    channels.map(async (ch: any) => {
      // Apply filters per channel
      if (!channelMatchesFilters(payload, ch.filters ?? undefined)) return;

      // Delivery audit (never store secrets)
      const delivery = await db.notificationDelivery.create({
        data: {
          tenantId: payload.tenantId,
          channelId: ch.id,
          kind: "incident_created",
          status: "pending",
          attemptCount: 0,
          payload: safePayload
        }
      });

      try {
        if (ch.type === "slack") {
          const cfg = slackConfigSchema.parse(ch.config);
          await sendSlack(cfg.webhookUrl, text);
        } else if (ch.type === "webhook") {
          const cfg = webhookConfigSchema.parse(ch.config);
          await sendWebhook(cfg.url, safePayload, cfg.secret);
        } else if (ch.type === "email") {
          const cfg = emailConfigSchema.parse(ch.config);

          const from = cfg.from ?? process.env.ALERT_EMAIL_FROM;
          if (!from) throw new Error("missing_ALERT_EMAIL_FROM");

          await sendEmailResend(
            cfg.to,
            from,
            `ThreatPulse: ${payload.verdict.toUpperCase()} ${hostname}`,
            [
              `ThreatPulse Incident`,
              `Tenant: ${payload.tenantId}`,
              `Host: ${hostname}`,
              `Verdict: ${payload.verdict}`,
              `Risk: ${payload.maxRisk}/100`,
              `Event: ${payload.eventType}`,
              `Reasons: ${payload.reasons.join(", ")}`
            ].join("\n")
          );
        } else {
          throw new Error("unsupported_channel_type");
        }

        await db.notificationDelivery.update({
          where: { id: delivery.id },
          data: {
            status: "sent",
            attemptCount: { increment: 1 },
            sentAt: new Date(),
            lastError: undefined
          }
        });
      } catch (err) {
        await db.notificationDelivery.update({
          where: { id: delivery.id },
          data: {
            status: "failed",
            attemptCount: { increment: 1 },
            lastError: err instanceof Error ? err.message : "unknown_error"
          }
        });

        // Never throw: notification failures must not break ingestion
      }
    })
  );
}
