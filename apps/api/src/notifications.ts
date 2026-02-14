import "dotenv/config";
import crypto from "node:crypto";
import { db } from "./db.js";

/**
 * ============================================================
 * notifications.ts
 * ============================================================
 * Immediate incident notifications (called by server.ts)
 *
 * Supported channels:
 * - slack   (Incoming Webhook)
 * - webhook (generic webhook + optional signature)
 * - email   (stub)
 *
 * Commandments:
 * - Secret management: never log webhook URLs or secrets.
 * - Safe logging: store short error summaries in DB.
 */

export type IncidentCreatedPayload = {
  tenantId: string;
  hostname: string;
  verdict: "warn" | "block";
  maxRisk: number;
  reasons: string[];
  firstSeenAt: Date;
  eventType: "NAVIGATE" | "DOWNLOAD";
};

type NotifyOptions = { onlyChannelId?: string };

type ChannelType = "slack" | "webhook" | "email";
type DeliveryStatus = "pending" | "sent" | "failed" | "skipped";

type ChannelRecord = {
  id: string;
  tenantId: string;
  type: ChannelType;
  enabled: boolean;
  config: unknown;
  filters: unknown | null;
};

type SlackBlock =
  | { type: "header"; text: { type: "plain_text"; text: string } }
  | {
      type: "section";
      text?: { type: "mrkdwn"; text: string };
      fields?: Array<{ type: "mrkdwn"; text: string }>;
    };

function alertsEnabled(): boolean {
  return process.env.ALERTS_ENABLED === "true" || process.env.NOTIFICATIONS_ENABLED === "true";
}

/**
 * attemptCount starts at 1
 * This version avoids any array-index undefined type issues entirely.
 */
function computeBackoffMs(attemptCount: number): number {
  if (attemptCount <= 1) return 60_000;
  if (attemptCount === 2) return 5 * 60_000;
  if (attemptCount === 3) return 30 * 60_000;
  return 2 * 60 * 60_000; // 2h for 4+
}

function isPermanentFailure(status: number, body: string): boolean {
  if (status === 403 && body.includes("invalid_token")) return true;
  if (status === 401) return true;
  if (status === 404) return true;
  if (status === 405) return true;
  return false;
}

function isTransientFailure(status: number): boolean {
  return status === 429 || status >= 500;
}

async function postJson(
  url: string,
  body: unknown,
  headers?: Record<string, string>
): Promise<{ ok: boolean; status: number; text: string }> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", ...(headers ?? {}) },
    body: JSON.stringify(body)
  });
  const text = await res.text().catch(() => "");
  return { ok: res.ok, status: res.status, text };
}

function signWebhook(secret: string, payload: unknown): string {
  const raw = JSON.stringify(payload);
  return crypto.createHmac("sha256", secret).update(raw).digest("hex");
}

function asRecord(v: unknown): Record<string, unknown> | null {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

function getString(obj: Record<string, unknown> | null, key: string): string | null {
  if (!obj) return null;
  const v = obj[key];
  return typeof v === "string" ? v : null;
}

function channelAllows(
  channel: { filters: unknown; enabled: boolean },
  ctx: { maxRisk: number; verdict: "warn" | "block"; eventType: "NAVIGATE" | "DOWNLOAD" }
): boolean {
  if (!channel.enabled) return false;

  const f = asRecord(channel.filters);
  if (!f) return true;

  const minRisk = f["minRisk"];
  if (typeof minRisk === "number" && ctx.maxRisk < minRisk) return false;

  const verdicts = f["verdicts"];
  if (Array.isArray(verdicts) && verdicts.length > 0) {
    if (!verdicts.includes(ctx.verdict)) return false;
  }

  const eventTypes = f["eventTypes"];
  if (Array.isArray(eventTypes) && eventTypes.length > 0) {
    if (!eventTypes.includes(ctx.eventType)) return false;
  }

  return true;
}

function buildSlackMessageIncident(payload: IncidentCreatedPayload): { text: string; blocks: SlackBlock[] } {
  const title = payload.verdict === "block" ? "🚫 Blocked" : "⚠️ Warned";
  const when = payload.firstSeenAt.toISOString();

  return {
    text: `${title}: ${payload.hostname} (risk ${payload.maxRisk})`,
    blocks: [
      { type: "header", text: { type: "plain_text", text: `${title}: ${payload.hostname}` } },
      {
        type: "section",
        fields: [
          { type: "mrkdwn", text: `*Risk:* ${payload.maxRisk}` },
          { type: "mrkdwn", text: `*Verdict:* ${payload.verdict}` },
          { type: "mrkdwn", text: `*Event:* ${payload.eventType}` },
          { type: "mrkdwn", text: `*First seen:* ${when}` }
        ]
      },
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text: payload.reasons?.length ? `*Reasons:* ${payload.reasons.join(", ")}` : "*Reasons:* (none)"
        }
      }
    ]
  };
}

async function recordDelivery(args: {
  tenantId: string;
  channelId: string;
  kind: string;
  status: DeliveryStatus;
  attemptCount: number;
  lastError: string | null;
  payload: unknown;
  sentAt: Date | null;
  nextAttemptAt: Date | null;
  lastAttemptAt: Date | null;
}) {
  return db.notificationDelivery.create({
    data: {
      tenantId: args.tenantId,
      channelId: args.channelId,
      kind: args.kind,
      status: args.status as any,
      attemptCount: args.attemptCount,
      lastError: args.lastError,
      payload: args.payload as any,
      sentAt: args.sentAt,
      nextAttemptAt: args.nextAttemptAt,
      lastAttemptAt: args.lastAttemptAt
    }
  });
}

async function updateDelivery(id: string, data: Record<string, unknown>) {
  return db.notificationDelivery.update({ where: { id }, data: data as any });
}

async function maybeAutoDisableChannel(channelId: string, reason: string) {
  const failures = await db.notificationDelivery.count({
    where: {
      channelId,
      status: "failed" as any,
      createdAt: { gt: new Date(Date.now() - 24 * 60 * 60_000) }
    }
  });

  if (failures < 5) return;

  await db.notificationChannel.update({ where: { id: channelId }, data: { enabled: false } });

  const ch = await db.notificationChannel.findUnique({ where: { id: channelId }, select: { tenantId: true } });
  if (!ch) return;

  await db.notificationDelivery.create({
    data: {
      tenantId: ch.tenantId,
      channelId,
      kind: "channel_disabled",
      status: "sent" as any,
      attemptCount: 0,
      lastError: reason.slice(0, 300),
      payload: { reason } as any,
      sentAt: new Date(),
      nextAttemptAt: null,
      lastAttemptAt: new Date()
    }
  });
}

export async function notifyIncidentCreated(payload: IncidentCreatedPayload, opts?: NotifyOptions) {
  if (!alertsEnabled()) return;

  const tenantId = payload.tenantId;

  const channelsRaw = await db.notificationChannel.findMany({
    where: { tenantId, enabled: true },
    orderBy: { createdAt: "desc" }
  });

  const only = opts?.onlyChannelId ? new Set([opts.onlyChannelId]) : null;

  const channels: ChannelRecord[] = channelsRaw
    .map((c) => ({
      id: c.id,
      tenantId: c.tenantId,
      type: c.type as ChannelType,
      enabled: c.enabled,
      config: c.config as unknown,
      filters: (c as any).filters ?? null
    }))
    .filter((c) => (only ? only.has(c.id) : true))
    .filter((c) => channelAllows(c, { maxRisk: payload.maxRisk, verdict: payload.verdict, eventType: payload.eventType }));

  if (channels.length === 0) return;

  await Promise.all(
    channels.map(async (channel) => {
      const delivery = await recordDelivery({
        tenantId,
        channelId: channel.id,
        kind: "incident_created",
        status: "pending",
        attemptCount: 1,
        lastError: null,
        payload,
        sentAt: null,
        nextAttemptAt: null,
        lastAttemptAt: new Date()
      });

      try {
        const configObj = asRecord(channel.config);

        if (channel.type === "slack") {
          const webhookUrl = getString(configObj, "webhookUrl");
          if (!webhookUrl) {
            await updateDelivery(delivery.id, { status: "failed", lastError: "slack_failed invalid_config" });
            return;
          }

          const msg = buildSlackMessageIncident(payload);
          const res = await postJson(webhookUrl, msg);

          if (!res.ok) {
            const errMsg = `slack_failed status=${res.status} body=${res.text}`.slice(0, 500);
            const nextAttemptAt = isTransientFailure(res.status) ? new Date(Date.now() + computeBackoffMs(1)) : null;

            await updateDelivery(delivery.id, { status: "failed", lastError: errMsg, nextAttemptAt });

            if (isPermanentFailure(res.status, res.text)) await maybeAutoDisableChannel(channel.id, errMsg);
            return;
          }

          await updateDelivery(delivery.id, { status: "sent", sentAt: new Date(), lastError: null, nextAttemptAt: null });
          return;
        }

        if (channel.type === "webhook") {
          const url = getString(configObj, "url");
          const secret = getString(configObj, "secret");

          if (!url) {
            await updateDelivery(delivery.id, { status: "failed", lastError: "webhook_failed invalid_config" });
            return;
          }

          const headers: Record<string, string> = {};
          if (secret && secret.length >= 16) {
            headers["x-threatpulse-signature"] = signWebhook(secret, payload);
          }

          const res = await postJson(url, { kind: "incident_created", payload }, headers);

          if (!res.ok) {
            const errMsg = `webhook_failed status=${res.status} body=${res.text}`.slice(0, 500);
            const nextAttemptAt = isTransientFailure(res.status) ? new Date(Date.now() + computeBackoffMs(1)) : null;

            await updateDelivery(delivery.id, { status: "failed", lastError: errMsg, nextAttemptAt });

            if (isPermanentFailure(res.status, res.text)) await maybeAutoDisableChannel(channel.id, errMsg);
            return;
          }

          await updateDelivery(delivery.id, { status: "sent", sentAt: new Date(), lastError: null, nextAttemptAt: null });
          return;
        }

        await updateDelivery(delivery.id, { status: "failed", lastError: "email_failed not_implemented" });
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : "unknown_error";
        await updateDelivery(delivery.id, { status: "failed", lastError: `send_failed ${msg}`.slice(0, 500) });
      }
    })
  );
}
