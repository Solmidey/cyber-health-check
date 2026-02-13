import "dotenv/config";
import { db } from "./db.js";
import type { Prisma } from "@prisma/client";

/**
 * ============================================================
 * Notifications (Top-tier MVP)
 * ============================================================
 * Decisions:
 * - Slack = Incoming Webhook
 * - Validate channel config on save (fail-fast)
 * - Auto-disable permanently broken Slack channels (no retry storms)
 *
 * Commandments:
 * - Secret management: never return webhook URLs/secrets to clients
 * - Careful error handling: notifications never block ingestion
 * - Safe logging: never log webhook URLs/tokens
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

export type NotifyOptions = {
  onlyChannelId?: string;
  reason?: string; // e.g. "test"
};

type JsonObject = { [k: string]: Prisma.JsonValue };

type SlackConfig = { webhookUrl: string };
type WebhookConfig = { url: string; secret?: string };
type EmailConfig = { to: string; from?: string };

function isJsonObject(v: Prisma.JsonValue): v is JsonObject {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function getSlackConfig(config: Prisma.JsonValue): SlackConfig | null {
  if (!isJsonObject(config)) return null;
  const w = config["webhookUrl"];
  if (typeof w !== "string") return null;
  return { webhookUrl: w };
}

function getWebhookConfig(config: Prisma.JsonValue): WebhookConfig | null {
  if (!isJsonObject(config)) return null;
  const url = config["url"];
  if (typeof url !== "string") return null;
  const secretVal = config["secret"];
  const secret = typeof secretVal === "string" ? secretVal : undefined;
  return { url, secret };
}

function getEmailConfig(config: Prisma.JsonValue): EmailConfig | null {
  if (!isJsonObject(config)) return null;
  const to = config["to"];
  if (typeof to !== "string") return null;
  const fromVal = config["from"];
  const from = typeof fromVal === "string" ? fromVal : undefined;
  return { to, from };
}

function truncate(s: string, n: number) {
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

/**
 * Feature flag kill-switch.
 */
export function alertsEnabled(): boolean {
  return process.env.ALERTS_ENABLED === "true";
}

/**
 * Optional global mute window (keeps your "suppressed_until" behavior).
 */
function alertsMutedUntil(): Date | null {
  const raw = process.env.ALERTS_MUTE_UNTIL;
  if (!raw) return null;
  const d = new Date(raw);
  return Number.isNaN(d.getTime()) ? null : d;
}

function slackWebhookPayload(incident: IncidentCreatedPayload) {
  const title = incident.verdict === "block" ? "🛑 BLOCKED" : "⚠️ WARN";
  const reasons = incident.reasons?.length ? incident.reasons.join(", ") : "none";
  const when = incident.firstSeenAt.toISOString();

  return {
    text:
      `${title} ThreatPulse alert\n` +
      `• Host: ${incident.hostname}\n` +
      `• Risk: ${incident.maxRisk}\n` +
      `• Event: ${incident.eventType}\n` +
      `• Reasons: ${truncate(reasons, 240)}\n` +
      `• First seen: ${when}`
  };
}

async function sendSlackWebhook(webhookUrl: string, incident: IncidentCreatedPayload) {
  const res = await fetch(webhookUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(slackWebhookPayload(incident))
  });

  const body = await res.text().catch(() => "");
  if (!res.ok) {
    throw new Error(`slack_failed status=${res.status} body=${truncate(body, 200)}`);
  }
}

async function sendGenericWebhook(url: string, secret: string | undefined, incident: IncidentCreatedPayload) {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (secret) headers["x-webhook-secret"] = secret;

  const res = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify({
      kind: "incident_created",
      incident: {
        tenantId: incident.tenantId,
        hostname: incident.hostname,
        verdict: incident.verdict,
        maxRisk: incident.maxRisk,
        reasons: incident.reasons,
        firstSeenAt: incident.firstSeenAt,
        eventType: incident.eventType
      }
    })
  });

  const body = await res.text().catch(() => "");
  if (!res.ok) {
    throw new Error(`webhook_failed status=${res.status} body=${truncate(body, 200)}`);
  }
}

function channelPassesFilters(channel: any, incident: IncidentCreatedPayload): boolean {
  const filters = channel.filters ?? null;
  if (!filters) return true;

  if (typeof filters.minRisk === "number" && incident.maxRisk < filters.minRisk) return false;

  if (Array.isArray(filters.verdicts) && filters.verdicts.length > 0) {
    if (!filters.verdicts.includes(incident.verdict)) return false;
  }

  if (Array.isArray(filters.eventTypes) && filters.eventTypes.length > 0) {
    if (!filters.eventTypes.includes(incident.eventType)) return false;
  }

  return true;
}

function ruleMatchesIncident(rule: any, incident: IncidentCreatedPayload): boolean {
  if (!rule.enabled) return false;

  if (typeof rule.minRisk === "number" && incident.maxRisk < rule.minRisk) return false;

  if (Array.isArray(rule.verdicts) && rule.verdicts.length > 0) {
    if (!rule.verdicts.includes(incident.verdict)) return false;
  }

  if (Array.isArray(rule.eventTypes) && rule.eventTypes.length > 0) {
    if (!rule.eventTypes.includes(incident.eventType)) return false;
  }

  if (Array.isArray(rule.hostDeny) && rule.hostDeny.includes(incident.hostname)) return false;

  if (Array.isArray(rule.hostAllow) && rule.hostAllow.length > 0) {
    if (!rule.hostAllow.includes(incident.hostname)) return false;
  }

  return true;
}

/**
 * Auto-disable on permanent Slack auth/config errors (ops-quality).
 */
async function maybeDisableChannelOnPermanentError(channelId: string, errMsg: string) {
  const permanent =
    errMsg.includes("invalid_token") ||
    errMsg.includes("invalid_auth") ||
    errMsg.includes("account_inactive") ||
    errMsg.includes("not_authed") ||
    errMsg.includes("token_revoked");

  if (!permanent) return;

  await db.notificationChannel.update({
    where: { id: channelId },
    data: { enabled: false }
  });
}

/**
 * ============================================================
 * Public: notifyIncidentCreated
 * ============================================================
 */
export async function notifyIncidentCreated(incident: IncidentCreatedPayload, opts: NotifyOptions = {}) {
  if (!alertsEnabled()) return;

  const muteUntil = alertsMutedUntil();
  if (muteUntil && new Date() < muteUntil) {
    const channels = await db.notificationChannel.findMany({
      where: {
        tenantId: incident.tenantId,
        enabled: true,
        ...(opts.onlyChannelId ? { id: opts.onlyChannelId } : {})
      },
      select: { id: true }
    });

    if (channels.length) {
      await db.notificationDelivery.createMany({
        data: channels.map((c) => ({
          tenantId: incident.tenantId,
          channelId: c.id,
          kind: "incident_created",
          status: "skipped" as any,
          attemptCount: 0,
          lastError: `suppressed_until=${muteUntil.toISOString()} reason=${opts.reason ?? "mute"}`,
          payload: incident as any
        }))
      });
    }
    return;
  }

  const channels = await db.notificationChannel.findMany({
    where: {
      tenantId: incident.tenantId,
      enabled: true,
      ...(opts.onlyChannelId ? { id: opts.onlyChannelId } : {})
    }
  });

  if (!channels.length) return;

  const rules = await db.notificationRule.findMany({
    where: { tenantId: incident.tenantId, enabled: true },
    include: { channels: true }
  });

  let targetChannelIds: string[] = [];

  if (rules.length > 0) {
    const matched = new Set<string>();
    for (const rule of rules) {
      if (!ruleMatchesIncident(rule, incident)) continue;
      for (const link of rule.channels) matched.add(link.channelId);
    }
    targetChannelIds = [...matched];
  } else {
    targetChannelIds = channels.filter((c) => channelPassesFilters(c, incident)).map((c) => c.id);
  }

  if (opts.onlyChannelId) targetChannelIds = targetChannelIds.filter((id) => id === opts.onlyChannelId);
  if (!targetChannelIds.length) return;

  await db.notificationDelivery.createMany({
    data: targetChannelIds.map((channelId) => ({
      tenantId: incident.tenantId,
      channelId,
      kind: "incident_created",
      status: "pending",
      attemptCount: 0,
      payload: incident as any
    }))
  });

  const pending = await db.notificationDelivery.findMany({
    where: { tenantId: incident.tenantId, kind: "incident_created", status: "pending" },
    orderBy: { createdAt: "desc" },
    take: targetChannelIds.length
  });

  const channelById = new Map(channels.map((c) => [c.id, c]));

  for (const d of pending) {
    const channel = channelById.get(d.channelId);
    if (!channel) continue;

    const attemptAt = new Date();

    try {
      if (channel.type === "slack") {
        const slackCfg = getSlackConfig(channel.config as Prisma.JsonValue);
        if (!slackCfg) throw new Error("slack_config_missing_webhookUrl");
        await sendSlackWebhook(slackCfg.webhookUrl, incident);
      } else if (channel.type === "webhook") {
        const whCfg = getWebhookConfig(channel.config as Prisma.JsonValue);
        if (!whCfg) throw new Error("webhook_config_missing_url");
        await sendGenericWebhook(whCfg.url, whCfg.secret, incident);
      } else if (channel.type === "email") {
        const emailCfg = getEmailConfig(channel.config as Prisma.JsonValue);
        if (!emailCfg) throw new Error("email_config_invalid");
        throw new Error("email_not_implemented");
      } else {
        throw new Error(`unsupported_channel_type_${String(channel.type)}`);
      }

      await db.notificationDelivery.update({
        where: { id: d.id },
        data: {
          status: "sent",
          attemptCount: { increment: 1 },
          lastError: null,
          sentAt: new Date(),
          lastAttemptAt: attemptAt as any,
          nextAttemptAt: null as any
        } as any
      });
    } catch (err: any) {
      const msg = err?.message ? String(err.message) : "send_failed";

      try {
        await maybeDisableChannelOnPermanentError(d.channelId, msg);
      } catch {
        // ignore
      }

      await db.notificationDelivery.update({
        where: { id: d.id },
        data: {
          status: "failed",
          attemptCount: { increment: 1 },
          lastError: msg,
          sentAt: null,
          lastAttemptAt: attemptAt as any,
          nextAttemptAt: null as any
        } as any
      });
    }
  }
}

/**
 * ============================================================
 * Public: validateChannelConfig (fail-fast on save)
 * ============================================================
 */
export async function validateChannelConfig(type: string, config: any) {
  if (type === "slack") {
    const webhookUrl = config?.webhookUrl;
    if (typeof webhookUrl !== "string" || !webhookUrl.startsWith("https://hooks.slack.com/")) {
      return { ok: false as const, error: "invalid_slack_webhookUrl" as const };
    }

    const res = await fetch(webhookUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ text: "✅ ThreatPulse: Slack channel connected." })
    });

    const body = await res.text().catch(() => "");
    if (!res.ok) {
      return {
        ok: false as const,
        error: `slack_failed status=${res.status} body=${truncate(body, 200)}` as const
      };
    }

    return { ok: true as const };
  }

  if (type === "webhook") {
    const url = config?.url;
    if (typeof url !== "string") return { ok: false as const, error: "invalid_webhook_url" as const };

    try {
      const res = await fetch(url, { method: "HEAD" });
      if (res.status === 405) return { ok: true as const };
      if (res.ok) return { ok: true as const };
      return { ok: false as const, error: `webhook_failed status=${res.status}` as const };
    } catch {
      return { ok: false as const, error: "webhook_unreachable" as const };
    }
  }

  if (type === "email") {
    return { ok: true as const };
  }

  return { ok: false as const, error: "unsupported_channel_type" as const };
}
