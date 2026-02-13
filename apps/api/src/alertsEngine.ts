import "dotenv/config";
import crypto from "node:crypto";
import type { Prisma } from "@prisma/client";
import { db } from "./db.js";

/**
 * ============================================================
 * Alerts Engine
 * ============================================================
 * Immediate (server.ts):
 * - notify on NEW incident creation using rules -> channels
 *
 * Worker (worker.ts):
 * - digest rollups (mode=digest)
 * - retry failed deliveries when nextAttemptAt is due
 * - auto-disable channels after repeated permanent failures
 *
 * Commandments:
 * - Server-side logic: routing and filtering here, not client
 * - Secret management: never log webhook URLs or secrets
 * - Safe logging: store short error summaries in DB
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

type DigestTopHost = { hostname: string; verdict: "warn" | "block"; maxRisk: number; count: number };

type DigestPayload = {
  tenantId: string;
  windowStart: Date;
  windowEnd: Date;
  summary: {
    blocks: number;
    warns: number;
    topHosts: DigestTopHost[];
  };
};

type NotifyOptions = { onlyChannelId?: string };

/**
 * ============================================================
 * Flags
 * ============================================================
 */
function alertsEnabled(): boolean {
  // keep compatibility with older env var name
  return process.env.ALERTS_ENABLED === "true" || process.env.NOTIFICATIONS_ENABLED === "true";
}

/**
 * ============================================================
 * Backoff + failure classification
 * ============================================================
 */
function computeBackoffMs(attemptCountRaw: number | null | undefined): number {
  // Normalize: attemptCount starts at 1, but DB may have 0/null
  const attemptCount = typeof attemptCountRaw === "number" && Number.isFinite(attemptCountRaw) ? attemptCountRaw : 1;

  const base = [60_000, 5 * 60_000, 30 * 60_000, 2 * 60 * 60_000]; // 1m, 5m, 30m, 2h
  const idx = Math.min(Math.max(attemptCount - 1, 0), base.length - 1);
  return base[idx] ?? 60_000;
}

function isPermanentFailure(status: number, body: string): boolean {
  // Slack webhook errors + typical "never retry" HTTP statuses
  if (status === 403 && body.includes("invalid_token")) return true;
  if (status === 401) return true;
  if (status === 404) return true;
  if (status === 405) return true;
  return false;
}

function isTransientFailure(status: number): boolean {
  return status === 429 || status >= 500;
}

/**
 * ============================================================
 * Small helpers
 * ============================================================
 */
function truncate(s: string, n: number) {
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

async function postJson(url: string, body: any, headers?: Record<string, string>) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", ...(headers ?? {}) },
    body: JSON.stringify(body)
  });
  const text = await res.text().catch(() => "");
  return { ok: res.ok, status: res.status, text };
}

function signWebhook(secret: string, payload: any): string {
  const raw = JSON.stringify(payload);
  return crypto.createHmac("sha256", secret).update(raw).digest("hex");
}

/**
 * ============================================================
 * JsonValue guards for Prisma Json fields (config/filters/payload)
 * ============================================================
 */
type JsonObject = { [k: string]: Prisma.JsonValue };

function isJsonObject(v: Prisma.JsonValue): v is JsonObject {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function getSlackWebhookUrl(config: Prisma.JsonValue): string | null {
  if (!isJsonObject(config)) return null;
  const w = config["webhookUrl"];
  return typeof w === "string" ? w : null;
}

function getWebhookConfig(config: Prisma.JsonValue): { url: string; secret?: string } | null {
  if (!isJsonObject(config)) return null;
  const url = config["url"];
  if (typeof url !== "string") return null;
  const secretVal = config["secret"];
  const secret = typeof secretVal === "string" ? secretVal : undefined;
  return { url, secret };
}

/**
 * ============================================================
 * Verdict guards (Prisma Incident.verdict is String => TS sees string)
 * ============================================================
 */
type IncidentVerdict = "warn" | "block";

function asIncidentVerdict(v: unknown): IncidentVerdict | null {
  return v === "warn" || v === "block" ? v : null;
}

/**
 * ============================================================
 * Slack message builders
 * ============================================================
 */
function buildSlackMessageIncident(payload: IncidentCreatedPayload) {
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

function buildSlackMessageDigest(p: DigestPayload) {
  const ws = p.windowStart.toISOString();
  const we = p.windowEnd.toISOString();

  const lines = [
    `*Window:* ${ws} → ${we}`,
    `*Blocked:* ${p.summary.blocks}`,
    `*Warned:* ${p.summary.warns}`,
    "",
    "*Top Hosts:*"
  ];

  for (const h of p.summary.topHosts.slice(0, 10)) {
    const icon = h.verdict === "block" ? "🚫" : "⚠️";
    lines.push(`${icon} \`${h.hostname}\` — maxRisk ${h.maxRisk} — events ${h.count}`);
  }

  return {
    text: `ThreatPulse digest (${p.summary.blocks} blocked, ${p.summary.warns} warned)`,
    blocks: [
      { type: "header", text: { type: "plain_text", text: "ThreatPulse Digest" } },
      { type: "section", text: { type: "mrkdwn", text: lines.join("\n") } }
    ]
  };
}

/**
 * ============================================================
 * Filters + rule matching
 * ============================================================
 */
function channelAllows(
  channel: { filters: Prisma.JsonValue | null; enabled: boolean },
  ctx: { maxRisk: number; verdict: IncidentVerdict; eventType: "NAVIGATE" | "DOWNLOAD" }
): boolean {
  if (!channel.enabled) return false;

  const f = channel.filters;
  if (!f || !isJsonObject(f)) return true;

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

function ruleMatches(
  rule: any,
  ctx: { hostname: string; maxRisk: number; verdict: IncidentVerdict; eventType: "NAVIGATE" | "DOWNLOAD" }
): boolean {
  if (!rule.enabled) return false;

  if (rule.minRisk != null && ctx.maxRisk < rule.minRisk) return false;
  if (Array.isArray(rule.verdicts) && rule.verdicts.length > 0 && !rule.verdicts.includes(ctx.verdict)) return false;
  if (Array.isArray(rule.eventTypes) && rule.eventTypes.length > 0 && !rule.eventTypes.includes(ctx.eventType)) return false;

  const host = ctx.hostname.toLowerCase();
  if (Array.isArray(rule.hostDeny) && rule.hostDeny.includes(host)) return false;
  if (Array.isArray(rule.hostAllow) && rule.hostAllow.length > 0 && !rule.hostAllow.includes(host)) return false;

  return true;
}

/**
 * ============================================================
 * Suppression
 * ============================================================
 */
async function getActiveSuppression(tenantId: string, hostname: string) {
  // NOTE: requires NotificationSuppression model in schema
  const row = await db.notificationSuppression.findFirst({
    where: { tenantId, hostname: hostname.toLowerCase(), mutedUntil: { gt: new Date() } },
    select: { mutedUntil: true, reason: true }
  });
  return row ? { mutedUntil: row.mutedUntil, reason: row.reason ?? null } : null;
}

/**
 * ============================================================
 * Delivery helpers
 * ============================================================
 */
async function recordDelivery(args: {
  tenantId: string;
  channelId: string;
  kind: string;
  status: "pending" | "sent" | "failed" | "skipped";
  attemptCount: number;
  lastError: string | null;
  payload: any;
  sentAt: Date | null;
  nextAttemptAt: Date | null;
  lastAttemptAt: Date | null;
}) {
  return db.notificationDelivery.create({
    data: {
      tenantId: args.tenantId,
      channelId: args.channelId,
      kind: args.kind,
      status: args.status,
      attemptCount: args.attemptCount,
      lastError: args.lastError,
      payload: args.payload,
      sentAt: args.sentAt,
      nextAttemptAt: args.nextAttemptAt,
      lastAttemptAt: args.lastAttemptAt
    } as any
  });
}

async function updateDelivery(id: string, data: Record<string, unknown>) {
  return db.notificationDelivery.update({ where: { id }, data: data as any });
}

async function maybeAutoDisableChannel(channelId: string, reason: string) {
  // Auto-disable after repeated failures in 24h — prevents noisy loops
  const failures = await db.notificationDelivery.count({
    where: { channelId, status: "failed", createdAt: { gt: new Date(Date.now() - 24 * 60 * 60_000) } }
  });

  if (failures < 5) return;

  await db.notificationChannel.update({ where: { id: channelId }, data: { enabled: false } });

  // Leave an audit trail (no secrets)
  const ch = await db.notificationChannel.findUnique({
    where: { id: channelId },
    select: { tenantId: true }
  });
  if (!ch) return;

  await db.notificationDelivery.create({
    data: {
      tenantId: ch.tenantId,
      channelId,
      kind: "channel_disabled",
      status: "sent",
      attemptCount: 0,
      lastError: reason.slice(0, 300),
      payload: { reason },
      sentAt: new Date()
    } as any
  });
}

/**
 * ============================================================
 * PUBLIC: Immediate notification (called by server.ts)
 * ============================================================
 */
export async function notifyIncidentCreated(payload: IncidentCreatedPayload, opts?: NotifyOptions) {
  if (!alertsEnabled()) return;

  const tenantId = payload.tenantId;
  const hostname = payload.hostname.toLowerCase();

  const [rules, channels] = await Promise.all([
    db.notificationRule.findMany({
      where: { tenantId, enabled: true },
      include: { channels: true }
    }),
    db.notificationChannel.findMany({
      where: { tenantId, enabled: true },
      orderBy: { createdAt: "desc" }
    })
  ]);

  const channelMap = new Map(channels.map((c) => [c.id, c]));
  const only = opts?.onlyChannelId ? new Set([opts.onlyChannelId]) : null;

  const matchedChannelIds = new Set<string>();
  for (const rule of rules) {
    if (rule.mode !== "immediate") continue;

    if (
      !ruleMatches(rule, {
        hostname,
        maxRisk: payload.maxRisk,
        verdict: payload.verdict,
        eventType: payload.eventType
      })
    ) {
      continue;
    }

    for (const link of rule.channels ?? []) {
      if (only && !only.has(link.channelId)) continue;
      matchedChannelIds.add(link.channelId);
    }
  }

  if (matchedChannelIds.size === 0) return;

  const targets: any[] = [];
  for (const id of matchedChannelIds) {
    const ch = channelMap.get(id);
    if (!ch) continue;
    if (!channelAllows(ch, { maxRisk: payload.maxRisk, verdict: payload.verdict, eventType: payload.eventType }))
      continue;
    targets.push(ch);
  }
  if (targets.length === 0) return;

  // Suppression → SKIPPED deliveries for audit
  const suppression = await getActiveSuppression(tenantId, hostname);
  if (suppression) {
    const reason = `suppressed_until=${suppression.mutedUntil.toISOString()} reason=${suppression.reason ?? "n/a"}`;
    await Promise.all(
      targets.map((ch) =>
        recordDelivery({
          tenantId,
          channelId: ch.id,
          kind: "incident_created",
          status: "skipped",
          attemptCount: 0,
          lastError: reason.slice(0, 300),
          payload,
          sentAt: null,
          nextAttemptAt: null,
          lastAttemptAt: null
        })
      )
    );
    return;
  }

  await Promise.all(
    targets.map(async (ch) => {
      const delivery = await recordDelivery({
        tenantId,
        channelId: ch.id,
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
        if (ch.type === "slack") {
          const webhookUrl = getSlackWebhookUrl(ch.config as Prisma.JsonValue);
          if (!webhookUrl) {
            await updateDelivery(delivery.id, { status: "failed", lastError: "slack_failed invalid_config" });
            return;
          }

          const msg = buildSlackMessageIncident(payload);
          const res = await postJson(webhookUrl, msg);

          if (!res.ok) {
            const errMsg = `slack_failed status=${res.status} body=${truncate(res.text, 300)}`.slice(0, 500);

            const nextAttemptAt = isTransientFailure(res.status)
              ? new Date(Date.now() + computeBackoffMs(1))
              : null;

            await updateDelivery(delivery.id, {
              status: "failed",
              lastError: errMsg,
              nextAttemptAt
            });

            if (isPermanentFailure(res.status, res.text)) await maybeAutoDisableChannel(ch.id, errMsg);
            return;
          }

          await updateDelivery(delivery.id, {
            status: "sent",
            sentAt: new Date(),
            lastError: null,
            nextAttemptAt: null
          });
          return;
        }

        if (ch.type === "webhook") {
          const wh = getWebhookConfig(ch.config as Prisma.JsonValue);
          if (!wh) {
            await updateDelivery(delivery.id, { status: "failed", lastError: "webhook_failed invalid_config" });
            return;
          }

          const headers: Record<string, string> = {};
          if (wh.secret && wh.secret.length >= 16) {
            headers["x-threatpulse-signature"] = signWebhook(wh.secret, payload);
          }

          const res = await postJson(wh.url, { kind: "incident_created", payload }, headers);

          if (!res.ok) {
            const errMsg = `webhook_failed status=${res.status} body=${truncate(res.text, 300)}`.slice(0, 500);
            const nextAttemptAt = isTransientFailure(res.status)
              ? new Date(Date.now() + computeBackoffMs(1))
              : null;

            await updateDelivery(delivery.id, {
              status: "failed",
              lastError: errMsg,
              nextAttemptAt
            });

            if (isPermanentFailure(res.status, res.text)) await maybeAutoDisableChannel(ch.id, errMsg);
            return;
          }

          await updateDelivery(delivery.id, {
            status: "sent",
            sentAt: new Date(),
            lastError: null,
            nextAttemptAt: null
          });
          return;
        }

        // Email: stub (future)
        await updateDelivery(delivery.id, { status: "failed", lastError: "email_failed not_implemented" });
      } catch (err: any) {
        await updateDelivery(delivery.id, {
          status: "failed",
          lastError: `send_failed ${truncate(String(err?.message ?? "unknown_error"), 300)}`.slice(0, 500)
        });
      }
    })
  );
}

/**
 * ============================================================
 * WORKER: Digest rollups
 * ============================================================
 */
export async function runDigestOnce(now = new Date()) {
  if (!alertsEnabled()) return;

  // 60m window, worker runs every 5m by default
  const windowEnd = now;
  const windowStart = new Date(now.getTime() - 60 * 60_000);

  const digestRules = await db.notificationRule.findMany({
    where: { enabled: true, mode: "digest" },
    include: { channels: true }
  });

  if (digestRules.length === 0) return;

  const byTenant = new Map<string, any[]>();
  for (const r of digestRules) {
    const list = byTenant.get(r.tenantId) ?? [];
    list.push(r);
    byTenant.set(r.tenantId, list);
  }

  for (const [tenantId, rules] of byTenant) {
    const incidents = await db.incident.findMany({
      where: { tenantId, lastSeenAt: { gte: windowStart, lte: windowEnd } },
      orderBy: { lastSeenAt: "desc" },
      take: 500
    });
    if (incidents.length === 0) continue;

    const channels = await db.notificationChannel.findMany({ where: { tenantId, enabled: true } });
    const channelMap = new Map(channels.map((c) => [c.id, c]));

    for (const rule of rules) {
      const matching = incidents.filter((i) => {
        const v = asIncidentVerdict(i.verdict);
        if (!v) return false;
        return ruleMatches(rule, {
          hostname: i.hostname,
          maxRisk: i.maxRisk,
          verdict: v,
          // Digest is incident-based; treat as NAVIGATE for filtering unless you later add incident eventType
          eventType: "NAVIGATE"
        });
      });

      if (matching.length === 0) continue;

      const blocks = matching.filter((m) => m.verdict === "block").length;
      const warns = matching.filter((m) => m.verdict === "warn").length;

      const topHosts: DigestTopHost[] = matching
        .slice()
        .sort((a, b) => b.maxRisk - a.maxRisk)
        .slice(0, 20)
        .map((m) => {
          const vv = asIncidentVerdict(m.verdict) ?? "warn"; // safe fallback (shouldn’t hit because we filtered)
          return {
            hostname: m.hostname,
            verdict: vv,
            maxRisk: m.maxRisk,
            count: m.eventCount
          };
        });

      const digestPayload: DigestPayload = {
        tenantId,
        windowStart,
        windowEnd,
        summary: { blocks, warns, topHosts }
      };

      for (const link of rule.channels ?? []) {
        const ch = channelMap.get(link.channelId);
        if (!ch) continue;

        const maxRisk = topHosts[0]?.maxRisk ?? 0;
        const worstVerdict: IncidentVerdict = blocks > 0 ? "block" : "warn";
        if (!channelAllows(ch, { maxRisk, verdict: worstVerdict, eventType: "NAVIGATE" })) continue;

        const delivery = await recordDelivery({
          tenantId,
          channelId: ch.id,
          kind: "incident_digest",
          status: "pending",
          attemptCount: 1,
          lastError: null,
          payload: digestPayload,
          sentAt: null,
          nextAttemptAt: null,
          lastAttemptAt: new Date()
        });

        try {
          if (ch.type === "slack") {
            const webhookUrl = getSlackWebhookUrl(ch.config as Prisma.JsonValue);
            if (!webhookUrl) {
              await updateDelivery(delivery.id, { status: "failed", lastError: "slack_failed invalid_config" });
              continue;
            }

            const msg = buildSlackMessageDigest(digestPayload);
            const res = await postJson(webhookUrl, msg);

            if (!res.ok) {
              const errMsg = `slack_failed status=${res.status} body=${truncate(res.text, 300)}`.slice(0, 500);
              const nextAttemptAt = isTransientFailure(res.status)
                ? new Date(Date.now() + computeBackoffMs(1))
                : null;

              await updateDelivery(delivery.id, { status: "failed", lastError: errMsg, nextAttemptAt });
              if (isPermanentFailure(res.status, res.text)) await maybeAutoDisableChannel(ch.id, errMsg);
              continue;
            }

            await updateDelivery(delivery.id, { status: "sent", sentAt: new Date(), lastError: null, nextAttemptAt: null });
            continue;
          }

          if (ch.type === "webhook") {
            const wh = getWebhookConfig(ch.config as Prisma.JsonValue);
            if (!wh) {
              await updateDelivery(delivery.id, { status: "failed", lastError: "webhook_failed invalid_config" });
              continue;
            }

            const headers: Record<string, string> = {};
            if (wh.secret && wh.secret.length >= 16) {
              headers["x-threatpulse-signature"] = signWebhook(wh.secret, digestPayload);
            }

            const res = await postJson(wh.url, { kind: "incident_digest", payload: digestPayload }, headers);

            if (!res.ok) {
              const errMsg = `webhook_failed status=${res.status} body=${truncate(res.text, 300)}`.slice(0, 500);
              const nextAttemptAt = isTransientFailure(res.status)
                ? new Date(Date.now() + computeBackoffMs(1))
                : null;

              await updateDelivery(delivery.id, { status: "failed", lastError: errMsg, nextAttemptAt });
              if (isPermanentFailure(res.status, res.text)) await maybeAutoDisableChannel(ch.id, errMsg);
              continue;
            }

            await updateDelivery(delivery.id, { status: "sent", sentAt: new Date(), lastError: null, nextAttemptAt: null });
            continue;
          }

          await updateDelivery(delivery.id, { status: "failed", lastError: "unsupported_channel_for_digest" });
        } catch (err: any) {
          await updateDelivery(delivery.id, {
            status: "failed",
            lastError: `send_failed ${truncate(String(err?.message ?? "unknown_error"), 300)}`.slice(0, 500)
          });
        }
      }
    }
  }
}

/**
 * ============================================================
 * WORKER: Retry failed deliveries (nextAttemptAt due)
 * ============================================================
 */
export async function runRetryOnce(now = new Date()) {
  if (!alertsEnabled()) return;

  const due = await db.notificationDelivery.findMany({
    where: {
      status: "failed",
      nextAttemptAt: { not: null, lte: now }
    },
    orderBy: { nextAttemptAt: "asc" },
    take: 50
  });

  if (due.length === 0) return;

  const channelIds = Array.from(new Set(due.map((d) => d.channelId)));
  const channels = await db.notificationChannel.findMany({ where: { id: { in: channelIds } } });
  const channelMap = new Map(channels.map((c) => [c.id, c]));

  await Promise.all(
    due.map(async (d) => {
      const ch = channelMap.get(d.channelId);
      if (!ch || !ch.enabled) return;

      const attempt = (typeof d.attemptCount === "number" ? d.attemptCount : 0) + 1;
      const nextAttemptAt = attempt >= 4 ? null : new Date(Date.now() + computeBackoffMs(attempt));

      try {
        if (ch.type === "slack") {
          const webhookUrl = getSlackWebhookUrl(ch.config as Prisma.JsonValue);
          if (!webhookUrl) {
            await updateDelivery(d.id, {
              attemptCount: attempt,
              lastAttemptAt: new Date(),
              nextAttemptAt: null,
              lastError: "slack_failed invalid_config"
            });
            return;
          }

          const kind = d.kind;
          const payload = d.payload as any;

          const msg =
            kind === "incident_digest"
              ? buildSlackMessageDigest(payload as DigestPayload)
              : buildSlackMessageIncident(payload as IncidentCreatedPayload);

          const res = await postJson(webhookUrl, msg);

          if (!res.ok) {
            const errMsg = `slack_failed status=${res.status} body=${truncate(res.text, 300)}`.slice(0, 500);

            await updateDelivery(d.id, {
              attemptCount: attempt,
              lastAttemptAt: new Date(),
              lastError: errMsg,
              nextAttemptAt: isPermanentFailure(res.status, res.text) ? null : nextAttemptAt
            });

            if (isPermanentFailure(res.status, res.text)) await maybeAutoDisableChannel(ch.id, errMsg);
            return;
          }

          await updateDelivery(d.id, {
            status: "sent",
            sentAt: new Date(),
            attemptCount: attempt,
            lastAttemptAt: new Date(),
            lastError: null,
            nextAttemptAt: null
          });
          return;
        }

        if (ch.type === "webhook") {
          const wh = getWebhookConfig(ch.config as Prisma.JsonValue);
          if (!wh) {
            await updateDelivery(d.id, {
              attemptCount: attempt,
              lastAttemptAt: new Date(),
              nextAttemptAt: null,
              lastError: "webhook_failed invalid_config"
            });
            return;
          }

          const headers: Record<string, string> = {};
          if (wh.secret && wh.secret.length >= 16) {
            headers["x-threatpulse-signature"] = signWebhook(wh.secret, d.payload);
          }

          const res = await postJson(wh.url, { kind: d.kind, payload: d.payload }, headers);

          if (!res.ok) {
            const errMsg = `webhook_failed status=${res.status} body=${truncate(res.text, 300)}`.slice(0, 500);

            await updateDelivery(d.id, {
              attemptCount: attempt,
              lastAttemptAt: new Date(),
              lastError: errMsg,
              nextAttemptAt: isPermanentFailure(res.status, res.text) ? null : nextAttemptAt
            });

            if (isPermanentFailure(res.status, res.text)) await maybeAutoDisableChannel(ch.id, errMsg);
            return;
          }

          await updateDelivery(d.id, {
            status: "sent",
            sentAt: new Date(),
            attemptCount: attempt,
            lastAttemptAt: new Date(),
            lastError: null,
            nextAttemptAt: null
          });
          return;
        }

        await updateDelivery(d.id, {
          attemptCount: attempt,
          lastAttemptAt: new Date(),
          nextAttemptAt: null,
          lastError: "email_failed not_implemented"
        });
      } catch (err: any) {
        await updateDelivery(d.id, {
          attemptCount: attempt,
          lastAttemptAt: new Date(),
          lastError: `retry_failed ${truncate(String(err?.message ?? "unknown_error"), 300)}`.slice(0, 500),
          nextAttemptAt
        });
      }
    })
  );
}
