import "dotenv/config";
import crypto from "node:crypto";
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

type IncidentVerdict = "warn" | "block";
type ChannelType = "slack" | "webhook" | "email";

/** ✅ Fix #1: define DeliveryStatus (your TS error) */
type DeliveryStatus = "pending" | "sent" | "failed" | "skipped";

type DigestHost = { hostname: string; verdict: IncidentVerdict; maxRisk: number; count: number };

type DigestPayload = {
  tenantId: string;
  windowStart: Date;
  windowEnd: Date;
  summary: {
    blocks: number;
    warns: number;
    topHosts: DigestHost[];
  };
};

type NotifyOptions = { onlyChannelId?: string };

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
 * (No array indexing => no "number | undefined" problems)
 */
function computeBackoffMs(attemptCount: number): number {
  if (attemptCount <= 1) return 60_000;
  if (attemptCount === 2) return 5 * 60_000;
  if (attemptCount === 3) return 30 * 60_000;
  return 2 * 60 * 60_000;
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

async function postJson(url: string, body: unknown, headers?: Record<string, string>) {
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

function asIncidentVerdict(v: unknown): IncidentVerdict | null {
  return v === "warn" || v === "block" ? v : null;
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

function buildSlackMessageDigest(p: DigestPayload): { text: string; blocks: SlackBlock[] } {
  const ws = p.windowStart.toISOString();
  const we = p.windowEnd.toISOString();

  const lines: string[] = [
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

function channelAllows(
  channel: { filters: unknown; enabled: boolean },
  ctx: { maxRisk: number; verdict: IncidentVerdict; eventType: "NAVIGATE" | "DOWNLOAD" }
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

async function getActiveSuppression(tenantId: string, hostname: string) {
  const row = await db.notificationSuppression.findFirst({
    where: { tenantId, hostname: hostname.toLowerCase(), mutedUntil: { gt: new Date() } },
    select: { mutedUntil: true, reason: true }
  });
  return row ? { mutedUntil: row.mutedUntil, reason: row.reason ?? null } : null;
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
    where: { channelId, status: "failed" as any, createdAt: { gt: new Date(Date.now() - 24 * 60 * 60_000) } }
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
    db.notificationRule.findMany({ where: { tenantId, enabled: true }, include: { channels: true } }),
    db.notificationChannel.findMany({ where: { tenantId, enabled: true }, orderBy: { createdAt: "desc" } })
  ]);

  const channelMap = new Map(channels.map((c) => [c.id, c]));
  const only = opts?.onlyChannelId ? new Set([opts.onlyChannelId]) : null;

  const matchedChannelIds = new Set<string>();
  for (const rule of rules) {
    if (rule.mode !== "immediate") continue;
    if (!ruleMatches(rule, { hostname, maxRisk: payload.maxRisk, verdict: payload.verdict, eventType: payload.eventType }))
      continue;

    for (const link of rule.channels ?? []) {
      if (only && !only.has(link.channelId)) continue;
      matchedChannelIds.add(link.channelId);
    }
  }

  if (matchedChannelIds.size === 0) return;

  const targets = Array.from(matchedChannelIds)
    .map((id) => channelMap.get(id))
    .filter((c): c is NonNullable<typeof c> => Boolean(c))
    .filter((c) => channelAllows(c, { maxRisk: payload.maxRisk, verdict: payload.verdict, eventType: payload.eventType }));

  if (targets.length === 0) return;

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
        const cfg = asRecord(ch.config);

        if (ch.type === "slack") {
          const webhookUrl = getString(cfg, "webhookUrl");
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

            if (isPermanentFailure(res.status, res.text)) await maybeAutoDisableChannel(ch.id, errMsg);
            return;
          }

          await updateDelivery(delivery.id, { status: "sent", sentAt: new Date(), lastError: null, nextAttemptAt: null });
          return;
        }

        if (ch.type === "webhook") {
          const url = getString(cfg, "url");
          const secret = getString(cfg, "secret");

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

            if (isPermanentFailure(res.status, res.text)) await maybeAutoDisableChannel(ch.id, errMsg);
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

/**
 * ============================================================
 * WORKER: Digest rollups
 * ============================================================
 */
export async function runDigestOnce(now = new Date()) {
  if (!alertsEnabled()) return;

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
        return ruleMatches(rule, { hostname: i.hostname, maxRisk: i.maxRisk, verdict: v, eventType: "NAVIGATE" });
      });
      if (matching.length === 0) continue;

      const blocks = matching.filter((m) => m.verdict === "block").length;
      const warns = matching.filter((m) => m.verdict === "warn").length;

      const topHosts: DigestHost[] = matching
        .slice()
        .sort((a, b) => b.maxRisk - a.maxRisk)
        .slice(0, 20)
        .map((m) => ({
          hostname: m.hostname,
          verdict: (asIncidentVerdict(m.verdict) ?? "warn") as IncidentVerdict,
          maxRisk: m.maxRisk,
          count: m.eventCount
        }));

      const digestPayload: DigestPayload = {
        tenantId,
        windowStart,
        windowEnd,
        summary: { blocks, warns, topHosts }
      };

      /**
       * ✅ Fix #2: eliminate "Object is possibly 'undefined'"
       * No direct `[0].prop` access.
       */
      const maxRisk = topHosts.length > 0 ? topHosts[0]!.maxRisk : 0;
      const worstVerdict: IncidentVerdict = blocks > 0 ? "block" : "warn";

      for (const link of rule.channels ?? []) {
        const ch = channelMap.get(link.channelId);
        if (!ch) continue;

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
          const cfg = asRecord(ch.config);

          if (ch.type === "slack") {
            const webhookUrl = getString(cfg, "webhookUrl");
            if (!webhookUrl) {
              await updateDelivery(delivery.id, { status: "failed", lastError: "slack_failed invalid_config" });
              continue;
            }

            const msg = buildSlackMessageDigest(digestPayload);
            const res = await postJson(webhookUrl, msg);

            if (!res.ok) {
              const errMsg = `slack_failed status=${res.status} body=${res.text}`.slice(0, 500);
              const nextAttemptAt = isTransientFailure(res.status) ? new Date(Date.now() + computeBackoffMs(1)) : null;

              await updateDelivery(delivery.id, { status: "failed", lastError: errMsg, nextAttemptAt });
              if (isPermanentFailure(res.status, res.text)) await maybeAutoDisableChannel(ch.id, errMsg);
              continue;
            }

            await updateDelivery(delivery.id, { status: "sent", sentAt: new Date(), lastError: null, nextAttemptAt: null });
            continue;
          }

          if (ch.type === "webhook") {
            const url = getString(cfg, "url");
            const secret = getString(cfg, "secret");

            if (!url) {
              await updateDelivery(delivery.id, { status: "failed", lastError: "webhook_failed invalid_config" });
              continue;
            }

            const headers: Record<string, string> = {};
            if (secret && secret.length >= 16) {
              headers["x-threatpulse-signature"] = signWebhook(secret, digestPayload);
            }

            const res = await postJson(url, { kind: "incident_digest", payload: digestPayload }, headers);

            if (!res.ok) {
              const errMsg = `webhook_failed status=${res.status} body=${res.text}`.slice(0, 500);
              const nextAttemptAt = isTransientFailure(res.status) ? new Date(Date.now() + computeBackoffMs(1)) : null;

              await updateDelivery(delivery.id, { status: "failed", lastError: errMsg, nextAttemptAt });
              if (isPermanentFailure(res.status, res.text)) await maybeAutoDisableChannel(ch.id, errMsg);
              continue;
            }

            await updateDelivery(delivery.id, { status: "sent", sentAt: new Date(), lastError: null, nextAttemptAt: null });
            continue;
          }

          await updateDelivery(delivery.id, { status: "failed", lastError: "unsupported_channel_for_digest" });
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : "unknown_error";
          await updateDelivery(delivery.id, { status: "failed", lastError: `send_failed ${msg}`.slice(0, 500) });
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
    where: { status: "failed" as any, nextAttemptAt: { not: null, lte: now } },
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

      const attempt = (d.attemptCount ?? 0) + 1;
      const nextAttemptAt = attempt >= 4 ? null : new Date(Date.now() + computeBackoffMs(attempt));

      try {
        const cfg = asRecord(ch.config);

        if (ch.type === "slack") {
          const webhookUrl = getString(cfg, "webhookUrl");
          if (!webhookUrl) {
            await updateDelivery(d.id, {
              attemptCount: attempt,
              lastAttemptAt: new Date(),
              nextAttemptAt: null,
              lastError: "slack_failed invalid_config"
            });
            return;
          }

          const payload = d.payload as any;
          const msg =
            d.kind === "incident_digest"
              ? buildSlackMessageDigest(payload as DigestPayload)
              : buildSlackMessageIncident(payload as IncidentCreatedPayload);

          const res = await postJson(webhookUrl, msg);

          if (!res.ok) {
            const errMsg = `slack_failed status=${res.status} body=${res.text}`.slice(0, 500);

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
            status: "sent" as any,
            sentAt: new Date(),
            attemptCount: attempt,
            lastAttemptAt: new Date(),
            lastError: null,
            nextAttemptAt: null
          });
          return;
        }

        if (ch.type === "webhook") {
          const url = getString(cfg, "url");
          const secret = getString(cfg, "secret");

          if (!url) {
            await updateDelivery(d.id, {
              attemptCount: attempt,
              lastAttemptAt: new Date(),
              nextAttemptAt: null,
              lastError: "webhook_failed invalid_config"
            });
            return;
          }

          const headers: Record<string, string> = {};
          if (secret && secret.length >= 16) {
            headers["x-threatpulse-signature"] = signWebhook(secret, d.payload);
          }

          const res = await postJson(url, { kind: d.kind, payload: d.payload }, headers);

          if (!res.ok) {
            const errMsg = `webhook_failed status=${res.status} body=${res.text}`.slice(0, 500);

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
            status: "sent" as any,
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
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : "unknown_error";
        await updateDelivery(d.id, {
          attemptCount: attempt,
          lastAttemptAt: new Date(),
          lastError: `retry_failed ${msg}`.slice(0, 500),
          nextAttemptAt
        });
      }
    })
  );
}
