import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import cors from "@fastify/cors";
import { z } from "zod";
import "dotenv/config";
import crypto from "node:crypto";
import { db } from "./db.js";
import { notifyIncidentCreated } from "./notifications.js"; // NodeNext requires explicit extension

/**
 * =========================
 * Environment validation
 * =========================
 * Commandment: validation/sanitization at the boundary.
 */
const envSchema = z.object({
  PORT: z.coerce.number().default(4000),
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),

  // Commandment: secret management (never log; rotate in prod)
  TENANT_TOKEN_SECRET: z.string().min(20),
  DEVICE_TOKEN_SECRET: z.string().min(20),

  // Commandment: strict CORS (lock down origins)
  DASHBOARD_ORIGIN: z.string().url(),
  EXTENSION_ORIGIN: z.string().optional()
});

const env = envSchema.parse(process.env);

type TenantAuth = {
  tenantId: string;
  plan: "trial" | "pro" | "enterprise";
};

type DeviceAuth = {
  deviceId: string;
  userId: string;
};

type AuthContext = {
  tenant: TenantAuth;
  device: DeviceAuth;
};

declare module "fastify" {
  interface FastifyRequest {
    auth?: AuthContext;
  }
}

/**
 * Prisma transaction client type (version-proof)
 */
type TxCallback = Extract<Parameters<typeof db.$transaction>[0], (tx: any) => any>;
type TxClient = Parameters<TxCallback>[0];

type Verdict = "allow" | "warn" | "block";

/**
 * =========================
 * Helpers: crypto + auth token verification
 * =========================
 * Token format (HMAC):
 *   base64url(payloadJson).base64url(hmacSHA256(payloadJson, secret))
 *
 * Commandment: strict authorization
 * - Timing-safe signature comparisons
 * - No token contents logged
 */
function timingSafeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function verifyHmacToken<T>(token: string, secret: string): T | null {
  const parts = token.split(".");
  if (parts.length !== 2) return null;

  const [payloadB64, sigB64] = parts;
  if (!payloadB64 || !sigB64) return null;

  const payloadJson = Buffer.from(payloadB64, "base64url").toString("utf8");

  const expectedSig = crypto.createHmac("sha256", secret).update(payloadJson).digest("base64url");
  if (!timingSafeEqual(expectedSig, sigB64)) return null;

  try {
    return JSON.parse(payloadJson) as T;
  } catch {
    return null;
  }
}

/**
 * Commandment: safe logging (avoid full URL incl. query).
 */
function safeUrlForLog(urlStr: string): string {
  try {
    const u = new URL(urlStr);
    return `${u.protocol}//${u.hostname}${u.pathname}`;
  } catch {
    return "(invalid-url)";
  }
}

function requireAuth(req: FastifyRequest, reply: FastifyReply): AuthContext | null {
  if (!req.auth) {
    reply.code(401).send({ error: "unauthorized" });
    return null;
  }
  return req.auth;
}

/**
 * Normalize and validate hostnames (lightweight, no DNS).
 * - lowercases
 * - strips scheme/path if user pastes a URL
 * - rejects whitespace / suspicious chars
 */
function normalizeHostname(input: string): string | null {
  const raw = input.trim();
  if (!raw) return null;

  // If user pasted a URL, extract hostname.
  try {
    if (raw.includes("://")) {
      const u = new URL(raw);
      return u.hostname.toLowerCase();
    }
  } catch {
    // ignore; fall back to raw
  }

  const host = raw.toLowerCase();

  // basic sanity: no spaces, no slashes, no @, no port, no query
  if (/[ \t\r\n/@?#]/.test(host)) return null;

  // allow punycode + normal DNS-ish labels
  if (!/^[a-z0-9.-]+$/.test(host)) return null;
  if (host.length > 253) return null;

  // must contain at least one dot (prevents "localhost" noise in prod dashboards)
  if (!host.includes(".")) return null;

  return host;
}

/**
 * =========================
 * Zod schemas
 * =========================
 * Commandment: validation & sanitization at boundary
 */
const reputationCheckBody = z.object({
  url: z.string().url(),
  eventType: z.enum(["NAVIGATE", "DOWNLOAD"]).default("NAVIGATE")
});

const eventBody = z.object({
  type: z.enum(["NAVIGATE", "DOWNLOAD"]),
  url: z.string().url(),
  ts: z.number().int().positive()
});

const reputationResponse = z.object({
  risk: z.number().int().nonnegative(),
  verdict: z.enum(["allow", "warn", "block"]),
  reasons: z.array(z.string()),
  checked: z.object({
    hostname: z.string(),
    url: z.string().url()
  })
});

const channelFiltersSchema = z
  .object({
    minRisk: z.number().int().min(0).max(100).optional(),
    verdicts: z.array(z.enum(["warn", "block"])).optional(),
    eventTypes: z.array(z.enum(["NAVIGATE", "DOWNLOAD"])).optional()
  })
  .optional();

const channelUpsertBody = z.discriminatedUnion("type", [
  z.object({
    id: z.string().optional(),
    type: z.literal("slack"),
    enabled: z.boolean().optional(),
    name: z.string().min(1).optional(),
    config: z.object({ webhookUrl: z.string().url() }),
    filters: channelFiltersSchema
  }),
  z.object({
    id: z.string().optional(),
    type: z.literal("email"),
    enabled: z.boolean().optional(),
    name: z.string().min(1).optional(),
    config: z.object({
      to: z.string().email(),
      from: z.string().email().optional()
    }),
    filters: channelFiltersSchema
  }),
  z.object({
    id: z.string().optional(),
    type: z.literal("webhook"),
    enabled: z.boolean().optional(),
    name: z.string().min(1).optional(),
    config: z.object({
      url: z.string().url(),
      secret: z.string().min(16).optional()
    }),
    filters: channelFiltersSchema
  })
]);

const testChannelBody = z.object({
  channelId: z.string().min(1)
});

const deliveriesQuery = z.object({
  limit: z.coerce.number().int().min(1).max(200).default(50),
  cursor: z.string().optional(),
  status: z.enum(["pending", "sent", "failed", "skipped"]).optional(),
  channelId: z.string().optional()
});

/**
 * =========================
 * Notification Rules schemas
 * =========================
 * Rules define "when", channels define "where".
 */
const ruleSchema = z.object({
  name: z.string().min(1),
  enabled: z.boolean().optional(),
  mode: z.enum(["immediate", "digest"]).optional(),

  minRisk: z.number().int().min(0).max(100).optional(),
  verdicts: z.array(z.enum(["warn", "block"])).optional(),
  eventTypes: z.array(z.enum(["NAVIGATE", "DOWNLOAD"])).optional(),

  hostAllow: z.array(z.string().min(1)).optional(),
  hostDeny: z.array(z.string().min(1)).optional(),

  channelIds: z.array(z.string().min(1)).min(1)
});

const rulePatchSchema = ruleSchema.partial().extend({
  channelIds: z.array(z.string().min(1)).min(1).optional()
});

/**
 * =========================
 * Suppressions (Step 3)
 * =========================
 * Product move: “Mute this host for X minutes” with reason.
 */
const suppressionUpsertBody = z.object({
  hostname: z.string().min(1),
  minutes: z.number().int().min(5).max(30 * 24 * 60).default(60), // up to 30 days
  reason: z.string().min(1).max(120).optional()
});

const suppressionsListQuery = z.object({
  active: z
    .union([z.literal("true"), z.literal("false")])
    .optional()
    .transform((v) => (v === "false" ? false : true))
});

const suppressionDeleteByIdParams = z.object({
  id: z.string().min(1)
});

const suppressionDeleteByHostnameParams = z.object({
  hostname: z.string().min(1)
});

/**
 * Commandment: secret management — never return webhook URL / secrets to clients.
 */
function redactChannelForResponse(channel: any) {
  const cfg = channel.config ?? {};
  const redactedConfig: Record<string, unknown> = { ...(typeof cfg === "object" && cfg ? cfg : {}) };

  if (channel.type === "slack" && typeof (cfg as any).webhookUrl === "string") {
    redactedConfig.webhookUrl = "redacted";
  }
  if (channel.type === "webhook" && typeof (cfg as any).secret === "string") {
    redactedConfig.secret = "redacted";
  }

  return { ...channel, config: redactedConfig };
}

async function bootstrapDefaultRulesIfNeeded(tenantId: string, channelId: string) {
  /**
   * Top-tier onboarding:
   * If a tenant creates their first channel and has no rules yet,
   * auto-create two sensible defaults:
   * - Block -> Alerts
   * - Warn (>=70) -> Alerts
   */
  const existingRules = await db.notificationRule.count({ where: { tenantId } });
  if (existingRules > 0) return;

  await db.notificationRule.create({
    data: {
      tenantId,
      name: "Block → Alerts",
      enabled: true,
      mode: "immediate",
      minRisk: 90,
      verdicts: ["block"],
      eventTypes: [],
      hostAllow: [],
      hostDeny: [],
      channels: { create: [{ channelId }] }
    }
  });

  await db.notificationRule.create({
    data: {
      tenantId,
      name: "Warn → Alerts (High Risk)",
      enabled: true,
      mode: "immediate",
      minRisk: 70,
      verdicts: ["warn"],
      eventTypes: [],
      hostAllow: [],
      hostDeny: [],
      channels: { create: [{ channelId }] }
    }
  });
}

function createApp() {
  const app = Fastify({
    logger: {
      level: env.NODE_ENV === "production" ? "info" : "debug",
      // Commandment: safe logging (never log secrets/tokens)
      redact: ["req.headers.authorization", "req.headers['x-tenant-token']", "req.headers['x-device-token']"]
    }
  });

  /**
   * =========================
   * Security + platform basics
   * =========================
   */
  app.register(helmet);

  app.register(cors, {
    origin: (origin, cb) => {
      // Allow non-browser tools like curl (no Origin header).
      if (!origin) return cb(null, true);

      const allowed = new Set<string>([env.DASHBOARD_ORIGIN]);
      if (env.EXTENSION_ORIGIN) allowed.add(env.EXTENSION_ORIGIN);

      cb(null, allowed.has(origin));
    },
    credentials: false
  });

  /**
   * =========================
   * Rate limiting
   * =========================
   * Commandment: rate limiting and abuse protection.
   */
  app.register(rateLimit, {
    global: true,
    max: 120,
    timeWindow: "1 minute",
    keyGenerator: (req) => `${req.ip}`
  });

  /**
   * =========================
   * Health (no auth)
   * =========================
   */
  app.get("/health", async () => ({ ok: true }));

  /**
   * =========================
   * Auth preHandler for /v1/*
   * =========================
   * Commandment: strict authorization
   */
  app.addHook("preHandler", async (req, reply) => {
    if (!req.url.startsWith("/v1/")) return;

    const tenantToken = req.headers["x-tenant-token"];
    const deviceToken = req.headers["x-device-token"];

    if (typeof tenantToken !== "string" || typeof deviceToken !== "string") {
      return reply.code(401).send({ error: "unauthorized" });
    }

    const tenant = verifyHmacToken<TenantAuth>(tenantToken, env.TENANT_TOKEN_SECRET);
    const device = verifyHmacToken<DeviceAuth>(deviceToken, env.DEVICE_TOKEN_SECRET);

    if (!tenant || !device) {
      return reply.code(401).send({ error: "unauthorized" });
    }

    req.auth = { tenant, device };
  });

  /**
   * =========================
   * POST /v1/reputation/check
   * =========================
   */
  app.post("/v1/reputation/check", async (req, reply) => {
    const parsed = reputationCheckBody.safeParse(req.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "bad_request", details: parsed.error.flatten() });
    }

    const { url, eventType } = parsed.data;

    let u: URL;
    try {
      u = new URL(url);
    } catch {
      return reply.code(400).send({ error: "bad_request" });
    }

    const hostname = u.hostname.toLowerCase();
    const reasons: string[] = [];
    let risk = 0;

    /**
     * DEV-ONLY START: deterministic WARN/BLOCK triggers
     */
    if (env.NODE_ENV !== "production") {
      const t = u.searchParams.get("chc-test");
      if (t === "warn") {
        risk = Math.max(risk, 70);
        reasons.push("dev_test_warn");
      } else if (t === "block") {
        risk = Math.max(risk, 95);
        reasons.push("dev_test_block");
      }
    }

    if (hostname.startsWith("xn--")) {
      risk = Math.max(risk, 75);
      reasons.push("punycode_domain");
    }

    const suspiciousTlds = new Set(["zip", "mov"]);
    const tld = hostname.split(".").pop() ?? "";
    if (suspiciousTlds.has(tld)) {
      risk = Math.max(risk, 60);
      reasons.push("suspicious_tld");
    }

    if (eventType === "DOWNLOAD") {
      risk = Math.max(risk, 50);
      reasons.push("download_event");
    }

    const verdict: Verdict = risk >= 90 ? "block" : risk >= 60 ? "warn" : "allow";

    return reply.send({ risk, verdict, reasons, checked: { hostname, url } });
  });

  /**
   * =========================
   * Notifications: Channels
   * =========================
   */
  app.get("/v1/notifications/channels", async (req, reply) => {
    const auth = requireAuth(req, reply);
    if (!auth) return;

    const channels = await db.notificationChannel.findMany({
      where: { tenantId: auth.tenant.tenantId },
      orderBy: { createdAt: "desc" }
    });

    return reply.send({ channels: channels.map(redactChannelForResponse) });
  });

  app.post("/v1/notifications/channels", async (req, reply) => {
    const auth = requireAuth(req, reply);
    if (!auth) return;

    const parsed = channelUpsertBody.safeParse(req.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "bad_request", details: parsed.error.flatten() });
    }

    const body = parsed.data;
    const tenantId = auth.tenant.tenantId;
    const enabled = body.enabled ?? true;

    if (body.id) {
      const existing = await db.notificationChannel.findFirst({ where: { id: body.id, tenantId } });
      if (!existing) return reply.code(404).send({ error: "not_found" });

      const channel = await db.notificationChannel.update({
        where: { id: body.id },
        data: {
          enabled,
          name: body.name ?? null,
          type: body.type,
          config: body.config as any,
          filters: body.filters ?? undefined
        }
      });

      return reply.send({ channel: redactChannelForResponse(channel) });
    }

    const channel = await db.notificationChannel.create({
      data: {
        tenantId,
        enabled,
        name: body.name ?? null,
        type: body.type,
        config: body.config as any,
        filters: body.filters ?? undefined
      }
    });

    // ✅ Best-practice onboarding: create default rules if tenant has none
    try {
      await bootstrapDefaultRulesIfNeeded(tenantId, channel.id);
    } catch (err) {
      req.log.warn({ err }, "bootstrap_rules_failed");
    }

    return reply.send({ channel: redactChannelForResponse(channel) });
  });

  app.delete("/v1/notifications/channels/:id", async (req, reply) => {
    const auth = requireAuth(req, reply);
    if (!auth) return;

    const tenantId = auth.tenant.tenantId;
    const id = (req.params as any).id as string;

    const existing = await db.notificationChannel.findFirst({ where: { id, tenantId } });
    if (!existing) return reply.code(404).send({ error: "not_found" });

    await db.notificationChannel.delete({ where: { id } });
    return reply.send({ ok: true });
  });

  /**
   * =========================
   * Notifications: Rules CRUD
   * =========================
   */
  app.get("/v1/notifications/rules", async (req, reply) => {
    const auth = requireAuth(req, reply);
    if (!auth) return;

    const rules = await db.notificationRule.findMany({
      where: { tenantId: auth.tenant.tenantId },
      orderBy: { createdAt: "desc" },
      include: { channels: true }
    });

    return reply.send({
      rules: rules.map((r) => ({
        id: r.id,
        tenantId: r.tenantId,
        name: r.name,
        enabled: r.enabled,
        mode: r.mode,
        minRisk: r.minRisk,
        verdicts: r.verdicts,
        eventTypes: r.eventTypes,
        hostAllow: r.hostAllow,
        hostDeny: r.hostDeny,
        channelIds: r.channels.map((rc) => rc.channelId),
        createdAt: r.createdAt,
        updatedAt: r.updatedAt
      }))
    });
  });

  app.post("/v1/notifications/rules", async (req, reply) => {
    const auth = requireAuth(req, reply);
    if (!auth) return;

    const parsed = ruleSchema.safeParse(req.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "bad_request", details: parsed.error.flatten() });
    }

    const tenantId = auth.tenant.tenantId;
    const body = parsed.data;

    const channels = await db.notificationChannel.findMany({
      where: { tenantId, id: { in: body.channelIds } },
      select: { id: true }
    });
    if (channels.length !== body.channelIds.length) {
      return reply.code(400).send({ error: "bad_request", message: "invalid_channelIds" });
    }

    const rule = await db.notificationRule.create({
      data: {
        tenantId,
        name: body.name,
        enabled: body.enabled ?? true,
        mode: body.mode ?? "immediate",
        minRisk: body.minRisk ?? null,
        verdicts: body.verdicts ?? [],
        eventTypes: body.eventTypes ?? [],
        hostAllow: body.hostAllow ?? [],
        hostDeny: body.hostDeny ?? [],
        channels: { create: body.channelIds.map((channelId) => ({ channelId })) }
      },
      include: { channels: true }
    });

    return reply.send({
      rule: {
        id: rule.id,
        name: rule.name,
        enabled: rule.enabled,
        mode: rule.mode,
        minRisk: rule.minRisk,
        verdicts: rule.verdicts,
        eventTypes: rule.eventTypes,
        hostAllow: rule.hostAllow,
        hostDeny: rule.hostDeny,
        channelIds: rule.channels.map((rc) => rc.channelId),
        createdAt: rule.createdAt,
        updatedAt: rule.updatedAt
      }
    });
  });

  app.patch("/v1/notifications/rules/:id", async (req, reply) => {
    const auth = requireAuth(req, reply);
    if (!auth) return;

    const tenantId = auth.tenant.tenantId;
    const id = (req.params as any).id as string;

    const parsed = rulePatchSchema.safeParse(req.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "bad_request", details: parsed.error.flatten() });
    }

    const existing = await db.notificationRule.findFirst({ where: { id, tenantId } });
    if (!existing) return reply.code(404).send({ error: "not_found" });

    if (parsed.data.channelIds) {
      const channels = await db.notificationChannel.findMany({
        where: { tenantId, id: { in: parsed.data.channelIds } },
        select: { id: true }
      });
      if (channels.length !== parsed.data.channelIds.length) {
        return reply.code(400).send({ error: "bad_request", message: "invalid_channelIds" });
      }
    }

    const updated = await db.$transaction(async (tx: TxClient) => {
      if (parsed.data.channelIds) {
        await tx.notificationRuleChannel.deleteMany({ where: { ruleId: id } });
        await tx.notificationRuleChannel.createMany({
          data: parsed.data.channelIds.map((channelId) => ({ ruleId: id, channelId }))
        });
      }

      return tx.notificationRule.update({
        where: { id },
        data: {
          name: parsed.data.name ?? undefined,
          enabled: parsed.data.enabled ?? undefined,
          mode: parsed.data.mode ?? undefined,
          minRisk: parsed.data.minRisk ?? undefined,
          verdicts: parsed.data.verdicts ?? undefined,
          eventTypes: parsed.data.eventTypes ?? undefined,
          hostAllow: parsed.data.hostAllow ?? undefined,
          hostDeny: parsed.data.hostDeny ?? undefined
        },
        include: { channels: true }
      });
    });

    return reply.send({
      rule: {
        id: updated.id,
        name: updated.name,
        enabled: updated.enabled,
        mode: updated.mode,
        minRisk: updated.minRisk,
        verdicts: updated.verdicts,
        eventTypes: updated.eventTypes,
        hostAllow: updated.hostAllow,
        hostDeny: updated.hostDeny,
        channelIds: updated.channels.map((rc) => rc.channelId),
        createdAt: updated.createdAt,
        updatedAt: updated.updatedAt
      }
    });
  });

  app.delete("/v1/notifications/rules/:id", async (req, reply) => {
    const auth = requireAuth(req, reply);
    if (!auth) return;

    const tenantId = auth.tenant.tenantId;
    const id = (req.params as any).id as string;

    const existing = await db.notificationRule.findFirst({ where: { id, tenantId } });
    if (!existing) return reply.code(404).send({ error: "not_found" });

    await db.notificationRule.delete({ where: { id } });
    return reply.send({ ok: true });
  });

  /**
   * =========================
   * Notifications: Suppressions (Step 3)
   * =========================
   */
  app.get("/v1/notifications/suppressions", async (req, reply) => {
    const auth = requireAuth(req, reply);
    if (!auth) return;

    const q = suppressionsListQuery.safeParse(req.query);
    if (!q.success) {
      return reply.code(400).send({ error: "bad_request", details: q.error.flatten() });
    }

    const tenantId = auth.tenant.tenantId;
    const activeOnly = q.data.active;
    const now = new Date();

    const rows = await db.notificationSuppression.findMany({
      where: {
        tenantId,
        ...(activeOnly ? { mutedUntil: { gt: now } } : {})
      },
      orderBy: { mutedUntil: "desc" },
      take: 200
    });

    return reply.send({
      suppressions: rows.map((r) => ({
        id: r.id,
        hostname: r.hostname,
        mutedUntil: r.mutedUntil,
        reason: r.reason,
        createdAt: r.createdAt,
        updatedAt: r.updatedAt
      }))
    });
  });

  app.post("/v1/notifications/suppressions", async (req, reply) => {
    const auth = requireAuth(req, reply);
    if (!auth) return;

    const parsed = suppressionUpsertBody.safeParse(req.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "bad_request", details: parsed.error.flatten() });
    }

    const tenantId = auth.tenant.tenantId;

    const normalized = normalizeHostname(parsed.data.hostname);
    if (!normalized) {
      return reply.code(400).send({ error: "bad_request", message: "invalid_hostname" });
    }

    const mutedUntil = new Date(Date.now() + parsed.data.minutes * 60_000);
    const reason = parsed.data.reason ?? null;

    const existing = await db.notificationSuppression.findFirst({ where: { tenantId, hostname: normalized } });

    const row = existing
      ? await db.notificationSuppression.update({
          where: { id: existing.id },
          data: { mutedUntil, reason }
        })
      : await db.notificationSuppression.create({
          data: { tenantId, hostname: normalized, mutedUntil, reason }
        });

    return reply.send({
      suppression: {
        id: row.id,
        hostname: row.hostname,
        mutedUntil: row.mutedUntil,
        reason: row.reason,
        createdAt: row.createdAt,
        updatedAt: row.updatedAt
      }
    });
  });

  /**
   * Prefer delete-by-id to avoid “hostname collisions” and to support future multi-host features.
   */
  app.delete("/v1/notifications/suppressions/id/:id", async (req, reply) => {
    const auth = requireAuth(req, reply);
    if (!auth) return;

    const parsed = suppressionDeleteByIdParams.safeParse(req.params);
    if (!parsed.success) {
      return reply.code(400).send({ error: "bad_request", details: parsed.error.flatten() });
    }

    const tenantId = auth.tenant.tenantId;

    const row = await db.notificationSuppression.findFirst({ where: { id: parsed.data.id, tenantId } });
    if (!row) return reply.code(404).send({ error: "not_found" });

    await db.notificationSuppression.delete({ where: { id: row.id } });
    return reply.send({ ok: true });
  });

  /**
   * Backward-compatible delete by hostname (kept, but id route is preferred).
   */
  app.delete("/v1/notifications/suppressions/:hostname", async (req, reply) => {
    const auth = requireAuth(req, reply);
    if (!auth) return;

    const parsed = suppressionDeleteByHostnameParams.safeParse(req.params);
    if (!parsed.success) {
      return reply.code(400).send({ error: "bad_request", details: parsed.error.flatten() });
    }

    const tenantId = auth.tenant.tenantId;
    const normalized = normalizeHostname(parsed.data.hostname);
    if (!normalized) {
      return reply.code(400).send({ error: "bad_request", message: "invalid_hostname" });
    }

    await db.notificationSuppression.deleteMany({ where: { tenantId, hostname: normalized } });
    return reply.send({ ok: true });
  });

  /**
   * =========================
   * Notifications: Status (ops)
   * =========================
   */
  app.get("/v1/notifications/status", async (req, reply) => {
    const auth = requireAuth(req, reply);
    if (!auth) return;

    const tenantId = auth.tenant.tenantId;

    const now = new Date();
    const since24h = new Date(Date.now() - 24 * 60 * 60_000);

    const [
      channelsTotal,
      channelsEnabled,
      channelsDisabled,
      rulesTotal,
      rulesEnabled,
      suppressionsActive,
      lastDelivery,
      failed24h
    ] = await Promise.all([
      db.notificationChannel.count({ where: { tenantId } }),
      db.notificationChannel.count({ where: { tenantId, enabled: true } }),
      db.notificationChannel.count({ where: { tenantId, enabled: false } }),
      db.notificationRule.count({ where: { tenantId } }),
      db.notificationRule.count({ where: { tenantId, enabled: true } }),
      db.notificationSuppression.count({ where: { tenantId, mutedUntil: { gt: now } } }),
      db.notificationDelivery.findFirst({ where: { tenantId }, orderBy: { createdAt: "desc" } }),
      db.notificationDelivery.count({ where: { tenantId, status: "failed", createdAt: { gt: since24h } } })
    ]);

    return reply.send({
      alertsEnabled: process.env.ALERTS_ENABLED === "true" || process.env.NOTIFICATIONS_ENABLED === "true",
      tenantId,
      channels: { total: channelsTotal, enabled: channelsEnabled, disabled: channelsDisabled },
      rules: { total: rulesTotal, enabled: rulesEnabled },
      suppressions: { active: suppressionsActive },
      deliveries: { failedLast24h: failed24h },
      lastDelivery: lastDelivery
        ? {
            id: lastDelivery.id,
            channelId: lastDelivery.channelId,
            status: lastDelivery.status,
            lastError: lastDelivery.lastError,
            createdAt: lastDelivery.createdAt,
            sentAt: lastDelivery.sentAt,
            nextAttemptAt: lastDelivery.nextAttemptAt,
            lastAttemptAt: lastDelivery.lastAttemptAt
          }
        : null
    });
  });

  /**
   * =========================
   * Notifications: Deliveries (debug)
   * =========================
   */
  app.get("/v1/notifications/deliveries", async (req, reply) => {
    const auth = requireAuth(req, reply);
    if (!auth) return;

    const parsed = deliveriesQuery.safeParse(req.query);
    if (!parsed.success) {
      return reply.code(400).send({ error: "bad_request", details: parsed.error.flatten() });
    }

    const { limit, cursor, status, channelId } = parsed.data;
    const tenantId = auth.tenant.tenantId;

    const where: Record<string, unknown> = { tenantId };
    if (status) (where as any).status = status;
    if (channelId) (where as any).channelId = channelId;

    const deliveries = await db.notificationDelivery.findMany({
      where: where as any,
      orderBy: { createdAt: "desc" },
      take: limit + 1,
      ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {})
    });

    const hasMore = deliveries.length > limit;
    const page = hasMore ? deliveries.slice(0, limit) : deliveries;
    const nextCursor = hasMore ? page[page.length - 1]?.id : null;

    return reply.send({
      deliveries: page.map((d) => ({
        id: d.id,
        channelId: d.channelId,
        kind: d.kind,
        status: d.status,
        attemptCount: d.attemptCount,
        lastError: d.lastError,
        sentAt: d.sentAt,
        createdAt: d.createdAt,
        nextAttemptAt: d.nextAttemptAt,
        lastAttemptAt: d.lastAttemptAt
      })),
      nextCursor
    });
  });

  /**
   * =========================
   * Notifications: Test
   * =========================
   * Sends a test incident notification ONLY to the provided channelId.
   */
  app.post("/v1/notifications/test", async (req, reply) => {
    const auth = requireAuth(req, reply);
    if (!auth) return;

    const parsed = testChannelBody.safeParse(req.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "bad_request", details: parsed.error.flatten() });
    }

    const tenantId = auth.tenant.tenantId;

    const channel = await db.notificationChannel.findFirst({
      where: { id: parsed.data.channelId, tenantId }
    });

    if (!channel) return reply.code(404).send({ error: "not_found" });

    try {
      await notifyIncidentCreated(
        {
          tenantId,
          hostname: "example.com",
          verdict: "block",
          maxRisk: 95,
          reasons: ["test_notification"],
          firstSeenAt: new Date(),
          eventType: "DOWNLOAD"
        },
        { onlyChannelId: channel.id }
      );
    } catch (err) {
      req.log.warn({ err }, "notification_test_failed");
      return reply.code(500).send({ ok: false });
    }

    return reply.send({ ok: true });
  });

  /**
   * =========================
   * POST /v1/events
   * =========================
   */
  app.post("/v1/events", async (req, reply) => {
    const auth = requireAuth(req, reply);
    if (!auth) return;

    const parsed = eventBody.safeParse(req.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "bad_request", details: parsed.error.flatten() });
    }

    const { type, url, ts } = parsed.data;
    const { tenant, device } = auth;

    const injected = await app.inject({
      method: "POST",
      url: "/v1/reputation/check",
      headers: {
        "content-type": "application/json",
        "x-tenant-token": String(req.headers["x-tenant-token"]),
        "x-device-token": String(req.headers["x-device-token"])
      },
      payload: { url, eventType: type }
    });

    const scoredParsed = reputationResponse.safeParse(injected.json());
    if (!scoredParsed.success) {
      req.log.error({ url: safeUrlForLog(url) }, "reputation_check_invalid_response");
      return reply.code(500).send({ error: "internal_error" });
    }

    const scored = scoredParsed.data;
    const verdict: Verdict = scored.verdict;
    const risk = scored.risk;
    const reasons = scored.reasons;
    const hostname = scored.checked.hostname.toLowerCase();

    await db.tenant.upsert({
      where: { id: tenant.tenantId },
      update: { plan: tenant.plan },
      create: { id: tenant.tenantId, plan: tenant.plan }
    });

    await db.user.upsert({
      where: { id: device.userId },
      update: { tenantId: tenant.tenantId },
      create: { id: device.userId, tenantId: tenant.tenantId }
    });

    await db.device.upsert({
      where: { id: device.deviceId },
      update: { tenantId: tenant.tenantId, userId: device.userId },
      create: { id: device.deviceId, tenantId: tenant.tenantId, userId: device.userId }
    });

    const eventRow = await db.event.create({
      data: {
        tenantId: tenant.tenantId,
        userId: device.userId,
        deviceId: device.deviceId,
        type,
        url,
        hostname,
        risk,
        verdict,
        reasons,
        ts: new Date(ts)
      }
    });

    let createdIncidentPayload:
      | {
          tenantId: string;
          hostname: string;
          verdict: "warn" | "block";
          maxRisk: number;
          reasons: string[];
          firstSeenAt: Date;
          eventType: "NAVIGATE" | "DOWNLOAD";
        }
      | null = null;

    if (verdict === "warn" || verdict === "block") {
      const incidentVerdict: "warn" | "block" = verdict;

      const result = await db.$transaction(async (tx: TxClient) => {
        const existing = await tx.incident.findUnique({
          where: {
            tenantId_hostname_verdict: {
              tenantId: tenant.tenantId,
              hostname,
              verdict: incidentVerdict
            }
          }
        });

        if (!existing) {
          const created = await tx.incident.create({
            data: {
              tenantId: tenant.tenantId,
              hostname,
              verdict: incidentVerdict,
              maxRisk: risk,
              reasons,
              firstSeenAt: new Date(ts),
              lastSeenAt: new Date(ts),
              eventCount: 1
            }
          });

          return { created };
        }

        const mergedReasons = Array.from(new Set([...(existing.reasons || []), ...reasons])).slice(0, 20);

        await tx.incident.update({
          where: {
            tenantId_hostname_verdict: {
              tenantId: tenant.tenantId,
              hostname,
              verdict: incidentVerdict
            }
          },
          data: {
            maxRisk: Math.max(existing.maxRisk, risk),
            reasons: mergedReasons,
            lastSeenAt: new Date(ts),
            eventCount: { increment: 1 }
          }
        });

        return { created: null as null };
      });

      if (result.created) {
        createdIncidentPayload = {
          tenantId: result.created.tenantId,
          hostname: result.created.hostname,
          verdict: incidentVerdict,
          maxRisk: result.created.maxRisk,
          reasons: result.created.reasons,
          firstSeenAt: result.created.firstSeenAt,
          eventType: type
        };
      }
    }

    if (createdIncidentPayload) {
      try {
        await notifyIncidentCreated(createdIncidentPayload);
      } catch (err) {
        req.log.warn({ err }, "notify_failed");
      }
    }

    return reply.send({
      accepted: true,
      storedEventId: eventRow.id,
      tenantId: tenant.tenantId,
      deviceId: device.deviceId,
      userId: device.userId,
      event: { type, url, ts },
      scored
    });
  });

  /**
   * =========================
   * GET /v1/incidents
   * =========================
   */
  app.get("/v1/incidents", async (req, reply) => {
    const auth = requireAuth(req, reply);
    if (!auth) return;

    const incidents = await db.incident.findMany({
      where: { tenantId: auth.tenant.tenantId },
      orderBy: { lastSeenAt: "desc" },
      take: 50
    });

    return reply.send({ incidents });
  });

  /**
   * =========================
   * GET /v1/events/recent
   * =========================
   */
  app.get("/v1/events/recent", async (req, reply) => {
    const auth = requireAuth(req, reply);
    if (!auth) return;

    const events = await db.event.findMany({
      where: { tenantId: auth.tenant.tenantId },
      orderBy: { ts: "desc" },
      take: 50
    });

    return reply.send({ events });
  });

  /**
   * =========================
   * Central error handler
   * =========================
   * Commandment: careful error handling (no stack leaks).
   */
  app.setErrorHandler((err, req, reply) => {
    req.log.error({ err, url: safeUrlForLog(req.url) }, "request_error");
    reply.code(500).send({ error: "internal_error" });
  });

  return app;
}

const app = createApp();

app.listen({ port: env.PORT, host: "0.0.0.0" }).catch((err) => {
  app.log.error(err);
  process.exit(1);
});
