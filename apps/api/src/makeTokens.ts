import "dotenv/config";
import crypto from "node:crypto";

/**
 * Simple HMAC token format:
 * base64url(payloadJson).base64url(hmacSHA256(payloadJson, secret))
 *
 * NOTE: Dev-only helper. In production, mint tokens via an admin service
 * and store/rotate secrets in a real secrets manager.
 */
function sign(payload: object, secret: string) {
  const payloadJson = JSON.stringify(payload);
  const payloadB64 = Buffer.from(payloadJson).toString("base64url");
  const sig = crypto.createHmac("sha256", secret).update(payloadJson).digest("base64url");
  return `${payloadB64}.${sig}`;
}

const tenantSecret = process.env.TENANT_TOKEN_SECRET;
const deviceSecret = process.env.DEVICE_TOKEN_SECRET;

if (!tenantSecret || !deviceSecret) {
  console.error("Missing TENANT_TOKEN_SECRET or DEVICE_TOKEN_SECRET in .env");
  process.exit(1);
}

// You can tweak these IDs any time (safe dev defaults)
const tenant = {
  tenantId: "tenant_demo",
  plan: "trial" as const
};

const device = {
  deviceId: "device_demo_001",
  userId: "user_demo_001"
};

const tenantToken = sign(tenant, tenantSecret);
const deviceToken = sign(device, deviceSecret);

console.log("X-Tenant-Token:", tenantToken);
console.log("X-Device-Token:", deviceToken);
