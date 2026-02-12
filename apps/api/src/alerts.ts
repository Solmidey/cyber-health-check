import "dotenv/config";

export async function sendSlackIncidentAlert(payload: {
  tenantId: string;
  hostname: string;
  verdict: "warn" | "block";
  maxRisk: number;
  reasons: string[];
  firstSeenAt: Date;
}) {
  const enabled = process.env.ALERTS_ENABLED === "true";
  const webhook = process.env.SLACK_WEBHOOK_URL;

  if (!enabled || !webhook) return;

  // Commandment: safe logging + safe payload (no full URLs, no tokens)
  const text = `*ThreatPulse Incident*\n• Tenant: ${payload.tenantId}\n• Host: ${payload.hostname}\n• Verdict: ${payload.verdict.toUpperCase()}\n• Risk: ${payload.maxRisk}/100\n• Reasons: ${payload.reasons.slice(0, 6).join(", ")}`;

  await fetch(webhook, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ text })
  });
}
