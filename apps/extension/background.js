// ThreatPulse — background service worker (MV3)
//
// Notes (easy removal):
// - Search for "MVP:" to find minimal logic you can replace later.
//
// Commandments applied:
// - strict auth: requires tokens to send events
// - safe logging: never log tokens; minimize URL logging
// - careful error handling: never crash-loop the worker
// - rate limiting: enforced server-side; extension retries are conservative

const STORAGE_KEYS = {
  backendUrl: "backendUrl",
  tenantToken: "tenantToken",
  deviceToken: "deviceToken",
  events: "events"
};

const MAX_EVENTS = 50;

function now() {
  return Date.now();
}

// Avoid logging full URLs (queries can contain sensitive info)
function safeUrlForLog(urlStr) {
  try {
    const u = new URL(urlStr);
    return `${u.protocol}//${u.hostname}${u.pathname}`;
  } catch {
    return "(invalid-url)";
  }
}

async function getConfig() {
  const cfg = await chrome.storage.sync.get([
    STORAGE_KEYS.backendUrl,
    STORAGE_KEYS.tenantToken,
    STORAGE_KEYS.deviceToken
  ]);
  return {
    backendUrl: cfg[STORAGE_KEYS.backendUrl] || "http://localhost:4000",
    tenantToken: cfg[STORAGE_KEYS.tenantToken] || "",
    deviceToken: cfg[STORAGE_KEYS.deviceToken] || ""
  };
}

async function pushEventToStorage(item) {
  const res = await chrome.storage.local.get([STORAGE_KEYS.events]);
  const list = Array.isArray(res[STORAGE_KEYS.events]) ? res[STORAGE_KEYS.events] : [];
  const next = [item, ...list].slice(0, MAX_EVENTS);
  await chrome.storage.local.set({ [STORAGE_KEYS.events]: next });
}

async function notifyUserIfNeeded(scored) {
  const verdict = scored?.verdict;
  if (verdict !== "warn" && verdict !== "block") return;

  const risk = scored?.risk ?? "?";
  const reasons = Array.isArray(scored?.reasons) ? scored.reasons : [];

  const title = verdict === "block" ? "ThreatPulse blocked a risky page" : "ThreatPulse warning";
  const message = `Risk ${risk}/100 • ${reasons.slice(0, 2).join(", ") || "suspicious signals"}`;

  // icon.png must exist in extension root
  await chrome.notifications.create({
    type: "basic",
    iconUrl: "icon.png",
    title,
    message
  });
}

async function sendVerdictToTab(tabId, scored) {
  try {
    await chrome.tabs.sendMessage(tabId, { type: "TP_VERDICT", scored });
  } catch {
    // content script may not be ready; safe to ignore
  }
}

async function postEvent({ type, url, tabId }) {
  const cfg = await getConfig();

  // If not configured yet, we keep local visibility but do not send.
  if (!cfg.tenantToken || !cfg.deviceToken) {
    await pushEventToStorage({ ts: now(), type, url, status: "not_configured" });
    return;
  }

  const endpoint = `${cfg.backendUrl.replace(/\/$/, "")}/v1/events`;
  const payload = { type, url, ts: now() };

  try {
    const res = await fetch(endpoint, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-tenant-token": cfg.tenantToken,
        "x-device-token": cfg.deviceToken
      },
      body: JSON.stringify(payload)
    });

    const json = await res.json().catch(() => ({}));
    const scored = json?.scored;

    await pushEventToStorage({
      ts: payload.ts,
      type,
      url,
      status: res.ok ? "sent" : "error",
      httpStatus: res.status,
      verdict: scored?.verdict,
      risk: scored?.risk,
      reasons: scored?.reasons
    });

    if (res.ok && scored && typeof tabId === "number") {
      await notifyUserIfNeeded(scored);
      await sendVerdictToTab(tabId, scored);
    }
  } catch {
    await pushEventToStorage({ ts: payload.ts, type, url, status: "network_error" });
    console.debug("[ThreatPulse] network_error", safeUrlForLog(url));
  }
}

// NAVIGATION (top-level only)
chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  if (!details.url || !details.tabId) return;
  if (details.url.startsWith("chrome://") || details.url.startsWith("chrome-extension://")) return;

  postEvent({ type: "NAVIGATE", url: details.url, tabId: details.tabId });
});

// DOWNLOAD
chrome.downloads.onCreated.addListener((item) => {
  if (!item?.url) return;
  postEvent({ type: "DOWNLOAD", url: item.url, tabId: item.tabId });
});

// Popup -> get recent events
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === "TP_GET_EVENTS") {
    chrome.storage.local.get([STORAGE_KEYS.events]).then((res) => {
      sendResponse({ events: res[STORAGE_KEYS.events] || [] });
    });
    return true; // async
  }
});
