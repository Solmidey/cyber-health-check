const STORAGE_KEYS = {
  backendUrl: "backendUrl",
  tenantToken: "tenantToken",
  deviceToken: "deviceToken"
};

function byId(id) {
  return document.getElementById(id);
}

async function load() {
  const cfg = await chrome.storage.sync.get([
    STORAGE_KEYS.backendUrl,
    STORAGE_KEYS.tenantToken,
    STORAGE_KEYS.deviceToken
  ]);

  byId("backendUrl").value = cfg[STORAGE_KEYS.backendUrl] || "http://localhost:4000";
  byId("tenantToken").value = cfg[STORAGE_KEYS.tenantToken] || "";
  byId("deviceToken").value = cfg[STORAGE_KEYS.deviceToken] || "";
}

async function save() {
  await chrome.storage.sync.set({
    [STORAGE_KEYS.backendUrl]: byId("backendUrl").value.trim(),
    [STORAGE_KEYS.tenantToken]: byId("tenantToken").value.trim(),
    [STORAGE_KEYS.deviceToken]: byId("deviceToken").value.trim()
  });
  byId("status").textContent = "Saved.";
  setTimeout(() => (byId("status").textContent = ""), 1500);
}

async function testConnection() {
  const backendUrl = byId("backendUrl").value.trim().replace(/\/$/, "");
  const tenantToken = byId("tenantToken").value.trim();
  const deviceToken = byId("deviceToken").value.trim();

  if (!backendUrl || !tenantToken || !deviceToken) {
    byId("status").textContent = "Set backend + tokens first.";
    return;
  }

  try {
    const res = await fetch(`${backendUrl}/v1/reputation/check`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-tenant-token": tenantToken,
        "x-device-token": deviceToken
      },
      body: JSON.stringify({ url: "https://example.com/?chc-test=warn", eventType: "NAVIGATE" })
    });

    const json = await res.json().catch(() => ({}));
    byId("status").textContent = res.ok
      ? `OK: ${json.verdict} (risk ${json.risk})`
      : `Error: ${res.status}`;
  } catch {
    byId("status").textContent = "Network error. Is the backend reachable from your browser?";
  }
}

byId("save").addEventListener("click", save);
byId("test").addEventListener("click", testConnection);
load();
