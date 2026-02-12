function fmtTime(ts) {
  try { return new Date(ts).toLocaleString(); } catch { return ""; }
}

function safeHost(urlStr) {
  try { return new URL(urlStr).hostname; } catch { return "(invalid-url)"; }
}

async function load() {
  const res = await chrome.runtime.sendMessage({ type: "TP_GET_EVENTS" });
  const events = Array.isArray(res?.events) ? res.events : [];

  const list = document.getElementById("list");
  list.innerHTML = "";

  if (!events.length) {
    list.textContent = "No events yet. Browse or download something.";
    return;
  }

  for (const e of events.slice(0, 10)) {
    const row = document.createElement("div");
    row.className = "row";

    const verdict = e.verdict || "unknown";

    const pill = document.createElement("span");
    pill.className = "pill " + (verdict === "warn" ? "warn" : verdict === "block" ? "block" : "allow");
    pill.textContent = `${(e.type || "EVENT")} • ${verdict.toUpperCase()} • ${e.risk ?? "-"}`;

    const host = document.createElement("div");
    host.className = "meta";
    host.textContent = `${safeHost(e.url)} • ${fmtTime(e.ts)}`;

    const url = document.createElement("div");
    url.className = "url";
    url.textContent = e.url;

    const status = document.createElement("div");
    status.className = "meta";
    status.textContent = `status: ${e.status}${e.httpStatus ? ` (${e.httpStatus})` : ""}`;

    row.appendChild(pill);
    row.appendChild(host);
    row.appendChild(url);
    row.appendChild(status);
    list.appendChild(row);
  }
}

document.getElementById("refresh").addEventListener("click", load);
load();
