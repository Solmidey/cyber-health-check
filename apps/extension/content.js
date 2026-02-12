// ThreatPulse — content script
// Shows a top banner on WARN/BLOCK verdicts sent from background.

let bannerEl = null;

function removeBanner() {
  if (bannerEl) bannerEl.remove();
  bannerEl = null;
}

function renderBanner(scored) {
  removeBanner();

  const verdict = scored?.verdict || "allow";
  if (verdict === "allow") return;

  const risk = scored?.risk ?? "?";
  const reasons = Array.isArray(scored?.reasons) ? scored.reasons : [];

  bannerEl = document.createElement("div");
  bannerEl.style.position = "fixed";
  bannerEl.style.top = "0";
  bannerEl.style.left = "0";
  bannerEl.style.right = "0";
  bannerEl.style.zIndex = "2147483647";
  bannerEl.style.padding = "12px 14px";
  bannerEl.style.fontFamily = "system-ui, -apple-system, Segoe UI, Roboto, Arial";
  bannerEl.style.borderBottom = "1px solid rgba(0,0,0,0.2)";
  bannerEl.style.background = verdict === "block" ? "#2b0b0b" : "#2b240b";
  bannerEl.style.color = "#fff";

  const title = document.createElement("div");
  title.style.fontWeight = "700";
  title.textContent = verdict === "block" ? "THREATPULSE: BLOCKED" : "THREATPULSE: WARNING";

  const body = document.createElement("div");
  body.style.marginTop = "6px";
  body.style.fontSize = "13px";
  body.textContent = `Risk: ${risk}/100 • ${reasons.slice(0, 3).join(", ") || "suspicious signals"}`;

  const actions = document.createElement("div");
  actions.style.marginTop = "10px";
  actions.style.display = "flex";
  actions.style.gap = "10px";

  const closeBtn = document.createElement("button");
  closeBtn.textContent = "Dismiss";
  closeBtn.style.cursor = "pointer";
  closeBtn.onclick = removeBanner;

  actions.appendChild(closeBtn);

  bannerEl.appendChild(title);
  bannerEl.appendChild(body);
  bannerEl.appendChild(actions);

  document.documentElement.appendChild(bannerEl);

  // MVP: if block, add a translucent overlay to grab attention
  if (verdict === "block") {
    const overlay = document.createElement("div");
    overlay.style.position = "fixed";
    overlay.style.inset = "0";
    overlay.style.zIndex = "2147483646";
    overlay.style.background = "rgba(0,0,0,0.35)";
    overlay.onclick = () => overlay.remove();
    document.documentElement.appendChild(overlay);
  }
}

chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.type === "TP_VERDICT") renderBanner(msg.scored);
});
