const API = "https://phishguard-production-c8c7.up.railway.app/api";

console.log("PhishGuard content script loaded");

(async () => {
  try {
    const currentUrl = window.location.href;

    // 🚫 Skip chrome pages
    if (currentUrl.startsWith("chrome://")) return;

    console.log("Scanning:", currentUrl);

    const res = await fetch(`${API}/scan-url`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url: currentUrl })
    });

    const data = await res.json();
    console.log("Scan result:", data);

    // 🚨 Only show for risky sites
    let bgColor, borderColor, badgeColor, statusText;

    if (data.risk_score >= 70) {
      bgColor = "#fff1f1";
      borderColor = "#ff4d4d";
      badgeColor = "#ff4d4d";
      statusText = "High Risk";
    } else if (data.risk_score >= 40) {
      bgColor = "#fff8e6";
      borderColor = "#ffa500";
      badgeColor = "#ffa500";
      statusText = "Suspicious";
    } else {
      console.log("Site is safe, no banner shown");
      return;
    }

    // 🧱 Container
    const container = document.createElement("div");

    container.style.position = "fixed";
    container.style.top = "20px";
    container.style.right = "20px";
    container.style.width = "340px";
    container.style.backgroundColor = bgColor;
    container.style.border = `2px solid ${borderColor}`;
    container.style.borderRadius = "12px";
    container.style.boxShadow = "0 6px 18px rgba(0,0,0,0.2)";
    container.style.zIndex = "999999";
    container.style.fontFamily = "system-ui, -apple-system, sans-serif";
    container.style.overflow = "hidden";

    // 🔝 Header
    const header = document.createElement("div");
    header.style.padding = "12px";
    header.style.display = "flex";
    header.style.justifyContent = "space-between";
    header.style.alignItems = "center";
    header.style.borderBottom = "1px solid rgba(0,0,0,0.1)";

    const title = document.createElement("div");
    title.innerHTML = "🛡️ <strong>PhishGuard</strong>";
    title.style.fontSize = "15px";

    const closeBtn = document.createElement("span");
    closeBtn.innerText = "✕";
    closeBtn.style.cursor = "pointer";
    closeBtn.onclick = () => container.remove();

    header.appendChild(title);
    header.appendChild(closeBtn);

    // 📊 Status
    const status = document.createElement("div");
    status.style.padding = "10px";
    status.style.display = "flex";
    status.style.justifyContent = "space-between";

    const verdict = document.createElement("div");
    verdict.innerHTML = `<strong>${data.verdict}</strong>`;

    const badge = document.createElement("div");
    badge.innerText = statusText;
    badge.style.backgroundColor = badgeColor;
    badge.style.color = "white";
    badge.style.padding = "4px 8px";
    badge.style.borderRadius = "6px";
    badge.style.fontSize = "12px";

    status.appendChild(verdict);
    status.appendChild(badge);

    // 📊 Risk bar
    const barContainer = document.createElement("div");
    barContainer.style.height = "6px";
    barContainer.style.background = "#eee";

    const bar = document.createElement("div");
    bar.style.height = "100%";
    bar.style.width = `${data.risk_score}%`;
    bar.style.background = borderColor;

    barContainer.appendChild(bar);

    // 📄 Body
    const body = document.createElement("div");
    body.style.padding = "10px";
    body.style.fontSize = "13px";

    body.innerHTML = `
      <strong>Risk Score:</strong> ${data.risk_score}/100<br/>
      <strong>Reasons:</strong> ${data.reasons.join(", ")}
    `;

    // 🧩 Assemble
    container.appendChild(header);
    container.appendChild(status);
    container.appendChild(barContainer);
    container.appendChild(body);

    document.body.appendChild(container);

  } catch (err) {
    console.error("PhishGuard failed:", err);
  }
})();
