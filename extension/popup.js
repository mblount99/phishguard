const API = "http://localhost:3000/api";

// 🔥 Auto-scan current tab when popup opens
window.onload = () => {
  chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
    const currentUrl = tabs[0].url;

    document.getElementById("url").value = currentUrl;

    try {
      const res = await fetch(`${API}/scan-url`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ url: currentUrl })
      });

      const data = await res.json();

      document.getElementById("result").innerText =
        `Auto Scan:\nRisk: ${data.risk_score} (${data.verdict})\nReasons: ${data.reasons.join(", ")}`;
    } catch (err) {
      document.getElementById("result").innerText =
        "❌ Cannot connect to backend (is server running?)";
    }
  });
};

// 🔗 Manual URL scan
document.getElementById("scanUrl").onclick = async () => {
  const url = document.getElementById("url").value;

  try {
    const res = await fetch(`${API}/scan-url`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url })
    });

    const data = await res.json();

    document.getElementById("result").innerText =
      `Risk: ${data.risk_score} (${data.verdict})\nReasons: ${data.reasons.join(", ")}`;
  } catch (err) {
    document.getElementById("result").innerText =
      "❌ Failed to connect to backend";
  }
};

// 📧 Email scan (will fail gracefully if no credits)
document.getElementById("scanEmail").onclick = async () => {
  const emailText = document.getElementById("email").value;

  try {
    const res = await fetch(`${API}/analyze-email`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ emailText })
    });

    const data = await res.json();

    document.getElementById("result").innerText =
      `Risk: ${data.risk_score} (${data.verdict})\nReasons: ${data.reasons.join(", ")}`;
  } catch (err) {
    document.getElementById("result").innerText =
      "❌ Email analysis unavailable (no credits)";
  }
};
