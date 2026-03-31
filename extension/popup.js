const API = "https://phishguard-production-c8c7.up.railway.app/api";

// ========================
// UI HELPERS
// ========================
function updateUI(score, verdict, reasons) {
  const card = document.getElementById("resultCard");

  card.classList.remove("safe", "warning", "danger");

  let statusText = "";

  if (score <= 30) {
    card.classList.add("safe");
    statusText = "🟢 Safe";
  } else if (score <= 70) {
    card.classList.add("warning");
    statusText = "🟡 Suspicious";
  } else {
    card.classList.add("danger");
    statusText = "🔴 Dangerous";
  }

  card.querySelector(".status").innerText = statusText;
  card.querySelector(".score").innerText =
    `Risk Score: ${score} / 100 (${verdict})`;

  document.getElementById("reasons").innerHTML =
    (reasons || []).map(r => `• ${r}`).join("<br>");
}

function setLoading() {
  const card = document.getElementById("resultCard");

  card.className = "card";
  card.querySelector(".status").innerText = "🔍 Scanning...";
  card.querySelector(".score").innerText = "";
  document.getElementById("reasons").innerHTML = "";
}

function setError(message) {
  const card = document.getElementById("resultCard");

  card.className = "card danger";
  card.querySelector(".status").innerText = "❌ Error";
  card.querySelector(".score").innerText = message;
  document.getElementById("reasons").innerHTML = "";
}

// ========================
// PAGE LOAD (NO AUTOFILL)
// ========================
window.onload = () => {
  console.log("popup loaded");
};

// ========================
// SCAN PASTED URL
// ========================
document.getElementById("scanUrl").onclick = async () => {
  console.log("Scan URL clicked");

  const url = document.getElementById("url").value.trim();

  if (!url || url.startsWith("chrome://")) {
    return setError("Enter a valid website URL");
  }

  setLoading();

  try {
    const res = await fetch(`${API}/scan-url`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url })
    });

    const data = await res.json();

    updateUI(data.risk_score, data.verdict, data.reasons);
  } catch (err) {
    console.error(err);
    setError("Failed to scan URL");
  }
};

// ========================
// SCAN CURRENT TAB
// ========================
document.getElementById("scanCurrent").onclick = async () => {
  console.log("Scan current clicked");

  chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
    const currentUrl = tabs[0].url;

    if (!currentUrl || currentUrl.startsWith("chrome://")) {
      return setError("Cannot scan this page");
    }

    setLoading();

    try {
      const res = await fetch(`${API}/scan-url`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ url: currentUrl })
      });

      const data = await res.json();

      updateUI(data.risk_score, data.verdict, data.reasons);
    } catch (err) {
      console.error(err);
      setError("Failed to scan current site");
    }
  });
};

// ========================
// EMAIL SCAN
// ========================
document.getElementById("scanEmail").onclick = async () => {
  console.log("Scan email clicked");

  const emailText = document.getElementById("email").value.trim();

  if (!emailText) {
    return setError("Paste an email first");
  }

  setLoading();

  try {
    const res = await fetch(`${API}/analyze-email`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ text: emailText })
    });

    const data = await res.json();

    updateUI(data.risk_score, data.verdict, data.reasons || []);
  } catch (err) {
    console.error(err);
    setError("Email scan failed");
  }
};
