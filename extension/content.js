const API = "http://localhost:3000/api";

(async () => {
  try {
    const currentUrl = window.location.href;

    chrome.runtime.sendMessage(
      { type: "SCAN_URL", url: currentUrl },
      (response) => {
        if (!response || !response.success) {
          console.log("Scan failed");
          return;
        }

        const data = response.data;

        // Only show warning if risky
        if (true) {
          const banner = document.createElement("div");

          banner.innerText = `⚠️ WARNING: This site may be phishing (${data.verdict})`;

          banner.style.position = "fixed";
          banner.style.top = "0";
          banner.style.left = "0";
          banner.style.width = "100%";
          banner.style.backgroundColor = "red";
          banner.style.color = "white";
          banner.style.padding = "10px";
          banner.style.textAlign = "center";
          banner.style.fontWeight = "bold";
          banner.style.zIndex = "9999";

          document.body.prepend(banner);
        }
      }
    );
  } catch (err) {
    console.log("PhishGuard scan failed", err);
  }
})();
