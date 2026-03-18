import { analyzeWithAI } from "./aiAnalyzer.js";
import { getDomainAge } from "./domainCheck.js";
import { checkGoogleSafeBrowsing } from "./safeBrowsing.js";

export const scanUrl = async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({ error: "URL required" });
  }

  let score = 0;
  let reasons = [];

  // 🔍 Rule-based checks
  if (url.includes("@")) {
    score += 40;
    reasons.push("Contains @ symbol (URL masking)");
  }

  if (url.match(/login|secure|verify|account|update/i)) {
    score += 30;
    reasons.push("Phishing-related keywords");
  }

  if (!url.startsWith("https")) {
    score += 30;
    reasons.push("No HTTPS (insecure)");
  }

  // 🌐 Domain age check
  const age = await getDomainAge(url);

  if (age !== null && age < 30) {
    score += 50;
    reasons.push("Domain is very new (high phishing risk)");
  }

  // 🛑 Google Safe Browsing
  const isMalicious = await checkGoogleSafeBrowsing(url);

  if (isMalicious) {
    score += 80;
    reasons.push("Flagged by Google Safe Browsing");
  }

  // Cap score
  score = Math.min(score, 100);

  // Verdict
  let verdict = "Safe";
  if (score >= 70) verdict = "Phishing";
  else if (score >= 40) verdict = "Suspicious";

  res.json({
    url,
    risk_score: score,
    verdict,
    reasons,
    domain_age_days: age,
  });
};

// 📧 Email analysis (AI)
export const analyzeEmail = async (req, res) => {
  const { emailText } = req.body;

  if (!emailText) {
    return res.status(400).json({ error: "Email text required" });
  }

  try {
    const result = await analyzeWithAI(emailText);
    res.json(result);
  } catch (err) {
    console.error("❌ AI ERROR:", err.message);

    res.status(500).json({
      risk_score: 0,
      verdict: "Error",
      reasons: ["Failed to analyze email"],
    });
  }
};
