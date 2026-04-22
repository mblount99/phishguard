import { analyzeWithAI } from "./aiAnalyzer.js";
import { getDomainAge } from "./domainCheck.js";
import { checkGoogleSafeBrowsing } from "./safeBrowsing.js";
import { paidUsers } from "../store.js";

// ==============================
// 📊 USAGE TRACKING
// ==============================

const usageMap = {};

const trackUsage = (ip) => {
  if (!usageMap[ip]) {
    usageMap[ip] = { count: 0, lastReset: Date.now() };
  }

  const now = Date.now();

  if (now - usageMap[ip].lastReset > 86400000) {
    usageMap[ip] = { count: 0, lastReset: now };
  }

  usageMap[ip].count++;
  return usageMap[ip].count;
};

// ==============================
// 🧠 HELPERS
// ==============================

function levenshtein(a, b) {
  const matrix = [];

  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      matrix[i][j] =
        b[i - 1] === a[j - 1]
          ? matrix[i - 1][j - 1]
          : Math.min(
              matrix[i - 1][j - 1] + 1,
              matrix[i][j - 1] + 1,
              matrix[i - 1][j] + 1
            );
    }
  }

  return matrix[b.length][a.length];
}

// ==============================
// 🌐 ELITE URL SCAN
// ==============================

// ==============================
// 🌐 ELITE URL SCAN
// ==============================

export const scanUrl = async (req, res) => {
  let { url } = req.body;
  const userIp = req.ip;

  if (!url) {
    return res.json({
      risk_score: 0,
      verdict: "Error",
      reasons: ["URL required"]
    });
  }

  // ==============================
  // URL NORMALIZATION (CRITICAL FIX)
  // ==============================

  url = url.trim();

  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = "https://" + url;
  }

  // ==============================
  // USAGE LIMIT
  // ==============================

  const usage = trackUsage(userIp);
  const isPaid = paidUsers.has(userIp);

  if (!isPaid && usage > 20) {
    return res.json({
      risk_score: 0,
      verdict: "Upgrade Required",
      reasons: ["Free limit reached"]
    });
  }

  let score = 0;
  let confidence = 50;
  const reasons = [];

  let hostname = "";
  let rootDomain = "";
  let subdomain = "";
  let path = "";

  try {
    const parsed = new URL(url);
    hostname = parsed.hostname.toLowerCase();
    path = parsed.pathname.toLowerCase();

    const parts = hostname.split(".");
    rootDomain = parts.slice(-2).join(".");
    subdomain = parts.slice(0, -2).join(".");
  } catch {
    score += 60;
    reasons.push("Invalid URL format");
  }

  // ==============================
  // TRUSTED DOMAINS
  // ==============================

  const trusted = [
    "google.com",
    "chase.com",
    "paypal.com",
    "amazon.com",
    "apple.com",
    "microsoft.com"
  ];

  const isTrusted = trusted.some((d) => rootDomain === d);

  // ==============================
  // BASIC SIGNALS
  // ==============================

  if (url.includes("@")) {
    score += 40;
    reasons.push("URL masking with @");
  }

  if (!url.startsWith("https")) {
    score += 10;
    reasons.push("Not HTTPS");
  }

  if (url.length > 120) {
    score += 15;
    reasons.push("Unusually long URL");
  }

  if (path.match(/login|verify|secure|account|update|password/)) {
    score += 20;
    reasons.push("Sensitive path keywords");
  }

  // ==============================
  // SUBDOMAIN ATTACK
  // ==============================

  const brands = ["paypal", "chase", "amazon", "apple", "bank"];

  if (!isTrusted && subdomain) {
    for (const brand of brands) {
      if (subdomain.includes(brand)) {
        score += 50;
        reasons.push(`Brand "${brand}" hidden in subdomain`);
        break;
      }
    }
  }

  // ==============================
  // DOMAIN SPOOFING
  // ==============================

  if (!isTrusted) {
    for (const brand of brands) {
      const dist = levenshtein(rootDomain.split(".")[0], brand);

      if (dist <= 2 && rootDomain !== `${brand}.com`) {
        score += 45;
        reasons.push(`Domain mimics ${brand}`);
        break;
      }
    }
  }

  // ==============================
  // SUSPICIOUS TLD
  // ==============================

  const badTlds = ["xyz", "top", "click", "tk", "ml"];
  const tld = rootDomain.split(".")[1];

  if (!isTrusted && badTlds.includes(tld)) {
    score += 25;
    reasons.push(`Suspicious domain (.${tld})`);
  }

  // ==============================
  // DOMAIN AGE
  // ==============================

  let age = null;

  try {
    age = await getDomainAge(url);
  } catch {}

  if (!isTrusted) {
    if (age !== null && age < 7) {
      score += 35;
      reasons.push("Very new domain");
    } else if (age !== null && age < 30) {
      score += 20;
      reasons.push("New domain");
    }
  }

  // ==============================
  // GOOGLE SAFE BROWSING
  // ==============================

  try {
    const flagged = await checkGoogleSafeBrowsing(url);

    if (flagged) {
      score = 100;
      confidence = 100;
      reasons.push("Known phishing/malware site");
    }
  } catch {}

  // ==============================
  // FINAL
  // ==============================

  score = Math.min(score, 100);

  if (score >= 80) confidence = 95;
  else if (score >= 60) confidence = 85;
  else if (score >= 40) confidence = 70;

  let verdict = "Safe";
  if (score >= 70) verdict = "Dangerous";
  else if (score >= 40) verdict = "Suspicious";

  return res.json({
    url,
    risk_score: score,
    verdict,
    confidence,
    reasons,
    domain_age_days: age
  });
};

// ==============================
// 📧 EMAIL ANALYSIS
// ==============================

export const analyzeEmail = async (req, res) => {
  const { emailText } = req.body;

  if (!emailText) {
    return res.json({
      risk_score: 0,
      verdict: "Error",
      reasons: ["Email text required"]
    });
  }

  try {
    const result = await analyzeWithAI(emailText);

    return res.json({
      risk_score: Number(result?.risk_score) || 75,
      verdict: result?.verdict || "Suspicious",
      reasons: result?.reasons || ["Potential phishing detected"]
    });

  } catch (err) {
    return res.json({
      risk_score: 70,
      verdict: "Suspicious",
      reasons: ["AI fallback triggered"]
    });
  }
};
