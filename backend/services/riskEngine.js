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

function getEntropy(str) {
  const map = {};
  for (let c of str) map[c] = (map[c] || 0) + 1;

  let entropy = 0;
  for (let k in map) {
    const p = map[k] / str.length;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

// ==============================
// 🌐 URL SCAN
// ==============================

export const scanUrl = async (req, res) => {
  const { url } = req.body;
  const userIp = req.ip;

  if (!url) {
    return res.json({
      risk_score: 0,
      verdict: "Error",
      reasons: ["URL required"]
    });
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
  const reasons = [];
  const lowerUrl = url.toLowerCase();

  let hostname = "";
  let domainName = "";
  let tld = "";

  try {
    hostname = new URL(url).hostname.replace("www.", "");
    const parts = hostname.split(".");
    domainName = parts[0];
    tld = parts[parts.length - 1];
  } catch {
    score += 50;
    reasons.push("Invalid URL format");
  }

  // ==============================
  // TRUSTED DOMAINS
  // ==============================

  const trustedDomains = [
    "chase.com",
    "paypal.com",
    "amazon.com",
    "apple.com",
    "google.com"
  ];

  const isTrusted = trustedDomains.some((d) =>
    hostname.endsWith(d)
  );

  // ==============================
  // BASIC CHECKS
  // ==============================

  if (url.includes("@")) {
    score += 40;
    reasons.push("URL contains @ (possible masking)");
  }

  if (!url.startsWith("https")) {
    score += 15;
    reasons.push("Not using HTTPS");
  }

  if (url.length > 120) {
    score += 15;
    reasons.push("Very long URL");
  }

  if (lowerUrl.match(/login|verify|secure|account|update|password/)) {
    score += 15;
    reasons.push("Sensitive keywords in URL");
  }

  // ==============================
  // SUSPICIOUS TLD
  // ==============================

  const badTlds = ["xyz", "top", "click", "tk", "ml"];

  if (!isTrusted && badTlds.includes(tld)) {
    score += 25;
    reasons.push(`Suspicious domain (.${tld})`);
  }

  // ==============================
  // SUBDOMAIN ATTACK
  // ==============================

  if (!isTrusted && hostname.split(".").length > 3) {
    score += 25;
    reasons.push("Suspicious subdomain structure");
  }

  // ==============================
  // BRAND SPOOFING
  // ==============================

  const brands = ["paypal", "chase", "amazon", "apple", "bank"];

  if (!isTrusted) {
    for (const brand of brands) {
      const distance = levenshtein(domainName, brand);

      if (distance <= 2 && domainName !== brand) {
        score += 45;
        reasons.push(`Domain mimics ${brand}`);
        break;
      }
    }
  }

  // ==============================
  // ENTROPY (RANDOM DOMAINS)
  // ==============================

  const entropy = getEntropy(domainName);

  if (!isTrusted && entropy > 3.5) {
    score += 20;
    reasons.push("Random-looking domain");
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
  // SAFE BROWSING
  // ==============================

  try {
    const flagged = await checkGoogleSafeBrowsing(url);

    if (flagged) {
      score += 80;
      reasons.push("Reported as dangerous");
    }
  } catch {}

  // ==============================
  // FINAL
  // ==============================

  score = Math.min(score, 100);

  let verdict = "Safe";
  if (score >= 70) verdict = "Dangerous";
  else if (score >= 40) verdict = "Suspicious";

  return res.json({
    url,
    risk_score: score,
    verdict,
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
