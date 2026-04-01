import { analyzeWithAI } from "./aiAnalyzer.js";
import { getDomainAge } from "./domainCheck.js";
import { checkGoogleSafeBrowsing } from "./safeBrowsing.js";

// ==============================
// 🔐 PREMIUM USERS
// ==============================

import { paidUsers } from "../store.js";

// ==============================
// 📊 USAGE TRACKING
// ==============================

const usageMap = {};

const trackUsage = (ip) => {
  if (!usageMap[ip]) {
    usageMap[ip] = {
      count: 0,
      lastReset: Date.now()
    };
  }

  const now = Date.now();

  if (now - usageMap[ip].lastReset > 86400000) {
    usageMap[ip] = {
      count: 0,
      lastReset: now
    };
  }

  usageMap[ip].count++;

  return usageMap[ip].count;
};

// ==============================
// 🧠 HELPERS
// ==============================

// Simple similarity (typosquatting)
function isSimilar(a, b) {
  if (!a || !b) return false;

  let mismatches = 0;
  const len = Math.min(a.length, b.length);

  for (let i = 0; i < len; i++) {
    if (a[i] !== b[i]) mismatches++;
  }

  return mismatches <= 2;
}

// Entropy (random-looking domains)
function getEntropy(str) {
  const map = {};
  for (let char of str) {
    map[char] = (map[char] || 0) + 1;
  }

  let entropy = 0;
  const len = str.length;

  for (let key in map) {
    const p = map[key] / len;
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
    return res.status(400).json({
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
      reasons: ["Free limit reached (20 scans/day). Upgrade for unlimited scans."]
    });
  }

  // ==============================
  // INIT
  // ==============================

  let score = 0;
  const reasons = [];
  const lowerUrl = url.toLowerCase();

  // ==============================
  // BASIC CHECKS
  // ==============================

  if (url.includes("@")) {
    score += 40;
    reasons.push("Contains @ symbol (URL masking)");
  }

  if (!url.startsWith("https")) {
    score += 25;
    reasons.push("No HTTPS (insecure)");
  }

  if (lowerUrl.match(/login|secure|verify|account|update|bank|paypal|password/i)) {
    score += 20;
    reasons.push("Phishing-related keywords");
  }

  if (url.length > 100) {
    score += 15;
    reasons.push("Unusually long URL");
  }

  // ==============================
  // DOMAIN PARSING
  // ==============================

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

  const normalizedDomain = domainName
    .replace(/1/g, "l")
    .replace(/0/g, "o");

  console.log("DEBUG:", { hostname, domainName, normalizedDomain });

  // ==============================
  // 🔴 SUSPICIOUS TLD
  // ==============================

  const riskyTlds = ["xyz", "top", "click", "gq", "tk", "ml"];

  if (riskyTlds.includes(tld)) {
    score += 30;
    reasons.push(`Suspicious TLD (.${tld})`);
  }

  // ==============================
  // 🔴 BRAND SPOOFING
  // ==============================

  const brands = ["paypal", "chase", "bank", "amazon", "apple"];

  for (const brand of brands) {
    if (
      (normalizedDomain.includes(brand) && domainName !== brand) ||
      isSimilar(normalizedDomain, brand)
    ) {
      score += 50;
      reasons.push(`Possible spoofing of ${brand}`);
      break;
    }
  }

  // ==============================
  // 🔴 ENTROPY CHECK
  // ==============================

  const entropy = getEntropy(domainName);

  if (entropy > 3.5) {
    score += 20;
    reasons.push("Random-looking domain");
  }

  // ==============================
  // 🌐 DOMAIN AGE
  // ==============================

  let age = null;

  try {
    age = await getDomainAge(url);
  } catch {
    console.warn("⚠️ Domain age lookup failed");
  }

  if (age === null) {
    score += 10;
    reasons.push("Domain age unknown");
  } else if (age < 7) {
    score += 40;
    reasons.push("Very new domain");
  } else if (age < 30) {
    score += 25;
    reasons.push("New domain");
  }

  // ==============================
  // 🛑 GOOGLE SAFE BROWSING
  // ==============================

  try {
    const isMalicious = await checkGoogleSafeBrowsing(url);

    if (isMalicious) {
      score += 80;
      reasons.push("Flagged by Google Safe Browsing");
    }
  } catch {
    console.warn("⚠️ Safe Browsing failed");
  }

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
    domain_age_days: age,
    entropy
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
      reasons: Array.isArray(result?.reasons)
        ? result.reasons
        : [result?.reasons || "Potential phishing detected"]
    });

  } catch (err) {
    console.error("❌ AI ERROR:", err.message);

    return res.json({
      risk_score: 75,
      verdict: "Suspicious",
      reasons: ["AI failed — fallback triggered"]
    });
  }
};
