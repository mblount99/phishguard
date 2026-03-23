export const paidUsers = new Set();

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

import { analyzeWithAI } from "./aiAnalyzer.js";
import { getDomainAge } from "./domainCheck.js";
import { checkGoogleSafeBrowsing } from "./safeBrowsing.js";

// 🔍 Levenshtein Distance
function levenshtein(a, b) {
  const matrix = [];

  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }

  return matrix[b.length][a.length];
}

// 🔤 Normalize phishing tricks
function normalizeDomain(str) {
  return str
    .replace(/1/g, "l")
    .replace(/0/g, "o")
    .replace(/5/g, "s")
    .replace(/@/g, "a")
    .replace(/\$/g, "s");
}

// 🌍 Extract TLD
function getTLD(hostname) {
  const parts = hostname.split(".");
  return parts[parts.length - 1];
}

// 🧠 Extract root domain
function getDomainName(hostname) {
  return hostname.split(".")[0];
}

// ==============================
// 🚀 MAIN FUNCTION
// ==============================
export const scanUrl = async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({ error: "URL required" });
  }

  const hostname = new URL(url).hostname.replace("www.", "");
  const domainName = getDomainName(hostname);
  const normalizedDomain = normalizeDomain(domainName);

  console.log("DEBUG:", {
    hostname,
    domainName,
    normalizedDomain
  });

  const lowerUrl = url.toLowerCase();

  const brands = ["paypal", "chase", "bankofamerica", "apple", "amazon", "microsoft"];

  // 🔥 EARLY OVERRIDE (THIS FIXES YOUR ISSUE)
  for (const brand of brands) {
    if (normalizedDomain === brand && domainName !== brand) {
      return res.json({
        url,
        risk_score: 95,
        verdict: "Dangerous",
        reasons: [`Exact brand mimic via character substitution (${brand})`],
        domain_age_days: null
      });
    }
  }

  const userIp = req.ip;
  const usage = trackUsage(userIp);
  const isPaid = paidUsers.has(userIp);

  if (usage > 20 && !isPaid) {
    return res.json({
      risk_score: 0,
      verdict: "Upgrade Required",
      reasons: ["Free limit reached (20 scans/day). Upgrade for unlimited scans."]
    });
  }

  let score = 0;
  let reasons = [];

  // 🚨 Safe Browsing
  const isMalicious = await checkGoogleSafeBrowsing(url);
  if (isMalicious) {
    return res.json({
      url,
      risk_score: 100,
      verdict: "Dangerous",
      reasons: ["Listed in Google Safe Browsing"],
      domain_age_days: null
    });
  }

  // 🔍 Basic rules
  if (url.includes("@")) {
    score += 40;
    reasons.push("Contains @ symbol (URL masking)");
  }

  const phishingWords = ["login", "secure", "verify", "account", "update", "alert"];
  const keywordMatches = phishingWords.filter(word => lowerUrl.includes(word));

  if (keywordMatches.length >= 2) {
    score += 35;
    reasons.push("Multiple phishing keywords");
  } else if (keywordMatches.length === 1) {
    score += 15;
    reasons.push("Phishing-related keyword");
  }

  if (!url.startsWith("https")) {
    score += 20;
    reasons.push("No HTTPS (insecure)");
  }

  // 🏦 Brand detection (FIXED)
  for (const brand of brands) {
    if (normalizedDomain.includes(brand) && domainName !== brand) {
      score += 50;
      reasons.push(`Fake ${brand} domain`);
      break;
    }
  }

  // 🔍 Similarity
  const legitDomains = [
    "paypal.com",
    "chase.com",
    "bankofamerica.com",
    "apple.com",
    "amazon.com",
    "microsoft.com"
  ];

  for (const legit of legitDomains) {
    const legitName = legit.split(".")[0];
    const distance = levenshtein(domainName, legitName);

    if (distance > 0 && distance <= 2) {
      score += 60;
      reasons.push(`Domain mimics ${legit}`);
      break;
    }
  }

  // 🔤 Character substitution
  for (const brand of brands) {
    if (normalizedDomain.includes(brand) && !domainName.includes(brand)) {
      score += 60;
      reasons.push(`Character substitution attack (${brand})`);
      break;
    }
  }

  // 🌐 Domain age
  const age = await getDomainAge(url);

  if (age !== null && age < 7) {
    score += 40;
    reasons.push("Very new domain");
  } else if (age !== null && age < 30) {
    score += 25;
    reasons.push("New domain");
  }

  // 🌍 TLD risk
  const riskyTLDs = ["xyz", "ru", "tk", "ml", "ga", "cf", "gq", "top", "work"];
  const tld = getTLD(hostname);

  if (riskyTLDs.includes(tld)) {
    score += 25;
    reasons.push(`High-risk TLD (.${tld})`);
  }

  // 🔥 Combo boost
  if (reasons.length >= 3 && score >= 60) {
    score += 15;
    reasons.push("Multiple high-risk indicators");
  }

  // 🎯 Final
  score = Math.min(score, 100);

  let verdict = "Safe";
  if (score >= 80) verdict = "Dangerous";
  else if (score >= 50) verdict = "Suspicious";

  res.json({
    url,
    risk_score: score,
    verdict,
    reasons,
    domain_age_days: age,
  });
};

// 📧 Email analysis
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
