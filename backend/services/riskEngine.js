import { parse } from "tldts";
import { analyzeWithAI } from "./aiAnalyzer.js";
import { getDomainAge } from "./domainCheck.js";
import { checkGoogleSafeBrowsing } from "./safeBrowsing.js";
import { paidUsers } from "../store.js";

// ==============================
// 📊 USAGE
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

function entropy(str) {
  const map = {};
  for (let c of str) map[c] = (map[c] || 0) + 1;

  let result = 0;
  for (let k in map) {
    const p = map[k] / str.length;
    result -= p * Math.log2(p);
  }

  return result;
}

// ==============================
// 🌐 SCAN URL
// ==============================

export const scanUrl = async (req, res) => {
  let { url, domSignals } = req.body;

  if (typeof url !== "string" || url.length > 2000) {
    return res.json({
      risk_score: 0,
      verdict: "Error",
      reasons: ["Invalid URL input"]
    });
  }

  const userIp = req.ip;

  if (!url) {
    return res.json({
      risk_score: 0,
      verdict: "Error",
      reasons: ["URL required"]
    });
  }

  const usage = trackUsage(userIp);
  const isPaid = paidUsers.has(userIp);

  if (!isPaid && usage > 20) {
    return res.json({
      risk_score: 0,
      verdict: "Upgrade Required",
      reasons: ["Free limit reached"]
    });
  }

  // ==============================
  // NORMALIZE URL
  // ==============================

  url = url.trim();
  if (!url.startsWith("http")) url = "https://" + url;

  let hostname = "";
  let rootDomain = "";
  let subdomain = "";
  let path = "";

  try {
    const parsedUrl = new URL(url);
    path = parsedUrl.pathname.toLowerCase();

    const parsed = parse(url);
    hostname = parsed.hostname || "";
    rootDomain = parsed.domain || "";
    subdomain = parsed.subdomain || "";
  } catch {
    return res.json({
      risk_score: 85,
      verdict: "Dangerous",
      reasons: ["Malformed URL"]
    });
  }

  let features = {
    spoof: 0,
    subdomain: 0,
    path: 0,
    tld: 0,
    age: 0,
    dom: 0,
    http: 0
  };

  const reasons = [];

  const trusted = [
    "google.com",
    "chase.com",
    "paypal.com",
    "amazon.com",
    "apple.com",
    "microsoft.com"
  ];

  const isTrusted = trusted.includes(rootDomain);

  // ==============================
  // HOSTNAME TRICK DETECTION
  // ==============================

  if (
    hostname.includes("login") &&
    !rootDomain.includes("login")
  ) {
    features.path += 0.5;
    reasons.push("Misleading hostname structure (login keyword)");
  }

  if (
    hostname.split(".").length > 4 &&
    !isTrusted
  ) {
    features.subdomain += 0.5;
    reasons.push("Excessive subdomain depth");
  }

  // ==============================
  // BASIC SIGNALS
  // ==============================

  if (url.startsWith("http://")) {
    features.http = 1;
    reasons.push("Insecure HTTP connection");
  }

  const keywords = ["login", "verify", "secure", "account", "update"];
  if (keywords.some(k => path.includes(k))) {
    features.path = 1;
    reasons.push("Sensitive URL path detected");
  }

  const brands = ["paypal", "chase", "amazon", "apple"];

  if (!isTrusted && subdomain) {
    if (brands.some(b => subdomain.includes(b))) {
      features.subdomain = 1;
      reasons.push("Brand in subdomain");
    }
  }

  if (!isTrusted) {
    const name = rootDomain.split(".")[0];

    if (brands.some(b => levenshtein(name, b) <= 2 && name !== b)) {
      features.spoof = 1;
      reasons.push("Domain spoofing detected");
    }

    if (entropy(name) > 3.5) {
      features.spoof += 0.5;
      reasons.push("Random-looking domain");
    }
  }

  const badTlds = ["xyz", "top", "click"];
  if (!isTrusted && badTlds.includes(rootDomain.split(".")[1])) {
    features.tld = 1;
    reasons.push("Suspicious domain extension");
  }

  // ==============================
  // DOMAIN AGE
  // ==============================

  let age = null;
  try {
    age = await getDomainAge(url);

    if (!isTrusted && age !== null && age < 30) {
      features.age = 1;
      reasons.push("New domain");
    }
  } catch {}

  // ==============================
  // DOM SIGNALS
  // ==============================

  if (domSignals) {
    if (domSignals.hasPassword) {
      features.dom += 0.5;
      reasons.push("Password input detected");
    }

    if (domSignals.externalForm) {
      features.dom += 0.5;
      reasons.push("Form submits to external domain");
    }

    if (domSignals.hasPassword && domSignals.externalForm) {
      features.dom += 1;
      reasons.push("Login form submits credentials to external site");
    }
  }

  // ==============================
  // MODEL SCORING
  // ==============================

  const score =
    25 * features.spoof +
    20 * features.subdomain +
    15 * features.path +
    10 * features.tld +
    10 * features.age +
    10 * features.dom +
    10 * features.http;

  let finalScore = Math.min(score, 100);

  // ==============================
  // SAFE BROWSING
  // ==============================

  try {
    const flagged = await checkGoogleSafeBrowsing(url);

    if (flagged) {
      finalScore = 100;
      reasons.push("Flagged by Google Safe Browsing");
    }
  } catch (e) {
    console.error("SafeBrowsing error:", e.message);
  }

  // ==============================
  // ANALYTICS LOG
  // ==============================

  console.log("SCAN RESULT:", {
    url,
    rootDomain,
    score: finalScore,
    verdict: finalScore >= 70 ? "Dangerous" : finalScore >= 40 ? "Suspicious" : "Safe",
    reasons
  });

  let verdict = "Safe";
  if (finalScore >= 70) verdict = "Dangerous";
  else if (finalScore >= 40) verdict = "Suspicious";

  return res.json({
    url,
    risk_score: finalScore,
    verdict,
    reasons,
    domain_age_days: age
  });
};

// ==============================
// 📧 EMAIL
// ==============================

export const analyzeEmail = async (req, res) => {
  const { emailText } = req.body;

  if (!emailText) {
    return res.json({
      risk_score: 0,
      verdict: "Error",
      reasons: ["Email required"]
    });
  }

  try {
    return res.json(await analyzeWithAI(emailText));
  } catch {
    return res.json({
      risk_score: 70,
      verdict: "Suspicious",
      reasons: ["AI fallback"]
    });
  }
};
