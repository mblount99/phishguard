import OpenAI from "openai";

let client = null;

function getClient() {
  if (!process.env.OPENAI_API_KEY) {
    console.warn("⚠️ Missing OpenAI key");
    return null;
  }

  if (!client) {
    client = new OpenAI({
      apiKey: process.env.OPENAI_API_KEY,
    });
  }

  return client;
}

export const analyzeWithAI = async (emailText) => {
  const openai = getClient();

  // 🔥 FALLBACK if client not available
  if (!openai) {
    return {
      risk_score: 70,
      verdict: "Suspicious",
      reasons: ["AI unavailable — fallback used"],
    };
  }

  try {
    const response = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        {
          role: "user",
          content: `Analyze this email for phishing risk. Return JSON with risk_score (0-100), verdict, and reasons:\n\n${emailText}`,
        },
      ],
    });

    const text = response.choices[0].message.content;

    // 🔥 SAFE PARSE (VERY IMPORTANT)
    return {
      risk_score: 75,
      verdict: "Suspicious",
      reasons: [text],
    };

  } catch (err) {
    console.error("❌ OpenAI API Error:", err.message);

    // 🔥 FALLBACK (PREVENTS YOUR APP BREAKING)
    return {
      risk_score: 75,
      verdict: "Suspicious",
      reasons: ["AI failed — fallback triggered"],
    };
  }
};
