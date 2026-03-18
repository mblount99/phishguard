
import OpenAI from "openai";

const client = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY, // keep your key here for now
});

export const analyzeWithAI = async (emailText) => {
  try {
    const response = await client.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        {
          role: "system",
          content:
            "You are a cybersecurity expert specializing in phishing detection.",
        },
        {
          role: "user",
          content: `
Analyze the following email and determine if it is phishing.

Return ONLY valid JSON in this exact format:
{
  "risk_score": number (0-100),
  "verdict": "Safe" | "Suspicious" | "Phishing",
  "reasons": ["reason1", "reason2"]
}

Email:
${emailText}
          `,
        },
      ],
      temperature: 0,
    });

    const content = response.choices[0].message.content;

    // Try parsing AI response
    try {
      return JSON.parse(content);
    } catch (parseError) {
      console.log("⚠️ Failed to parse AI response:", content);

      return {
        risk_score: 50,
        verdict: "Suspicious",
        reasons: ["AI response was not valid JSON"],
      };
    }
  } catch (error) {
    console.error("❌ OpenAI API Error:", error.message);

    return {
      risk_score: 0,
      verdict: "Error",
      reasons: ["Failed to analyze email"],
    };
  }
};
