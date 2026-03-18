import axios from "axios";

export const checkGoogleSafeBrowsing = async (url) => {
  try {
    const res = await axios.post(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${process.env.GOOGLE_API_KEY}`,
      {
        client: {
          clientId: "phishguard",
          clientVersion: "1.0",
        },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url }],
        },
      }
    );

    return res.data.matches ? true : false;
  } catch (err) {
    console.log("Safe browsing check failed");
    return false;
  }
};
