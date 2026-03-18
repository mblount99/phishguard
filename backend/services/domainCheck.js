import axios from "axios";

export const getDomainAge = async (url) => {
  try {
    const domain = new URL(url).hostname;

    const res = await axios.get(
      `https://api.api-ninjas.com/v1/whois?domain=${domain}`,
      {
        headers: {
          "X-Api-Key": process.env.NINJA_API_KEY,
        },
      }
    );

    const creationDate = res.data.creation_date;

    if (!creationDate) return null;

    const created = new Date(creationDate);
    const now = new Date();

    const ageDays = Math.floor((now - created) / (1000 * 60 * 60 * 24));

    return ageDays;
  } catch (err) {
    console.log("Domain age lookup failed");
    return null;
  }
};
