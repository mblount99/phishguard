import dotenv from "dotenv";

dotenv.config();

console.log("✅ ENV LOADED:", process.env.STRIPE_SECRET_KEY);
