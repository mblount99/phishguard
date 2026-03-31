import express from "express";
import Stripe from "stripe";

import { scanUrl, analyzeEmail, paidUsers } from "./services/riskEngine.js";

const router = express.Router();

let stripe = null;

function getStripe() {
  if (!process.env.STRIPE_SECRET_KEY) {
    console.error("❌ Missing STRIPE_SECRET_KEY");
    return null;
  }

  if (!stripe) {
    stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
  }

  return stripe;
}

// ==============================
// 🔍 SCAN ROUTES
// ==============================
router.post("/scan-url", scanUrl);
router.post("/analyze-email", analyzeEmail);

// ==============================
// 💰 CREATE CHECKOUT SESSION
// ==============================

router.post("/create-checkout-session", async (req, res) => {
  const userIp = req.ip;

  const session = await stripe.checkout.sessions.create({
    payment_method_types: ["card"],
    mode: "subscription",

    client_reference_id: userIp, // 🔥 KEY LINE

    line_items: [
      {
        price_data: {
          currency: "usd",
          product_data: {
            name: "PhishGuard Premium",
          },
          unit_amount: 499,
          recurring: { interval: "month" },
        },
        quantity: 1,
      },
    ],

    success_url: "https://google.com?success=true",
    cancel_url: "https://google.com?canceled=true",
  });

  res.json({ url: session.url });
});


// ==============================
// 🔐 STRIPE WEBHOOK
// ==============================

// ⚠️ NOTE: raw body required for Stripe
router.post(
  "/webhook",
  express.raw({ type: "application/json" }),
  (req, res) => {
    const sig = req.headers["stripe-signature"];

    let event;

    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        sig,
        process.env.STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      console.error("❌ Webhook signature error:", err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    // ✅ Successful subscription/payment
    if (event.type === "checkout.session.completed") {
      const session = event.data.object;

      const ip = session.client_reference_id;

      if (ip) {
        paidUsers.add(ip);
        console.log("💰 User upgraded:", ip);
      }
    }

    res.json({ received: true });
  }
);

export default router;
