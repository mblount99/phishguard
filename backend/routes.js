import express from "express";
import Stripe from "stripe";

import { scanUrl, analyzeEmail } from "./services/riskEngine.js";
import { paidUsers } from "./store.js";

const router = express.Router();

// ==============================
// STRIPE INITIALIZATION
// ==============================

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
// SCAN ROUTES
// ==============================

router.post("/scan-url", scanUrl);
router.post("/analyze-email", analyzeEmail);

// ==============================
// CREATE CHECKOUT SESSION
// ==============================

router.post("/create-checkout-session", async (req, res) => {
  try {
    const stripeClient = getStripe();

    if (!stripeClient) {
      return res.status(500).json({ error: "Stripe not configured" });
    }

    const userIp = req.ip;

    const session = await stripeClient.checkout.sessions.create({
      payment_method_types: ["card"],
      mode: "subscription",

      client_reference_id: userIp, // 🔥 ties user to payment

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

  } catch (err) {
    console.error("❌ Stripe session error:", err.message);
    res.status(500).json({ error: "Failed to create checkout session" });
  }
});

// ==============================
// 🔐 STRIPE WEBHOOK
// ==============================

router.post(
  "/webhook",
  express.raw({ type: "application/json" }),
  (req, res) => {
    const stripeClient = getStripe();

    if (!stripeClient) {
      return res.status(500).send("Stripe not configured");
    }

    const sig = req.headers["stripe-signature"];

    let event;

    try {
      event = stripeClient.webhooks.constructEvent(
        req.body,
        sig,
        process.env.STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      console.error("❌ Webhook signature error:", err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    // ==============================
    // HANDLE SUCCESSFUL PAYMENT
    // ==============================

    if (event.type === "checkout.session.completed") {
      const session = event.data.object;

      const userIp = session.client_reference_id;

      if (userIp) {
        paidUsers.add(userIp);
        console.log("💰 User upgraded:", userIp);
      } else {
        console.warn("⚠️ No client_reference_id found");
      }
    }

    res.json({ received: true });
  }
);

// ==============================
// EXPORT
// ==============================

export default router;
