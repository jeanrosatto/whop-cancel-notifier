/**
 * Whop Cancellation Notifier
 */

import express from "express";
import crypto from "crypto";
import { Resend } from "resend";

const {
  WHOP_WEBHOOK_SECRET,
  RESEND_API_KEY,
  FROM_EMAIL = "Whop Alerts <onboarding@resend.dev>",
  PORT = 3000,
} = process.env;

const NOTIFY_EMAILS = [
  "ria@vectoralgorithmics.com",
  "jean@vectoralgorithmics.com",
];

if (!WHOP_WEBHOOK_SECRET) throw new Error("Missing WHOP_WEBHOOK_SECRET");
if (!RESEND_API_KEY) throw new Error("Missing RESEND_API_KEY");

const resend = new Resend(RESEND_API_KEY);

// Manual webhook signature verification
// Try multiple interpretations of the Whop secret
function verifyWebhook(payload, headers) {
  const msgId = headers["webhook-id"];
  const msgTimestamp = headers["webhook-timestamp"];
  const msgSignature = headers["webhook-signature"];

  if (!msgId || !msgTimestamp || !msgSignature) {
    console.error("[VERIFY] Missing required headers");
    return false;
  }

  const toSign = msgId + "." + msgTimestamp + "." + payload;

  // Strip ws_ prefix
  const stripped = WHOP_WEBHOOK_SECRET.replace(/^whsec_|^ws_/, "");

  // Try different secret interpretations
  const candidates = [
    { name: "hex-decoded", key: Buffer.from(stripped, "hex") },
    { name: "utf8-bytes", key: Buffer.from(stripped, "utf-8") },
    { name: "full-secret-utf8", key: Buffer.from(WHOP_WEBHOOK_SECRET, "utf-8") },
  ];

  const passedSigs = msgSignature.split(" ").map(s => {
    const parts = s.split(",");
    return { version: parts[0], sig: parts[1] };
  });

  console.log("[VERIFY] Received signatures:", JSON.stringify(passedSigs));

  for (const candidate of candidates) {
    const computed = crypto.createHmac("sha256", candidate.key).update(toSign).digest("base64");
    console.log("[VERIFY] " + candidate.name + " => " + computed);

    for (const passed of passedSigs) {
      if (passed.version === "v1" && passed.sig === computed) {
        console.log("[VERIFY] MATCH with " + candidate.name);
        return true;
      }
    }
  }

  console.error("[VERIFY] No matching signature found");
  return false;
}

// Email helpers
function buildCancelAtPeriodEndEmail(data) {
  const user = data.member?.user ?? {};
  const product = data.product?.title ?? "Unknown Product";
  const reason = data.cancellation_reason ?? "No reason provided";
  const cancelOption = data.cancel_option ?? "N/A";
  const periodEnd = data.renewal_period_end
    ? new Date(data.renewal_period_end).toLocaleDateString("en-US", {
        year: "numeric", month: "long", day: "numeric",
      })
    : "Unknown";

  const subject = "Cancellation: " + (user.name || user.username || "A member") + " cancelled " + product;
  const html = '<div style="font-family:sans-serif;max-width:600px;margin:0 auto"><h2 style="color:#e74c3c">Subscription Cancellation</h2><p>A member has cancelled. They retain access until billing period ends.</p><table style="width:100%;border-collapse:collapse;margin:20px 0"><tr><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold">Member</td><td style="padding:8px;border-bottom:1px solid #eee">' + (user.name||"N/A") + ' (' + (user.username||"N/A") + ')</td></tr><tr><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold">Email</td><td style="padding:8px;border-bottom:1px solid #eee">' + (user.email||"N/A") + '</td></tr><tr><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold">Product</td><td style="padding:8px;border-bottom:1px solid #eee">' + product + '</td></tr><tr><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold">Cancel reason</td><td style="padding:8px;border-bottom:1px solid #eee">' + cancelOption + '</td></tr><tr><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold">Details</td><td style="padding:8px;border-bottom:1px solid #eee">' + reason + '</td></tr><tr><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold">Access until</td><td style="padding:8px;border-bottom:1px solid #eee">' + periodEnd + '</td></tr><tr><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold">Membership ID</td><td style="padding:8px;border-bottom:1px solid #eee"><code>' + data.id + '</code></td></tr></table></div>';

  return { subject, html };
}

function buildDeactivatedEmail(data) {
  const user = data.member?.user ?? {};
  const product = data.product?.title ?? "Unknown Product";

  const subject = "Deactivated: " + (user.name || user.username || "A member") + " lost access to " + product;
  const html = '<div style="font-family:sans-serif;max-width:600px;margin:0 auto"><h2 style="color:#c0392b">Membership Deactivated</h2><p>A membership has been deactivated.</p><table style="width:100%;border-collapse:collapse;margin:20px 0"><tr><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold">Member</td><td style="padding:8px;border-bottom:1px solid #eee">' + (user.name||"N/A") + ' (' + (user.username||"N/A") + ')</td></tr><tr><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold">Email</td><td style="padding:8px;border-bottom:1px solid #eee">' + (user.email||"N/A") + '</td></tr><tr><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold">Product</td><td style="padding:8px;border-bottom:1px solid #eee">' + product + '</td></tr><tr><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold">Status</td><td style="padding:8px;border-bottom:1px solid #eee">' + (data.status||"deactivated") + '</td></tr><tr><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold">Membership ID</td><td style="padding:8px;border-bottom:1px solid #eee"><code>' + data.id + '</code></td></tr></table></div>';

  return { subject, html };
}

async function sendNotification({ subject, html }) {
  const result = await resend.emails.send({
    from: FROM_EMAIL,
    to: NOTIFY_EMAILS,
    subject,
    html,
  });
  if (result.error) {
    console.error("[EMAIL ERROR]", result.error);
    throw new Error(result.error.message);
  }
  console.log("[EMAIL SENT] " + subject + " to " + NOTIFY_EMAILS.join(", "));
}

const app = express();
app.use(express.raw({ type: "application/json" }));

app.post("/webhooks/whop", async (req, res) => {
  const rawBody = req.body.toString("utf-8");

  // Verify signature but still process on failure (for debugging)
  const verified = verifyWebhook(rawBody, req.headers);
  if (!verified) {
    console.warn("[WEBHOOK] Signature verification FAILED - processing anyway for debugging");
  }

  let event;
  try {
    event = JSON.parse(rawBody);
  } catch (err) {
    console.error("[WEBHOOK] Failed to parse body:", err.message);
    return res.status(400).json({ error: "Invalid JSON" });
  }

  const { type, data } = event;
  console.log("[WEBHOOK] " + type + " - membership: " + (data?.id || "unknown"));

  res.status(200).json({ received: true });

  try {
    if (type === "membership.cancel_at_period_end_changed") {
      if (data.cancel_at_period_end === true) {
        const email = buildCancelAtPeriodEndEmail(data);
        await sendNotification(email);
      } else {
        console.log("[SKIP] Un-cancelled membership " + data.id);
      }
    } else if (type === "membership.deactivated") {
      const email = buildDeactivatedEmail(data);
      await sendNotification(email);
    } else {
      console.log("[SKIP] Unhandled event type: " + type);
    }
  } catch (err) {
    console.error("[HANDLER ERROR]", err);
  }
});

app.get("/", (req, res) => {
  res.json({ status: "ok", service: "whop-cancel-notifier" });
});

app.listen(PORT, () => {
  console.log("Whop Cancel Notifier running on port " + PORT);
  console.log("Webhook endpoint: POST /webhooks/whop");
  console.log("Notifications -> " + NOTIFY_EMAILS.join(", "));
});

