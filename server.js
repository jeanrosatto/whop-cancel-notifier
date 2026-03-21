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

// Resend sandbox (onboarding@resend.dev) can only send to the account owner.
// Once you verify your domain at resend.com/domains, add ria@ back here.
const NOTIFY_EMAILS = [
  "jean@vectoralgorithmics.com",
];

if (!WHOP_WEBHOOK_SECRET) throw new Error("Missing WHOP_WEBHOOK_SECRET");
if (!RESEND_API_KEY) throw new Error("Missing RESEND_API_KEY");

const resend = new Resend(RESEND_API_KEY);

// Webhook signature verification (Standard Webhooks / HMAC-SHA256)
function verifyWebhook(payload, headers) {
  const msgId = headers["webhook-id"];
  const msgTimestamp = headers["webhook-timestamp"];
  const msgSignature = headers["webhook-signature"];

  if (!msgId || !msgTimestamp || !msgSignature) {
    console.error("[VERIFY] Missing required headers");
    return false;
  }

  const toSign = msgId + "." + msgTimestamp + "." + payload;
  const key = Buffer.from(WHOP_WEBHOOK_SECRET, "utf-8");
  const computed = crypto.createHmac("sha256", key).update(toSign).digest("base64");

  const passedSigs = msgSignature.split(" ").map(function(s) {
    var parts = s.split(",");
    return { version: parts[0], sig: parts[1] };
  });

  for (var i = 0; i < passedSigs.length; i++) {
    if (passedSigs[i].version === "v1" && passedSigs[i].sig === computed) {
      return true;
    }
  }

  console.error("[VERIFY] Signature mismatch");
  return false;
}

// Email helpers
function buildCancelAtPeriodEndEmail(data) {
  var user = data.member && data.member.user ? data.member.user : {};
  var product = data.product && data.product.title ? data.product.title : "Unknown Product";
  var reason = data.cancellation_reason || "No reason provided";
  var cancelOption = data.cancel_option || "N/A";
  var periodEnd = data.renewal_period_end
    ? new Date(data.renewal_period_end).toLocaleDateString("en-US", {
        year: "numeric", month: "long", day: "numeric",
      })
    : "Unknown";

  var subject = "Cancellation: " + (user.name || user.username || "A member") + " cancelled " + product;
  var html = '<div style="font-family:sans-serif;max-width:600px;margin:0 auto"><h2 style="color:#e74c3c">Subscription Cancellation</h2><p>A member has cancelled. They retain access until billing period ends.</p><table style="width:100%;border-collapse:collapse;margin:20px 0"><tr><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold">Member</td><td style="padding:8px;border-bottom:1px solid #eee">' + (user.name||"N/A") + ' (' + (user.username||"N/A") + ')</td></tr><tr><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold">Email</td><td style="padding:8px;border-bottom:1px solid #eee">' + (user.email||"N/A") + '</td></tr><tr><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold">Product</td><td style="padding:8px;border-bottom:1px solid #eee">' + product + '</td></tr><tr><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold">Cancel reason</td><td style="padding:8px;border-bottom:1px solid #eee">' + cancelOption + '</td></tr><tr><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold">Details</td><td style="padding:8px;border-bottom:1px solid #eee">' + reason + '</td></tr><tr><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold">Access until</td><td style="padding:8px;border-bottom:1px solid #eee">' + periodEnd + '</td></tr><tr><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold">Membership ID</td><td style="padding:8px;border-bottom:1px solid #eee"><code>' + data.id + '</code></td></tr></table></div>';

  return { subject: subject, html: html };
}

function buildDeactivatedEmail(data) {
  var user = data.member && data.member.user ? data.member.user : {};
  var product = data.product && data.product.title ? data.product.title : "Unknown Product";

  var subject = "Deactivated: " + (user.name || user.username || "A member") + " lost access to " + product;
  var html = '<div style="font-family:sans-serif;max-width:600px;margin:0 auto"><h2 style="color:#c0392b">Membership Deactivated</h2><p>A membership has been deactivated.</p><table style="width:100%;border-collapse:collapse;margin:20px 0"><tr><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold">Member</td><td style="padding:8px;border-bottom:1px solid #eee">' + (user.name||"N/A") + ' (' + (user.username||"N/A") + ')</td></tr><tr><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold">Email</td><td style="padding:8px;border-bottom:1px solid #eee">' + (user.email||"N/A") + '</td></tr><tr><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold">Product</td><td style="padding:8px;border-bottom:1px solid #eee">' + product + '</td></tr><tr><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold">Status</td><td style="padding:8px;border-bottom:1px solid #eee">' + (data.status||"deactivated") + '</td></tr><tr><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold">Membership ID</td><td style="padding:8px;border-bottom:1px solid #eee"><code>' + data.id + '</code></td></tr></table></div>';

  return { subject: subject, html: html };
}

async function sendNotification(email) {
  var result = await resend.emails.send({
    from: FROM_EMAIL,
    to: NOTIFY_EMAILS,
    subject: email.subject,
    html: email.html,
  });
  if (result.error) {
    console.error("[EMAIL ERROR]", result.error);
    throw new Error(result.error.message);
  }
  console.log("[EMAIL SENT] " + email.subject + " to " + NOTIFY_EMAILS.join(", "));
}

var app = express();
app.use(express.raw({ type: "application/json" }));

app.post("/webhooks/whop", async function(req, res) {
  var rawBody = req.body.toString("utf-8");

  var verified = verifyWebhook(rawBody, req.headers);
  if (!verified) {
    console.warn("[WEBHOOK] Signature verification FAILED - processing anyway");
  }

  var event;
  try {
    event = JSON.parse(rawBody);
  } catch (err) {
    console.error("[WEBHOOK] Failed to parse body:", err.message);
    return res.status(400).json({ error: "Invalid JSON" });
  }

  var type = event.type;
  var data = event.data;
  console.log("[WEBHOOK] " + type + " - membership: " + (data && data.id ? data.id : "unknown"));

  res.status(200).json({ received: true });

  try {
    if (type === "membership.cancel_at_period_end_changed") {
      if (data.cancel_at_period_end === true) {
        var email = buildCancelAtPeriodEndEmail(data);
        await sendNotification(email);
      } else {
        console.log("[SKIP] Un-cancelled membership " + data.id);
      }
    } else if (type === "membership.deactivated") {
      var email2 = buildDeactivatedEmail(data);
      await sendNotification(email2);
    } else {
      console.log("[SKIP] Unhandled event type: " + type);
    }
  } catch (err) {
    console.error("[HANDLER ERROR]", err);
  }
});

app.get("/", function(req, res) {
  res.json({ status: "ok", service: "whop-cancel-notifier" });
});

app.listen(PORT, function() {
  console.log("Whop Cancel Notifier running on port " + PORT);
  console.log("Webhook endpoint: POST /webhooks/whop");
  console.log("Notifications -> " + NOTIFY_EMAILS.join(", "));
});

