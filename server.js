/**
 * Whop Cancellation Notifier
 *
 * A lightweight Express server that listens for Whop webhook events
 * and emails you whenever a client cancels their subscription.
 *
 * Events handled:
 *   - membership.cancel_at_period_end_changed  (user clicks "cancel")
 *   - membership.deactivated                   (membership actually expires)
 */

import express from "express";
import { Webhook } from "standardwebhooks";
import { Resend } from "resend";

// ── Config ────────────────────────────────────────────────────────────────────
const {
  WHOP_WEBHOOK_SECRET,
  RESEND_API_KEY,
  FROM_EMAIL = "Whop Alerts <onboarding@resend.dev>",
  PORT = 3000,
} = process.env;

// Who receives cancellation notifications (add/remove as needed)
const NOTIFY_EMAILS = [
  "ria@vectoralgorithmics.com",
  "jean@vectoralgorithmics.com",  // testing — remove when no longer needed
];

if (!WHOP_WEBHOOK_SECRET) throw new Error("Missing WHOP_WEBHOOK_SECRET");
if (!RESEND_API_KEY) throw new Error("Missing RESEND_API_KEY");

const resend = new Resend(RESEND_API_KEY);

// ── Webhook signature verification ───────────────────────────────────────────
// Whop follows the Standard Webhooks spec.
// The standardwebhooks library expects a base64-encoded secret.
// Whop's ws_ secret is the raw signing key as a string — base64-encode it for the library.
const rawSecret = WHOP_WEBHOOK_SECRET.replace(/^whsec_|^ws_/, "");
const base64Secret = Buffer.from(rawSecret).toString("base64");
const webhookVerifier = new Webhook(base64Secret);

function verifyWebhook(payload, headers) {
  return webhookVerifier.verify(payload, {
    "webhook-id": headers["webhook-id"],
    "webhook-signature": headers["webhook-signature"],
    "webhook-timestamp": headers["webhook-timestamp"],
  });
}

// ── Email helpers ─────────────────────────────────────────────────────────────
function buildCancelAtPeriodEndEmail(data) {
  const user = data.member?.user ?? {};
  const product = data.product?.title ?? "Unknown Product";
  const reason = data.cancellation_reason ?? "No reason provided";
  const cancelOption = data.cancel_option ?? "N/A";
  const periodEnd = data.renewal_period_end
    ? new Date(data.renewal_period_end).toLocaleDateString("en-US", {
        year: "numeric",
        month: "long",
        day: "numeric",
      })
    : "Unknown";

  const subject = `⚠️ Cancellation: ${user.name || user.username || "A member"} cancelled ${product}`;

  const html = `
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #e74c3c;">Subscription Cancellation</h2>
      <p>A member has cancelled their subscription. They will retain access until the end of their current billing period.</p>

      <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
        <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold; width: 160px;">Member</td>
            <td style="padding: 8px; border-bottom: 1px solid #eee;">${user.name || "N/A"} (${user.username || "N/A"})</td></tr>
        <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Email</td>
            <td style="padding: 8px; border-bottom: 1px solid #eee;">${user.email || "N/A"}</td></tr>
        <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Product</td>
            <td style="padding: 8px; border-bottom: 1px solid #eee;">${product}</td></tr>
        <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Cancel reason</td>
            <td style="padding: 8px; border-bottom: 1px solid #eee;">${cancelOption}</td></tr>
        <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Details</td>
            <td style="padding: 8px; border-bottom: 1px solid #eee;">${reason}</td></tr>
        <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Access until</td>
            <td style="padding: 8px; border-bottom: 1px solid #eee;">${periodEnd}</td></tr>
        <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Membership ID</td>
            <td style="padding: 8px; border-bottom: 1px solid #eee;"><code>${data.id}</code></td></tr>
      </table>

      <p style="color: #888; font-size: 13px;">
        You can manage this membership at
        <a href="${data.manage_url || "#"}">${data.manage_url || "Whop Dashboard"}</a>.
      </p>
    </div>
  `;

  return { subject, html };
}

function buildDeactivatedEmail(data) {
  const user = data.member?.user ?? {};
  const product = data.product?.title ?? "Unknown Product";

  const subject = `🔴 Deactivated: ${user.name || user.username || "A member"} lost access to ${product}`;

  const html = `
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #c0392b;">Membership Deactivated</h2>
      <p>A membership has been deactivated — the member no longer has access.</p>

      <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
        <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold; width: 160px;">Member</td>
            <td style="padding: 8px; border-bottom: 1px solid #eee;">${user.name || "N/A"} (${user.username || "N/A"})</td></tr>
        <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Email</td>
            <td style="padding: 8px; border-bottom: 1px solid #eee;">${user.email || "N/A"}</td></tr>
        <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Product</td>
            <td style="padding: 8px; border-bottom: 1px solid #eee;">${product}</td></tr>
        <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Status</td>
            <td style="padding: 8px; border-bottom: 1px solid #eee;">${data.status || "deactivated"}</td></tr>
        <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Membership ID</td>
            <td style="padding: 8px; border-bottom: 1px solid #eee;"><code>${data.id}</code></td></tr>
      </table>

      <p style="color: #888; font-size: 13px;">This could be due to a cancelled subscription expiring, a failed payment, or the member leaving the community.</p>
    </div>
  `;

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

  console.log(`[EMAIL SENT] "${subject}" → ${NOTIFY_EMAILS.join(", ")} (id: ${result.data?.id})`);
}

// ── Express app ───────────────────────────────────────────────────────────────
const app = express();

// We need the raw body for signature verification
app.use(express.raw({ type: "application/json" }));

app.post("/webhooks/whop", async (req, res) => {
  const rawBody = req.body.toString("utf-8");

  // 1. Verify the webhook signature
  let event;
  try {
    event = verifyWebhook(rawBody, req.headers);
  } catch (err) {
    console.error("[WEBHOOK VERIFY FAILED]", err.message);
    return res.status(401).json({ error: "Invalid signature" });
  }

  // Parse if the verifier returned a string
  if (typeof event === "string") event = JSON.parse(event);

  const { type, data } = event;
  console.log(`[WEBHOOK] ${type} — membership: ${data?.id}`);

  // 2. Return 200 quickly so Whop doesn't retry
  res.status(200).json({ received: true });

  // 3. Handle the event asynchronously
  try {
    if (type === "membership.cancel_at_period_end_changed") {
      // Only notify when cancel_at_period_end is true (user cancelled),
      // not when they un-cancel.
      if (data.cancel_at_period_end === true) {
        const email = buildCancelAtPeriodEndEmail(data);
        await sendNotification(email);
      } else {
        console.log(`[SKIP] Membership ${data.id} was un-cancelled (cancel_at_period_end=false)`);
      }
    } else if (type === "membership.deactivated") {
      const email = buildDeactivatedEmail(data);
      await sendNotification(email);
    } else {
      console.log(`[SKIP] Unhandled event type: ${type}`);
    }
  } catch (err) {
    console.error("[HANDLER ERROR]", err);
  }
});

// Health check
app.get("/", (req, res) => {
  res.json({ status: "ok", service: "whop-cancel-notifier" });
});

app.listen(PORT, () => {
  console.log(`\n🚀 Whop Cancel Notifier running on port ${PORT}`);
  console.log(`   Webhook endpoint: POST http://localhost:${PORT}/webhooks/whop`);
  console.log(`   Notifications → ${NOTIFY_EMAILS.join(", ")}\n`);
});/**
 * Whop Cancellation Notifier
 *
 * A lightweight Express server that listens for Whop webhook events
 * and emails you whenever a client cancels their subscription.
 *
 * Events handled:
 *   - membership.cancel_at_period_end_changed  (user clicks "cancel")
 *   - membership.deactivated                   (membership actually expires)
 */

import express from "express";
import { Webhook } from "standardwebhooks";
import { Resend } from "resend";

// ── Config ────────────────────────────────────────────────────────────────────
const {
  WHOP_WEBHOOK_SECRET,
  RESEND_API_KEY,
  FROM_EMAIL = "Whop Alerts <onboarding@resend.dev>",
  PORT = 3000,
} = process.env;

// Who receives cancellation notifications (add/remove as needed)
const NOTIFY_EMAILS = [
  "ria@vectoralgorithmics.com",
  "jean@vectoralgorithmics.com",  // testing — remove when no longer needed
];

if (!WHOP_WEBHOOK_SECRET) throw new Error("Missing WHOP_WEBHOOK_SECRET");
if (!RESEND_API_KEY) throw new Error("Missing RESEND_API_KEY");

const resend = new Resend(RESEND_API_KEY);

// ── Webhook signature verification ───────────────────────────────────────────
// Whop follows the Standard Webhooks spec.
// The standardwebhooks library expects a base64-encoded secret.
// Whop's secret is a hex string (with optional "ws_" prefix), so we convert it.
const rawSecret = WHOP_WEBHOOK_SECRET.replace(/^whsec_|^ws_/, "");
const secretBytes = Buffer.from(rawSecret, "hex");
const base64Secret = secretBytes.toString("base64");
const webhookVerifier = new Webhook(base64Secret);

function verifyWebhook(payload, headers) {
  return webhookVerifier.verify(payload, {
    "webhook-id": headers["webhook-id"],
    "webhook-signature": headers["webhook-signature"],
    "webhook-timestamp": headers["webhook-timestamp"],
  });
}

// ── Email helpers ─────────────────────────────────────────────────────────────
function buildCancelAtPeriodEndEmail(data) {
  const user = data.member?.user ?? {};
  const product = data.product?.title ?? "Unknown Product";
  const reason = data.cancellation_reason ?? "No reason provided";
  const cancelOption = data.cancel_option ?? "N/A";
  const periodEnd = data.renewal_period_end
    ? new Date(data.renewal_period_end).toLocaleDateString("en-US", {
        year: "numeric",
        month: "long",
        day: "numeric",
      })
    : "Unknown";

  const subject = `⚠️ Cancellation: ${user.name || user.username || "A member"} cancelled ${product}`;

  const html = `
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #e74c3c;">Subscription Cancellation</h2>
      <p>A member has cancelled their subscription. They will retain access until the end of their current billing period.</p>

      <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
        <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold; width: 160px;">Member</td>
            <td style="padding: 8px; border-bottom: 1px solid #eee;">${user.name || "N/A"} (${user.username || "N/A"})</td></tr>
        <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Email</td>
            <td style="padding: 8px; border-bottom: 1px solid #eee;">${user.email || "N/A"}</td></tr>
        <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Product</td>
            <td style="padding: 8px; border-bottom: 1px solid #eee;">${product}</td></tr>
        <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Cancel reason</td>
            <td style="padding: 8px; border-bottom: 1px solid #eee;">${cancelOption}</td></tr>
        <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Details</td>
            <td style="padding: 8px; border-bottom: 1px solid #eee;">${reason}</td></tr>
        <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Access until</td>
            <td style="padding: 8px; border-bottom: 1px solid #eee;">${periodEnd}</td></tr>
        <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Membership ID</td>
            <td style="padding: 8px; border-bottom: 1px solid #eee;"><code>${data.id}</code></td></tr>
      </table>

      <p style="color: #888; font-size: 13px;">
        You can manage this membership at
        <a href="${data.manage_url || "#"}">${data.manage_url || "Whop Dashboard"}</a>.
      </p>
    </div>
  `;

  return { subject, html };
}

function buildDeactivatedEmail(data) {
  const user = data.member?.user ?? {};
  const product = data.product?.title ?? "Unknown Product";

  const subject = `🔴 Deactivated: ${user.name || user.username || "A member"} lost access to ${product}`;

  const html = `
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #c0392b;">Membership Deactivated</h2>
      <p>A membership has been deactivated — the member no longer has access.</p>

      <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
        <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold; width: 160px;">Member</td>
            <td style="padding: 8px; border-bottom: 1px solid #eee;">${user.name || "N/A"} (${user.username || "N/A"})</td></tr>
        <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Email</td>
            <td style="padding: 8px; border-bottom: 1px solid #eee;">${user.email || "N/A"}</td></tr>
        <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Product</td>
            <td style="padding: 8px; border-bottom: 1px solid #eee;">${product}</td></tr>
        <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Status</td>
            <td style="padding: 8px; border-bottom: 1px solid #eee;">${data.status || "deactivated"}</td></tr>
        <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Membership ID</td>
            <td style="padding: 8px; border-bottom: 1px solid #eee;"><code>${data.id}</code></td></tr>
      </table>

      <p style="color: #888; font-size: 13px;">This could be due to a cancelled subscription expiring, a failed payment, or the member leaving the community.</p>
    </div>
  `;

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

  console.log(`[EMAIL SENT] "${subject}" → ${NOTIFY_EMAILS.join(", ")} (id: ${result.data?.id})`);
}

// ── Express app ───────────────────────────────────────────────────────────────
const app = express();

// We need the raw body for signature verification
app.use(express.raw({ type: "application/json" }));

app.post("/webhooks/whop", async (req, res) => {
  const rawBody = req.body.toString("utf-8");

  // 1. Verify the webhook signature
  let event;
  try {
    event = verifyWebhook(rawBody, req.headers);
  } catch (err) {
    console.error("[WEBHOOK VERIFY FAILED]", err.message);
    return res.status(401).json({ error: "Invalid signature" });
  }

  // Parse if the verifier returned a string
  if (typeof event === "string") event = JSON.parse(event);

  const { type, data } = event;
  console.log(`[WEBHOOK] ${type} — membership: ${data?.id}`);

  // 2. Return 200 quickly so Whop doesn't retry
  res.status(200).json({ received: true });

  // 3. Handle the event asynchronously
  try {
    if (type === "membership.cancel_at_period_end_changed") {
      // Only notify when cancel_at_period_end is true (user cancelled),
      // not when they un-cancel.
      if (data.cancel_at_period_end === true) {
        const email = buildCancelAtPeriodEndEmail(data);
        await sendNotification(email);
      } else {
        console.log(`[SKIP] Membership ${data.id} was un-cancelled (cancel_at_period_end=false)`);
      }
    } else if (type === "membership.deactivated") {
      const email = buildDeactivatedEmail(data);
      await sendNotification(email);
    } else {
      console.log(`[SKIP] Unhandled event type: ${type}`);
    }
  } catch (err) {
    console.error("[HANDLER ERROR]", err);
  }
});

// Health check
app.get("/", (req, res) => {
  res.json({ status: "ok", service: "whop-cancel-notifier" });
});

app.listen(PORT, () => {
  console.log(`\n🚀 Whop Cancel Notifier running on port ${PORT}`);
  console.log(`   Webhook endpoint: POST http://localhost:${PORT}/webhooks/whop`);
  console.log(`   Notifications → ${NOTIFY_EMAILS.join(", ")}\n`);
});
