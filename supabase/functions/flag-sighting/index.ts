// Coyote sighting community flag endpoint. Triggered by the "🚩 Report this pin"
// link in each pin's popup. Per-IP-per-sighting deduplicated via flag_log.
// At 3 unique-IP flags on a live pin, the pin auto-holds and emails the moderator.

import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.4";

const TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const FLAG_RATE_LIMIT_WINDOW_HOURS = 1;
const FLAG_RATE_LIMIT_MAX = 5;
const AUTO_HOLD_THRESHOLD = 3;
const ALLOWED_ORIGIN = "https://iloveclaremontca.com";
const MODERATE_LINK_BASE =
  "https://mfsovchlmxzyqrehvdik.supabase.co/functions/v1/moderate-sighting";
const MODERATE_LINK_TTL_HOURS = 24;

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  };
}

function jsonResp(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders() },
  });
}

async function hashIp(ip: string, salt: string): Promise<string> {
  const data = new TextEncoder().encode(ip + salt);
  const buf = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .slice(0, 32);
}

async function hmacHex(message: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function buildModerationLink(
  sightingId: string,
  action: "approve" | "remove",
  secret: string,
): Promise<string> {
  const expiry = Math.floor(Date.now() / 1000) + MODERATE_LINK_TTL_HOURS * 3600;
  const sig = await hmacHex(`${sightingId}.${expiry}.${action}`, secret);
  const token = `${sightingId}.${expiry}.${sig}`;
  return `${MODERATE_LINK_BASE}?action=${action}&token=${token}`;
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!)
  );
}

async function verifyTurnstile(token: string, secret: string, ip: string): Promise<boolean> {
  const form = new FormData();
  form.append("secret", secret);
  form.append("response", token);
  form.append("remoteip", ip);
  const res = await fetch(TURNSTILE_VERIFY_URL, { method: "POST", body: form });
  if (!res.ok) return false;
  const data = await res.json();
  return data.success === true;
}

async function sendFlagModeratorEmail(
  sighting: {
    id: string;
    description: string | null;
    cross_street: string | null;
    reported_at: string;
    animal_condition: string;
    flag_count: number;
  },
  resendKey: string,
  moderatorEmail: string,
  signingSecret: string,
): Promise<void> {
  const approveUrl = await buildModerationLink(sighting.id, "approve", signingSecret);
  const removeUrl = await buildModerationLink(sighting.id, "remove", signingSecret);
  const reportedAtFmt = new Date(sighting.reported_at).toLocaleString("en-US", {
    timeZone: "America/Los_Angeles",
    dateStyle: "medium",
    timeStyle: "short",
  });

  const nearRow = sighting.cross_street && sighting.cross_street.length > 0
    ? `<tr><td style="font-weight:600;padding-right:12px;">Near:</td><td>${escapeHtml(sighting.cross_street)}</td></tr>`
    : "";
  const descRow = sighting.description && sighting.description.length > 0
    ? `<tr><td style="font-weight:600;padding-right:12px;vertical-align:top;">Description:</td><td>${escapeHtml(sighting.description)}</td></tr>`
    : "";

  const html = `<!DOCTYPE html>
<html><body style="font-family:system-ui,sans-serif;max-width:560px;margin:0 auto;padding:20px;color:#3d2e1e;">
<h2 style="color:#C67A4B;">Pin flagged by the community</h2>
<p>This sighting hit ${sighting.flag_count} community flags and was auto-hidden from the public map pending your review.</p>
<table style="background:#faf5f0;border-radius:12px;padding:16px;margin:16px 0;width:100%;border-collapse:separate;border-spacing:0 6px;">
  <tr><td style="font-weight:600;padding-right:12px;">When:</td><td>${escapeHtml(reportedAtFmt)} PT</td></tr>
  <tr><td style="font-weight:600;padding-right:12px;">Condition:</td><td>${escapeHtml(sighting.animal_condition)}</td></tr>
  ${nearRow}
  ${descRow}
</table>
<p style="margin:24px 0;">
  <a href="${approveUrl}" style="display:inline-block;background:#5a8c4a;color:#fff;text-decoration:none;padding:12px 24px;border-radius:8px;margin-right:8px;font-weight:600;">&#10003; Approve &amp; restore</a>
  <a href="${removeUrl}" style="display:inline-block;background:#a44;color:#fff;text-decoration:none;padding:12px 24px;border-radius:8px;font-weight:600;">&#10005; Remove permanently</a>
</p>
<p style="font-size:0.85rem;color:#888;">Links expire in ${MODERATE_LINK_TTL_HOURS} hours. If you do nothing, the pin stays hidden from the public map.</p>
</body></html>`;

  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${resendKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: "Claremont Coyote Map <coyote-map@iloveclaremontca.com>",
      to: [moderatorEmail],
      subject: (sighting.cross_street && sighting.cross_street.length > 0
        ? `Coyote pin flagged by community — near ${sighting.cross_street}`
        : `Coyote pin flagged by community`).slice(0, 120),
      html,
    }),
  });

  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    console.error("Resend flag email failed", res.status, detail);
  }
}

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders() });
  }
  if (req.method !== "POST") {
    return jsonResp(405, { error: "method not allowed" });
  }

  let payload: Record<string, unknown>;
  try {
    payload = await req.json();
  } catch {
    return jsonResp(400, { error: "invalid JSON" });
  }

  const { sighting_id, turnstile_token, honeypot } = payload as {
    sighting_id?: unknown;
    turnstile_token?: unknown;
    honeypot?: unknown;
  };

  if (typeof honeypot === "string" && honeypot.length > 0) {
    return jsonResp(400, { error: "invalid submission" });
  }
  if (typeof sighting_id !== "string" || !/^[0-9a-f-]{36}$/i.test(sighting_id)) {
    return jsonResp(400, { error: "invalid sighting_id" });
  }
  if (typeof turnstile_token !== "string" || turnstile_token.length === 0) {
    return jsonResp(400, { error: "missing turnstile_token" });
  }

  const ip =
    req.headers.get("cf-connecting-ip") ||
    req.headers.get("x-forwarded-for")?.split(",")[0].trim() ||
    "unknown";

  const turnstileSecret = Deno.env.get("TURNSTILE_SECRET_KEY");
  if (!turnstileSecret) return jsonResp(500, { error: "server misconfigured" });
  const turnstileOk = await verifyTurnstile(turnstile_token, turnstileSecret, ip);
  if (!turnstileOk) return jsonResp(403, { error: "captcha failed" });

  const salt = Deno.env.get("IP_HASH_SALT");
  if (!salt) return jsonResp(500, { error: "server misconfigured" });
  const ipHash = await hashIp(ip, salt);

  const supabase = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
  );

  const since = new Date(Date.now() - FLAG_RATE_LIMIT_WINDOW_HOURS * 3600 * 1000).toISOString();
  const { count } = await supabase
    .from("flag_log")
    .select("*", { count: "exact", head: true })
    .eq("submitter_ip_hash", ipHash)
    .gte("created_at", since);
  if ((count ?? 0) >= FLAG_RATE_LIMIT_MAX) {
    return jsonResp(429, { error: "rate limit exceeded" });
  }

  const { error: insertErr } = await supabase
    .from("flag_log")
    .insert({ sighting_id, submitter_ip_hash: ipHash });

  if (insertErr) {
    // 23505 = unique_violation: same IP already flagged this pin
    if (insertErr.code === "23505") {
      return jsonResp(200, { ok: true, already_flagged: true });
    }
    // 23503 = foreign_key_violation: pin doesn't exist
    if (insertErr.code === "23503") {
      return jsonResp(404, { error: "sighting not found" });
    }
    console.error("flag_log insert failed", insertErr);
    return jsonResp(500, { error: "flag insert failed" });
  }

  const { data: rpcRows, error: rpcErr } = await supabase
    .rpc("increment_sighting_flag_count", { p_sighting_id: sighting_id });

  if (rpcErr || !rpcRows || (Array.isArray(rpcRows) && rpcRows.length === 0)) {
    console.error("flag_count increment failed", rpcErr);
    return jsonResp(500, { error: "increment failed" });
  }

  const sighting = Array.isArray(rpcRows) ? rpcRows[0] : rpcRows;
  const newCount = sighting.flag_count as number;
  const currentStatus = sighting.status as string;
  const removedAt = sighting.removed_at as string | null;

  if (removedAt) {
    return jsonResp(200, { ok: true, flagged: true, flag_count: newCount, held: false });
  }

  let held = false;
  if (newCount >= AUTO_HOLD_THRESHOLD && currentStatus === "live") {
    const { error: holdErr } = await supabase
      .from("sightings")
      .update({ status: "held" })
      .eq("id", sighting_id)
      .eq("status", "live");
    if (!holdErr) {
      held = true;
      const resendKey = Deno.env.get("RESEND_API_KEY");
      const moderatorEmail = Deno.env.get("MODERATOR_EMAIL");
      const moderateSecret = Deno.env.get("MODERATE_LINK_SIGNING_SECRET");
      if (resendKey && moderatorEmail && moderateSecret) {
        try {
          await sendFlagModeratorEmail(
            {
              id: sighting_id,
              description: sighting.description,
              cross_street: sighting.cross_street,
              reported_at: sighting.reported_at,
              animal_condition: sighting.animal_condition,
              flag_count: newCount,
            },
            resendKey,
            moderatorEmail,
            moderateSecret,
          );
        } catch (err) {
          console.error("flag moderator email error", err);
        }
      } else {
        console.warn("pin auto-held by flags but email env not configured", {
          id: sighting_id,
          flag_count: newCount,
        });
      }
    }
  }

  return jsonResp(200, { ok: true, flagged: true, flag_count: newCount, held });
});
