// Coyote sighting submission endpoint.
// Verifies Turnstile, validates Claremont bounds, snaps lat/lng to block grid for privacy,
// hashes submitter IP for rate limiting, inserts via service_role bypassing anon RLS.
// Phase 2: hybrid auto-hold heuristics. Suspicious pins are inserted with status='held'
// and trigger a moderator email containing signed Approve/Remove links.

import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
import { createClient, SupabaseClient } from "https://esm.sh/@supabase/supabase-js@2.45.4";

const TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const RATE_LIMIT_WINDOW_HOURS = 1;
const RATE_LIMIT_MAX_SUBMISSIONS = 3;
const BLOCK_SNAP_PRECISION = 0.0015;

const CLAREMONT_BOUNDS = {
  latMin: 34.07,
  latMax: 34.16,
  lngMin: -117.78,
  lngMax: -117.68,
};

const VALID_CONDITIONS = ["healthy_passing", "bold_aggressive", "sick_injured", "unknown"];

const ALLOWED_ORIGIN = "https://iloveclaremontca.com";

const MODERATE_LINK_BASE =
  "https://mfsovchlmxzyqrehvdik.supabase.co/functions/v1/moderate-sighting";
const MODERATE_LINK_TTL_HOURS = 24;

// Two-tier wordlist:
//   HARD_REJECT_WORDS — slurs + explicit curses. Submission is 400'd outright
//     and never lands in the DB. Word-boundary match (\bword) keeps name-like
//     substrings (e.g. "Cunningham" vs "cunt") from false-positiving.
//   PROFANITY_WORDS  — spam/suggestive terms. Substring match. Holds the pin
//     for moderator review (might be a legitimate edge case).
const HARD_REJECT_WORDS = [
  "fuck", "shit", "bitch", "cunt", "asshole", "bastard", "whore", "slut",
  "nigg", "fagg", "retard", "kike", "chink", "tranny", "pussy",
];

const PROFANITY_WORDS = [
  "dick", "cock", "spic",
  "viagra", "casino", "bitcoin", "crypto", "porn", "xxx", "onlyfans",
  "telegram", "whatsapp", "click here",
  "sexy", "horny", "milf", "lottery", "loan",
];

function containsHardRejectWord(text: string): boolean {
  const lowered = text.toLowerCase();
  return HARD_REJECT_WORDS.some((w) => new RegExp(`\\b${w}`, "i").test(lowered));
}

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

function snapToBlock(coord: number): number {
  return Math.round(coord / BLOCK_SNAP_PRECISION) * BLOCK_SNAP_PRECISION;
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

async function evaluateHoldHeuristics(
  desc: string,
  ipHash: string,
  supabase: SupabaseClient,
): Promise<{ hold: boolean; reasons: string[] }> {
  const reasons: string[] = [];

  if (desc.length < 12) reasons.push("short_description");

  if (desc.length > 8) {
    const letters = desc.replace(/[^a-zA-Z]/g, "");
    if (letters.length > 0) {
      const upperCount = (letters.match(/[A-Z]/g) || []).length;
      if (upperCount / letters.length > 0.7) reasons.push("all_caps");
    }
  }

  if (/https?:\/\//i.test(desc)) reasons.push("contains_url");

  const lowered = desc.toLowerCase();
  if (PROFANITY_WORDS.some((w) => lowered.includes(w))) reasons.push("profanity");

  // Any single token repeating ≥4 times is a strong nonsense/spam signal
  // (e.g. "yo yo yo yo yo"). 4 stays above what real reports naturally hit.
  const tokens = lowered.split(/[^a-z0-9']+/).filter(Boolean);
  const tokenCounts = new Map<string, number>();
  for (const t of tokens) tokenCounts.set(t, (tokenCounts.get(t) ?? 0) + 1);
  for (const count of tokenCounts.values()) {
    if (count >= 4) { reasons.push("repeated_token"); break; }
  }

  const since = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
  const { count: heldCount } = await supabase
    .from("sightings")
    .select("*", { count: "exact", head: true })
    .eq("submitter_ip_hash", ipHash)
    .eq("status", "held")
    .gte("created_at", since);
  if ((heldCount ?? 0) >= 2) reasons.push("repeat_held_ip");

  return { hold: reasons.length > 0, reasons };
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!)
  );
}

async function sendModeratorEmail(
  sighting: {
    id: string;
    description: string;
    cross_street: string;
    reported_at: string;
    animal_condition: string;
  },
  reasons: string[],
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

  const html = `<!DOCTYPE html>
<html><body style="font-family:system-ui,sans-serif;max-width:560px;margin:0 auto;padding:20px;color:#3d2e1e;">
<h2 style="color:#C67A4B;">Coyote pin held for review</h2>
<p>A new sighting tripped the auto-hold heuristics and is waiting for your decision.</p>
<table style="background:#faf5f0;border-radius:12px;padding:16px;margin:16px 0;width:100%;border-collapse:separate;border-spacing:0 6px;">
  <tr><td style="font-weight:600;padding-right:12px;">When:</td><td>${escapeHtml(reportedAtFmt)} PT</td></tr>
  <tr><td style="font-weight:600;padding-right:12px;">Condition:</td><td>${escapeHtml(sighting.animal_condition)}</td></tr>
  <tr><td style="font-weight:600;padding-right:12px;">Near:</td><td>${escapeHtml(sighting.cross_street)}</td></tr>
  <tr><td style="font-weight:600;padding-right:12px;vertical-align:top;">Description:</td><td>${escapeHtml(sighting.description)}</td></tr>
  <tr><td style="font-weight:600;padding-right:12px;vertical-align:top;">Flagged for:</td><td>${escapeHtml(reasons.join(", "))}</td></tr>
</table>
<p style="margin:24px 0;">
  <a href="${approveUrl}" style="display:inline-block;background:#5a8c4a;color:#fff;text-decoration:none;padding:12px 24px;border-radius:8px;margin-right:8px;font-weight:600;">&#10003; Approve &amp; publish</a>
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
      subject: `Coyote pin held: ${reasons[0]} — near ${sighting.cross_street}`.slice(0, 120),
      html,
    }),
  });

  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    console.error("Resend email failed", res.status, detail);
  }
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

  const {
    lat,
    lng,
    description,
    animal_condition,
    reported_at,
    turnstile_token,
    honeypot,
    cross_street,
    submitter_email,
  } = payload as {
    lat?: unknown;
    lng?: unknown;
    description?: unknown;
    animal_condition?: unknown;
    reported_at?: unknown;
    turnstile_token?: unknown;
    honeypot?: unknown;
    cross_street?: unknown;
    submitter_email?: unknown;
  };

  if (typeof honeypot === "string" && honeypot.length > 0) {
    return jsonResp(400, { error: "invalid submission" });
  }

  if (
    typeof lat !== "number" ||
    typeof lng !== "number" ||
    typeof description !== "string" ||
    description.length < 1 ||
    description.length > 280 ||
    typeof turnstile_token !== "string" ||
    turnstile_token.length === 0
  ) {
    return jsonResp(400, { error: "missing or invalid fields" });
  }

  const cleanCrossStreet =
    typeof cross_street === "string"
      ? cross_street.replace(/<[^>]*>/g, "").trim().slice(0, 80)
      : "";
  if (cleanCrossStreet.length < 3) {
    return jsonResp(400, { error: "cross_street required (3-80 chars)" });
  }

  let cleanEmail: string | null = null;
  if (typeof submitter_email === "string" && submitter_email.trim().length > 0) {
    const e = submitter_email.trim().slice(0, 200);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)) {
      return jsonResp(400, { error: "invalid email format" });
    }
    cleanEmail = e;
  }

  if (
    lat < CLAREMONT_BOUNDS.latMin ||
    lat > CLAREMONT_BOUNDS.latMax ||
    lng < CLAREMONT_BOUNDS.lngMin ||
    lng > CLAREMONT_BOUNDS.lngMax
  ) {
    return jsonResp(400, { error: "location outside Claremont" });
  }

  const ip =
    req.headers.get("cf-connecting-ip") ||
    req.headers.get("x-forwarded-for")?.split(",")[0].trim() ||
    "unknown";

  const turnstileSecret = Deno.env.get("TURNSTILE_SECRET_KEY");
  if (!turnstileSecret) return jsonResp(500, { error: "server misconfigured" });

  const turnstileOk = await verifyTurnstile(turnstile_token, turnstileSecret, ip);
  if (!turnstileOk) {
    return jsonResp(403, { error: "captcha failed" });
  }

  const salt = Deno.env.get("IP_HASH_SALT");
  if (!salt) return jsonResp(500, { error: "server misconfigured" });
  const ipHash = await hashIp(ip, salt);

  const supabase = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
  );

  const since = new Date(Date.now() - RATE_LIMIT_WINDOW_HOURS * 3600 * 1000).toISOString();
  const { count } = await supabase
    .from("sightings")
    .select("*", { count: "exact", head: true })
    .eq("submitter_ip_hash", ipHash)
    .gte("created_at", since);
  if ((count ?? 0) >= RATE_LIMIT_MAX_SUBMISSIONS) {
    return jsonResp(429, { error: "rate limit exceeded" });
  }

  let reportedAt: string;
  if (typeof reported_at === "string" && reported_at.length > 0) {
    const d = new Date(reported_at);
    const now = Date.now();
    if (
      isNaN(d.getTime()) ||
      d.getTime() > now + 3600 * 1000 ||
      d.getTime() < now - 7 * 24 * 3600 * 1000
    ) {
      return jsonResp(400, { error: "invalid reported_at" });
    }
    reportedAt = d.toISOString();
  } else {
    reportedAt = new Date().toISOString();
  }

  const condition =
    typeof animal_condition === "string" && VALID_CONDITIONS.includes(animal_condition)
      ? animal_condition
      : "unknown";

  const cleanDesc = description.replace(/<[^>]*>/g, "").trim().slice(0, 280);
  if (cleanDesc.length === 0) {
    return jsonResp(400, { error: "description empty after sanitization" });
  }

  if (containsHardRejectWord(cleanDesc) || containsHardRejectWord(cleanCrossStreet)) {
    return jsonResp(400, { error: "Please remove inappropriate language and resubmit." });
  }

  const snappedLat = snapToBlock(lat);
  const snappedLng = snapToBlock(lng);

  const { hold, reasons } = await evaluateHoldHeuristics(cleanDesc, ipHash, supabase);
  const status = hold ? "held" : "live";

  const { data, error } = await supabase
    .from("sightings")
    .insert({
      lat: snappedLat,
      lng: snappedLng,
      description: cleanDesc,
      animal_condition: condition,
      reported_at: reportedAt,
      submitter_ip_hash: ipHash,
      cross_street: cleanCrossStreet,
      submitter_email: cleanEmail,
      status,
    })
    .select("id, lat, lng, reported_at, animal_condition, description, cross_street, status")
    .single();

  if (error) {
    return jsonResp(500, { error: "insert failed", detail: error.message });
  }

  if (hold) {
    const resendKey = Deno.env.get("RESEND_API_KEY");
    const moderatorEmail = Deno.env.get("MODERATOR_EMAIL");
    const moderateSecret = Deno.env.get("MODERATE_LINK_SIGNING_SECRET");
    if (resendKey && moderatorEmail && moderateSecret) {
      try {
        await sendModeratorEmail(
          {
            id: data.id,
            description: data.description,
            cross_street: data.cross_street,
            reported_at: data.reported_at,
            animal_condition: data.animal_condition,
          },
          reasons,
          resendKey,
          moderatorEmail,
          moderateSecret,
        );
      } catch (err) {
        console.error("moderator email error", err);
      }
    } else {
      console.warn("held pin but moderation email env not configured", {
        id: data.id,
        reasons,
      });
    }
    return jsonResp(200, { ok: true, held: true });
  }

  return jsonResp(200, { ok: true, sighting: data });
});
