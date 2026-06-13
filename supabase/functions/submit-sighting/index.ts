// Coyote sighting submission endpoint.
// Verifies Turnstile, validates Claremont bounds, snaps lat/lng to block grid for privacy,
// hashes submitter IP for rate limiting, inserts via service_role bypassing anon RLS.

import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.4";

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

  const { lat, lng, description, animal_condition, reported_at, turnstile_token, honeypot } = payload as {
    lat?: unknown;
    lng?: unknown;
    description?: unknown;
    animal_condition?: unknown;
    reported_at?: unknown;
    turnstile_token?: unknown;
    honeypot?: unknown;
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

  const snappedLat = snapToBlock(lat);
  const snappedLng = snapToBlock(lng);

  const { data, error } = await supabase
    .from("sightings")
    .insert({
      lat: snappedLat,
      lng: snappedLng,
      description: cleanDesc,
      animal_condition: condition,
      reported_at: reportedAt,
      submitter_ip_hash: ipHash,
    })
    .select("id, lat, lng, reported_at, animal_condition, description")
    .single();

  if (error) {
    return jsonResp(500, { error: "insert failed", detail: error.message });
  }

  return jsonResp(200, { ok: true, sighting: data });
});
