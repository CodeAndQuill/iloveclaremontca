// Sighting removal endpoint. Triggered by signed links emailed in the daily digest.
// Token format: <sighting_id>.<expiry_unix>.<hmac_sha256_hex>
// HMAC covers `<sighting_id>.<expiry_unix>` using REMOVE_LINK_SIGNING_SECRET.

import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.4";

function htmlResp(status: number, title: string, body: string) {
  const page = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title} — Coyote Map</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 540px; margin: 80px auto; padding: 24px; color: #3d2e1e; }
  h1 { color: #C67A4B; font-family: Georgia, serif; }
  .box { background: #faf5f0; border-radius: 12px; padding: 24px; margin-top: 16px; }
  a { color: #7B5EA7; }
</style></head>
<body><h1>${title}</h1><div class="box">${body}</div>
<p style="margin-top:24px;font-size:0.9rem;color:#888">
<a href="https://iloveclaremontca.com/Guides/coyote-sighting-map.html">Back to the sighting map</a>
</p></body></html>`;
  return new Response(page, { status, headers: { "Content-Type": "text/html; charset=utf-8" } });
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

function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

serve(async (req) => {
  const url = new URL(req.url);
  const token = url.searchParams.get("token");
  if (!token) return htmlResp(400, "Missing token", "<p>No token provided.</p>");

  const parts = token.split(".");
  if (parts.length !== 3) return htmlResp(400, "Bad token", "<p>Token format is invalid.</p>");
  const [sightingId, expiryStr, providedSig] = parts;

  const expiry = parseInt(expiryStr, 10);
  if (isNaN(expiry)) return htmlResp(400, "Bad token", "<p>Token expiry is malformed.</p>");
  if (Date.now() / 1000 > expiry) {
    return htmlResp(410, "Link expired",
      "<p>This removal link has expired. Open the sighting in the Supabase dashboard to remove it manually.</p>");
  }

  const signingSecret = Deno.env.get("REMOVE_LINK_SIGNING_SECRET");
  if (!signingSecret) return htmlResp(500, "Server error", "<p>Signing secret not configured.</p>");

  const expectedSig = await hmacHex(`${sightingId}.${expiryStr}`, signingSecret);
  if (!constantTimeEqual(providedSig, expectedSig)) {
    return htmlResp(403, "Invalid signature", "<p>This link's signature did not verify.</p>");
  }

  const supabase = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
  );

  const { data: existing, error: fetchErr } = await supabase
    .from("sightings")
    .select("id, removed_at, description")
    .eq("id", sightingId)
    .maybeSingle();

  if (fetchErr) return htmlResp(500, "Lookup failed", `<p>${fetchErr.message}</p>`);
  if (!existing) return htmlResp(404, "Not found", "<p>That sighting does not exist.</p>");
  if (existing.removed_at) {
    return htmlResp(200, "Already removed",
      `<p>This sighting was already removed at ${new Date(existing.removed_at).toLocaleString()}.</p>`);
  }

  const { error: updateErr } = await supabase
    .from("sightings")
    .update({ removed_at: new Date().toISOString(), removed_reason: "removed via digest link" })
    .eq("id", sightingId);

  if (updateErr) return htmlResp(500, "Removal failed", `<p>${updateErr.message}</p>`);

  return htmlResp(200, "Sighting removed",
    `<p>The sighting <code>${sightingId.slice(0, 8)}…</code> has been removed from the public map.</p>
     <p>This change takes effect within ~60 seconds.</p>`);
});
