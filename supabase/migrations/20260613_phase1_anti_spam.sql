-- Phase 1: anti-spam schema additions for sightings table
-- Adds: status (for held/live/removed gating), cross_street (required UGC field),
--       submitter_email (optional, private), flag_count (for Phase 3 community flagging).
-- Updates RLS so only status='live' pins surface to anon and submitter_email is column-blocked.

BEGIN;

-- New columns. All have safe defaults so existing rows remain visible.
ALTER TABLE sightings
  ADD COLUMN IF NOT EXISTS status        TEXT NOT NULL DEFAULT 'live'
    CHECK (status IN ('live', 'held', 'removed')),
  ADD COLUMN IF NOT EXISTS cross_street  TEXT,
  ADD COLUMN IF NOT EXISTS submitter_email TEXT,
  ADD COLUMN IF NOT EXISTS flag_count    INT NOT NULL DEFAULT 0;

-- Helpful index for the RLS predicate and for moderator queries.
CREATE INDEX IF NOT EXISTS sightings_status_reported_at_idx
  ON sightings (status, reported_at DESC)
  WHERE removed_at IS NULL;

-- Replace the anon SELECT policy: now also requires status='live'.
DROP POLICY IF EXISTS "anon read live recent sightings" ON sightings;
CREATE POLICY "anon read live recent sightings"
  ON sightings
  FOR SELECT
  TO anon
  USING (
    removed_at IS NULL
    AND status = 'live'
    AND reported_at > now() - INTERVAL '72 hours'
  );

-- Column-level privacy: anon must never see submitter_email.
-- Revoke broad SELECT, then grant explicit per-column SELECT for the public columns only.
REVOKE SELECT ON sightings FROM anon;
GRANT SELECT (
  id,
  lat,
  lng,
  description,
  animal_condition,
  reported_at,
  cross_street,
  flag_count,
  status
) ON sightings TO anon;

COMMIT;
