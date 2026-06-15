-- Phase 3: community flag button.
-- Adds the flag_log table for per-IP-per-sighting dedup, plus an atomic
-- increment_sighting_flag_count() RPC so the flag-sighting edge function
-- can bump flag_count and read the resulting row in one round-trip.

CREATE TABLE flag_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  sighting_id UUID NOT NULL REFERENCES sightings(id) ON DELETE CASCADE,
  submitter_ip_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(sighting_id, submitter_ip_hash)
);

CREATE INDEX flag_log_sighting_id_idx ON flag_log(sighting_id);
CREATE INDEX flag_log_created_at_idx ON flag_log(created_at);

-- Anon never touches flag_log directly; all writes go through the
-- flag-sighting edge function using the service role.
ALTER TABLE flag_log ENABLE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION increment_sighting_flag_count(p_sighting_id UUID)
RETURNS TABLE (
  flag_count INT,
  status TEXT,
  description TEXT,
  cross_street TEXT,
  reported_at TIMESTAMPTZ,
  animal_condition TEXT,
  removed_at TIMESTAMPTZ
)
LANGUAGE sql
AS $$
  UPDATE sightings
  SET flag_count = flag_count + 1
  WHERE id = p_sighting_id
  RETURNING
    flag_count,
    status,
    description,
    cross_street,
    reported_at,
    animal_condition,
    removed_at;
$$;
