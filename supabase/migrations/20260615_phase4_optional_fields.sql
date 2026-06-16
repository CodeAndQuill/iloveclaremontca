-- Phase 4: cross-street + description become optional.
-- cross_street was added as nullable in Phase 1, but description predates
-- Phase 1 and was originally NOT NULL. Drop the constraint so the edge
-- function can insert NULL when the user leaves the field blank.
-- Idempotent — no-op if description is already nullable.

ALTER TABLE sightings ALTER COLUMN description DROP NOT NULL;
