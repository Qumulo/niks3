-- A pulled NAR is verified as Nix verifies one it substitutes: decompressed
-- with compression, it must parse as a NAR matching nar_hash and nar_size,
-- and ca when there is one. file_hash and file_size no longer take part
-- (upstream may replace the file they describe, and Nix ignores them) but
-- are still written, so a rollback finds them.
--
-- Rows from before this migration have an empty nar_hash. The narinfo is
-- read back from S3 when such a row's NAR is next pulled.

-- +goose Up
-- +goose StatementBegin

ALTER TABLE pulled_nars
ADD COLUMN nar_hash text NOT NULL DEFAULT '',
ADD COLUMN compression text NOT NULL DEFAULT '', -- as Nix reads it: bzip2 when the narinfo named none
ADD COLUMN ca text NOT NULL DEFAULT ''; -- empty when not content-addressed

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE pulled_nars
DROP COLUMN ca,
DROP COLUMN compression,
DROP COLUMN nar_hash;

-- +goose StatementEnd
