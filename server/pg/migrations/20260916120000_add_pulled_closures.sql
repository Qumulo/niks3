-- Pull-through closures are roots created by the read proxy when it fills
-- the bucket from an upstream cache (e.g. cache.nixos.org). They age and
-- expire exactly like uploaded closures; what sets them apart is the
-- signature that vouched for them.

-- +goose Up
-- +goose StatementBegin

-- pulled_sig says how a closure came to be and what vouched for it:
--   NULL         a native upload
--   name:base64  pulled, and the narinfo's fingerprint (StorePath, NarHash,
--                NarSize, References; not FileHash or URL) was verified
--                against this signature by a trusted key; also expires once
--                the key is no longer trusted
ALTER TABLE closures ADD COLUMN pulled_sig text;

-- What a pulled narinfo said about its NAR, so a later NAR miss can be
-- verified against the FileHash without the narinfo in memory: after a
-- restart, on another replica, or when the narinfo was served as a hit.
-- Rows live as long as the narinfo's objects row and are swept by GC.
CREATE TABLE pulled_nars (
    key varchar(1024) PRIMARY KEY,
    narinfo_key varchar(1024) NOT NULL,
    file_hash varchar(128) NOT NULL,
    file_size bigint NOT NULL, -- 0 when the narinfo had no FileSize
    nar_size bigint NOT NULL -- 0 when the narinfo had no NarSize
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE pulled_nars;
ALTER TABLE closures DROP COLUMN pulled_sig;

-- +goose StatementEnd
