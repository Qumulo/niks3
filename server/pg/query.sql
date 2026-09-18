-- name: InsertPendingClosure :one
INSERT INTO pending_closures (started_at, key)
VALUES (timezone('UTC', now()), $1)
RETURNING *;

-- name: InsertPendingObjects :copyfrom
INSERT INTO pending_objects (pending_closure_id, key, refs, size) VALUES ($1, $2, $3, $4);

-- name: GetObjectStats :one
SELECT object_count, total_bytes FROM object_stats WHERE id;

-- name: CountPendingClosures :one
SELECT count(*) FROM pending_closures;

-- name: GetPendingObjectKeys :many
SELECT key FROM pending_objects
WHERE pending_closure_id = $1;

-- name: GetExistingObjects :many
WITH ct AS (
    SELECT timezone('UTC', now()) AS now
)

SELECT
    o.key AS key,
    (CASE
        WHEN o.first_deleted_at IS NULL THEN NULL
        ELSE ct.now - o.first_deleted_at
    END)::interval AS deleted_at
FROM objects AS o, ct
WHERE key = any($1::varchar []);

-- name: CommitPendingClosure :exec
SELECT commit_pending_closure($1::bigint);

-- name: RegisterCompletedObject :exec
-- Record an object as soon as its upload completes so later closures don't
-- re-offer it if this closure never commits. Conflict handling matches
-- commit_pending_closure: merge refs, keep a known size, resurrect tombstones.
INSERT INTO objects (key, refs, size)
VALUES (sqlc.arg(key), sqlc.arg(refs)::varchar [], sqlc.arg(size))
ON CONFLICT (key) DO UPDATE SET
    refs = (
        SELECT ARRAY(
            SELECT DISTINCT unnest(objects.refs || excluded.refs)
        )
    ),
    size = coalesce(objects.size, excluded.size),
    deleted_at = NULL,
    first_deleted_at = NULL;

-- name: GetPendingObject :one
SELECT refs, size FROM pending_objects
WHERE pending_closure_id = $1 AND key = $2;

-- name: GetPendingObjectByKey :one
-- Any pending closure's row for this key; used to recover refs/size when the
-- upload is registered outside closure commit.
SELECT refs, size FROM pending_objects
WHERE key = $1
LIMIT 1;

-- name: CleanupPendingClosures :execrows
WITH cutoff_time AS (
    SELECT timezone('UTC', now()) - interval '1 second' * $1::int AS time
),

old_closures AS (
    SELECT id
    FROM pending_closures, cutoff_time
    WHERE started_at < cutoff_time.time
),

-- Insert pending objects into objects table if they don't already exist
-- We mark them as deleted so they can be cleaned up later
inserted_objects AS (
    INSERT INTO objects (key, refs, deleted_at, first_deleted_at)
    SELECT
        po.key,
        po.refs,
        cutoff_time.time,
        cutoff_time.time
    FROM pending_objects AS po
    JOIN old_closures oc ON po.pending_closure_id = oc.id, cutoff_time
    ON CONFLICT (key) DO NOTHING
    RETURNING key
),

-- Delete pending objects that were inserted into the objects table
deleted_pending_objects AS (
    DELETE FROM pending_objects
    USING old_closures
    WHERE pending_objects.pending_closure_id = old_closures.id
    RETURNING pending_closure_id
)

-- Delete pending closures older than the specified interval
-- This will cascade to pending_objects
DELETE FROM pending_closures
USING old_closures
WHERE pending_closures.id = old_closures.id;

-- name: GetClosure :one
SELECT updated_at FROM closures
WHERE key = $1 LIMIT 1;

-- name: GetClosureObjects :many
-- Return objects reachable from the given closure key
WITH RECURSIVE closure_reach AS (
    -- Start with the provided closure key
    SELECT o.key, o.refs 
    FROM objects o
    WHERE o.key = $1
    UNION
    -- Recursively add all referenced objects
    SELECT o.key, o.refs 
    FROM objects o
    INNER JOIN closure_reach cr ON o.key = ANY(cr.refs)
)
SELECT DISTINCT key FROM closure_reach;

-- name: DeleteClosures :execrows
-- Delete old closures, uploaded or pulled alike, but exclude any that are
-- pinned.
DELETE FROM closures
WHERE closures.updated_at < $1
  AND closures.key NOT IN (SELECT narinfo_key FROM pins);

-- name: DeletePulledClosuresNotSignedBy :execrows
-- Expire pull-through closures whose narinfo was verified by a key since
-- dropped from the trusted set. Keys are matched by name, which is how Nix
-- identifies them too: rotating a key means a new name (cache.nixos.org-1,
-- -2), and a replacement key that reuses a name keeps what the old one
-- vouched for. Pinned closures are kept, as under the other expiries.
DELETE FROM closures
WHERE closures.pulled_sig IS NOT NULL
  AND split_part(closures.pulled_sig, ':', 1) <> ALL($1::text [])
  AND closures.key NOT IN (SELECT narinfo_key FROM pins);

-- name: CountPinnedPulledClosuresNotSignedBy :one
-- The pinned closures DeletePulledClosuresNotSignedBy would otherwise have
-- expired, so the operator can be told a pin is holding one.
SELECT count(*) FROM closures
WHERE closures.pulled_sig IS NOT NULL
  AND split_part(closures.pulled_sig, ':', 1) <> ALL($1::text [])
  AND closures.key IN (SELECT narinfo_key FROM pins);

-- name: UpsertPulledClosure :exec
-- Root a pulled narinfo, recording the signature it was verified with. A
-- re-fill records the latest verification. An existing upload closure for
-- the same key is left untouched: it already keeps the object alive.
INSERT INTO closures (key, updated_at, pulled_sig)
VALUES ($1, timezone('UTC', now()), $2)
ON CONFLICT (key) DO UPDATE SET updated_at = timezone('UTC', now()), pulled_sig = excluded.pulled_sig
WHERE closures.pulled_sig IS NOT NULL;

-- name: UpsertPulledNar :exec
-- Remember what a pulled narinfo said about its NAR.
INSERT INTO pulled_nars (key, narinfo_key, file_hash, file_size, nar_size)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (key) DO UPDATE SET
    narinfo_key = excluded.narinfo_key,
    file_hash = excluded.file_hash,
    file_size = excluded.file_size,
    nar_size = excluded.nar_size;

-- name: GetPulledNar :one
SELECT narinfo_key, file_hash, file_size, nar_size FROM pulled_nars
WHERE key = $1;

-- name: DeleteOrphanedPulledNars :execrows
-- Drop NAR metadata whose narinfo is no longer tracked at all.
DELETE FROM pulled_nars
WHERE NOT EXISTS (
    SELECT 1 FROM objects
    WHERE objects.key = pulled_nars.narinfo_key
);

-- name: ObjectIsLive :one
-- Whether the object is tracked and not tombstoned. The read proxy uses
-- this instead of an S3 HEAD before redirecting NAR reads.
SELECT EXISTS (
    SELECT 1 FROM objects
    WHERE key = $1 AND deleted_at IS NULL
)::boolean AS live;

-- name: ObjectIsTracked :one
-- Whether the object has a row at all, tombstoned or not. The hit path
-- adopts a tagged pull-through object that has none.
SELECT EXISTS (
    SELECT 1 FROM objects
    WHERE key = $1
)::boolean AS tracked;

-- name: MarkObjectsAsActive :exec
UPDATE objects SET deleted_at = NULL
WHERE key = any($1::varchar []);

-- name: DeleteObjects :exec
-- Drop the rows of objects GC removed from S3. A row that was resurrected
-- in the meantime (a pull-through fill or an upload re-registered the key
-- between the S3 delete and this batched flush) is left alone: its new
-- object is tracked, and untracking it would leak it in the bucket.
DELETE FROM objects
WHERE key = any($1::varchar [])
  AND deleted_at IS NOT NULL;

-- name: InsertMultipartUpload :exec
INSERT INTO multipart_uploads (pending_closure_id, object_key, upload_id)
VALUES ($1, $2, $3);

-- name: GetOldMultipartUploads :many
SELECT upload_id, object_key
FROM multipart_uploads mu
JOIN pending_closures pc ON mu.pending_closure_id = pc.id
WHERE pc.started_at < timezone('UTC', now()) - interval '1 second' * $1::int;

-- name: DeleteMultipartUpload :exec
DELETE FROM multipart_uploads
WHERE upload_id = $1;

-- name: GetRedundantMultipartUploads :many
-- Upload IDs other pending_closures opened for object_key, used to abort
-- duplicates once one upload of the NAR completes.
SELECT upload_id
FROM multipart_uploads
WHERE object_key = $1 AND upload_id <> $2;

-- name: GetMultipartUpload :one
SELECT pending_closure_id, object_key, upload_id
FROM multipart_uploads
WHERE upload_id = $1 AND object_key = $2;

-- name: ResurrectReachableObjects :execrows
-- Clear the tombstone of objects that became reachable again after they
-- were marked: a pull-through fill re-rooted a narinfo whose NAR was still
-- tombstoned, or an upload re-offered them. Runs under the GC lock before
-- the tombstones are read for S3 deletion, so no delete can be in flight
-- for these keys and their S3 objects are known to exist.
WITH RECURSIVE closure_reach AS (
    SELECT o.key, o.refs
    FROM objects o
    INNER JOIN closures c ON o.key = c.key
    UNION
    SELECT o.key, o.refs
    FROM objects o
    INNER JOIN closure_reach cr ON o.key = ANY(cr.refs)
)

UPDATE objects
SET deleted_at = NULL, first_deleted_at = NULL
WHERE objects.deleted_at IS NOT NULL
  AND EXISTS (
      SELECT 1 FROM closure_reach cr
      WHERE cr.key = objects.key
  );

-- name: MarkStaleObjects :execrows
WITH RECURSIVE ct AS (
    SELECT timezone('UTC', now()) AS now
),
-- Find all objects reachable from any closure
closure_reach AS (
    -- Start with all closure keys
    SELECT o.key, o.refs
    FROM objects o
    INNER JOIN closures c ON o.key = c.key
    UNION
    -- Recursively add all referenced objects
    SELECT o.key, o.refs
    FROM objects o
    INNER JOIN closure_reach cr ON o.key = ANY(cr.refs)
),
reachable_objects AS (
    SELECT DISTINCT key FROM closure_reach
),
stale_objects AS (
    SELECT o.key
    FROM objects AS o, ct
    WHERE
        NOT EXISTS (
            SELECT 1
            FROM reachable_objects ro
            WHERE ro.key = o.key
        )
        AND NOT EXISTS (
            SELECT 1
            FROM pending_objects AS po
            WHERE po.key = o.key
        )
        AND o.deleted_at IS NULL  -- Only mark fresh objects
    FOR UPDATE
)
UPDATE objects
SET
    deleted_at = ct.now,
    first_deleted_at = COALESCE(first_deleted_at, ct.now)
FROM stale_objects, ct
WHERE objects.key = stale_objects.key;

-- name: GetObjectsReadyForDeletion :many
-- Returns objects marked for >= grace_period, safe to delete from S3
SELECT key
FROM objects
WHERE first_deleted_at IS NOT NULL
  AND deleted_at IS NOT NULL
  AND first_deleted_at <= timezone('UTC', now()) - interval '1 second' * sqlc.arg(grace_period_seconds)::int
LIMIT sqlc.arg(limit_count);

-- name: GetClosureForShare :one
-- Lock the closure row so concurrent GC cannot delete it between the
-- existence check and the pin upsert.
SELECT updated_at FROM closures
WHERE key = $1 LIMIT 1
FOR SHARE;

-- name: UpsertPin :exec
-- Create or update a pin. Updates the narinfo_key, store_path, and updated_at if the pin already exists.
INSERT INTO pins (name, narinfo_key, store_path, created_at, updated_at)
VALUES ($1, $2, $3, timezone('UTC', now()), timezone('UTC', now()))
ON CONFLICT (name) DO UPDATE SET
    narinfo_key = EXCLUDED.narinfo_key,
    store_path = EXCLUDED.store_path,
    updated_at = timezone('UTC', now());

-- name: GetPin :one
SELECT name, narinfo_key, store_path, created_at, updated_at
FROM pins
WHERE name = $1;

-- name: DeletePin :exec
DELETE FROM pins
WHERE name = $1;

-- name: ListPins :many
SELECT name, narinfo_key, store_path, created_at, updated_at
FROM pins
ORDER BY name;
