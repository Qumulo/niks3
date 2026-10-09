package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"github.com/Mic92/niks3/server/pg"
	"github.com/minio/minio-go/v7"
)

const (
	DeletionBatchSize = 1000
)

// ObjectCleanupStats contains statistics about object cleanup operations.
type ObjectCleanupStats struct {
	MarkedCount  int
	DeletedCount int
	FailedCount  int
}

// sweepBatch deletes one batch of tombstoned objects from S3 and then their
// rows. The rows stay locked from the query to the commit, so a push that
// wants to treat one of them as present waits and finds it gone. Keys whose
// S3 delete fails keep their tombstone for the next run. It returns the last
// key it looked at, or "" when nothing is left.
func (s *Service) sweepBatch(ctx context.Context, gracePeriod int32, afterKey string, stats *ObjectCleanupStats) (string, []error, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("begin sweep transaction: %w", err)
	}

	defer func() { _ = tx.Rollback(ctx) }()

	keys, err := pg.New(tx).LockObjectsReadyForDeletion(ctx, pg.LockObjectsReadyForDeletionParams{
		GracePeriodSeconds: gracePeriod,
		AfterKey:           afterKey,
		LimitCount:         DeletionBatchSize,
	})
	if err != nil {
		return "", nil, fmt.Errorf("failed to get objects ready for deletion: %w", err)
	}

	if len(keys) == 0 {
		return "", nil, nil
	}

	unpending, err := pg.New(tx).GetKeysNotPending(ctx, keys)
	if err != nil {
		return "", nil, fmt.Errorf("recheck pending objects: %w", err)
	}

	objectCh := make(chan minio.ObjectInfo, len(unpending))
	for _, key := range unpending {
		objectCh <- minio.ObjectInfo{Key: key}
	}

	close(objectCh)

	var (
		deleted []string
		s3Errs  []error
	)

	for result := range s.MinioClient.RemoveObjectsWithResult(ctx, s.Bucket, objectCh, minio.RemoveObjectsOptions{}) {
		switch {
		case result.Err == nil:
			s.S3RateLimiter.RecordSuccess()
		case isRateLimitError(result.Err):
			s.S3RateLimiter.RecordThrottle()
		}

		// NoSuchKey: the object is gone already, so the row can go too.
		if result.Err != nil && minio.ToErrorResponse(result.Err).Code != minio.NoSuchKey {
			slog.Error("failed to remove object", "object", result.ObjectName, "error", result.Err)

			s3Errs = append(s3Errs, fmt.Errorf("failed to remove object %q: %w", result.ObjectName, result.Err))
			stats.FailedCount++

			continue
		}

		deleted = append(deleted, result.ObjectName)
	}

	if err := pg.New(tx).DeleteObjects(ctx, deleted); err != nil {
		return "", s3Errs, fmt.Errorf("delete object rows: %w", err)
	}

	if err := pg.New(tx).DeleteClaims(ctx, deleted); err != nil {
		return "", s3Errs, fmt.Errorf("delete claims: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return "", s3Errs, fmt.Errorf("commit sweep transaction: %w", err)
	}

	stats.DeletedCount += len(deleted)

	return keys[len(keys)-1], s3Errs, nil
}

// resurrectReachableObjects clears the tombstones of objects that became
// reachable again since they were marked, so the sweep keeps them. It runs
// under the GC lock, so no S3 delete is in flight, but an earlier run may have
// deleted an object and failed before deleting its row, as when S3's answer to
// the delete was lost. Only objects S3 still holds come back; the sweep deletes
// the rows of the rest.
func (s *Service) resurrectReachableObjects(ctx context.Context) error {
	queries := pg.New(s.Pool)

	keys, err := queries.ListReachableTombstonedObjects(ctx)
	if err != nil {
		return fmt.Errorf("failed to list reachable tombstoned objects: %w", err)
	}

	missing, err := s.checkS3ObjectsExist(ctx, keys)
	if err != nil {
		// They stay tombstoned, as they would without this step.
		slog.Warn("Not keeping tombstoned objects that are reachable again", "count", len(keys), "error", err)

		return nil
	}

	present := slices.DeleteFunc(keys, func(key string) bool { return missing[key] })

	resurrected, err := queries.ResurrectObjects(ctx, present)
	if err != nil {
		return fmt.Errorf("failed to resurrect reachable objects: %w", err)
	}

	if resurrected > 0 {
		slog.Info("Kept tombstoned objects that are reachable again", "count", resurrected)
	}

	return nil
}

// cleanupOrphanObjects marks unreachable objects and deletes them from S3.
// When onProgress is non-nil it is called after every batch so callers can
// expose live counters.
func (s *Service) cleanupOrphanObjects(ctx context.Context, gracePeriod int32, onProgress func(ObjectCleanupStats)) (*ObjectCleanupStats, error) {
	stats := &ObjectCleanupStats{}

	notify := func() {
		if onProgress != nil {
			onProgress(*stats)
		}
	}

	if err := s.resurrectReachableObjects(ctx); err != nil {
		return stats, err
	}

	// Without a grace period the second mark comes right away.
	marks := 1
	if gracePeriod == 0 {
		marks = 2
	}

	for range marks {
		if err := pg.New(s.Pool).AwaitRecordingPushes(ctx, recordingPushesLockKey); err != nil {
			return stats, fmt.Errorf("failed to wait for recording pushes: %w", err)
		}

		marked, err := pg.New(s.Pool).MarkStaleObjects(ctx)
		if err != nil {
			return stats, fmt.Errorf("failed to mark stale objects: %w", err)
		}

		stats.MarkedCount = int(marked)
		notify()
	}

	var errs []error

	for afterKey := ""; ; {
		last, batchErrs, err := s.sweepBatch(ctx, gracePeriod, afterKey, stats)
		errs = append(errs, batchErrs...)

		if err != nil {
			errs = append(errs, err)

			break
		}

		notify()

		if last == "" {
			break
		}

		afterKey = last
	}

	if len(errs) > 0 {
		return stats, fmt.Errorf("%d sweep failures: %w", len(errs), errors.Join(errs...))
	}

	return stats, nil
}
