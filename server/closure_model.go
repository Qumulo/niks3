package server

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/Mic92/niks3/server/pg"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ClosureResponse struct {
	Key       string    `json:"id"`
	UpdatedAt time.Time `json:"updated_at"`
	Objects   []string  `json:"objects"`
}

func getClosure(ctx context.Context, pool *pgxpool.Pool, closureKey string) (*ClosureResponse, error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get database connection: %w", err)
	}

	defer conn.Release()

	queries := pg.New(conn)

	closure, err := queries.GetClosure(ctx, closureKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get closure: %w", err)
	}

	objects, err := queries.GetClosureObjects(ctx, closureKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get closure objects: %w", err)
	}

	return &ClosureResponse{
		Key:       closureKey,
		UpdatedAt: closure.Time,
		Objects:   objects,
	}, nil
}

// deleteClosuresBefore deletes the closures not updated since cutoff, except
// pinned ones. A pin that commits after the lock is seen by the delete.
func deleteClosuresBefore(ctx context.Context, pool *pgxpool.Pool, cutoff time.Time) (int, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
	}

	defer func() { _ = tx.Rollback(ctx) }()

	queries := pg.New(tx)

	keys, err := queries.LockOldClosures(ctx, pgtype.Timestamp{Time: cutoff, Valid: true})
	if err != nil {
		return 0, fmt.Errorf("failed to lock older closures: %w", err)
	}

	count, err := queries.DeleteUnpinnedClosures(ctx, keys)
	if err != nil {
		return 0, fmt.Errorf("failed to delete older closures: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("failed to commit closure cleanup: %w", err)
	}

	return int(count), nil
}

// cleanupUntrustedPulledClosures expires pull-through roots whose key is no
// longer in the trusted set. Their objects then fall out on the orphan
// sweep. A pin holds such a closure like any other; it is
// counted and reported so the operator knows. Like deleteClosuresBefore it
// locks first, so a pin that commits after the lock is seen by the delete.
func (s *Service) cleanupUntrustedPulledClosures(ctx context.Context) (int, error) {
	names := s.PullThrough.TrustedKeyNames()

	count, err := deleteUntrustedPulledClosures(ctx, s.Pool, names)
	if err != nil {
		return 0, err
	}

	if count > 0 {
		slog.Warn("Expired pulled closures no trusted key verified", "count", count, "trusted_keys", names)
	}

	pinned, err := pg.New(s.Pool).CountPinnedPulledClosuresNotSignedBy(ctx, names)
	if err != nil {
		return 0, fmt.Errorf("failed to count pinned untrusted pulled closures: %w", err)
	}

	if pinned > 0 {
		slog.Warn("Pins are holding pulled closures no trusted key verified", "count", pinned, "trusted_keys", names)
	}

	return count, nil
}

// deleteUntrustedPulledClosures deletes the pulled closures no key in names
// verified, except pinned ones.
func deleteUntrustedPulledClosures(ctx context.Context, pool *pgxpool.Pool, names []string) (int, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
	}

	defer func() { _ = tx.Rollback(ctx) }()

	queries := pg.New(tx)

	keys, err := queries.LockPulledClosuresNotSignedBy(ctx, names)
	if err != nil {
		return 0, fmt.Errorf("failed to lock untrusted pulled closures: %w", err)
	}

	count, err := queries.DeleteUnpinnedClosures(ctx, keys)
	if err != nil {
		return 0, fmt.Errorf("failed to delete untrusted pulled closures: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("failed to commit untrusted pulled closure cleanup: %w", err)
	}

	return int(count), nil
}
