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

func cleanupClosureOlderThan(ctx context.Context, pool *pgxpool.Pool, age time.Duration) (int, error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to get database connection: %w", err)
	}

	defer conn.Release()

	queries := pg.New(conn)

	timeOlder := pgtype.Timestamp{
		Time:  time.Now().UTC().Add(-age),
		Valid: true,
	}

	count, err := queries.DeleteClosures(ctx, timeOlder)
	if err != nil {
		return 0, fmt.Errorf("failed to delete older closures: %w", err)
	}

	return int(count), nil
}

// cleanupUntrustedPulledClosures expires pull-through roots whose key is no
// longer in the trusted set. Their objects then fall out on the orphan
// sweep. A pin holds such a closure like any other; it is
// counted and reported so the operator knows.
func (s *Service) cleanupUntrustedPulledClosures(ctx context.Context) (int, error) {
	names := s.PullThrough.TrustedKeyNames()
	queries := pg.New(s.Pool)

	count, err := queries.DeletePulledClosuresNotSignedBy(ctx, names)
	if err != nil {
		return 0, fmt.Errorf("failed to delete untrusted pulled closures: %w", err)
	}

	if count > 0 {
		slog.Warn("Expired pulled closures no trusted key verified", "count", count, "trusted_keys", names)
	}

	pinned, err := queries.CountPinnedPulledClosuresNotSignedBy(ctx, names)
	if err != nil {
		return 0, fmt.Errorf("failed to count pinned untrusted pulled closures: %w", err)
	}

	if pinned > 0 {
		slog.Warn("Pins are holding pulled closures no trusted key verified", "count", pinned, "trusted_keys", names)
	}

	return int(count), nil
}
