package pg

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
)

//go:embed migrations/*.sql functions/*.sql
var embedMigrations embed.FS

// DefaultMaxConns caps the pool when neither the caller nor the connection
// string sizes it. pgx would open one connection per core, 192 on a large
// node, while Postgres allows 100 by default. Two servers must fit, as during
// a rolling update, or the new one cannot open a connection at all.
const DefaultMaxConns = 32

// Connect opens a pool on connString and brings the schema up to date.
//
// maxConns sizes the pool when it is above zero. Otherwise the connection
// string's pool_max_conns does, and without one pgx's size, capped at
// DefaultMaxConns.
//
// A goose Provider avoids the package-level goose globals, which race, and
// its session lock serialises replicas starting against one database.
//
// ctx bounds reaching the database, not migrating it, so a slow migration
// cannot fail every restart.
func Connect(ctx context.Context, connString string, maxConns int32) (*pgxpool.Pool, error) {
	slog.Debug("connecting to database", "connection_string", connString)

	config, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to database: %w", err)
	}

	config.MaxConns = poolMaxConns(config.MaxConns, connString, maxConns)
	slog.Info("Database connection pool", "max_conns", config.MaxConns)

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to database: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()

		return nil, fmt.Errorf("unable to connect to database: %w", err)
	}

	if err := migrate(context.WithoutCancel(ctx), pool); err != nil {
		pool.Close()

		return nil, err
	}

	return pool, nil
}

// poolMaxConns picks the pool size. parsed is what pgx read from connString,
// its default when the string names none.
func poolMaxConns(parsed int32, connString string, maxConns int32) int32 {
	switch {
	case maxConns > 0:
		return maxConns
	case strings.Contains(connString, "pool_max_conns"):
		return parsed
	default:
		return min(parsed, DefaultMaxConns)
	}
}

func migrate(ctx context.Context, pool *pgxpool.Pool) error {
	slog.Debug("migrating database")

	db := stdlib.OpenDBFromPool(pool)

	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return fmt.Errorf("failed to create migration locker: %w", err)
	}

	migrations, err := fs.Sub(embedMigrations, "migrations")
	if err != nil {
		return fmt.Errorf("failed to open embedded migrations: %w", err)
	}

	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations, goose.WithSessionLocker(locker))
	if err != nil {
		return fmt.Errorf("failed to create migration provider: %w", err)
	}

	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("failed to migrate db: %w", err)
	}

	// Stored procedures are re-applied on every start, so they are not versioned.
	functions, err := fs.Sub(embedMigrations, "functions")
	if err != nil {
		return fmt.Errorf("failed to open embedded functions: %w", err)
	}

	provider, err = goose.NewProvider(goose.DialectPostgres, db, functions,
		goose.WithSessionLocker(locker), goose.WithDisableVersioning(true))
	if err != nil {
		return fmt.Errorf("failed to create stored procedure provider: %w", err)
	}

	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("failed to migrate stored procedures: %w", err)
	}

	return nil
}
