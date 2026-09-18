package server_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Mic92/niks3/server"
	"github.com/Mic92/niks3/server/pg"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// The pulled-closure bookkeeping exercised on its own, before anything
// writes it: the column and table a read proxy that fills the bucket from
// an upstream cache will record its fills in, and the GC steps that keep
// them consistent.

type closureRow struct {
	pulledSig pgtype.Text
	updatedAt time.Time
}

func getClosureRow(ctx context.Context, tb testing.TB, service *server.Service, key string) (closureRow, bool) {
	tb.Helper()

	var row closureRow

	err := service.Pool.QueryRow(ctx, "SELECT pulled_sig, updated_at FROM closures WHERE key = $1", key).Scan(&row.pulledSig, &row.updatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return row, false
	}

	ok(tb, err)

	return row, true
}

func hasPulledNarRow(ctx context.Context, tb testing.TB, service *server.Service, narKey string) bool {
	tb.Helper()

	var found bool

	err := service.Pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pulled_nars WHERE key = $1)", narKey).Scan(&found)
	ok(tb, err)

	return found
}

func pulledSig(sig string) pgtype.Text {
	return pgtype.Text{String: sig, Valid: true}
}

// A pulled closure records the signature that vouched for it and a re-fill
// records the latest one. A native upload of the same path takes the root
// over: pulled_sig becomes NULL, and a later pull leaves the upload's
// closure alone.
func TestPulledClosureTakenOverByUpload(t *testing.T) {
	t.Parallel()

	service := createTestService(t)
	defer service.Close()

	ctx := t.Context()
	queries := pg.New(service.Pool)

	hash := "26xbg1ndr7hbcncrlf9nhx5is2b25d13"
	key := hash + ".narinfo"

	ok(t, queries.UpsertPulledClosure(ctx, pg.UpsertPulledClosureParams{Key: key, PulledSig: pulledSig("upstream-1:first")}))

	row, found := getClosureRow(ctx, t, service, key)
	if !found || row.pulledSig.String != "upstream-1:first" {
		t.Fatalf("closure row = %+v found=%v, want pulled_sig upstream-1:first", row, found)
	}

	ok(t, queries.UpsertPulledClosure(ctx, pg.UpsertPulledClosureParams{Key: key, PulledSig: pulledSig("upstream-1:second")}))

	if row, _ = getClosureRow(ctx, t, service, key); row.pulledSig.String != "upstream-1:second" {
		t.Fatalf("closure row = %+v after re-fill, want the latest signature", row)
	}

	createTestClosure(t, service, queries, hash)

	uploaded, _ := getClosureRow(ctx, t, service, key)
	if uploaded.pulledSig.Valid {
		t.Fatalf("closure row = %+v after upload, want pulled_sig NULL", uploaded)
	}

	ok(t, queries.UpsertPulledClosure(ctx, pg.UpsertPulledClosureParams{Key: key, PulledSig: pulledSig("upstream-1:third")}))

	if row, _ = getClosureRow(ctx, t, service, key); row.pulledSig.Valid || !row.updatedAt.Equal(uploaded.updatedAt) {
		t.Errorf("closure row = %+v after a pull of an uploaded path, want it untouched (%+v)", row, uploaded)
	}
}

// pulled_sig names the key that verified a closure. Dropping a key from
// the trusted set expires what it vouched for, matched by key name; a pin
// holds its closure and is counted instead; uploads are never touched.
func TestDeletePulledClosuresNotSignedBy(t *testing.T) {
	t.Parallel()

	service := createTestService(t)
	defer service.Close()

	ctx := t.Context()
	queries := pg.New(service.Pool)

	for key, sig := range map[string]string{
		"0000000000000000000000000000000a.narinfo": "signer-1:aaaa",
		"0000000000000000000000000000000b.narinfo": "signer-2:bbbb",
		"0000000000000000000000000000000c.narinfo": "signer-2:cccc",
	} {
		ok(t, queries.UpsertPulledClosure(ctx, pg.UpsertPulledClosureParams{Key: key, PulledSig: pulledSig(sig)}))
	}

	createTestClosure(t, service, queries, "0000000000000000000000000000000d")

	ok(t, queries.UpsertPin(ctx, pg.UpsertPinParams{
		Name:       "held",
		NarinfoKey: "0000000000000000000000000000000c.narinfo",
		StorePath:  "/nix/store/0000000000000000000000000000000c-held",
	}))

	trusted := []string{"signer-1", "signer-3"}

	deleted, err := queries.DeletePulledClosuresNotSignedBy(ctx, trusted)
	ok(t, err)

	if deleted != 1 {
		t.Errorf("deleted %d closures, want 1", deleted)
	}

	pinned, err := queries.CountPinnedPulledClosuresNotSignedBy(ctx, trusted)
	ok(t, err)

	if pinned != 1 {
		t.Errorf("counted %d pinned closures, want 1", pinned)
	}

	for key, want := range map[string]bool{
		"0000000000000000000000000000000a.narinfo": true,
		"0000000000000000000000000000000b.narinfo": false,
		"0000000000000000000000000000000c.narinfo": true,
		"0000000000000000000000000000000d.narinfo": true,
	} {
		if _, found := getClosureRow(ctx, t, service, key); found != want {
			t.Errorf("%s: found=%v, want %v", key, found, want)
		}
	}
}

// What a narinfo says about its NAR lives as long as the narinfo's objects
// row and is swept by GC once that is gone.
func TestGCSweepsOrphanedPulledNars(t *testing.T) {
	t.Parallel()

	service := createTestService(t)
	defer service.Close()

	ctx := t.Context()
	queries := pg.New(service.Pool)

	narinfoKey := "26xbg1ndr7hbcncrlf9nhx5is2b25d13.narinfo"
	narKey := "nar/1ngi2dxw1f7khrrjamzkkdai393lwcm8s78gvs1ag8k3n82w7bvp.nar.xz"
	orphanKey := "nar/0000000000000000000000000000000000000000000000000000.nar.xz"

	ok(t, queries.RegisterCompletedObject(ctx, pg.RegisterCompletedObjectParams{Key: narinfoKey, Refs: []string{narKey}}))
	ok(t, queries.UpsertPulledClosure(ctx, pg.UpsertPulledClosureParams{Key: narinfoKey, PulledSig: pulledSig("upstream-1:sig")}))

	ok(t, queries.UpsertPulledNar(ctx, pg.UpsertPulledNarParams{
		Key: narKey, NarinfoKey: narinfoKey, FileHash: "sha256:abc", FileSize: 42, NarSize: 64,
	}))
	ok(t, queries.UpsertPulledNar(ctx, pg.UpsertPulledNarParams{
		Key: orphanKey, NarinfoKey: "0000000000000000000000000000000a.narinfo", FileHash: "sha256:def", FileSize: 1, NarSize: 2,
	}))

	meta, err := queries.GetPulledNar(ctx, narKey)
	ok(t, err)

	if meta.NarinfoKey != narinfoKey || meta.FileHash != "sha256:abc" || meta.FileSize != 42 || meta.NarSize != 64 {
		t.Errorf("GetPulledNar = %+v", meta)
	}

	if status := service.RunGCForTest(24*time.Hour, time.Hour, true); status.Error != "" {
		t.Fatalf("GC failed: %s", status.Error)
	}

	if !hasPulledNarRow(ctx, t, service, narKey) {
		t.Error("NAR metadata was swept while its narinfo is tracked")
	}

	if hasPulledNarRow(ctx, t, service, orphanKey) {
		t.Error("NAR metadata without a narinfo survived GC")
	}

	// The closure expires; the narinfo's row goes on the orphan sweep and
	// the metadata with it.
	_, err = service.Pool.Exec(ctx, "UPDATE closures SET updated_at = now() - interval '2 days' WHERE key = $1", narinfoKey)
	ok(t, err)

	if status := service.RunGCForTest(24*time.Hour, time.Hour, true); status.Error != "" {
		t.Fatalf("GC failed: %s", status.Error)
	}

	if hasPulledNarRow(ctx, t, service, narKey) {
		t.Error("NAR metadata survived its narinfo")
	}

	if _, err := queries.GetPulledNar(ctx, narKey); !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("GetPulledNar after the sweep: err=%v, want no rows", err)
	}
}

// The objects table answers whether a key is tracked at all and whether it
// is live, so the read proxy can decide without an S3 round trip.
func TestObjectIsLiveAndTracked(t *testing.T) {
	t.Parallel()

	service := createTestService(t)
	defer service.Close()

	ctx := t.Context()
	queries := pg.New(service.Pool)

	key := "nar/1ngi2dxw1f7khrrjamzkkdai393lwcm8s78gvs1ag8k3n82w7bvp.nar.xz"

	check := func(wantLive, wantTracked bool) {
		t.Helper()

		live, err := queries.ObjectIsLive(ctx, key)
		ok(t, err)

		tracked, err := queries.ObjectIsTracked(ctx, key)
		ok(t, err)

		if live != wantLive || tracked != wantTracked {
			t.Errorf("live=%v tracked=%v, want live=%v tracked=%v", live, tracked, wantLive, wantTracked)
		}
	}

	check(false, false)

	ok(t, queries.RegisterCompletedObject(ctx, pg.RegisterCompletedObjectParams{Key: key, Refs: []string{}}))
	check(true, true)

	_, err := service.Pool.Exec(ctx, "UPDATE objects SET deleted_at = now(), first_deleted_at = now() WHERE key = $1", key)
	ok(t, err)
	check(false, true)

	ok(t, queries.DeleteObjects(ctx, []string{key}))
	check(false, false)
}
