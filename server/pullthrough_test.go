package server_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Mic92/niks3/client"
	"github.com/Mic92/niks3/server"
	"github.com/Mic92/niks3/server/signing"
	"github.com/jackc/pgx/v5"
	"github.com/klauspost/compress/zstd"
	minio "github.com/minio/minio-go/v7"
)

// fakeUpstream is an in-memory binary cache served over HTTP.
type fakeUpstream struct {
	mu      sync.Mutex
	objects map[string][]byte
	hits    map[string]int
	srv     *httptest.Server
}

func newFakeUpstream(tb testing.TB) *fakeUpstream {
	tb.Helper()

	u := &fakeUpstream{objects: map[string][]byte{}, hits: map[string]int{}}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, "/")

		u.mu.Lock()
		u.hits[key]++
		data, found := u.objects[key]
		u.mu.Unlock()

		if !found {
			http.NotFound(w, r)

			return
		}

		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.WriteHeader(http.StatusOK)

		if r.Method != http.MethodHead {
			_, _ = w.Write(data)
		}
	}))
	tb.Cleanup(u.srv.Close)

	return u
}

func (u *fakeUpstream) put(key string, data []byte) {
	u.mu.Lock()
	defer u.mu.Unlock()

	u.objects[key] = data
}

func (u *fakeUpstream) hitCount(key string) int {
	u.mu.Lock()
	defer u.mu.Unlock()

	return u.hits[key]
}

// fixture is a consistent narinfo + NAR pair, signed by signer.
type fixture struct {
	hash       string
	narinfoKey string
	narKey     string
	narinfo    []byte
	nar        []byte
	signer     *signing.Key
	publicKey  string
	sig        string // the Sig line the narinfo carries
}

func newFixture(tb testing.TB, hash string, nar []byte) *fixture {
	tb.Helper()

	return newFixtureSignedBy(tb, hash, nar, "upstream-1")
}

// newFixtureSignedBy signs the fixture with a fresh key of the given name.
func newFixtureSignedBy(tb testing.TB, hash string, nar []byte, keyName string) *fixture {
	tb.Helper()

	seed := make([]byte, 32)
	_, err := rand.Read(seed)
	ok(tb, err)

	signer, err := signing.ParseKey(keyName + ":" + base64.StdEncoding.EncodeToString(seed))
	ok(tb, err)

	publicKey, err := signer.PublicKey()
	ok(tb, err)

	fileDigest := sha256.Sum256(nar)
	fileHash := client.EncodeNixBase32(fileDigest[:])
	narKey := "nar/" + fileHash + ".nar.xz"

	info := &signing.NarInfo{
		StorePath:  "/nix/store/" + hash + "-hello-2.12.1",
		NarHash:    "sha256:1mkvday29m2qxg1fnbv8xh9s6151bh8a2xzhh0k86j7lqhyfwibh",
		NarSize:    226560,
		References: []string{"/nix/store/4hcdxyjf9yiq7qf3i4548drb6sjmwa1v-glibc-2.39-52"},
	}

	sigs, err := signing.SignNarinfo([]*signing.Key{signer}, info)
	ok(tb, err)

	narinfo := fmt.Sprintf(`StorePath: %s
URL: %s
Compression: xz
FileHash: sha256:%s
FileSize: %d
NarHash: %s
NarSize: %d
References: 4hcdxyjf9yiq7qf3i4548drb6sjmwa1v-glibc-2.39-52
Sig: %s
`, info.StorePath, narKey, fileHash, len(nar), info.NarHash, info.NarSize, sigs[0])

	return &fixture{
		hash:       hash,
		narinfoKey: hash + ".narinfo",
		narKey:     narKey,
		narinfo:    []byte(narinfo),
		nar:        nar,
		signer:     signer,
		publicKey:  publicKey,
		sig:        sigs[0],
	}
}

func (f *fixture) publish(u *fakeUpstream) {
	u.put(f.narinfoKey, f.narinfo)
	u.put(f.narKey, f.nar)
}

func randomNar(tb testing.TB, size int) []byte {
	tb.Helper()

	nar := make([]byte, size)
	_, err := rand.Read(nar)
	ok(tb, err)

	return nar
}

func createPullThroughTestService(tb testing.TB, upstream *fakeUpstream, trustedKeys ...string) *server.Service {
	tb.Helper()

	service := createProxyTestService(tb)

	pullThrough, err := server.NewPullThrough(server.PullThroughConfig{
		Upstreams:   []string{upstream.srv.URL},
		TrustedKeys: trustedKeys,
		NegativeTTL: time.Minute,
	})
	ok(tb, err)

	service.PullThrough = pullThrough

	return service
}

// s3Object fetches an object from the test bucket; found is false on NoSuchKey.
func s3Object(ctx context.Context, tb testing.TB, service *server.Service, key string) ([]byte, minio.ObjectInfo, bool) {
	tb.Helper()

	obj, err := service.MinioClient.GetObject(ctx, service.Bucket, key, minio.GetObjectOptions{})
	ok(tb, err)

	defer func() { _ = obj.Close() }()

	data, err := io.ReadAll(obj)
	if err != nil {
		if minio.ToErrorResponse(err).Code == "NoSuchKey" {
			return nil, minio.ObjectInfo{}, false
		}

		ok(tb, err)
	}

	info, err := obj.Stat()
	ok(tb, err)

	return data, info, true
}

func zstdDecompress(tb testing.TB, data []byte) []byte {
	tb.Helper()

	dec, err := zstd.NewReader(nil)
	ok(tb, err)

	defer dec.Close()

	plain, err := dec.DecodeAll(data, nil)
	ok(tb, err)

	return plain
}

func getObjectRow(ctx context.Context, tb testing.TB, service *server.Service, key string) ([]string, bool, bool) {
	tb.Helper()

	var (
		refs []string
		live bool
	)

	err := service.Pool.QueryRow(ctx, "SELECT refs, deleted_at IS NULL FROM objects WHERE key = $1", key).Scan(&refs, &live)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, false
	}

	ok(tb, err)

	return refs, live, true
}

func TestPullThroughNarinfoMissThenHit(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	upstream := newFakeUpstream(t)
	fx := newFixture(t, "26xbg1ndr7hbcncrlf9nhx5is2b25d13", randomNar(t, 4096))
	fx.publish(upstream)

	service := createPullThroughTestService(t, upstream, fx.publicKey)
	defer service.Close()

	ts := setupProxyServer(t, service)
	defer ts.Close()

	header, body := proxyGet(t, ts, "/"+fx.narinfoKey, http.StatusOK)

	if !bytes.Equal(body, fx.narinfo) {
		t.Fatalf("narinfo not served verbatim:\n%s", body)
	}

	if got := header.Get("X-Cache-Status"); got != "MISS" {
		t.Errorf("X-Cache-Status = %q, want MISS", got)
	}

	if ct := header.Get("Content-Type"); ct != "text/x-nix-narinfo" {
		t.Errorf("Content-Type = %q", ct)
	}

	// Stored like a native upload: zstd with Content-Encoding, same bytes.
	stored, info, found := s3Object(ctx, t, service, fx.narinfoKey)
	if !found {
		t.Fatal("narinfo was not stored in S3")
	}

	if ce := info.Metadata.Get("Content-Encoding"); ce != "zstd" {
		t.Logf("Content-Encoding = %q (some S3 servers drop it; the magic sniff still applies)", ce)
	}

	if !bytes.Equal(zstdDecompress(t, stored), fx.narinfo) {
		t.Error("stored narinfo differs from upstream")
	}

	// Rooted by a pulled closure that records the signature it was verified
	// with; refs point at the NAR and the reference's narinfo.
	row, found := getClosureRow(ctx, t, service, fx.narinfoKey)
	if !found || !row.pulledSig.Valid || row.pulledSig.String != fx.sig {
		t.Fatalf("closure row = %+v found=%v, want pulled_sig %q", row, found, fx.sig)
	}

	refs, live, found := getObjectRow(ctx, t, service, fx.narinfoKey)
	if !found || !live {
		t.Fatalf("object row missing or tombstoned (found=%v live=%v)", found, live)
	}

	wantRefs := []string{fx.narKey, "4hcdxyjf9yiq7qf3i4548drb6sjmwa1v.narinfo"}
	if strings.Join(refs, ",") != strings.Join(wantRefs, ",") {
		t.Errorf("refs = %v, want %v", refs, wantRefs)
	}

	// Second read is a hit and never touches the upstream.
	header, body = proxyGet(t, ts, "/"+fx.narinfoKey, http.StatusOK)
	if !bytes.Equal(body, fx.narinfo) {
		t.Error("hit body differs")
	}

	if got := header.Get("X-Cache-Status"); got != "HIT" {
		t.Errorf("X-Cache-Status = %q, want HIT", got)
	}

	if n := upstream.hitCount(fx.narinfoKey); n != 1 {
		t.Errorf("upstream hits = %d, want 1", n)
	}
}

func TestPullThroughHeadMiss(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	upstream := newFakeUpstream(t)
	fx := newFixture(t, "26xbg1ndr7hbcncrlf9nhx5is2b25d13", randomNar(t, 1024))
	fx.publish(upstream)

	service := createPullThroughTestService(t, upstream, fx.publicKey)
	defer service.Close()

	ts := setupProxyServer(t, service)
	defer ts.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, ts.URL+"/"+fx.narinfoKey, nil)
	ok(t, err)

	resp, err := http.DefaultClient.Do(req)
	ok(t, err)

	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Cache-Status") != "MISS" {
		t.Errorf("HEAD: status=%d cache=%q", resp.StatusCode, resp.Header.Get("X-Cache-Status"))
	}

	if resp.ContentLength != int64(len(fx.narinfo)) {
		t.Errorf("Content-Length = %d, want %d", resp.ContentLength, len(fx.narinfo))
	}

	// HEAD never fills.
	if _, _, found := s3Object(ctx, t, service, fx.narinfoKey); found {
		t.Error("HEAD must not store the object")
	}
}

// A HEAD answers from the same validation as a GET: Nix asks with HEAD
// whether a path exists before deciding not to upload it.
func TestPullThroughHeadRejectsLikeGet(t *testing.T) {
	t.Parallel()

	upstream := newFakeUpstream(t)
	fx := newFixture(t, "26xbg1ndr7hbcncrlf9nhx5is2b25d13", randomNar(t, 1024))
	fx.publish(upstream)
	// fx's narinfo under a hash its StorePath does not match.
	upstream.put("4hcdxyjf9yiq7qf3i4548drb6sjmwa1v.narinfo", fx.narinfo)

	// Trust an unrelated key only.
	other := newFixture(t, "sl141d1g77wvhr050ah87lcyz2czdxa3", randomNar(t, 16))

	service := createPullThroughTestService(t, upstream, other.publicKey)
	defer service.Close()

	ts := setupProxyServer(t, service)
	defer ts.Close()

	head := func(key string) int {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodHead, ts.URL+"/"+key, nil)
		ok(t, err)

		resp, err := http.DefaultClient.Do(req)
		ok(t, err)

		_ = resp.Body.Close()

		return resp.StatusCode
	}

	if status := head(fx.narinfoKey); status != http.StatusBadGateway {
		t.Errorf("HEAD of an untrusted narinfo: status %d, want 502", status)
	}

	if status := head("4hcdxyjf9yiq7qf3i4548drb6sjmwa1v.narinfo"); status != http.StatusBadGateway {
		t.Errorf("HEAD of a mismatched narinfo: status %d, want 502", status)
	}

	if n := upstream.hitCount(fx.narinfoKey); n != 1 {
		t.Errorf("upstream hits = %d, want 1", n)
	}
}

func TestPullThroughNegativeCache(t *testing.T) {
	t.Parallel()

	upstream := newFakeUpstream(t)
	fx := newFixture(t, "26xbg1ndr7hbcncrlf9nhx5is2b25d13", randomNar(t, 16))

	service := createPullThroughTestService(t, upstream, fx.publicKey)
	defer service.Close()

	ts := setupProxyServer(t, service)
	defer ts.Close()

	key := "/4hcdxyjf9yiq7qf3i4548drb6sjmwa1v.narinfo"

	header, _ := proxyGet(t, ts, key, http.StatusNotFound)
	if got := header.Get("X-Cache-Status"); got != "MISS" {
		t.Errorf("first 404: X-Cache-Status = %q, want MISS", got)
	}

	header, _ = proxyGet(t, ts, key, http.StatusNotFound)
	if got := header.Get("X-Cache-Status"); got != "NEGATIVE" {
		t.Errorf("second 404: X-Cache-Status = %q, want NEGATIVE", got)
	}

	if n := upstream.hitCount(strings.TrimPrefix(key, "/")); n != 1 {
		t.Errorf("upstream hits = %d, want 1", n)
	}

	// Keys outside the allowlist never reach the upstream.
	proxyGet(t, ts, "/4hcdxyjf9yiq7qf3i4548drb6sjmwa1v.ls", http.StatusNotFound)

	if n := upstream.hitCount("4hcdxyjf9yiq7qf3i4548drb6sjmwa1v.ls"); n != 0 {
		t.Errorf(".ls reached upstream %d times", n)
	}
}

// An S3-hosted upstream answers with the Content-Encoding its object was
// stored with, whatever Accept-Encoding asked for; niks3's own buckets
// store narinfos as zstd. The fill decodes such a narinfo, serves it plain
// and stores it like any other.
func TestPullThroughNarinfoCompressedUpstream(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	upstream := newFakeUpstream(t)
	fx := newFixture(t, "26xbg1ndr7hbcncrlf9nhx5is2b25d13", randomNar(t, 16))
	upstream.put(fx.narinfoKey, zstdCompress(t, fx.narinfo))

	service := createPullThroughTestService(t, upstream, fx.publicKey)
	defer service.Close()

	ts := setupProxyServer(t, service)
	defer ts.Close()

	if _, body := proxyGet(t, ts, "/"+fx.narinfoKey, http.StatusOK); !bytes.Equal(body, fx.narinfo) {
		t.Fatalf("narinfo not served decoded:\n%s", body)
	}

	stored, _, found := s3Object(ctx, t, service, fx.narinfoKey)
	if !found || !bytes.Equal(zstdDecompress(t, stored), fx.narinfo) {
		t.Errorf("stored narinfo found=%v, want the decoded upstream bytes", found)
	}
}

func TestPullThroughTrustedKeys(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	upstream := newFakeUpstream(t)
	fx := newFixture(t, "26xbg1ndr7hbcncrlf9nhx5is2b25d13", randomNar(t, 1024))
	fx.publish(upstream)

	// An unrelated key: fx's signature must not verify against it.
	other := newFixture(t, "4hcdxyjf9yiq7qf3i4548drb6sjmwa1v", randomNar(t, 16))

	service := createPullThroughTestService(t, upstream, other.publicKey)
	defer service.Close()

	ts := setupProxyServer(t, service)
	defer ts.Close()

	proxyGet(t, ts, "/"+fx.narinfoKey, http.StatusBadGateway)

	if _, _, found := s3Object(ctx, t, service, fx.narinfoKey); found {
		t.Error("rejected narinfo must not be stored")
	}

	// Now trust the right key as well: served, and the upstream Sig survives verbatim.
	service.PullThrough, _ = server.NewPullThrough(server.PullThroughConfig{
		Upstreams:   []string{upstream.srv.URL},
		TrustedKeys: []string{other.publicKey, fx.publicKey},
	})

	_, body := proxyGet(t, ts, "/"+fx.narinfoKey, http.StatusOK)

	parsed, err := server.ParseNarinfo(body)
	ok(t, err)

	sig, err := signing.VerifyNarinfo([]*signing.PublicKey{mustPublicKey(t, fx.publicKey)},
		&signing.NarInfo{
			StorePath:  parsed.StorePath,
			NarHash:    parsed.NarHash,
			NarSize:    parsed.NarSize,
			References: []string{"/nix/store/4hcdxyjf9yiq7qf3i4548drb6sjmwa1v-glibc-2.39-52"},
		}, parsed.Sigs)
	ok(t, err)

	if sig != fx.sig {
		t.Errorf("served narinfo verifies with %q, want the upstream Sig %q", sig, fx.sig)
	}

	// The closure records which signature vouched for it.
	if row, found := getClosureRow(ctx, t, service, fx.narinfoKey); !found || row.pulledSig.String != fx.sig {
		t.Errorf("closure row = %+v found=%v, want pulled_sig %q", row, found, fx.sig)
	}
}

func mustPublicKey(tb testing.TB, s string) *signing.PublicKey {
	tb.Helper()

	k, err := signing.ParsePublicKey(s)
	ok(tb, err)

	return k
}

func TestPullThroughRejectsMismatchedStorePath(t *testing.T) {
	t.Parallel()

	upstream := newFakeUpstream(t)
	fx := newFixture(t, "26xbg1ndr7hbcncrlf9nhx5is2b25d13", randomNar(t, 64))
	// Publish fx's narinfo under a different hash.
	upstream.put("4hcdxyjf9yiq7qf3i4548drb6sjmwa1v.narinfo", fx.narinfo)

	service := createPullThroughTestService(t, upstream, fx.publicKey)
	defer service.Close()

	ts := setupProxyServer(t, service)
	defer ts.Close()

	proxyGet(t, ts, "/4hcdxyjf9yiq7qf3i4548drb6sjmwa1v.narinfo", http.StatusBadGateway)
}

func TestNewPullThroughValidation(t *testing.T) {
	t.Parallel()

	key := newFixture(t, "26xbg1ndr7hbcncrlf9nhx5is2b25d13", randomNar(t, 16)).publicKey

	bad := []server.PullThroughConfig{
		{},
		{Upstreams: []string{"cache.nixos.org"}, TrustedKeys: []string{key}},
		{Upstreams: []string{"ftp://cache.nixos.org"}, TrustedKeys: []string{key}},
		{Upstreams: []string{"https://cache.nixos.org"}, TrustedKeys: []string{"nocolon"}},
		{Upstreams: []string{"https://cache.nixos.org"}}, // no trusted key
	}

	for _, cfg := range bad {
		if _, err := server.NewPullThrough(cfg); err == nil {
			t.Errorf("NewPullThrough(%+v) succeeded, want error", cfg)
		}
	}

	p, err := server.NewPullThrough(server.PullThroughConfig{
		Upstreams:   []string{"https://cache.nixos.org/", "http://mirror:8080/cache/"},
		TrustedKeys: []string{key},
	})
	ok(t, err)

	if got := strings.Join(p.Upstreams(), " "); got != "https://cache.nixos.org http://mirror:8080/cache" {
		t.Errorf("Upstreams = %q", got)
	}
}

// The server's own signing keys are always trusted, so a pull-through
// with no --trusted-key still verifies against something.
func TestTrustedKeysWithSigning(t *testing.T) {
	t.Parallel()

	fx := newFixture(t, "26xbg1ndr7hbcncrlf9nhx5is2b25d13", randomNar(t, 16))

	keys, err := server.TrustedKeysWithSigning([]string{"cache.nixos.org-1:abc"}, []*signing.Key{fx.signer})
	ok(t, err)

	if got := strings.Join(keys, " "); got != "cache.nixos.org-1:abc "+fx.publicKey {
		t.Errorf("keys = %q", got)
	}

	keys, err = server.TrustedKeysWithSigning(nil, []*signing.Key{fx.signer})
	ok(t, err)

	if len(keys) != 1 || keys[0] != fx.publicKey {
		t.Errorf("keys = %v, want just the signing key's public half", keys)
	}
}
