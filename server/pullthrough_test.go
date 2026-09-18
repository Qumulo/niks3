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
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Mic92/niks3/client"
	"github.com/Mic92/niks3/server"
	"github.com/Mic92/niks3/server/pg"
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
	// beforeServe, when set, runs before each object is served. Tests use
	// it to slow a transfer or to synchronise concurrent requests.
	beforeServe func(key string, w http.ResponseWriter) (handled bool)
	srv         *httptest.Server
}

func newFakeUpstream(tb testing.TB) *fakeUpstream {
	tb.Helper()

	u := &fakeUpstream{objects: map[string][]byte{}, hits: map[string]int{}}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, "/")

		u.mu.Lock()
		u.hits[key]++
		data, found := u.objects[key]
		hook := u.beforeServe
		u.mu.Unlock()

		if !found {
			http.NotFound(w, r)

			return
		}

		if hook != nil && hook(key, w) {
			return
		}

		if r.Header.Get("Range") != "" {
			http.ServeContent(w, r, key, time.Time{}, bytes.NewReader(data))

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

// withTLSS3 points the service's S3 clients at a TLS reverse proxy in front
// of the rustfs fixture. The transport changes how minio-go uploads: over
// plain HTTP it signs the body as aws-chunked, so a cut-short body is
// rejected by S3 as an incomplete stream; over HTTPS, which is what
// production speaks, it sends an unsigned payload with a plain
// Content-Length and S3 commits the moment that many bytes have arrived.
// The fill tests run under both, since they exist to prove a NAR that
// fails verification never becomes an object.
func withTLSS3(tb testing.TB, service *server.Service) {
	tb.Helper()

	target, err := url.Parse("http://" + service.MinioClient.EndpointURL().Host)
	ok(tb, err)

	// The Host header is left as the client sent it, so SigV4 verifies.
	proxy := httptest.NewTLSServer(httputil.NewSingleHostReverseProxy(target))
	tb.Cleanup(proxy.Close)

	minioClient, err := minio.New(proxy.Listener.Addr().String(), &minio.Options{
		Creds:     testRustfsServer.Creds(),
		Secure:    true,
		Transport: proxy.Client().Transport,
	})
	ok(tb, err)

	service.MinioClient = minioClient
	service.PresignClient = minioClient
}

// forEachS3Transport runs fn against the plain HTTP fixture and through
// the TLS proxy; secure says which.
func forEachS3Transport(t *testing.T, fn func(t *testing.T, secure bool)) {
	t.Helper()

	for _, tc := range []struct {
		name   string
		secure bool
	}{{"http", false}, {"https", true}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fn(t, tc.secure)
		})
	}
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

// waitForFill polls until key is stored in S3 and registered live in the
// database. The client sees the last byte before the S3 upload completes.
func waitForFill(ctx context.Context, tb testing.TB, service *server.Service, key string) []byte {
	tb.Helper()

	deadline := time.Now().Add(30 * time.Second)

	for {
		data, _, found := s3Object(ctx, tb, service, key)
		if found {
			if _, live, ok := getObjectRow(ctx, tb, service, key); ok && live {
				return data
			}
		}

		if time.Now().After(deadline) {
			tb.Fatalf("%s: fill did not complete (s3=%v)", key, found)
		}

		time.Sleep(20 * time.Millisecond)
	}
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

// waitForNoFill gives a fill that must not happen time to happen, then
// asserts key is neither in S3 nor registered.
func waitForNoFill(ctx context.Context, tb testing.TB, service *server.Service, key string) {
	tb.Helper()

	time.Sleep(200 * time.Millisecond)

	if _, _, found := s3Object(ctx, tb, service, key); found {
		tb.Errorf("%s was stored", key)
	}

	if _, _, found := getObjectRow(ctx, tb, service, key); found {
		tb.Errorf("%s was registered", key)
	}
}

func setClosureAge(ctx context.Context, tb testing.TB, service *server.Service, key string, age time.Duration) {
	tb.Helper()

	_, err := service.Pool.Exec(ctx, "UPDATE closures SET updated_at = $2 WHERE key = $1", key, time.Now().UTC().Add(-age))
	ok(tb, err)
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

func TestPullThroughNarMissThenHit(t *testing.T) {
	t.Parallel()
	forEachS3Transport(t, testPullThroughNarMissThenHit)
}

func testPullThroughNarMissThenHit(t *testing.T, secure bool) {
	t.Helper()

	ctx := t.Context()
	upstream := newFakeUpstream(t)
	// Larger than one minio part so the multipart path is exercised.
	fx := newFixture(t, "26xbg1ndr7hbcncrlf9nhx5is2b25d13", randomNar(t, 20<<20))
	fx.publish(upstream)

	service := createPullThroughTestService(t, upstream, fx.publicKey)
	defer service.Close()

	if secure {
		withTLSS3(t, service)
	}

	ts := setupProxyServer(t, service)
	defer ts.Close()

	// The narinfo first, as Nix does, so the NAR's FileHash is known.
	proxyGet(t, ts, "/"+fx.narinfoKey, http.StatusOK)

	header, body := proxyGet(t, ts, "/"+fx.narKey, http.StatusOK)
	if !bytes.Equal(body, fx.nar) {
		t.Fatal("NAR body differs from upstream")
	}

	if got := header.Get("X-Cache-Status"); got != "MISS" {
		t.Errorf("X-Cache-Status = %q, want MISS", got)
	}

	if got := header.Get("Content-Length"); got != strconv.Itoa(len(fx.nar)) {
		t.Errorf("Content-Length = %q", got)
	}

	if stored := waitForFill(ctx, t, service, fx.narKey); !bytes.Equal(stored, fx.nar) {
		t.Fatal("NAR not stored intact")
	}

	// A NAR is not a root of its own; only the narinfo is.
	if _, found := getClosureRow(ctx, t, service, fx.narKey); found {
		t.Error("NAR must not get a closure row")
	}

	header, body = proxyGet(t, ts, "/"+fx.narKey, http.StatusOK)
	if !bytes.Equal(body, fx.nar) || header.Get("X-Cache-Status") != "HIT" {
		t.Errorf("second read: status=%q", header.Get("X-Cache-Status"))
	}

	if n := upstream.hitCount(fx.narKey); n != 1 {
		t.Errorf("upstream hits = %d, want 1", n)
	}
}

// A Range on a miss is what Nix sends to resume a download that dropped
// mid-transfer. It is answered from upstream and never fills.
func TestPullThroughRangeOnMissPassesThrough(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	upstream := newFakeUpstream(t)
	fx := newFixture(t, "26xbg1ndr7hbcncrlf9nhx5is2b25d13", randomNar(t, 8192))
	fx.publish(upstream)

	service := createPullThroughTestService(t, upstream, fx.publicKey)
	defer service.Close()

	ts := setupProxyServer(t, service)
	defer ts.Close()

	proxyGet(t, ts, "/"+fx.narinfoKey, http.StatusOK)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/"+fx.narKey, nil)
	ok(t, err)
	req.Header.Set("Range", "bytes=100-199")

	resp, err := http.DefaultClient.Do(req)
	ok(t, err)

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	ok(t, err)

	if resp.StatusCode != http.StatusPartialContent || !bytes.Equal(body, fx.nar[100:200]) {
		t.Errorf("status=%d len=%d, want 206 and bytes 100-199", resp.StatusCode, len(body))
	}

	if cr := resp.Header.Get("Content-Range"); cr != "bytes 100-199/8192" {
		t.Errorf("Content-Range = %q", cr)
	}

	if got := resp.Header.Get("X-Cache-Status"); got != "MISS" {
		t.Errorf("X-Cache-Status = %q, want MISS", got)
	}

	waitForNoFill(ctx, t, service, fx.narKey)

	// A full miss advertises that a resume is possible.
	header, _ := proxyGet(t, ts, "/"+fx.narKey, http.StatusOK)
	if got := header.Get("Accept-Ranges"); got != "bytes" {
		t.Errorf("Accept-Ranges = %q on a miss, want bytes", got)
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

// A native upload of a path the read proxy pulled earlier takes the root
// over: pulled_sig becomes NULL and the trusted-key expiry no longer
// applies to it.
func TestPullThroughUploadTakesOverPulledClosure(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	upstream := newFakeUpstream(t)
	fx := newFixture(t, "26xbg1ndr7hbcncrlf9nhx5is2b25d13", randomNar(t, 64))
	fx.publish(upstream)

	service := createPullThroughTestService(t, upstream, fx.publicKey)
	defer service.Close()

	ts := setupProxyServer(t, service)
	defer ts.Close()

	proxyGet(t, ts, "/"+fx.narinfoKey, http.StatusOK)

	row, found := getClosureRow(ctx, t, service, fx.narinfoKey)
	if !found || row.pulledSig.String != fx.sig {
		t.Fatalf("closure row = %+v found=%v, want pulled_sig %q", row, found, fx.sig)
	}

	createTestClosure(t, service, pg.New(service.Pool), fx.hash)

	row, found = getClosureRow(ctx, t, service, fx.narinfoKey)
	if !found || row.pulledSig.Valid {
		t.Fatalf("closure row = %+v found=%v after upload, want pulled_sig NULL", row, found)
	}

	// Dropping the key that signed the pull no longer matters.
	other := newFixtureSignedBy(t, "4hcdxyjf9yiq7qf3i4548drb6sjmwa1v", randomNar(t, 16), "signer-2")
	service.PullThrough, _ = server.NewPullThrough(server.PullThroughConfig{
		Upstreams:   []string{upstream.srv.URL},
		TrustedKeys: []string{other.publicKey},
	})

	status := service.RunGCForTest(365*24*time.Hour, time.Hour, true)
	if status.Error != "" {
		t.Fatalf("GC failed: %s", status.Error)
	}

	if status.Stats.PulledClosuresUntrusted != 0 {
		t.Errorf("stats = %+v, want no closure expired", status.Stats)
	}

	if _, found := getClosureRow(ctx, t, service, fx.narinfoKey); !found {
		t.Error("uploaded closure was expired by the trusted-key sweep")
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

func TestPullThroughNarFileHashMismatchNotStored(t *testing.T) {
	t.Parallel()
	forEachS3Transport(t, testPullThroughNarFileHashMismatchNotStored)
}

func testPullThroughNarFileHashMismatchNotStored(t *testing.T, secure bool) {
	t.Helper()

	ctx := t.Context()
	upstream := newFakeUpstream(t)
	fx := newFixture(t, "26xbg1ndr7hbcncrlf9nhx5is2b25d13", randomNar(t, 4096))
	upstream.put(fx.narinfoKey, fx.narinfo)
	// Same size, different bytes: only the hash check can catch this.
	upstream.put(fx.narKey, randomNar(t, len(fx.nar)))

	service := createPullThroughTestService(t, upstream, fx.publicKey)
	defer service.Close()

	if secure {
		withTLSS3(t, service)
	}

	ts := setupProxyServer(t, service)
	defer ts.Close()

	proxyGet(t, ts, "/"+fx.narinfoKey, http.StatusOK)
	// The client still receives the bytes (the status is already sent),
	// and Nix will reject them by NarHash. We must not keep them.
	proxyGet(t, ts, "/"+fx.narKey, http.StatusOK)

	time.Sleep(200 * time.Millisecond)

	if _, _, found := s3Object(ctx, t, service, fx.narKey); found {
		t.Error("NAR with wrong FileHash was stored")
	}

	if _, _, found := getObjectRow(ctx, t, service, fx.narKey); found {
		t.Error("NAR with wrong FileHash was registered")
	}
}

func TestPullThroughNarWithoutNarinfoNotStored(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	upstream := newFakeUpstream(t)
	fx := newFixture(t, "26xbg1ndr7hbcncrlf9nhx5is2b25d13", randomNar(t, 4096))
	fx.publish(upstream)

	service := createPullThroughTestService(t, upstream, fx.publicKey)
	defer service.Close()

	ts := setupProxyServer(t, service)
	defer ts.Close()

	// Nothing vouches for this NAR yet: it is served but not kept.
	header, body := proxyGet(t, ts, "/"+fx.narKey, http.StatusOK)
	if !bytes.Equal(body, fx.nar) || header.Get("X-Cache-Status") != "MISS" {
		t.Fatalf("unverified read: status=%q len=%d", header.Get("X-Cache-Status"), len(body))
	}

	waitForNoFill(ctx, t, service, fx.narKey)

	// Once the narinfo has been seen the next miss is verified and kept.
	proxyGet(t, ts, "/"+fx.narinfoKey, http.StatusOK)
	proxyGet(t, ts, "/"+fx.narKey, http.StatusOK)

	if stored := waitForFill(ctx, t, service, fx.narKey); !bytes.Equal(stored, fx.nar) {
		t.Fatal("NAR not stored intact")
	}

	if n := upstream.hitCount(fx.narKey); n != 2 {
		t.Errorf("upstream hits = %d, want 2", n)
	}
}

func TestPullThroughNarVerifiedFromDatabase(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	upstream := newFakeUpstream(t)
	fx := newFixture(t, "26xbg1ndr7hbcncrlf9nhx5is2b25d13", randomNar(t, 4096))
	upstream.put(fx.narinfoKey, fx.narinfo)
	upstream.put(fx.narKey, randomNar(t, len(fx.nar)))

	service := createPullThroughTestService(t, upstream, fx.publicKey)
	defer service.Close()

	ts := setupProxyServer(t, service)
	defer ts.Close()

	proxyGet(t, ts, "/"+fx.narinfoKey, http.StatusOK)

	// A restart (or another replica) has no in-memory metadata; the
	// database still knows what the narinfo said.
	fresh, err := server.NewPullThrough(server.PullThroughConfig{
		Upstreams:   []string{upstream.srv.URL},
		TrustedKeys: []string{fx.publicKey},
	})
	ok(t, err)

	service.PullThrough = fresh

	proxyGet(t, ts, "/"+fx.narKey, http.StatusOK)
	waitForNoFill(ctx, t, service, fx.narKey)

	// With the right bytes upstream the same restart-fresh server fills.
	upstream.put(fx.narKey, fx.nar)
	proxyGet(t, ts, "/"+fx.narKey, http.StatusOK)

	if stored := waitForFill(ctx, t, service, fx.narKey); !bytes.Equal(stored, fx.nar) {
		t.Fatal("NAR not stored intact")
	}
}

// A chunked upstream with no FileSize to size the transfer by must be
// bounded by progress, not by the flat budget for a zero-byte object.
func TestPullThroughUnknownSizeBoundedByProgress(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	upstream := newFakeUpstream(t)
	fx := newFixture(t, "26xbg1ndr7hbcncrlf9nhx5is2b25d13", randomNar(t, 2<<20))

	// FileSize is not covered by the signature, so dropping it keeps the
	// narinfo valid while leaving the NAR's size unknown.
	var lines []string

	for line := range strings.SplitSeq(string(fx.narinfo), "\n") {
		if !strings.HasPrefix(line, "FileSize:") {
			lines = append(lines, line)
		}
	}

	upstream.put(fx.narinfoKey, []byte(strings.Join(lines, "\n")))
	upstream.put(fx.narKey, fx.nar)

	// Trickle the NAR chunked over well over the idle budget below.
	upstream.beforeServe = func(key string, w http.ResponseWriter) bool {
		if key != fx.narKey {
			return false
		}

		w.WriteHeader(http.StatusOK)

		flusher, _ := w.(http.Flusher)

		for off := 0; off < len(fx.nar); off += 64 << 10 {
			end := min(off+64<<10, len(fx.nar))
			_, _ = w.Write(fx.nar[off:end])

			if flusher != nil {
				flusher.Flush()
			}

			time.Sleep(20 * time.Millisecond)
		}

		return true
	}

	service := createPullThroughTestService(t, upstream, fx.publicKey)
	defer service.Close()

	service.PullThrough.SetIdleBudget(200 * time.Millisecond)

	ts := setupProxyServer(t, service)
	defer ts.Close()

	proxyGet(t, ts, "/"+fx.narinfoKey, http.StatusOK)

	header, body := proxyGet(t, ts, "/"+fx.narKey, http.StatusOK)
	if header.Get("Content-Length") != "" {
		t.Errorf("Content-Length = %q, want none for an unknown size", header.Get("Content-Length"))
	}

	if !bytes.Equal(body, fx.nar) {
		t.Fatalf("got %d bytes, want the whole %d-byte NAR", len(body), len(fx.nar))
	}

	if stored := waitForFill(ctx, t, service, fx.narKey); !bytes.Equal(stored, fx.nar) {
		t.Fatal("NAR not stored intact")
	}
}

func TestPullThroughNarLongerThanFileSizeNotStored(t *testing.T) {
	t.Parallel()
	forEachS3Transport(t, testPullThroughNarLongerThanFileSizeNotStored)
}

func testPullThroughNarLongerThanFileSizeNotStored(t *testing.T, secure bool) {
	t.Helper()

	ctx := t.Context()
	upstream := newFakeUpstream(t)
	fx := newFixture(t, "26xbg1ndr7hbcncrlf9nhx5is2b25d13", randomNar(t, 4096))
	fx.publish(upstream)

	// A chunked upstream (no Content-Length) that keeps sending past the
	// FileSize the narinfo announced. minio stops reading at that size and
	// completes the upload; the fill must notice, not hang on the dead
	// pipe, and take the object back out. The pause makes the NAR and the
	// surplus arrive as separate reads, so the fill has released the
	// whole announced size to S3 before it learns the body runs long.
	upstream.beforeServe = func(key string, w http.ResponseWriter) bool {
		if key != fx.narKey {
			return false
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fx.nar)
		_ = http.NewResponseController(w).Flush()

		time.Sleep(100 * time.Millisecond)

		_, _ = w.Write([]byte("trailing garbage"))

		return true
	}

	service := createPullThroughTestService(t, upstream, fx.publicKey)
	defer service.Close()

	if secure {
		withTLSS3(t, service)
	}

	ts := setupProxyServer(t, service)
	defer ts.Close()

	proxyGet(t, ts, "/"+fx.narinfoKey, http.StatusOK)

	done := make(chan struct{})

	go func() {
		defer close(done)

		// The announced Content-Length is the FileSize, so the client sees
		// exactly the NAR.
		_, body := proxyGet(t, ts, "/"+fx.narKey, http.StatusOK)
		if !bytes.Equal(body, fx.nar) {
			t.Error("client did not receive the NAR")
		}
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("NAR request hung")
	}

	deadline := time.Now().Add(10 * time.Second)

	for {
		_, _, inS3 := s3Object(ctx, t, service, fx.narKey)
		_, _, inDB := getObjectRow(ctx, t, service, fx.narKey)

		if !inS3 && !inDB {
			break
		}

		if time.Now().After(deadline) {
			t.Fatalf("over-long NAR kept (s3=%v db=%v)", inS3, inDB)
		}

		time.Sleep(20 * time.Millisecond)
	}
}

func TestPullThroughConcurrentFillsOnce(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	upstream := newFakeUpstream(t)
	fx := newFixture(t, "26xbg1ndr7hbcncrlf9nhx5is2b25d13", randomNar(t, 1<<20))
	fx.publish(upstream)

	// Hold both NAR requests until they have both arrived, so both are in
	// flight at once.
	var arrived sync.WaitGroup

	arrived.Add(2)

	upstream.beforeServe = func(key string, _ http.ResponseWriter) bool {
		if key == fx.narKey {
			arrived.Done()
			arrived.Wait()
		}

		return false
	}

	service := createPullThroughTestService(t, upstream, fx.publicKey)
	defer service.Close()

	ts := setupProxyServer(t, service)
	defer ts.Close()

	proxyGet(t, ts, "/"+fx.narinfoKey, http.StatusOK)

	var wg sync.WaitGroup

	for range 2 {
		wg.Go(func() {
			_, body := proxyGet(t, ts, "/"+fx.narKey, http.StatusOK)
			if !bytes.Equal(body, fx.nar) {
				t.Error("concurrent reader got a wrong body")
			}
		})
	}

	wg.Wait()

	if stored := waitForFill(ctx, t, service, fx.narKey); !bytes.Equal(stored, fx.nar) {
		t.Fatal("NAR not stored intact")
	}

	if n := upstream.hitCount(fx.narKey); n != 2 {
		t.Errorf("upstream hits = %d, want 2 (one fill, one passthrough)", n)
	}
}

func TestPullThroughFillSurvivesClientDisconnect(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	upstream := newFakeUpstream(t)
	fx := newFixture(t, "26xbg1ndr7hbcncrlf9nhx5is2b25d13", randomNar(t, 4<<20))
	fx.publish(upstream)

	// Trickle the NAR so the client can go away mid-transfer.
	upstream.beforeServe = func(key string, w http.ResponseWriter) bool {
		if key != fx.narKey {
			return false
		}

		w.Header().Set("Content-Length", strconv.Itoa(len(fx.nar)))
		w.WriteHeader(http.StatusOK)

		flusher, _ := w.(http.Flusher)

		for off := 0; off < len(fx.nar); off += 64 << 10 {
			end := min(off+64<<10, len(fx.nar))
			_, _ = w.Write(fx.nar[off:end])

			if flusher != nil {
				flusher.Flush()
			}

			time.Sleep(2 * time.Millisecond)
		}

		return true
	}

	service := createPullThroughTestService(t, upstream, fx.publicKey)
	defer service.Close()

	ts := setupProxyServer(t, service)
	defer ts.Close()

	proxyGet(t, ts, "/"+fx.narinfoKey, http.StatusOK)

	reqCtx, cancel := context.WithCancel(ctx)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, ts.URL+"/"+fx.narKey, nil)
	ok(t, err)

	resp, err := http.DefaultClient.Do(req)
	ok(t, err)

	// Read a little, then hang up.
	_, err = io.ReadFull(resp.Body, make([]byte, 100<<10))
	ok(t, err)

	cancel()

	_ = resp.Body.Close()

	if stored := waitForFill(ctx, t, service, fx.narKey); !bytes.Equal(stored, fx.nar) {
		t.Fatal("stored NAR is not intact")
	}
}

func TestPullThroughRedirectUsesDatabase(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	upstream := newFakeUpstream(t)
	fx := newFixture(t, "26xbg1ndr7hbcncrlf9nhx5is2b25d13", randomNar(t, 2048))
	fx.publish(upstream)

	service := createPullThroughTestService(t, upstream, fx.publicKey)
	defer service.Close()

	service.ReadRedirectTTL = time.Minute

	ts := setupProxyServer(t, service)
	defer ts.Close()

	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	// get drains and closes the body; redirects are not followed.
	get := func(key string) (int, http.Header) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/"+key, nil)
		ok(t, err)

		resp, err := noRedirect.Do(req)
		ok(t, err)

		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		return resp.StatusCode, resp.Header
	}

	proxyGet(t, ts, "/"+fx.narinfoKey, http.StatusOK)

	// Untracked and absent: filled from upstream and streamed.
	status, header := get(fx.narKey)
	if status != http.StatusOK || header.Get("X-Cache-Status") != "MISS" {
		t.Fatalf("first read: status=%d cache=%q", status, header.Get("X-Cache-Status"))
	}

	waitForFill(ctx, t, service, fx.narKey)

	// Now tracked: redirected on the strength of the objects row.
	status, header = get(fx.narKey)
	if status != http.StatusTemporaryRedirect {
		t.Fatalf("tracked read: status=%d, want 307", status)
	}

	if loc := header.Get("Location"); !strings.Contains(loc, fx.narKey) {
		t.Errorf("Location = %q", loc)
	}

	// Present in S3 but unknown to the database (written outside niks3):
	// the S3 fallback still redirects instead of refilling.
	foreign := "nar/" + strings.Repeat("z", 52) + ".nar.zst"
	putTestObject(ctx, t, service, foreign, []byte("foreign"), minio.PutObjectOptions{})

	if status, _ = get(foreign); status != http.StatusTemporaryRedirect {
		t.Errorf("foreign object: status=%d, want 307", status)
	}

	if n := upstream.hitCount(foreign); n != 0 {
		t.Errorf("foreign object reached upstream %d times", n)
	}

	// Tombstoned rows do not count as live: with the object gone from S3
	// the read falls through to upstream again.
	_, err := service.Pool.Exec(ctx, "UPDATE objects SET deleted_at = now(), first_deleted_at = now() WHERE key = $1", fx.narKey)
	ok(t, err)
	ok(t, service.MinioClient.RemoveObject(ctx, service.Bucket, fx.narKey, minio.RemoveObjectOptions{}))

	status, header = get(fx.narKey)
	if status != http.StatusOK || header.Get("X-Cache-Status") != "MISS" {
		t.Errorf("after tombstone: status=%d cache=%q", status, header.Get("X-Cache-Status"))
	}

	// The refill resurrects the row.
	waitForFill(ctx, t, service, fx.narKey)
}

// Pulled and uploaded closures age under the same GC cutoff.
func TestPullThroughGCSameAgeAsUploads(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	upstream := newFakeUpstream(t)
	fx := newFixture(t, "26xbg1ndr7hbcncrlf9nhx5is2b25d13", randomNar(t, 64))
	fx.publish(upstream)

	service := createPullThroughTestService(t, upstream, fx.publicKey)
	defer service.Close()

	ts := setupProxyServer(t, service)
	defer ts.Close()

	proxyGet(t, ts, "/"+fx.narinfoKey, http.StatusOK)
	proxyGet(t, ts, "/"+fx.narKey, http.StatusOK)
	waitForFill(ctx, t, service, fx.narKey)

	// A native closure of the same age for comparison.
	queries := pg.New(service.Pool)
	createTestClosure(t, service, queries, "4hcdxyjf9yiq7qf3i4548drb6sjmwa1v")

	setClosureAge(ctx, t, service, fx.narinfoKey, 10*24*time.Hour)
	setClosureAge(ctx, t, service, "4hcdxyjf9yiq7qf3i4548drb6sjmwa1v.narinfo", 10*24*time.Hour)

	status := service.RunGCForTest(30*24*time.Hour, time.Hour, true)
	if status.Error != "" {
		t.Fatalf("GC failed: %s", status.Error)
	}

	if status.Stats.OldClosuresDeleted != 0 {
		t.Fatalf("stats = %+v, want nothing deleted under a 30d cutoff", status.Stats)
	}

	if !hasPulledNarRow(ctx, t, service, fx.narKey) {
		t.Fatal("NAR metadata was swept while its narinfo is tracked")
	}

	// A one-day cutoff expires both, and the orphan sweep removes the
	// pulled objects from S3.
	status = service.RunGCForTest(24*time.Hour, time.Hour, true)
	if status.Error != "" {
		t.Fatalf("GC failed: %s", status.Error)
	}

	if status.Stats.OldClosuresDeleted != 2 {
		t.Fatalf("stats = %+v, want both closures deleted", status.Stats)
	}

	for _, key := range []string{fx.narinfoKey, fx.narKey} {
		if _, _, found := s3Object(ctx, t, service, key); found {
			t.Errorf("%s survived GC", key)
		}
	}

	if hasPulledNarRow(ctx, t, service, fx.narKey) {
		t.Error("NAR metadata survived its narinfo")
	}

	// And the next read fills again.
	header, _ := proxyGet(t, ts, "/"+fx.narinfoKey, http.StatusOK)
	if header.Get("X-Cache-Status") != "MISS" {
		t.Errorf("post-GC read: X-Cache-Status = %q, want MISS", header.Get("X-Cache-Status"))
	}
}

// GC deletes from S3 first and flushes the matching rows in batches of a
// thousand, so a fill can resurrect a row in between. The flush must not
// take the fresh row down with the stale ones.
func TestPullThroughFillSurvivesGCRowFlush(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	upstream := newFakeUpstream(t)
	fx := newFixture(t, "26xbg1ndr7hbcncrlf9nhx5is2b25d13", randomNar(t, 64))
	fx.publish(upstream)

	service := createPullThroughTestService(t, upstream, fx.publicKey)
	defer service.Close()

	ts := setupProxyServer(t, service)
	defer ts.Close()

	proxyGet(t, ts, "/"+fx.narinfoKey, http.StatusOK)
	proxyGet(t, ts, "/"+fx.narKey, http.StatusOK)
	waitForFill(ctx, t, service, fx.narKey)

	// GC has tombstoned both, removed them from S3 and is about to flush
	// the rows.
	_, err := service.Pool.Exec(ctx,
		"UPDATE objects SET deleted_at = now(), first_deleted_at = now() WHERE key = any($1)",
		[]string{fx.narinfoKey, fx.narKey})
	ok(t, err)

	for _, key := range []string{fx.narinfoKey, fx.narKey} {
		ok(t, service.MinioClient.RemoveObject(ctx, service.Bucket, key, minio.RemoveObjectOptions{}))
	}

	// A reader refills both before the flush lands.
	proxyGet(t, ts, "/"+fx.narinfoKey, http.StatusOK)
	proxyGet(t, ts, "/"+fx.narKey, http.StatusOK)
	waitForFill(ctx, t, service, fx.narKey)

	ok(t, pg.New(service.Pool).DeleteObjects(ctx, []string{fx.narinfoKey, fx.narKey}))

	for _, key := range []string{fx.narinfoKey, fx.narKey} {
		if _, live, found := getObjectRow(ctx, t, service, key); !found || !live {
			t.Errorf("%s: row found=%v live=%v after the GC flush, want a live row", key, found, live)
		}
	}

	if row, found := getClosureRow(ctx, t, service, fx.narinfoKey); !found || !row.pulledSig.Valid {
		t.Errorf("closure row = %+v found=%v, want pulled", row, found)
	}
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

// A narinfo re-fill roots its NAR again while the NAR's row may still be
// tombstoned from the closure's expiry. GC must keep the reachable NAR
// rather than delete it from S3 after the grace period, which would cost
// a full upstream refetch on the next read.
func TestPullThroughGCKeepsReachableTombstonedNar(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	upstream := newFakeUpstream(t)
	fx := newFixture(t, "26xbg1ndr7hbcncrlf9nhx5is2b25d13", randomNar(t, 64))
	fx.publish(upstream)

	service := createPullThroughTestService(t, upstream, fx.publicKey)
	defer service.Close()

	ts := setupProxyServer(t, service)
	defer ts.Close()

	proxyGet(t, ts, "/"+fx.narinfoKey, http.StatusOK)
	proxyGet(t, ts, "/"+fx.narKey, http.StatusOK)
	waitForFill(ctx, t, service, fx.narKey)

	// The closure expires; a non-force GC tombstones both objects but
	// leaves them in S3 for the grace period.
	setClosureAge(ctx, t, service, fx.narinfoKey, 2*24*time.Hour)

	if status := service.RunGCForTest(24*time.Hour, time.Hour, false); status.Error != "" {
		t.Fatalf("GC failed: %s", status.Error)
	}

	for _, key := range []string{fx.narinfoKey, fx.narKey} {
		if _, live, found := getObjectRow(ctx, t, service, key); !found || live {
			t.Fatalf("%s: found=%v live=%v after expiry, want a tombstoned row", key, found, live)
		}
	}

	// Only the narinfo is gone from S3 when a reader comes back: the
	// re-fill roots it, and with it the NAR that is still in the bucket.
	ok(t, service.MinioClient.RemoveObject(ctx, service.Bucket, fx.narinfoKey, minio.RemoveObjectOptions{}))
	ok(t, pg.New(service.Pool).DeleteObjects(ctx, []string{fx.narinfoKey}))

	header, _ := proxyGet(t, ts, "/"+fx.narinfoKey, http.StatusOK)
	if header.Get("X-Cache-Status") != "MISS" {
		t.Fatalf("X-Cache-Status = %q, want MISS", header.Get("X-Cache-Status"))
	}

	if _, live, found := getObjectRow(ctx, t, service, fx.narKey); !found || live {
		t.Fatalf("NAR row found=%v live=%v after the narinfo re-fill, want still tombstoned", found, live)
	}

	// The grace period has passed by the next GC. The NAR is reachable
	// again, so it must be kept, not deleted.
	_, err := service.Pool.Exec(ctx,
		"UPDATE objects SET first_deleted_at = first_deleted_at - interval '1 day' WHERE key = $1", fx.narKey)
	ok(t, err)

	if status := service.RunGCForTest(24*time.Hour, time.Hour, false); status.Error != "" {
		t.Fatalf("GC failed: %s", status.Error)
	}

	if _, live, found := getObjectRow(ctx, t, service, fx.narKey); !found || !live {
		t.Errorf("NAR row found=%v live=%v after GC, want live", found, live)
	}

	if _, _, found := s3Object(ctx, t, service, fx.narKey); !found {
		t.Error("NAR was deleted from S3 although its narinfo roots it again")
	}
}

// Once a key leaves the trusted set, GC expires every closure that key
// vouched for. A pin holds its closure through that, as through the other
// expiries. Keys are told apart by name, as Nix does, so each fixture
// here signs under its own name.
func TestPullThroughGCExpiresUntrustedKeys(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	upstream := newFakeUpstream(t)
	signed := newFixtureSignedBy(t, "26xbg1ndr7hbcncrlf9nhx5is2b25d13", randomNar(t, 64), "signer-1")
	pinned := newFixtureSignedBy(t, "0000000000000000000000000000000a", randomNar(t, 64), "signer-2")
	replacement := newFixtureSignedBy(t, "4hcdxyjf9yiq7qf3i4548drb6sjmwa1v", randomNar(t, 64), "signer-3")

	signed.publish(upstream)
	pinned.publish(upstream)

	service := createPullThroughTestService(t, upstream, signed.publicKey, pinned.publicKey)
	defer service.Close()

	ts := setupProxyServer(t, service)
	defer ts.Close()

	proxyGet(t, ts, "/"+signed.narinfoKey, http.StatusOK)
	proxyGet(t, ts, "/"+pinned.narinfoKey, http.StatusOK)

	queries := pg.New(service.Pool)
	ok(t, queries.UpsertPin(ctx, pg.UpsertPinParams{
		Name:       "held",
		NarinfoKey: pinned.narinfoKey,
		StorePath:  "/nix/store/" + pinned.hash + "-hello-2.12.1",
	}))

	// With the same keys still trusted nothing expires.
	status := service.RunGCForTest(365*24*time.Hour, time.Hour, true)
	if status.Error != "" {
		t.Fatalf("GC failed: %s", status.Error)
	}

	if status.Stats.PulledClosuresUntrusted != 0 {
		t.Fatalf("stats = %+v, want nothing expired", status.Stats)
	}

	// Replace both keys: the signer's closure goes, the pinned one is held.
	service.PullThrough, _ = server.NewPullThrough(server.PullThroughConfig{
		Upstreams:   []string{upstream.srv.URL},
		TrustedKeys: []string{replacement.publicKey},
	})

	status = service.RunGCForTest(365*24*time.Hour, time.Hour, true)
	if status.Error != "" {
		t.Fatalf("GC failed: %s", status.Error)
	}

	if status.Stats.PulledClosuresUntrusted != 1 {
		t.Fatalf("stats = %+v, want 1 closure expired for its dropped key", status.Stats)
	}

	if _, found := getClosureRow(ctx, t, service, signed.narinfoKey); found {
		t.Error("closure signed by a dropped key survived")
	}

	if _, found := getClosureRow(ctx, t, service, pinned.narinfoKey); !found {
		t.Error("pinned closure was expired")
	}

	for key, want := range map[string]bool{signed.narinfoKey: false, pinned.narinfoKey: true} {
		if _, _, found := s3Object(ctx, t, service, key); found != want {
			t.Errorf("%s in S3 = %v, want %v", key, found, want)
		}
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
