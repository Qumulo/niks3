package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Mic92/niks3/server/pg"
	"github.com/Mic92/niks3/server/signing"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/klauspost/compress/zstd"
	minio "github.com/minio/minio-go/v7"
)

// Pull-through fills the bucket from upstream binary caches on a read miss,
// the way numtide/nixos-passthru-cache does with nginx's proxy_cache, but
// with S3 as the cache and the objects table as the index. Narinfos are
// stored byte for byte so the upstream signatures remain valid.

const (
	// pullThroughMaxNarinfo bounds an upstream narinfo we buffer in memory.
	pullThroughMaxNarinfo = 1 << 20

	// pullThroughMapCap bounds the in-memory bookkeeping maps; on overflow
	// they are cleared rather than evicted, which only costs a few extra
	// upstream requests.
	pullThroughMapCap = 100_000

	// pullThroughPartSize is the multipart part size when the upstream does
	// not announce a Content-Length. Bounds per-fill memory: minio would
	// otherwise size parts for a 5 TiB object.
	pullThroughPartSize = 16 << 20

	// pullThroughCopyBuf is the chunk size when fanning an upstream body
	// out to the client and S3.
	pullThroughCopyBuf = 256 << 10

	// pullThroughHeaderTimeout bounds the wait for upstream response headers.
	pullThroughHeaderTimeout = 30 * time.Second

	// pullThroughDBTimeout bounds bookkeeping writes detached from a request.
	pullThroughDBTimeout = 10 * time.Second

	// pullThroughBudgetRenewal is how often, at most, a progressing
	// transfer of unknown size renews its idle budget; the write deadline
	// is a syscall.
	pullThroughBudgetRenewal = time.Second

	// pullThroughDefaultConcurrency bounds simultaneous NAR fills. Each
	// holds up to a multipart part in memory, so this is a memory knob.
	pullThroughDefaultConcurrency = 16

	// pullThroughDefaultNarinfoConcurrency bounds simultaneous narinfo
	// fills, which are a few KiB each: the bound protects the upstream and
	// file descriptors, not memory. A nixpkgs bump produces thousands of
	// narinfo misses at once.
	pullThroughDefaultNarinfoConcurrency = 256

	// cacheStatusHeader mirrors nginx's X-Cache-Status on proxied reads.
	cacheStatusHeader = "X-Cache-Status"

	kindNarinfo = "narinfo"
	kindNar     = "nar"
)

var (
	errUpstreamNotFound = errors.New("not found upstream")
	errBadNarinfo       = errors.New("unusable narinfo")
	errFileHashMismatch = errors.New("pulled NAR does not match the FileHash in its narinfo")
	errFillAbandoned    = errors.New("client disconnected and S3 fill failed")
)

// PullThroughConfig configures upstream fills for the read proxy.
type PullThroughConfig struct {
	// Upstreams are binary cache base URLs tried in order on a miss.
	Upstreams []string
	// TrustedKeys are "name:base64" public keys one of which must have
	// signed an upstream narinfo for it to be served and stored. At least
	// one is required. See options.TrustedKeys.
	TrustedKeys []string
	// NegativeTTL is how long an upstream 404 is remembered.
	NegativeTTL time.Duration
	// Concurrency bounds simultaneous NAR fills. 0 means the default.
	Concurrency int
	// NarinfoConcurrency bounds simultaneous narinfo fills. 0 means the default.
	NarinfoConcurrency int
}

// narMeta is what a narinfo told us about its NAR, used to verify the NAR
// when it is pulled and to size the fill. The in-memory map is a cache of
// the pulled_nars table, which is what survives restarts and is shared
// between replicas.
type narMeta struct {
	narinfoKey string
	fileHash   string
	fileSize   uint64
	narSize    uint64
}

// narMetaFromNarinfo extracts what a narinfo says about its NAR. ok is false when
// the narinfo carries no FileHash: such a NAR cannot be verified.
func narMetaFromNarinfo(key string, info *narinfo) (narMeta, bool) {
	if info.FileHash == "" {
		return narMeta{}, false
	}

	return narMeta{narinfoKey: key, fileHash: info.FileHash, fileSize: info.FileSize, narSize: info.NarSize}, true
}

// PullThrough holds the upstream client and the in-memory bookkeeping for
// fills: which keys are being filled, recent upstream 404s and NAR
// metadata learned from narinfos.
type PullThrough struct {
	upstreams   []*url.URL
	trustedKeys []*signing.PublicKey
	negativeTTL time.Duration
	// idleBudget is how long a NAR transfer of unknown size may go
	// without progress before it is cut off.
	idleBudget time.Duration
	client     *http.Client
	narSem     chan struct{}
	narinfoSem chan struct{}

	mu       sync.Mutex
	inflight map[string]struct{}
	negative map[string]time.Time
	narMeta  map[string]narMeta
}

// NewPullThrough validates cfg and builds the upstream client.
func NewPullThrough(cfg PullThroughConfig) (*PullThrough, error) {
	if len(cfg.Upstreams) == 0 {
		return nil, errors.New("pull-through requires at least one upstream")
	}

	if len(cfg.TrustedKeys) == 0 {
		return nil, errors.New("pull-through requires at least one trusted key")
	}

	concurrency := cfg.Concurrency
	if concurrency <= 0 {
		concurrency = pullThroughDefaultConcurrency
	}

	narinfoConcurrency := cfg.NarinfoConcurrency
	if narinfoConcurrency <= 0 {
		narinfoConcurrency = pullThroughDefaultNarinfoConcurrency
	}

	p := &PullThrough{
		negativeTTL: cfg.NegativeTTL,
		idleBudget:  proxyTimeoutSlack,
		narSem:      make(chan struct{}, concurrency),
		narinfoSem:  make(chan struct{}, narinfoConcurrency),
		inflight:    make(map[string]struct{}),
		negative:    make(map[string]time.Time),
		narMeta:     make(map[string]narMeta),
	}

	for _, raw := range cfg.Upstreams {
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("pull-through upstream %q: %w", raw, err)
		}

		if (u.Scheme != schemeHTTP && u.Scheme != schemeHTTPS) || u.Host == "" {
			return nil, fmt.Errorf("pull-through upstream %q: must be an http(s) URL", raw)
		}

		u.Path = strings.TrimRight(u.Path, "/")
		u.RawPath = ""
		u.RawQuery = ""
		u.Fragment = ""
		p.upstreams = append(p.upstreams, u)
	}

	for _, raw := range cfg.TrustedKeys {
		key, err := signing.ParsePublicKey(raw)
		if err != nil {
			return nil, fmt.Errorf("trusted key: %w", err)
		}

		p.trustedKeys = append(p.trustedKeys, key)
	}

	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("http.DefaultTransport is not an *http.Transport")
	}

	transport = transport.Clone()
	transport.ResponseHeaderTimeout = pullThroughHeaderTimeout
	transport.MaxIdleConnsPerHost = max(concurrency, narinfoConcurrency)

	p.client = &http.Client{Transport: transport}

	return p, nil
}

// TrustedKeyNames returns the names of the configured trusted keys, which
// are what a narinfo's Sig lines and closures.pulled_sig carry.
func (p *PullThrough) TrustedKeyNames() []string {
	names := make([]string, len(p.trustedKeys))
	for i, k := range p.trustedKeys {
		names[i] = k.Name
	}

	return names
}

// Upstreams returns the configured upstream URLs, for logging.
func (p *PullThrough) Upstreams() []string {
	out := make([]string, len(p.upstreams))
	for i, u := range p.upstreams {
		out[i] = u.String()
	}

	return out
}

// acquire takes a slot from sem, giving up when ctx ends. On success it
// returns the release function to defer.
func acquire(ctx context.Context, sem chan struct{}) (func(), bool) {
	select {
	case sem <- struct{}{}:
		return func() { <-sem }, true
	case <-ctx.Done():
		return nil, false
	}
}

// beginFill claims key for filling. False means another request is already
// filling it; the caller should stream without persisting.
func (p *PullThrough) beginFill(key string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, busy := p.inflight[key]; busy {
		return false
	}

	p.inflight[key] = struct{}{}

	return true
}

func (p *PullThrough) endFill(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	delete(p.inflight, key)
}

func (p *PullThrough) isNegative(key string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	expiry, ok := p.negative[key]
	if !ok {
		return false
	}

	if time.Now().After(expiry) {
		delete(p.negative, key)

		return false
	}

	return true
}

func (p *PullThrough) setNegative(key string) {
	if p.negativeTTL <= 0 {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.negative) >= pullThroughMapCap {
		clear(p.negative)
	}

	p.negative[key] = time.Now().Add(p.negativeTTL)
}

func (p *PullThrough) setNarMeta(narKey string, meta narMeta) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.narMeta) >= pullThroughMapCap {
		clear(p.narMeta)
	}

	p.narMeta[narKey] = meta
}

func (p *PullThrough) getNarMeta(narKey string) (narMeta, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	meta, ok := p.narMeta[narKey]

	return meta, ok
}

// pulledNarMeta looks up what the narinfo for narKey said about it, from
// memory first and then from the database, which is what survives a
// restart, a narinfo served as a hit, or a fill on another replica.
func (s *Service) pulledNarMeta(ctx context.Context, narKey string) (narMeta, bool) {
	p := s.PullThrough

	if meta, ok := p.getNarMeta(narKey); ok {
		return meta, true
	}

	row, err := pg.New(s.Pool).GetPulledNar(ctx, narKey)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			slog.Warn("Failed to look up pulled NAR metadata", "key", narKey, "error", err)
		}

		return narMeta{}, false
	}

	meta := narMeta{
		narinfoKey: row.NarinfoKey,
		fileHash:   row.FileHash,
		fileSize:   uint64(max(row.FileSize, 0)),
		narSize:    uint64(max(row.NarSize, 0)),
	}
	p.setNarMeta(narKey, meta)

	return meta, true
}

// fetch tries each upstream in order. It returns errUpstreamNotFound when
// every upstream answered 404, otherwise the last failure. The caller owns
// resp.Body. With a Range, a 206 is accepted too; an upstream that ignores
// the Range answers 200 with the whole object, which is passed on as is.
func (p *PullThrough) fetch(ctx context.Context, method, key, byteRange string) (*http.Response, error) {
	var lastErr error

	for _, upstream := range p.upstreams {
		target := upstream.String() + "/" + key

		// The host comes from operator config; key is narrowed by the
		// cache path allowlist before we get here.
		req, err := http.NewRequestWithContext(ctx, method, target, nil) //nolint:gosec // G704: see above
		if err != nil {
			return nil, fmt.Errorf("building upstream request: %w", err)
		}

		// Identity keeps Content-Length meaningful for NARs.
		req.Header.Set("Accept-Encoding", "identity")
		req.Header.Set("User-Agent", "niks3 pull-through")

		if byteRange != "" {
			req.Header.Set("Range", byteRange)
		}

		resp, err := p.client.Do(req) //nolint:gosec // G704: operator-configured upstream
		if err != nil {
			lastErr = err

			continue
		}

		switch {
		case resp.StatusCode == http.StatusOK,
			resp.StatusCode == http.StatusPartialContent && byteRange != "":
			return resp, nil
		case resp.StatusCode == http.StatusNotFound:
			closeBody(resp)
		default:
			closeBody(resp)

			lastErr = fmt.Errorf("%s: unexpected status %s", target, resp.Status)
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}

	return nil, errUpstreamNotFound
}

func closeBody(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
}

// readNarinfo reads a narinfo of at most pullThroughMaxNarinfo bytes from
// r, decompressing it when it is a zstd frame. An S3-hosted upstream sends
// the Content-Encoding its object was stored with whatever the request's
// Accept-Encoding says, and niks3 itself stores narinfos that way. A read
// failure is returned as is; a narinfo too large or undecodable is
// errBadNarinfo, wrapped with the reason.
func readNarinfo(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, pullThroughMaxNarinfo+1))
	if err != nil {
		return nil, err //nolint:wrapcheck // the caller says where it read from
	}

	if len(data) > pullThroughMaxNarinfo {
		return nil, fmt.Errorf("%w: larger than 1 MiB", errBadNarinfo)
	}

	if !bytes.HasPrefix(data, []byte(zstdMagic)) {
		return data, nil
	}

	decoder, err := zstd.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%w: zstd: %w", errBadNarinfo, err)
	}
	defer decoder.Close()

	plain, err := io.ReadAll(io.LimitReader(decoder, pullThroughMaxNarinfo+1))
	if err != nil {
		return nil, fmt.Errorf("%w: zstd: %w", errBadNarinfo, err)
	}

	if len(plain) > pullThroughMaxNarinfo {
		return nil, fmt.Errorf("%w: larger than 1 MiB", errBadNarinfo)
	}

	return plain, nil
}

var zstdEncoderPool = sync.Pool{ //nolint:gochecknoglobals // sync.Pool should be global
	New: func() any {
		encoder, err := zstd.NewWriter(nil)
		if err != nil {
			panic("failed to create zstd encoder: " + err.Error())
		}

		return encoder
	},
}

func zstdCompress(data []byte) ([]byte, error) {
	encoder, ok := zstdEncoderPool.Get().(*zstd.Encoder)
	if !ok {
		return nil, errors.New("failed to get zstd encoder from pool")
	}
	defer zstdEncoderPool.Put(encoder)

	return encoder.EncodeAll(data, nil), nil
}

// pullThroughMiss handles an S3 miss for a key pull-through can fill.
// Returns false when pull-through is off, err is not a missing key, or the
// key is not a narinfo or NAR, in which case the caller reports the error.
func (s *Service) pullThroughMiss(w http.ResponseWriter, r *http.Request, key string, err error) bool {
	if s.PullThrough == nil || !isNoSuchKey(err) {
		return false
	}

	switch {
	case narinfoRe.MatchString(key):
		s.pullThroughNarinfo(w, r, key)
	case narRe.MatchString(key):
		s.pullThroughNar(w, r, key)
	default:
		return false
	}

	return true
}

// markProxyHit labels a read served from S3.
func (s *Service) markProxyHit(w http.ResponseWriter, key string) {
	if s.PullThrough == nil {
		return
	}

	w.Header().Set(cacheStatusHeader, "HIT")

	switch {
	case narinfoRe.MatchString(key):
		s.Metrics.recordPullThrough(kindNarinfo, "hit")
	case narRe.MatchString(key):
		s.Metrics.recordPullThrough(kindNar, "hit")
	}
}

// redirectOrPull is the NAR path in redirect mode. The objects table says
// whether the NAR is tracked and live, which avoids an S3 HEAD before every
// presign. A database error degrades to today's behaviour: a blind presign
// that 404s at S3 when the object is missing.
func (s *Service) redirectOrPull(w http.ResponseWriter, r *http.Request, key string) {
	if s.PullThrough == nil {
		s.redirectToS3(w, r, key)

		return
	}

	if s.objectIsLive(r.Context(), key) {
		s.redirectToS3(w, r, key)

		return
	}

	// Not tracked: objects written outside niks3 never are, so confirm
	// against S3 before filling from upstream.
	if err := s.S3RateLimiter.Wait(r.Context()); err != nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)

		return
	}

	if _, ok := s.statOrPull(w, r, key); ok {
		s.redirectToS3(w, r, key)
	}
}

func (s *Service) objectIsLive(ctx context.Context, key string) bool {
	live, err := pg.New(s.Pool).ObjectIsLive(ctx, key)
	if err != nil {
		slog.Warn("Failed to check whether object is live; redirecting blindly", "key", key, "error", err)
		s.Metrics.recordPullThroughLiveCheckError()

		return true
	}

	if live {
		s.Metrics.recordPullThrough(kindNar, "hit")
	}

	return live
}

func (s *Service) pullThroughNotFound(w http.ResponseWriter, r *http.Request, kind, result string) {
	w.Header().Set(cacheStatusHeader, strings.ToUpper(result))
	http.NotFound(w, r)
	s.Metrics.recordPullThrough(kind, result)
}

func (s *Service) pullThroughUpstreamError(w http.ResponseWriter, r *http.Request, kind, key string, err error) {
	if errors.Is(err, errUpstreamNotFound) {
		s.PullThrough.setNegative(key)
		s.pullThroughNotFound(w, r, kind, "miss")

		return
	}

	slog.Warn("Upstream fetch failed", "key", key, "error", err)
	http.Error(w, "Bad Gateway", http.StatusBadGateway)
	s.Metrics.recordPullThrough(kind, "upstream_error")
}

func (s *Service) pullThroughReject(w http.ResponseWriter, kind, key, reason string) {
	slog.Warn("Rejected upstream object", "key", key, "reason", reason)
	http.Error(w, "Bad Gateway", http.StatusBadGateway)
	s.Metrics.recordPullThrough(kind, "rejected")
}

// pullThroughHeadNar forwards a HEAD for a missing NAR upstream without
// persisting anything. There is nothing to validate about a NAR without
// its body, so the upstream's answer is passed on as is. It buffers
// nothing either, so it takes a narinfo slot rather than one of the NAR
// fill slots that size memory.
func (s *Service) pullThroughHeadNar(w http.ResponseWriter, r *http.Request, key string) {
	p := s.PullThrough

	release, ok := acquire(r.Context(), p.narinfoSem)
	if !ok {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)

		return
	}
	defer release()

	resp, err := p.fetch(r.Context(), http.MethodHead, key, "")
	if err != nil {
		s.pullThroughUpstreamError(w, r, kindNar, key, err)

		return
	}

	closeBody(resp)

	w.Header().Set("Content-Type", proxyContentType(key, ""))
	w.Header().Set("Accept-Ranges", "bytes")

	if resp.ContentLength >= 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	}

	w.Header().Set(cacheStatusHeader, "MISS")
	w.WriteHeader(http.StatusOK)
	s.Metrics.recordPullThrough(kindNar, "miss")
}

// pullThroughNarRange answers a Range request for a missing NAR straight
// from upstream without filling. Nix resumes a dropped download with a
// Range when the first response advertised Accept-Ranges; the partial
// body is of no use to the bucket, and the fill that the interrupted
// download started may well still be running.
func (s *Service) pullThroughNarRange(w http.ResponseWriter, r *http.Request, key string) {
	p := s.PullThrough

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	resp, err := p.fetch(ctx, http.MethodGet, key, r.Header.Get("Range"))
	if err != nil {
		s.pullThroughUpstreamError(w, r, kindNar, key, err)

		return
	}
	defer closeBody(resp)

	budget := newTransferBudget(w, cancel, resp.ContentLength, p.idleBudget, key)
	defer budget.stop()

	w.Header().Set("Content-Type", proxyContentType(key, ""))
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set(cacheStatusHeader, "MISS")

	if cr := resp.Header.Get("Content-Range"); cr != "" {
		w.Header().Set("Content-Range", cr)
	}

	if resp.ContentLength >= 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	}

	w.WriteHeader(resp.StatusCode)

	n, _ := io.Copy(w, budget.reader(resp.Body))
	s.Metrics.addPullThroughBytes(n)
	s.Metrics.recordPullThrough(kindNar, "range")
}

// pullThroughNarinfo fetches a narinfo upstream, validates it, stores it
// verbatim (zstd-compressed like native uploads) and serves it. A HEAD
// fetches and validates exactly like a GET, so the two agree on whether
// the path exists (Nix decides from a HEAD whether `nix copy` needs to
// upload it), but never persists anything.
func (s *Service) pullThroughNarinfo(w http.ResponseWriter, r *http.Request, key string) {
	p := s.PullThrough

	if p.isNegative(key) {
		s.pullThroughNotFound(w, r, kindNarinfo, "negative")

		return
	}

	release, ok := acquire(r.Context(), p.narinfoSem)
	if !ok {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)

		return
	}
	defer release()

	s.Metrics.pullThroughInFlightAdd(1)
	defer s.Metrics.pullThroughInFlightAdd(-1)

	pulled, ok := s.fetchNarinfo(w, r, key)
	if !ok {
		return
	}

	if r.Method != http.MethodHead {
		// Store before answering so the row exists by the time the client
		// asks for the NAR. A failed store is logged; the client still gets
		// the data.
		s.persistNarinfo(context.WithoutCancel(r.Context()), key, pulled)
	}

	w.Header().Set("Content-Type", proxyContentType(key, ""))
	w.Header().Set(cacheStatusHeader, "MISS")
	w.Header().Set("Content-Length", strconv.Itoa(len(pulled.data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pulled.data) // net/http discards the body of a HEAD

	s.Metrics.recordPullThrough(kindNarinfo, "miss")
}

// pulledNarinfo is a validated upstream narinfo: its verbatim bytes, the
// parsed form, and the trusted signature that verified it, which is what
// closures.pulled_sig records.
type pulledNarinfo struct {
	data []byte
	info *narinfo
	sig  string
}

// validateNarinfo checks a narinfo's bytes for key: syntax, the StorePath
// against the requested hash, the URL against the NAR allowlist and the
// signature against the trusted keys. The error is the reason a narinfo
// is rejected, worded for the log. A narinfo that passes is remembered:
// what it says about its NAR is kept in memory so the NAR can be
// verified when it is pulled; registerPulled writes the same to the
// database.
func (p *PullThrough) validateNarinfo(key string, data []byte) (*pulledNarinfo, error) {
	info, err := parseNarinfo(data)
	if err != nil {
		return nil, fmt.Errorf("invalid narinfo: %w", err)
	}

	if info.hashPart() != strings.TrimSuffix(key, ".narinfo") {
		return nil, errors.New("StorePath does not match the requested hash")
	}

	if !narRe.MatchString(info.URL) {
		return nil, errors.New("URL is not a nar/ path: " + info.URL)
	}

	sig, err := signing.VerifyNarinfo(p.trustedKeys, info.signingInfo(), info.Sigs)
	if err != nil {
		return nil, fmt.Errorf("cannot fingerprint: %w", err)
	}

	if sig == "" {
		return nil, errors.New("no valid signature from a trusted key")
	}

	if meta, ok := narMetaFromNarinfo(key, info); ok {
		p.setNarMeta(info.URL, meta)
	}

	return &pulledNarinfo{data: data, info: info, sig: sig}, nil
}

// fetchNarinfo fetches key upstream and validates it, size included. On
// failure the response has been written and ok is false.
func (s *Service) fetchNarinfo(w http.ResponseWriter, r *http.Request, key string) (*pulledNarinfo, bool) {
	p := s.PullThrough

	resp, err := p.fetch(r.Context(), http.MethodGet, key, "")
	if err != nil {
		s.pullThroughUpstreamError(w, r, kindNarinfo, key, err)

		return nil, false
	}
	defer closeBody(resp)

	data, err := readNarinfo(resp.Body)
	if errors.Is(err, errBadNarinfo) {
		s.pullThroughReject(w, kindNarinfo, key, err.Error())

		return nil, false
	}

	if err != nil {
		s.pullThroughUpstreamError(w, r, kindNarinfo, key, fmt.Errorf("reading narinfo: %w", err))

		return nil, false
	}

	s.Metrics.addPullThroughBytes(int64(len(data)))

	pulled, err := p.validateNarinfo(key, data)
	if err != nil {
		s.pullThroughReject(w, kindNarinfo, key, err.Error())

		return nil, false
	}

	return pulled, true
}

func (s *Service) persistNarinfo(ctx context.Context, key string, pulled *pulledNarinfo) {
	plain, info := pulled.data, pulled.info

	ctx, cancel := context.WithTimeout(ctx, ProxyWriteTimeout(int64(len(plain))))
	defer cancel()

	compressed, err := zstdCompress(plain)
	if err != nil {
		slog.Error("Failed to compress pulled narinfo", "key", key, "error", err)

		return
	}

	if err := s.S3RateLimiter.Wait(ctx); err != nil {
		slog.Warn("Skipped storing pulled narinfo", "key", key, "error", err)

		return
	}

	_, err = s.MinioClient.PutObject(ctx, s.Bucket, key, bytes.NewReader(compressed), int64(len(compressed)),
		minio.PutObjectOptions{
			ContentType:     proxyContentType(key, ""),
			ContentEncoding: "zstd",
		})
	if err != nil {
		if isRateLimitError(err) {
			s.S3RateLimiter.RecordThrottle()
		}

		slog.Error("Failed to store pulled narinfo", "key", key, "error", err)

		return
	}

	s.S3RateLimiter.RecordSuccess()

	size := uint64(len(plain))
	if err := s.registerPulled(ctx, key, info.refKeys(), &size, info, pulled.sig); err != nil {
		slog.Error("Failed to register pulled narinfo", "key", key, "error", err)
	}
}

// registerPulled records a filled object in one transaction. For a narinfo
// (info != nil) it also roots the object with a pulled closure that records
// sig, the trusted signature the narinfo was verified with, and remembers
// what the narinfo said about its NAR, so the NAR can be verified when it
// is pulled later.
//
// Lock order is closures, then objects, then pulled_nars: the same order
// commit_pending_closure takes for a native upload of the same key, so
// the two cannot deadlock when they race. Keep it that way.
func (s *Service) registerPulled(ctx context.Context, key string, refs []string, size *uint64, info *narinfo, sig string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	queries := pg.New(tx)

	if info != nil {
		if err := queries.UpsertPulledClosure(ctx, pg.UpsertPulledClosureParams{
			Key:       key,
			PulledSig: pgtype.Text{String: sig, Valid: true},
		}); err != nil {
			return fmt.Errorf("upsert pulled closure: %w", err)
		}
	}

	if refs == nil {
		refs = []string{}
	}

	if err := queries.RegisterCompletedObject(ctx, pg.RegisterCompletedObjectParams{
		Key:  key,
		Refs: refs,
		Size: optionalSize(size),
	}); err != nil {
		return fmt.Errorf("register object: %w", err)
	}

	if info != nil {
		if meta, ok := narMetaFromNarinfo(key, info); ok {
			if err := queries.UpsertPulledNar(ctx, pg.UpsertPulledNarParams{
				Key:        info.URL,
				NarinfoKey: key,
				FileHash:   meta.fileHash,
				FileSize:   int64(min(meta.fileSize, math.MaxInt64)),
				NarSize:    int64(min(meta.narSize, math.MaxInt64)),
			}); err != nil {
				return fmt.Errorf("upsert pulled nar: %w", err)
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}

	return nil
}

// pullThroughNar streams a NAR from upstream to the client while filling
// S3. The fill is detached from the request so a client that disconnects
// mid-download still leaves the object behind for the next reader. A NAR
// whose narinfo we have not seen (or that carried no FileHash) cannot be
// verified, so it is streamed but not stored. A narinfo miss records what
// to check its NAR against; a narinfo hit does not, so this repeats on
// every read of a NAR under a narinfo niks3 never pulled (uploaded
// natively, or written by another tool) until that narinfo is pulled
// again, and is logged so the operator can tell.
func (s *Service) pullThroughNar(w http.ResponseWriter, r *http.Request, key string) {
	p := s.PullThrough

	if p.isNegative(key) {
		s.pullThroughNotFound(w, r, kindNar, "negative")

		return
	}

	if r.Method == http.MethodHead {
		s.pullThroughHeadNar(w, r, key)

		return
	}

	release, ok := acquire(r.Context(), p.narSem)
	if !ok {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)

		return
	}
	defer release()

	s.Metrics.pullThroughInFlightAdd(1)
	defer s.Metrics.pullThroughInFlightAdd(-1)

	if r.Header.Get("Range") != "" {
		s.pullThroughNarRange(w, r, key)

		return
	}

	ctx, cancel := context.WithCancel(context.WithoutCancel(r.Context()))
	defer cancel()

	resp, err := p.fetch(ctx, http.MethodGet, key, "")
	if err != nil {
		s.pullThroughUpstreamError(w, r, kindNar, key, err)

		return
	}
	defer closeBody(resp)

	meta, haveMeta := s.pulledNarMeta(r.Context(), key)

	size := resp.ContentLength
	if size < 0 && haveMeta && meta.fileSize > 0 && meta.fileSize <= math.MaxInt64 {
		size = int64(meta.fileSize)
	}

	if haveMeta && meta.fileSize > 0 && size >= 0 && uint64(size) != meta.fileSize {
		s.pullThroughReject(w, kindNar, key, fmt.Sprintf("upstream size %d differs from narinfo FileSize %d", size, meta.fileSize))

		return
	}

	budget := newTransferBudget(w, cancel, size, p.idleBudget, key)
	defer budget.stop()

	body := budget.reader(resp.Body)

	w.Header().Set("Content-Type", proxyContentType(key, ""))
	w.Header().Set(cacheStatusHeader, "MISS")
	// Lets Nix resume a dropped download with a Range instead of failing
	// it; the Range is then passed through to upstream.
	w.Header().Set("Accept-Ranges", "bytes")

	if size >= 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	}

	w.WriteHeader(http.StatusOK)

	if !haveMeta {
		slog.Warn("Streaming NAR without its narinfo's FileHash; not stored", "key", key)

		n, _ := io.Copy(w, body)
		s.Metrics.addPullThroughBytes(n)
		s.Metrics.recordPullThrough(kindNar, "unverified")

		return
	}

	if !p.beginFill(key) {
		// Another request is filling this key; stream without persisting.
		n, _ := io.Copy(w, body)
		s.Metrics.addPullThroughBytes(n)
		s.Metrics.recordPullThrough(kindNar, "passthrough")

		return
	}
	defer p.endFill(key)

	fan := &fanOut{client: w, clientCtx: r.Context(), clientLeft: size, hasher: sha256.New()}
	s.fillNar(ctx, cancel, key, body, size, meta, fan)
}

// transferBudget bounds a NAR transfer. With a known size it is one
// deadline proportional to the size, as the S3 streaming path uses. With
// an unknown size (a chunked upstream, no narinfo FileSize) it is an idle
// budget renewed as bytes flow: a flat deadline would cut off any large
// NAR from such an upstream on every attempt.
type transferBudget struct {
	idle    time.Duration // 0 when the size was known
	renewal time.Duration // how long between renewals
	timer   *time.Timer
	rc      *http.ResponseController
	renewed time.Time
	key     string
}

func newTransferBudget(w http.ResponseWriter, cancel context.CancelFunc, size int64, idle time.Duration, key string) *transferBudget {
	b := &transferBudget{rc: http.NewResponseController(w), key: key}

	d := ProxyWriteTimeout(size)
	if size < 0 {
		b.idle = idle
		b.renewal = min(pullThroughBudgetRenewal, idle/4)
		d = idle
	}

	b.timer = time.AfterFunc(d, cancel)
	b.renewed = time.Now()
	b.setWriteDeadline(d)

	return b
}

func (b *transferBudget) setWriteDeadline(d time.Duration) {
	if err := b.rc.SetWriteDeadline(time.Now().Add(d)); err != nil {
		slog.Debug("Failed to extend write deadline", "key", b.key, "error", err)
	}
}

// progress renews an idle budget. A known-size budget does not move.
func (b *transferBudget) progress() {
	if b.idle == 0 {
		return
	}

	now := time.Now()
	if now.Sub(b.renewed) < b.renewal {
		return
	}

	b.renewed = now
	b.timer.Reset(b.idle)
	b.setWriteDeadline(b.idle)
}

func (b *transferBudget) stop() {
	b.timer.Stop()
}

// reader wraps r so every successful read counts as progress.
func (b *transferBudget) reader(r io.Reader) io.Reader {
	return &progressReader{r: r, progress: b.progress}
}

type progressReader struct {
	r        io.Reader
	progress func()
}

func (p *progressReader) Read(buf []byte) (int, error) {
	n, err := p.r.Read(buf)
	if n > 0 {
		p.progress()
	}

	return n, err //nolint:wrapcheck // transparent wrapper
}

// fillNar fans body out through fan to its client and to an S3 upload. The
// S3 side is primary: the client is dropped on its first write error, while an S3
// failure only stops the fill. The NAR is hashed inline and the S3 side
// lags the client by one chunk, so the last chunk is only released once
// the whole body has been read and verified against the size and the
// FileHash its narinfo announced. A NAR that fails verification is cut
// short so it does not become a complete upload, and is deleted again in
// the cases where S3 committed it anyway; the client still gets every
// byte and Nix rejects it by NarHash on its side.
func (s *Service) fillNar(
	ctx context.Context,
	cancel context.CancelFunc,
	key string,
	body io.Reader,
	size int64,
	meta narMeta,
	fan *fanOut,
) {
	pr, pw := io.Pipe()
	fan.s3 = pw
	putDone := make(chan error, 1)

	go func() {
		err := s.putNar(ctx, key, pr, size)
		// Close the read side whatever happened. On an error further
		// pw.Write calls fail with err instead of blocking; after a
		// successful completion (the body ran past the announced size,
		// which minio stops reading at) they fail with ErrClosedPipe
		// instead of hanging forever on a reader that is gone.
		_ = pr.CloseWithError(err)

		putDone <- err
	}()

	buf := make([]byte, pullThroughCopyBuf)

	var readErr error

	for {
		n, err := body.Read(buf)
		if n > 0 && !fan.write(buf[:n]) {
			readErr = errFillAbandoned

			break
		}

		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			readErr = err

			break
		}
	}

	s.Metrics.addPullThroughBytes(fan.total)

	var verifyErr error
	if readErr == nil {
		verifyErr = verifyPulledNar(fan.total, size, fan.hasher.Sum(nil), meta)
	}

	switch {
	case readErr != nil:
		_ = pw.CloseWithError(fmt.Errorf("upstream read: %w", readErr))

		cancel()
	case verifyErr != nil:
		// The held-back tail never reaches S3: the upload ends short of
		// its Content-Length (or its last part) and fails instead of
		// committing a NAR we cannot vouch for.
		_ = pw.CloseWithError(verifyErr)
	default:
		fan.flush()

		_ = pw.Close()
	}

	putErr := <-putDone

	switch {
	case readErr == nil && verifyErr == nil && putErr == nil:
		var narSize *uint64
		if meta.narSize > 0 {
			narSize = &meta.narSize
		}

		dbCtx, dbCancel := context.WithTimeout(context.WithoutCancel(ctx), pullThroughDBTimeout)
		defer dbCancel()

		if err := s.registerPulled(dbCtx, key, nil, narSize, nil, ""); err != nil {
			slog.Error("Failed to register pulled NAR", "key", key, "error", err)
		}

		s.Metrics.recordPullThrough(kindNar, "miss")

		return
	case verifyErr != nil:
		slog.Error("Discarded pulled NAR", "key", key, "error", verifyErr)
		s.Metrics.recordPullThrough(kindNar, "rejected")
	default:
		slog.Warn("Failed to store pulled NAR", "key", key, "bytes", fan.total, "error", errors.Join(readErr, putErr))
		s.Metrics.recordPullThrough(kindNar, "fill_failed")
	}

	if putErr == nil || verifyErr != nil {
		// An object we will not vouch for may be sitting in the bucket
		// untracked. It certainly is when minio completed before the fill
		// was cut short (it stops reading at the announced size). It may
		// be when the body ran past a size we announced to S3 over HTTPS:
		// the transport sends exactly that many bytes, S3 commits, and
		// only then does the transport notice the surplus and report the
		// upload as failed. Deleting a key that is not there is one
		// request and no error, so on any rejection take it back out.
		s.removePulledNar(ctx, key)
	}
}

// verifyPulledNar checks a fully read NAR against what we knew about it
// up front: the size it was announced with and the FileHash its narinfo
// carried.
func verifyPulledNar(total, size int64, digest []byte, meta narMeta) error {
	if size >= 0 && total != size {
		return fmt.Errorf("upstream sent %d bytes, expected %d", total, size)
	}

	if !hashMatches(meta.fileHash, digest) {
		return errFileHashMismatch
	}

	return nil
}

// removePulledNar deletes an object the fill left behind but could not
// verify. Failure leaves an untracked object in the bucket, which is
// logged loudly: nothing else will ever collect it. The delete is by key
// alone: were a native upload or another replica's fill to commit a good
// object at this key in the same moment, it would go too, and its live
// row would then point at nothing. That takes a bad upstream body for a
// key something else is writing at that instant, which is accepted.
func (s *Service) removePulledNar(ctx context.Context, key string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), pullThroughDBTimeout)
	defer cancel()

	if err := s.S3RateLimiter.Wait(ctx); err != nil {
		slog.Error("Unverified pulled NAR left in S3 untracked", "key", key, "error", err)

		return
	}

	if err := s.MinioClient.RemoveObject(ctx, s.Bucket, key, minio.RemoveObjectOptions{}); err != nil {
		if isRateLimitError(err) {
			s.S3RateLimiter.RecordThrottle()
		}

		slog.Error("Unverified pulled NAR left in S3 untracked", "key", key, "error", err)

		return
	}

	s.S3RateLimiter.RecordSuccess()
}

// fanOut writes each chunk to the client and, one chunk late, to the S3
// pipe, dropping either side on its first failure, and hashes everything
// it sees. The lag lets the caller verify the whole body before the last
// chunk is released to S3.
type fanOut struct {
	s3        io.Writer
	client    io.Writer
	clientCtx context.Context //nolint:containedctx // request context, checked per chunk
	// clientLeft is how many more bytes the client's Content-Length
	// allows, or negative when no length was announced. An upstream body
	// that runs long is still read and hashed in full, so the fill can
	// reject it, but the client gets a well-formed response.
	clientLeft int64
	hasher     hash.Hash
	hold       []byte // the chunk S3 has not been given yet
	total      int64
	s3Down     bool
	clientOff  bool
}

// write returns false once neither side can take more data.
func (f *fanOut) write(chunk []byte) bool {
	f.total += int64(len(chunk))
	_, _ = f.hasher.Write(chunk)

	if !f.s3Down {
		f.releaseHeld()
		f.hold = append(f.hold[:0], chunk...)
	}

	if !f.clientOff && f.clientCtx.Err() != nil {
		f.clientOff = true
	}

	if !f.clientOff {
		out := chunk
		if f.clientLeft >= 0 && int64(len(out)) > f.clientLeft {
			out = out[:f.clientLeft]
		}

		if _, err := f.client.Write(out); err != nil {
			f.clientOff = true
		} else if f.clientLeft >= 0 {
			f.clientLeft -= int64(len(out))
		}
	}

	return !f.s3Down || !f.clientOff
}

// flush releases the held-back chunk to S3 once the body is verified.
func (f *fanOut) flush() {
	if !f.s3Down {
		f.releaseHeld()
	}

	f.hold = f.hold[:0]
}

func (f *fanOut) releaseHeld() {
	if len(f.hold) == 0 {
		return
	}

	if _, err := f.s3.Write(f.hold); err != nil {
		f.s3Down = true
	}
}

func (s *Service) putNar(ctx context.Context, key string, body io.Reader, size int64) error {
	if err := s.S3RateLimiter.Wait(ctx); err != nil {
		return fmt.Errorf("rate limiter: %w", err)
	}

	opts := minio.PutObjectOptions{ContentType: proxyContentType(key, "")}
	if size < 0 {
		opts.PartSize = pullThroughPartSize
	}

	if _, err := s.MinioClient.PutObject(ctx, s.Bucket, key, body, size, opts); err != nil {
		if isRateLimitError(err) {
			s.S3RateLimiter.RecordThrottle()
		}

		return fmt.Errorf("put object: %w", err)
	}

	s.S3RateLimiter.RecordSuccess()

	return nil
}
