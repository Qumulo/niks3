package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Mic92/niks3/server/pg"
	"github.com/Mic92/niks3/server/signing"
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

	// pullThroughHeaderTimeout bounds the wait for upstream response headers.
	pullThroughHeaderTimeout = 30 * time.Second

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
	// NarinfoConcurrency bounds simultaneous narinfo fills. 0 means the default.
	NarinfoConcurrency int
}

// PullThrough holds the upstream client and the in-memory bookkeeping for
// fills: recent upstream 404s.
type PullThrough struct {
	upstreams   []*url.URL
	trustedKeys []*signing.PublicKey
	negativeTTL time.Duration
	client      *http.Client
	narinfoSem  chan struct{}

	mu       sync.Mutex
	negative map[string]time.Time
}

// NewPullThrough validates cfg and builds the upstream client.
func NewPullThrough(cfg PullThroughConfig) (*PullThrough, error) {
	if len(cfg.Upstreams) == 0 {
		return nil, errors.New("pull-through requires at least one upstream")
	}

	if len(cfg.TrustedKeys) == 0 {
		return nil, errors.New("pull-through requires at least one trusted key")
	}

	narinfoConcurrency := cfg.NarinfoConcurrency
	if narinfoConcurrency <= 0 {
		narinfoConcurrency = pullThroughDefaultNarinfoConcurrency
	}

	p := &PullThrough{
		negativeTTL: cfg.NegativeTTL,
		narinfoSem:  make(chan struct{}, narinfoConcurrency),
		negative:    make(map[string]time.Time),
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
	transport.MaxIdleConnsPerHost = narinfoConcurrency

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

// fetch tries each upstream in order. It returns errUpstreamNotFound when
// every upstream answered 404, otherwise the last failure. The caller owns
// resp.Body.
func (p *PullThrough) fetch(ctx context.Context, method, key string) (*http.Response, error) {
	var lastErr error

	for _, upstream := range p.upstreams {
		target := upstream.String() + "/" + key

		// The host comes from operator config; key is narrowed by the
		// cache path allowlist before we get here.
		req, err := http.NewRequestWithContext(ctx, method, target, nil) //nolint:gosec // G704: see above
		if err != nil {
			return nil, fmt.Errorf("building upstream request: %w", err)
		}

		// Identity keeps Content-Length meaningful.
		req.Header.Set("Accept-Encoding", "identity")
		req.Header.Set("User-Agent", "niks3 pull-through")

		resp, err := p.client.Do(req) //nolint:gosec // G704: operator-configured upstream
		if err != nil {
			lastErr = err

			continue
		}

		switch resp.StatusCode {
		case http.StatusOK:
			return resp, nil
		case http.StatusNotFound:
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
// key is not a narinfo, in which case the caller reports the error.
func (s *Service) pullThroughMiss(w http.ResponseWriter, r *http.Request, key string, err error) bool {
	if s.PullThrough == nil || !isNoSuchKey(err) {
		return false
	}

	if !narinfoRe.MatchString(key) {
		return false
	}

	s.pullThroughNarinfo(w, r, key)

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
// is rejected, worded for the log.
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

	return &pulledNarinfo{data: data, info: info, sig: sig}, nil
}

// fetchNarinfo fetches key upstream and validates it, size included. On
// failure the response has been written and ok is false.
func (s *Service) fetchNarinfo(w http.ResponseWriter, r *http.Request, key string) (*pulledNarinfo, bool) {
	p := s.PullThrough

	resp, err := p.fetch(r.Context(), http.MethodGet, key)
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

	if err := s.registerPulled(ctx, key, info.refKeys(), uint64(len(plain)), pulled.sig); err != nil {
		slog.Error("Failed to register pulled narinfo", "key", key, "error", err)
	}
}

// registerPulled records a filled narinfo in one transaction: rooted by a
// pulled closure that records sig, the trusted signature the narinfo was
// verified with, and tracked as an object with its references.
//
// Lock order is closures, then objects: the same order
// commit_pending_closure takes for a native upload of the same key, so
// the two cannot deadlock when they race. Keep it that way.
func (s *Service) registerPulled(ctx context.Context, key string, refs []string, size uint64, sig string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	queries := pg.New(tx)

	if err := queries.UpsertPulledClosure(ctx, pg.UpsertPulledClosureParams{
		Key:       key,
		PulledSig: pgtype.Text{String: sig, Valid: true},
	}); err != nil {
		return fmt.Errorf("upsert pulled closure: %w", err)
	}

	if err := queries.RegisterCompletedObject(ctx, pg.RegisterCompletedObjectParams{
		Key:  key,
		Refs: refs,
		Size: optionalSize(&size),
	}); err != nil {
		return fmt.Errorf("register object: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}

	return nil
}
