package server

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	minio "github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// redirectRouteLoadTimeout bounds the lookup of the primary bucket's
// region, which redirect routes that name no region share.
const redirectRouteLoadTimeout = 30 * time.Second

// primaryEndpoint labels redirects signed by the server's own S3.
const primaryEndpoint = "primary"

// RedirectRouteConfig sends the NAR redirects of clients in CIDRs to another
// S3 endpoint that serves the same objects under the same keys, such as a
// read-only replica of the bucket closer to those clients. Its keys sign only
// those redirects, so they need nothing beyond read access.
//
// The endpoint must serve an object as soon as the primary does, as a Qumulo
// portal of the bucket's directory does. One that copies asynchronously 404s
// a NAR pushed or pulled through moments ago, after its narinfo said the NAR
// exists, and Nix fails that substitution.
type RedirectRouteConfig struct {
	CIDRs []string `json:"cidrs"`
	// S3URL is the endpoint's http(s)://host[:port], as clients reach it.
	S3URL string `json:"s3_url"`
	// Bucket defaults to the server's own bucket name.
	Bucket string `json:"bucket,omitempty"`
	// Region defaults to the server's own bucket region, so the server
	// never sends the endpoint a request of its own.
	Region        string `json:"region,omitempty"`
	AccessKeyPath string `json:"access_key_path"`
	SecretKeyPath string `json:"secret_key_path"`
}

// RedirectRoute is a loaded RedirectRouteConfig.
type RedirectRoute struct {
	Networks      []netip.Prefix
	PresignClient *minio.Client
	Bucket        string
	// Endpoint is the host[:port] its redirects point at, for metrics.
	Endpoint string
}

// LoadRedirectRoutes reads a JSON list of RedirectRouteConfig from path.
func LoadRedirectRoutes(path string) ([]RedirectRouteConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read redirect routes: %w", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var configs []RedirectRouteConfig
	if err := decoder.Decode(&configs); err != nil {
		return nil, fmt.Errorf("failed to parse redirect routes %s: %w", path, err)
	}

	return configs, nil
}

// NewRedirectRoute loads cfg's keys and builds the client that signs its
// redirects, offline. defaultBucket and defaultRegion are used when cfg names
// none.
func NewRedirectRoute(
	cfg RedirectRouteConfig,
	defaultBucket, defaultRegion string,
	lookup minio.BucketLookupType,
) (RedirectRoute, error) {
	networks, err := ParsePrefixes(cfg.CIDRs)
	if err != nil {
		return RedirectRoute{}, fmt.Errorf("redirect route to %s: %w", cfg.S3URL, err)
	}

	if len(networks) == 0 {
		return RedirectRoute{}, fmt.Errorf("redirect route to %s: no cidrs", cfg.S3URL)
	}

	u, err := parseS3PublicURL(cfg.S3URL)
	if err != nil {
		return RedirectRoute{}, err
	}

	accessKey, err := readSecretFile(cfg.AccessKeyPath)
	if err != nil {
		return RedirectRoute{}, fmt.Errorf("redirect route to %s: access key: %w", cfg.S3URL, err)
	}

	secretKey, err := readSecretFile(cfg.SecretKeyPath)
	if err != nil {
		return RedirectRoute{}, fmt.Errorf("redirect route to %s: secret key: %w", cfg.S3URL, err)
	}

	if accessKey == "" || secretKey == "" {
		return RedirectRoute{}, fmt.Errorf("redirect route to %s: access_key_path and secret_key_path are required", cfg.S3URL)
	}

	bucket := cmp.Or(cfg.Bucket, defaultBucket)

	// A known region keeps presigning offline.
	region := cmp.Or(cfg.Region, defaultRegion)
	if region == "" {
		return RedirectRoute{}, fmt.Errorf("redirect route to %s: no region, and the server's own is unknown", cfg.S3URL)
	}

	presignClient, err := newPresignClient(u, credentials.NewStaticV4(accessKey, secretKey, ""), region, lookup)
	if err != nil {
		return RedirectRoute{}, fmt.Errorf("redirect route to %s: %w", cfg.S3URL, err)
	}

	return RedirectRoute{Networks: networks, PresignClient: presignClient, Bucket: bucket, Endpoint: u.Host}, nil
}

func (s *Service) loadRedirectRoutes(opts *options) error {
	trustedProxies, err := ParsePrefixes(opts.TrustedProxies)
	if err != nil {
		return fmt.Errorf("--trusted-proxy: %w", err)
	}

	s.TrustedProxies = trustedProxies

	if opts.ReadRedirectRoutesPath == "" {
		return nil
	}

	configs, err := LoadRedirectRoutes(opts.ReadRedirectRoutesPath)
	if err != nil {
		return err
	}

	defaultRegion, err := s.primaryRegion(opts, configs)
	if err != nil {
		return err
	}

	for _, cfg := range configs {
		route, err := NewRedirectRoute(cfg, s.Bucket, defaultRegion, opts.S3BucketLookup)
		if err != nil {
			return err
		}

		s.RedirectRoutes = append(s.RedirectRoutes, route)
		slog.Info("NAR reads redirect to another S3 endpoint for some clients",
			"cidrs", cfg.CIDRs, "s3_url", cfg.S3URL, "bucket", route.Bucket)
	}

	return nil
}

// primaryRegion is the server's own bucket region, for routes that name none.
// It asks the primary, which startup depends on already, only when a route
// needs it and --s3-region doesn't give it.
func (s *Service) primaryRegion(opts *options, configs []RedirectRouteConfig) (string, error) {
	if opts.S3Region != "" || !slices.ContainsFunc(configs, func(c RedirectRouteConfig) bool { return c.Region == "" }) {
		return opts.S3Region, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), redirectRouteLoadTimeout)
	defer cancel()

	region, err := s.MinioClient.GetBucketLocation(ctx, s.Bucket)
	if err != nil {
		return "", fmt.Errorf("failed to look up the bucket region for redirect routes: %w", err)
	}

	return region, nil
}

// ParsePrefixes parses CIDRs such as "10.0.0.0/8" or "fd00::/8". A bare
// address is taken as a single-host prefix.
func ParsePrefixes(cidrs []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(cidrs))

	for _, cidr := range cidrs {
		if !strings.Contains(cidr, "/") {
			addr, err := netip.ParseAddr(cidr)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
			}

			prefixes = append(prefixes, netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()))

			continue
		}

		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
		}

		prefixes = append(prefixes, prefix.Masked())
	}

	return prefixes, nil
}

func prefixesContain(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}

	return false
}

var errNoClientAddr = errors.New("no client address")

// clientAddr is the address of the client that sent r. Behind proxies in
// trustedProxies it's the nearest X-Forwarded-For hop that isn't one of them,
// since a client can put anything it likes in the header's earlier hops.
func clientAddr(r *http.Request, trustedProxies []netip.Prefix) (netip.Addr, error) {
	addrPort, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%w: remote address %q: %w", errNoClientAddr, r.RemoteAddr, err)
	}

	addr := addrPort.Addr().Unmap()
	if !prefixesContain(trustedProxies, addr) {
		return addr, nil
	}

	var hops []string
	for _, header := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(header, ",")...)
	}

	for _, raw := range slices.Backward(hops) {
		hop, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil {
			return netip.Addr{}, fmt.Errorf("%w: X-Forwarded-For hop %q: %w", errNoClientAddr, raw, err)
		}

		addr = hop.Unmap()
		if !prefixesContain(trustedProxies, addr) {
			return addr, nil
		}
	}

	// Every hop is a trusted proxy, so the farthest one, the leftmost, is the
	// client.
	return addr, nil
}

// presignTarget is the client and bucket that sign r's NAR redirect, and the
// endpoint label for metrics: those of the first redirect route whose
// networks hold the client, else the server's own.
func (s *Service) presignTarget(r *http.Request) (*minio.Client, string, string) {
	if len(s.RedirectRoutes) == 0 {
		return s.PresignClient, s.Bucket, primaryEndpoint
	}

	addr, err := clientAddr(r, s.TrustedProxies)
	if err != nil {
		slog.Debug("NAR redirect goes to the primary: client address unreadable", "error", err)

		return s.PresignClient, s.Bucket, primaryEndpoint
	}

	for _, route := range s.RedirectRoutes {
		if prefixesContain(route.Networks, addr) {
			slog.Debug("NAR redirect goes to a route", "client", addr, "endpoint", route.Endpoint)

			return route.PresignClient, route.Bucket, route.Endpoint
		}
	}

	slog.Debug("NAR redirect goes to the primary: client in no route", "client", addr)

	return s.PresignClient, s.Bucket, primaryEndpoint
}
