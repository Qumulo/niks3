package server_test

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mic92/niks3/server"
	minio "github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

func TestClientAddr(t *testing.T) {
	t.Parallel()

	proxies, err := server.ParsePrefixes([]string{"203.0.113.0/24", "192.0.2.7"})
	ok(t, err)

	tests := []struct {
		name       string
		remoteAddr string
		forwarded  []string
		want       string
	}{
		{"direct client", "198.51.100.4:5555", nil, "198.51.100.4"},
		{"direct client ignores its own header", "198.51.100.4:5555", []string{"192.0.2.200"}, "198.51.100.4"},
		{"behind a proxy", "203.0.113.10:5555", []string{"198.51.100.4"}, "198.51.100.4"},
		{"forged earlier hop", "203.0.113.10:5555", []string{"192.0.2.200, 198.51.100.4"}, "198.51.100.4"},
		{"two trusted proxies", "203.0.113.10:5555", []string{"198.51.100.4, 192.0.2.7"}, "198.51.100.4"},
		{"repeated header", "203.0.113.10:5555", []string{"192.0.2.200", "198.51.100.4"}, "198.51.100.4"},
		{"no header", "203.0.113.10:5555", nil, "203.0.113.10"},
		{"only proxies", "203.0.113.10:5555", []string{"192.0.2.7"}, "192.0.2.7"},
		{"IPv4-mapped remote", "[::ffff:198.51.100.4]:5555", nil, "198.51.100.4"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := &http.Request{RemoteAddr: tt.remoteAddr, Header: http.Header{}}
			for _, value := range tt.forwarded {
				r.Header.Add("X-Forwarded-For", value)
			}

			got, err := server.ClientAddr(r, proxies)
			ok(t, err)

			if got != netip.MustParseAddr(tt.want) {
				t.Errorf("ClientAddr = %s, want %s", got, tt.want)
			}
		})
	}

	r := &http.Request{RemoteAddr: "203.0.113.10:5555", Header: http.Header{"X-Forwarded-For": {"not-an-ip"}}}
	if _, err := server.ClientAddr(r, proxies); err == nil {
		t.Error("ClientAddr accepted an unparseable X-Forwarded-For hop")
	}
}

func TestParsePrefixes(t *testing.T) {
	t.Parallel()

	got, err := server.ParsePrefixes([]string{"198.51.100.9/24", "192.0.2.7", "fd00::/8"})
	ok(t, err)

	want := []netip.Prefix{
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("192.0.2.7/32"),
		netip.MustParsePrefix("fd00::/8"),
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("prefix %d = %s, want %s", i, got[i], want[i])
		}
	}

	for _, bad := range []string{"198.51.100.0/33", "replica", ""} {
		if _, err := server.ParsePrefixes([]string{bad}); err == nil {
			t.Errorf("ParsePrefixes accepted %q", bad)
		}
	}
}

// writeRouteKeys writes the test S3 server's keys where a redirect route can
// read them, and returns a config for a route that uses them.
func writeRouteKeys(t *testing.T, s3URL string, cidrs ...string) server.RedirectRouteConfig {
	t.Helper()

	creds, err := testRustfsServer.Creds().GetWithContext(&credentials.CredContext{Client: http.DefaultClient})
	ok(t, err)

	dir := t.TempDir()
	accessKeyPath := filepath.Join(dir, "access-key")
	secretKeyPath := filepath.Join(dir, "secret-key")
	ok(t, os.WriteFile(accessKeyPath, []byte(creds.AccessKeyID+"\n"), 0o600))
	ok(t, os.WriteFile(secretKeyPath, []byte(creds.SecretAccessKey+"\n"), 0o600))

	return server.RedirectRouteConfig{
		CIDRs:         cidrs,
		S3URL:         s3URL,
		Region:        "us-east-1",
		AccessKeyPath: accessKeyPath,
		SecretKeyPath: secretKeyPath,
	}
}

func TestReadRedirectRoutesByClientNetwork(t *testing.T) {
	t.Parallel()

	service := createProxyTestService(t)
	service.ReadRedirectTTL = time.Minute

	defer service.Close()

	ctx := t.Context()

	unused, err := server.NewRedirectRoute(
		writeRouteKeys(t, "https://s3.elsewhere.example", "192.0.2.128/25"), service.Bucket, "", minio.BucketLookupPath)
	ok(t, err)

	replica, err := server.NewRedirectRoute(
		writeRouteKeys(t, "https://s3.replica.example", "198.51.100.0/24"), service.Bucket, "", minio.BucketLookupPath)
	ok(t, err)

	service.RedirectRoutes = []server.RedirectRoute{unused, replica}

	key := "nar/1ngi2dxw1f7khrrjamzkkdai393lwcm8s78gvs1ag8k3n82w7bvp.nar.zst"
	putTestObject(ctx, t, service, key, []byte("x"), minio.PutObjectOptions{})

	ts := setupProxyServer(t, service)
	defer ts.Close()

	noFollow := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	location := func(forwardedFor string) *url.URL {
		t.Helper()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/"+key, nil)
		ok(t, err)

		if forwardedFor != "" {
			req.Header.Set("X-Forwarded-For", forwardedFor)
		}

		resp, err := noFollow.Do(req)
		ok(t, err)
		_ = resp.Body.Close()

		if resp.StatusCode != http.StatusTemporaryRedirect {
			t.Fatalf("X-Forwarded-For %q: status = %d, want 307", forwardedFor, resp.StatusCode)
		}

		u, err := url.Parse(resp.Header.Get("Location"))
		ok(t, err)

		if u.Query().Get("X-Amz-Signature") == "" {
			t.Errorf("X-Forwarded-For %q: Location is not presigned: %s", forwardedFor, u)
		}

		return u
	}

	// The test client connects from loopback, which no route holds and which
	// isn't yet a trusted proxy, so the header is ignored.
	if got := location("198.51.100.4"); got.Host == "s3.replica.example" {
		t.Errorf("untrusted X-Forwarded-For chose the replica: %s", got)
	}

	service.TrustedProxies, err = server.ParsePrefixes([]string{"127.0.0.0/8", "::1"})
	ok(t, err)

	if got := location("198.51.100.4"); got.Host != "s3.replica.example" || got.Path != "/"+service.Bucket+"/"+key {
		t.Errorf("client in 198.51.100.0/24: Location = %s, want https://s3.replica.example/%s/%s", got, service.Bucket, key)
	}

	if got := location("192.0.2.1"); got.Host == "s3.replica.example" || got.Host == "s3.elsewhere.example" {
		t.Errorf("client in no route: Location = %s, want the server's own S3", got)
	}

	if got := location("not-an-ip"); got.Host == "s3.replica.example" || got.Host == "s3.elsewhere.example" {
		t.Errorf("unreadable client address: Location = %s, want the server's own S3", got)
	}

	rec := httptest.NewRecorder()
	service.Metrics.Handler().ServeHTTP(rec, httptest.NewRequestWithContext(ctx, http.MethodGet, "/metrics", nil))

	for _, want := range []string{
		`niks3_read_redirects_total{endpoint="s3.replica.example"} 1`,
		`niks3_read_redirects_total{endpoint="primary"} 3`,
	} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("metrics output missing %q", want)
		}
	}
}

func TestNewRedirectRouteRejectsBadConfig(t *testing.T) {
	t.Parallel()

	good := writeRouteKeys(t, "https://s3.replica.example", "198.51.100.0/24")

	route, err := server.NewRedirectRoute(good, "nix-store", "", minio.BucketLookupPath)
	ok(t, err)

	if route.Bucket != "nix-store" || route.Endpoint != "s3.replica.example" {
		t.Errorf("Bucket, Endpoint = %q, %q, want the default nix-store and s3.replica.example", route.Bucket, route.Endpoint)
	}

	// The endpoint doesn't resolve, so a region lookup would fail: the
	// default region keeps the route offline.
	noRegion := good
	noRegion.Region = ""

	if _, err := server.NewRedirectRoute(noRegion, "nix-store", "us-east-1", minio.BucketLookupPath); err != nil {
		t.Errorf("NewRedirectRoute with the server's region: %v", err)
	}

	if _, err := server.NewRedirectRoute(noRegion, "nix-store", "", minio.BucketLookupPath); err == nil {
		t.Error("NewRedirectRoute accepted a route with no region and no default")
	}

	for name, mutate := range map[string]func(*server.RedirectRouteConfig){
		"no cidrs":         func(c *server.RedirectRouteConfig) { c.CIDRs = nil },
		"bad cidr":         func(c *server.RedirectRouteConfig) { c.CIDRs = []string{"198.51.100.0/40"} },
		"bad url":          func(c *server.RedirectRouteConfig) { c.S3URL = "s3.replica.example" },
		"url with path":    func(c *server.RedirectRouteConfig) { c.S3URL = "https://s3.replica.example/nix-store" },
		"no access key":    func(c *server.RedirectRouteConfig) { c.AccessKeyPath = "" },
		"no secret key":    func(c *server.RedirectRouteConfig) { c.SecretKeyPath = "" },
		"missing key file": func(c *server.RedirectRouteConfig) { c.SecretKeyPath = filepath.Join(t.TempDir(), "absent") },
	} {
		cfg := good
		mutate(&cfg)

		if _, err := server.NewRedirectRoute(cfg, "nix-store", "", minio.BucketLookupPath); err == nil {
			t.Errorf("%s: NewRedirectRoute accepted %+v", name, cfg)
		}
	}
}

func TestLoadRedirectRoutes(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	path := filepath.Join(dir, "routes.json")
	ok(t, os.WriteFile(path, []byte(`[{
		"cidrs": ["198.51.100.0/24"],
		"s3_url": "https://replica.example.com:9000",
		"bucket": "nix-store",
		"access_key_path": "/run/secrets/replica/access-key",
		"secret_key_path": "/run/secrets/replica/secret-key"
	}]`), 0o600))

	configs, err := server.LoadRedirectRoutes(path)
	ok(t, err)

	if len(configs) != 1 || configs[0].S3URL != "https://replica.example.com:9000" || configs[0].CIDRs[0] != "198.51.100.0/24" {
		t.Errorf("LoadRedirectRoutes = %+v", configs)
	}

	typo := filepath.Join(dir, "typo.json")
	ok(t, os.WriteFile(typo, []byte(`[{"cidr": ["198.51.100.0/24"]}]`), 0o600))

	if _, err := server.LoadRedirectRoutes(typo); err == nil {
		t.Error("LoadRedirectRoutes accepted an unknown field")
	}
}

func TestValidateReadRedirect(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name    string
		ttl     time.Duration
		routes  string
		proxies []string
		wantErr bool
	}{
		{"routes and proxies", time.Minute, "routes.json", []string{"203.0.113.0/24"}, false},
		{"routes without proxies", time.Minute, "routes.json", nil, false},
		{"routes without a ttl", 0, "routes.json", nil, true},
		{"proxies without routes", time.Minute, "", []string{"203.0.113.0/24"}, true},
	} {
		err := server.ValidateReadRedirectForTest(tt.ttl, tt.routes, tt.proxies)
		if (err != nil) != tt.wantErr {
			t.Errorf("%s: error = %v, want error %v", tt.name, err, tt.wantErr)
		}
	}
}
