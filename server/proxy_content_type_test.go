package server_test

import (
	"net/http"
	"testing"

	"github.com/Mic92/niks3/server"
	minio "github.com/minio/minio-go/v7"
)

func TestProxyContentType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		key, reported, want string
	}{
		// Specific types from S3 are kept.
		{"index.html", "text/html", "text/html"},
		{"log/abc-foo.drv", "text/plain; charset=utf-8", "text/plain; charset=utf-8"},
		{"nar/1ngi2dxw1f7khrrjamzkkdai393lwcm8s78gvs1ag8k3n82w7bvp.nar.zst", "application/zstd", "application/zstd"},

		// Missing or generic types are derived from the key.
		{"index.html", "", "text/html; charset=utf-8"},
		{"index.html", "binary/octet-stream", "text/html; charset=utf-8"},
		{"index.html", "application/octet-stream", "text/html; charset=utf-8"},
		{"nix-cache-info", "binary/octet-stream", "text/x-nix-cache-info"},
		{"26xbg1ndr7hbcncrlf9nhx5is2b25d13.narinfo", "", "text/x-nix-narinfo"},
		{"nar/1ngi2dxw1f7khrrjamzkkdai393lwcm8s78gvs1ag8k3n82w7bvp.nar.zst", "application/octet-stream", "application/x-nix-nar"},
		{"26xbg1ndr7hbcncrlf9nhx5is2b25d13.ls", "", "application/json"},
		{"realisations/sha256:abc!out.doi", "", "application/json"},
		{"log/abc-foo.drv", "binary/octet-stream", "text/plain; charset=utf-8"},

		// Unknown keys keep whatever was reported.
		{"something/else", "binary/octet-stream", "binary/octet-stream"},
		{"something/else", "", ""},
	}

	for _, tt := range tests {
		if got := server.ProxyContentType(tt.key, tt.reported); got != tt.want {
			t.Errorf("proxyContentType(%q, %q) = %q, want %q", tt.key, tt.reported, got, tt.want)
		}
	}
}

// TestReadProxyContentTypeFallback covers an S3 store that does not persist
// the Content-Type given at upload and reports a generic one instead.
func TestReadProxyContentTypeFallback(t *testing.T) {
	t.Parallel()

	service := createProxyTestService(t)
	defer service.Close()

	ctx := t.Context()

	generic := minio.PutObjectOptions{ContentType: "binary/octet-stream"}
	putTestObject(ctx, t, service, "index.html", []byte("<!doctype html><title>cache</title>"), generic)
	putTestObject(ctx, t, service, "nix-cache-info", []byte("StoreDir: /nix/store\n"), generic)
	putTestObject(ctx, t, service, "nar/1ngi2dxw1f7khrrjamzkkdai393lwcm8s78gvs1ag8k3n82w7bvp.nar.zst", []byte("nar"),
		minio.PutObjectOptions{ContentType: "application/octet-stream"})
	putTestObject(ctx, t, service, "log/abc-foo.drv", []byte("log"),
		minio.PutObjectOptions{ContentType: "text/plain; charset=utf-8"})

	ts := setupProxyServer(t, service)
	defer ts.Close()

	want := map[string]string{
		"/index.html":     "text/html; charset=utf-8",
		"/nix-cache-info": "text/x-nix-cache-info",
		"/nar/1ngi2dxw1f7khrrjamzkkdai393lwcm8s78gvs1ag8k3n82w7bvp.nar.zst": "application/x-nix-nar",
		"/log/abc-foo.drv": "text/plain; charset=utf-8",
	}

	for path, ct := range want {
		header, _ := proxyGet(t, ts, path, http.StatusOK)
		if got := header.Get("Content-Type"); got != ct {
			t.Errorf("GET %s: Content-Type = %q, want %q", path, got, ct)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodHead, ts.URL+path, nil)
		ok(t, err)

		resp, err := http.DefaultClient.Do(req)
		ok(t, err)

		_ = resp.Body.Close()

		if got := resp.Header.Get("Content-Type"); got != ct {
			t.Errorf("HEAD %s: Content-Type = %q, want %q", path, got, ct)
		}
	}
}
