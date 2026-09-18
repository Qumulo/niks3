package cmdutil_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Mic92/niks3/cmdutil"
)

// TestResolveTokenSourceEnvScript checks NIKS3_AUTH_TOKEN_SCRIPT: it beats
// NIKS3_AUTH_TOKEN_FILE, and any explicit flag beats it.
func TestResolveTokenSourceEnvScript(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")

	if err := os.WriteFile(tokenFile, []byte("file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("XDG_CONFIG_HOME", dir) // keep the XDG default from resolving
	t.Setenv("NIKS3_AUTH_TOKEN_FILE", tokenFile)
	t.Setenv("NIKS3_AUTH_TOKEN_SCRIPT", `echo '{"token":"script-token","expires_at":"2999-01-01T00:00:00Z"}'`)

	tests := []struct {
		name      string
		flagPath  string
		flagToken string
		want      string
	}{
		{name: "env script beats env file", want: "script-token"},
		{name: "flag path beats env script", flagPath: tokenFile, want: "file-token"},
		{name: "flag token beats env script", flagToken: "literal", want: "literal"},
	}

	// Sequential on purpose: the cases share the process environment set
	// above, so they cannot run as parallel subtests.
	for _, tc := range tests {
		src, err := cmdutil.ResolveTokenSource(tc.flagToken, tc.flagPath, "", false)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}

		got, err := src(context.Background())
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}

		if got != tc.want {
			t.Errorf("%s: got token %q, want %q", tc.name, got, tc.want)
		}
	}
}
