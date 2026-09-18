package signing_test

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/Mic92/niks3/server/signing"
)

func newTestKey(t *testing.T, name string) *signing.Key {
	t.Helper()

	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}

	key, err := signing.ParseKey(name + ":" + base64.StdEncoding.EncodeToString(seed))
	if err != nil {
		t.Fatal(err)
	}

	return key
}

func TestVerifyNarinfo(t *testing.T) {
	t.Parallel()

	info := &signing.NarInfo{
		StorePath:  "/nix/store/26xbg1ndr7hbcncrlf9nhx5is2b25d13-hello-2.12.1",
		NarHash:    "sha256:1mkvday29m2qxg1fnbv8xh9s6151bh8a2xzhh0k86j7lqhyfwibh",
		NarSize:    226560,
		References: []string{"/nix/store/4hcdxyjf9yiq7qf3i4548drb6sjmwa1v-glibc-2.39"},
	}

	signer := newTestKey(t, "cache.example.org-1")
	other := newTestKey(t, "other-1")

	sigs, err := signing.SignNarinfo([]*signing.Key{signer}, info)
	if err != nil {
		t.Fatal(err)
	}

	pubOf := func(k *signing.Key) *signing.PublicKey {
		s, err := k.PublicKey()
		if err != nil {
			t.Fatal(err)
		}

		pub, err := signing.ParsePublicKey(s)
		if err != nil {
			t.Fatal(err)
		}

		return pub
	}

	tests := []struct {
		name string
		keys []*signing.PublicKey
		sigs []string
		info *signing.NarInfo
		want string
	}{
		{"matching key", []*signing.PublicKey{pubOf(signer)}, sigs, info, sigs[0]},
		{"matching key among several", []*signing.PublicKey{pubOf(other), pubOf(signer)}, sigs, info, sigs[0]},
		{"matching signature among several", []*signing.PublicKey{pubOf(signer)}, []string{"other-1:" + sigs[0][len("cache.example.org-1:"):], sigs[0]}, info, sigs[0]},
		{"wrong key", []*signing.PublicKey{pubOf(other)}, sigs, info, ""},
		{"no signatures", []*signing.PublicKey{pubOf(signer)}, nil, info, ""},
		{"garbage signature ignored", []*signing.PublicKey{pubOf(signer)}, []string{"cache.example.org-1:!!!", "nocolon"}, info, ""},
		{
			"tampered NarSize",
			[]*signing.PublicKey{pubOf(signer)},
			sigs,
			&signing.NarInfo{StorePath: info.StorePath, NarHash: info.NarHash, NarSize: 1, References: info.References}, "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := signing.VerifyNarinfo(tt.keys, tt.info, tt.sigs)
			if err != nil {
				t.Fatal(err)
			}

			if got != tt.want {
				t.Errorf("VerifyNarinfo = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParsePublicKey(t *testing.T) {
	t.Parallel()

	pubStr, err := newTestKey(t, "k").PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	pub, err := signing.ParsePublicKey(pubStr)
	if err != nil {
		t.Fatal(err)
	}

	if pub.String() != pubStr {
		t.Errorf("round trip: got %q, want %q", pub.String(), pubStr)
	}

	for _, bad := range []string{"", "nocolon", ":abc", "k:", "k:notbase64!", "k:" + base64.StdEncoding.EncodeToString([]byte("short"))} {
		if _, err := signing.ParsePublicKey(bad); err == nil {
			t.Errorf("ParsePublicKey(%q) succeeded, want error", bad)
		}
	}
}
