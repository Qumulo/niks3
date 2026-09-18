package server_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/Mic92/niks3/client"
	"github.com/Mic92/niks3/server"
	"github.com/Mic92/niks3/server/signing"
)

const sampleNarinfo = `StorePath: /nix/store/26xbg1ndr7hbcncrlf9nhx5is2b25d13-hello-2.12.1
URL: nar/1ngi2dxw1f7khrrjamzkkdai393lwcm8s78gvs1ag8k3n82w7bvp.nar.xz
Compression: xz
FileHash: sha256:1ngi2dxw1f7khrrjamzkkdai393lwcm8s78gvs1ag8k3n82w7bvp
FileSize: 50088
NarHash: sha256:1mkvday29m2qxg1fnbv8xh9s6151bh8a2xzhh0k86j7lqhyfwibh
NarSize: 226560
References: 26xbg1ndr7hbcncrlf9nhx5is2b25d13-hello-2.12.1 4hcdxyjf9yiq7qf3i4548drb6sjmwa1v-glibc-2.39-52
Deriver: jwsdpq2yxw43ixalh93z726czz7bay2j-hello-2.12.1.drv
Sig: cache.nixos.org-1:AAAA
Sig: other-1:BBBB
`

func TestParseNarinfo(t *testing.T) {
	t.Parallel()

	info, err := server.ParseNarinfo([]byte(sampleNarinfo))
	ok(t, err)

	if info.StorePath != "/nix/store/26xbg1ndr7hbcncrlf9nhx5is2b25d13-hello-2.12.1" {
		t.Errorf("StorePath = %q", info.StorePath)
	}

	if info.URL != "nar/1ngi2dxw1f7khrrjamzkkdai393lwcm8s78gvs1ag8k3n82w7bvp.nar.xz" {
		t.Errorf("URL = %q", info.URL)
	}

	if info.FileSize != 50088 || info.NarSize != 226560 {
		t.Errorf("sizes = %d/%d", info.FileSize, info.NarSize)
	}

	if !reflect.DeepEqual(info.Sigs, []string{"cache.nixos.org-1:AAAA", "other-1:BBBB"}) {
		t.Errorf("Sigs = %v", info.Sigs)
	}

	// Self-reference is dropped; the NAR and the other reference remain.
	wantRefs := []string{
		"nar/1ngi2dxw1f7khrrjamzkkdai393lwcm8s78gvs1ag8k3n82w7bvp.nar.xz",
		"4hcdxyjf9yiq7qf3i4548drb6sjmwa1v.narinfo",
	}
	if got := info.RefKeys(); !reflect.DeepEqual(got, wantRefs) {
		t.Errorf("RefKeys = %v, want %v", got, wantRefs)
	}

	// The fingerprint is computed over full store paths, self-reference included.
	wantSigning := &signing.NarInfo{
		StorePath: info.StorePath,
		NarHash:   info.NarHash,
		NarSize:   info.NarSize,
		References: []string{
			"/nix/store/26xbg1ndr7hbcncrlf9nhx5is2b25d13-hello-2.12.1",
			"/nix/store/4hcdxyjf9yiq7qf3i4548drb6sjmwa1v-glibc-2.39-52",
		},
	}
	if got := info.SigningInfo(); !reflect.DeepEqual(got, wantSigning) {
		t.Errorf("SigningInfo = %+v, want %+v", got, wantSigning)
	}

	for _, bad := range []string{
		"",
		"URL: nar/x.nar\nNarHash: sha256:abc\n",
		"StorePath: /nix/store/short\nURL: nar/x.nar\nNarHash: sha256:abc\n",
		"StorePath: /nix/store/26xbg1ndr7hbcncrlf9nhx5is2b25d13-hello\nURL: nar/x.nar\nNarHash: sha256:abc\nNarSize: notanumber\n",
		"garbage line without colon\n",
	} {
		if _, err := server.ParseNarinfo([]byte(bad)); err == nil {
			t.Errorf("ParseNarinfo(%q) succeeded, want error", bad)
		}
	}
}

func TestHashMatches(t *testing.T) {
	t.Parallel()

	digest := sha256.Sum256([]byte("hello"))

	cases := map[string]bool{
		"sha256:" + client.EncodeNixBase32(digest[:]):                true,
		"sha256:" + hex.EncodeToString(digest[:]):                    true,
		"sha256:" + base64.StdEncoding.EncodeToString(digest[:]):     true,
		"sha256:" + client.EncodeNixBase32([]byte("something else")): false,
		"sha512:" + hex.EncodeToString(digest[:]):                    false,
		"nocolon": false,
	}

	for hash, want := range cases {
		if got := server.HashMatches(hash, digest[:]); got != want {
			t.Errorf("HashMatches(%q) = %v, want %v", hash, got, want)
		}
	}
}
