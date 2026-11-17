package server_test

import (
	"bytes"
	"compress/gzip"
	"crypto/sha1" //nolint:gosec // content addresses may name sha1
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Mic92/niks3/client"
	"github.com/Mic92/niks3/server"
	"github.com/klauspost/compress/zstd"
)

// narOf serialises NAR tokens. Every NAR field, file contents included, is
// a length-prefixed string padded to 8 bytes, so a NAR is just its tokens.
func narOf(tokens ...string) []byte {
	var b bytes.Buffer

	for _, t := range tokens {
		_ = binary.Write(&b, binary.LittleEndian, uint64(len(t)))
		b.WriteString(t)
		b.Write(make([]byte, (8-len(t)%8)%8))
	}

	return b.Bytes()
}

func narFile(contents string) []byte {
	return narOf("nix-archive-1", "(", "type", "regular", "contents", contents, ")")
}

// helloNar is narFile("hello\n"); the bzip2 and xz fixtures below are it,
// compressed by Python's bz2 and lzma (xz, CRC64 check).
func helloNar() []byte { return narFile("hello\n") }

const (
	helloBzip2 = "QlpoOTFBWSZTWRadevYAAB/ZgG3SAGIgACrl32AgAFRENTI0xNDANNCNKZDZJpoB5Q0VWcSSU1VKGAWRkATGAVHuJoCttWOV/doP6mDxLS3MgI8mQM7aCtGHGxdyRThQkBadevY="
	helloXz    = "/Td6WFoAAATm1rRGAgAhARYAAAB0L+Wj4AB3AEJdAAaANh/vps6/droaek8r6qRTJO2hIwRx/1u/l2m68ym+JEmkcF2PMAtHKBMzvRezszyuOH2U7Eam+xwfZuTYKgHJfAAAAFclbGgP86qfAAFeeP88YFoftvN9AQAAAAAEWVo="
	// helloXzBigDict is helloNar as xz with a 128 MiB dictionary.
	helloXzBigDict = "/Td6WFoAAATm1rRGAgAhAR4AAACbB1Fm4AB3AEJdAAaANh/vps6/droaek8r6qRTJO2hIwRx/1u/l2m68ym+JEmkcF2PMAtHKBMzvRezszyuOH2U7Eam+xwfZuTYKgHJfAAAAFclbGgP86qfAAFeeP88YFoftvN9AQAAAAAEWVo="
)

func b64(tb testing.TB, s string) []byte {
	tb.Helper()

	data, err := base64.StdEncoding.DecodeString(s)
	ok(tb, err)

	return data
}

func zstdOf(tb testing.TB, data []byte) []byte {
	tb.Helper()

	enc, err := zstd.NewWriter(nil)
	ok(tb, err)

	return enc.EncodeAll(data, nil)
}

func gzipOf(tb testing.TB, data []byte) []byte {
	tb.Helper()

	var b bytes.Buffer

	w := gzip.NewWriter(&b)
	_, err := w.Write(data)
	ok(tb, err)
	ok(tb, w.Close())

	return b.Bytes()
}

func nix32(digest []byte) string { return client.EncodeNixBase32(digest) }

func sha256Of(data []byte) []byte {
	d := sha256.Sum256(data)

	return d[:]
}

// expectFor is what a narinfo for nar would say, uncompressed.
func expectFor(nar []byte) server.NarExpectation {
	return server.NarExpectation{
		Compression: "none",
		NarHash:     "sha256:" + nix32(sha256Of(nar)),
		NarSize:     uint64(len(nar)),
		HashPart:    "26xbg1ndr7hbcncrlf9nhx5is2b25d13",
	}
}

type verdict int

const (
	accept verdict = iota
	mismatch
	unverifiable
)

func checkVerdict(t *testing.T, err error, want verdict) {
	t.Helper()

	switch want {
	case accept:
		if err != nil {
			t.Fatalf("rejected: %v", err)
		}
	case mismatch:
		if !errors.Is(err, server.ErrNarMismatch) {
			t.Fatalf("got %v, want a mismatch", err)
		}
	case unverifiable:
		if !errors.Is(err, server.ErrNarUnverifiable) {
			t.Fatalf("got %v, want unverifiable", err)
		}
	}
}

func TestVerifyNarStructure(t *testing.T) {
	t.Parallel()

	nonZeroPadding := narFile("hello\n")
	nonZeroPadding[len(nonZeroPadding)-17] = 1 // padding after "hello\n"

	deep := make([]string, 0, 1+64*8+6+64*2)
	deep = append(deep, "nix-archive-1")
	for range 64 {
		deep = append(deep, "(", "type", "directory", "entry", "(", "name", "d", "node")
	}

	deep = append(deep, "(", "type", "regular", "contents", "", ")")

	for range 64 {
		deep = append(deep, ")", ")")
	}

	for _, tc := range []struct {
		name string
		nar  []byte
		want verdict
	}{
		{"regular", narFile("hello\n"), accept},
		{"empty file", narFile(""), accept},
		{"executable", narOf("nix-archive-1", "(", "type", "regular", "executable", "", "contents", "#!/bin/sh\n", ")"), accept},
		{"symlink", narOf("nix-archive-1", "(", "type", "symlink", "target", "/nix/store/x", ")"), accept},
		{"directory", narOf("nix-archive-1", "(", "type", "directory",
			"entry", "(", "name", "a", "node", "(", "type", "regular", "contents", "1", ")", ")",
			"entry", "(", "name", "b", "node", "(", "type", "symlink", "target", "a", ")", ")",
			")"), accept},
		{"empty directory", narOf("nix-archive-1", "(", "type", "directory", ")"), accept},
		{"bad magic", narOf("nix-archive-2", "(", "type", "regular", "contents", "", ")"), mismatch},
		{"unsorted directory", narOf("nix-archive-1", "(", "type", "directory",
			"entry", "(", "name", "b", "node", "(", "type", "regular", "contents", "", ")", ")",
			"entry", "(", "name", "a", "node", "(", "type", "regular", "contents", "", ")", ")",
			")"), mismatch},
		{"duplicate entry", narOf("nix-archive-1", "(", "type", "directory",
			"entry", "(", "name", "a", "node", "(", "type", "regular", "contents", "", ")", ")",
			"entry", "(", "name", "a", "node", "(", "type", "regular", "contents", "", ")", ")",
			")"), mismatch},
		{"dot name", narOf("nix-archive-1", "(", "type", "directory",
			"entry", "(", "name", "..", "node", "(", "type", "regular", "contents", "", ")", ")", ")"), mismatch},
		{"slash in name", narOf("nix-archive-1", "(", "type", "directory",
			"entry", "(", "name", "a/b", "node", "(", "type", "regular", "contents", "", ")", ")", ")"), mismatch},
		{"name too long", narOf("nix-archive-1", "(", "type", "directory",
			"entry", "(", "name", strings.Repeat("a", 256), "node", "(", "type", "regular", "contents", "", ")", ")", ")"), mismatch},
		{"empty symlink", narOf("nix-archive-1", "(", "type", "symlink", "target", "", ")"), mismatch},
		{"executable marker with a value", narOf("nix-archive-1", "(", "type", "regular", "executable", "x", "contents", "", ")"), mismatch},
		{"unknown type", narOf("nix-archive-1", "(", "type", "fifo", ")"), mismatch},
		{"non-zero padding", nonZeroPadding, mismatch},
		{"truncated", narFile("hello\n")[:50], mismatch},
		{"too deep", narOf(deep...), mismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			checkVerdict(t, server.VerifyNar(bytes.NewReader(tc.nar), expectFor(tc.nar)), tc.want)
		})
	}
}

func TestVerifyNarHashAndSize(t *testing.T) {
	t.Parallel()

	nar := helloNar()

	wrongHash := expectFor(nar)
	wrongHash.NarHash = "sha256:" + nix32(sha256Of([]byte("other")))
	checkVerdict(t, server.VerifyNar(bytes.NewReader(nar), wrongHash), mismatch)

	wrongSize := expectFor(nar)
	wrongSize.NarSize++
	checkVerdict(t, server.VerifyNar(bytes.NewReader(nar), wrongSize), mismatch)

	for _, encoded := range []string{
		"sha256:" + hex.EncodeToString(sha256Of(nar)),
		"sha256:" + base64.StdEncoding.EncodeToString(sha256Of(nar)),
		"sha256-" + base64.StdEncoding.EncodeToString(sha256Of(nar)),
	} {
		want := expectFor(nar)
		want.NarHash = encoded
		checkVerdict(t, server.VerifyNar(bytes.NewReader(nar), want), accept)
	}

	// Nix stops at the end of the NAR: what decompresses after it is
	// neither hashed nor counted.
	trailing := append(append([]byte{}, nar...), "TRAILINGJUNK"...)
	checkVerdict(t, server.VerifyNar(bytes.NewReader(trailing), expectFor(nar)), accept)
	checkVerdict(t, server.VerifyNar(bytes.NewReader(zstdOf(t, trailing)), withCompression(expectFor(nar), "zstd")), accept)
}

func withCompression(e server.NarExpectation, compression string) server.NarExpectation {
	e.Compression = compression

	return e
}

func TestVerifyNarCompression(t *testing.T) {
	t.Parallel()

	nar := helloNar()
	want := expectFor(nar)
	zst := zstdOf(t, nar)
	xz := b64(t, helloXz)

	for _, tc := range []struct {
		name        string
		compression string
		file        []byte
		want        verdict
	}{
		{"none", "none", nar, accept},
		{"identity is not a compression", "identity", nar, mismatch},
		{"zstd", "zstd", zst, accept},
		{"xz", "xz", xz, accept},
		{"bzip2", "bzip2", b64(t, helloBzip2), accept},
		{"no Compression means bzip2", "", b64(t, helloBzip2), accept},
		{"no Compression is not none", "", nar, mismatch},
		{"gzip", "gzip", gzipOf(t, nar), accept},
		{"named xz but zstd", "xz", zst, mismatch},
		{"named none but zstd", "none", zst, mismatch},
		{"junk after zstd", "zstd", append(append([]byte{}, zst...), "JUNKJUNK"...), mismatch},
		{"junk after xz", "xz", append(append([]byte{}, xz...), "JUNKJUNK"...), mismatch},
		{"truncated zstd", "zstd", zst[:len(zst)-4], mismatch},
		{"truncated xz", "xz", xz[:len(xz)-12], mismatch},
		{"xz dictionary over 64 MiB", "xz", b64(t, helloXzBigDict), unverifiable},
		{"brotli", "br", nar, unverifiable},
		{"lz4", "lz4", nar, unverifiable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			checkVerdict(t, server.VerifyNar(bytes.NewReader(tc.file), withCompression(want, tc.compression)), tc.want)
		})
	}
}

// moduloOf is what Nix 2.35's HashModuloSink hashes for data: every
// occurrence of hashPart replaced with NUL bytes, then "|<offset>" for
// each occurrence.
func moduloOf(data []byte, hashPart string) []byte {
	out := bytes.ReplaceAll(data, []byte(hashPart), make([]byte, len(hashPart)))

	for i := 0; ; {
		j := bytes.Index(data[i:], []byte(hashPart))
		if j < 0 {
			return out
		}

		out = fmt.Appendf(out, "|%d", i+j)
		i += j + len(hashPart)
	}
}

// zstdWithWindow is data as one zstd frame whose header announces the
// window described by desc (exponent<<3 | mantissa, for a window of
// 2^(10+exponent) plus mantissa eighths of that), without a content size.
func zstdWithWindow(tb testing.TB, data []byte, desc byte) []byte {
	tb.Helper()

	frame := zstdOf(tb, data)
	fhd := frame[4]
	single := fhd&0x20 != 0
	fcsSize := map[byte]int{0: 0, 1: 2, 2: 4, 3: 8}[fhd>>6]

	if fhd>>6 == 0 && single {
		fcsSize = 1
	}

	header := 5 + fcsSize + map[byte]int{0: 0, 1: 1, 2: 2, 3: 4}[fhd&3]
	if !single {
		header++
	}

	// Keep only the checksum flag: multi-segment, no dictionary, no
	// content size.
	out := append([]byte{}, frame[:4]...)
	out = append(out, fhd&0x04, desc)

	return append(out, frame[header:]...)
}

// Nix decompresses zstd through libarchive and libzstd, which refuses a
// window larger than 2^27 (plus one byte) unless told otherwise.
func TestVerifyNarZstdWindow(t *testing.T) {
	t.Parallel()

	nar := helloNar()
	want := withCompression(expectFor(nar), "zstd")

	checkVerdict(t, server.VerifyNar(bytes.NewReader(zstdWithWindow(t, nar, 17<<3)), want), accept)
	checkVerdict(t, server.VerifyNar(bytes.NewReader(zstdWithWindow(t, nar, 17<<3|1)), want), mismatch)
}

// A content-addressed path that refers to itself, as Nix 2.35.5 made it:
// a runCommand writing "$out and again $out" to $out/f and "$out" to
// $out/g, rewritten by `nix store make-content-addressed`.
const (
	selfRefNarB64   = "DQAAAAAAAABuaXgtYXJjaGl2ZS0xAAAAAQAAAAAAAAAoAAAAAAAAAAQAAAAAAAAAdHlwZQAAAAAJAAAAAAAAAGRpcmVjdG9yeQAAAAAAAAAFAAAAAAAAAGVudHJ5AAAAAQAAAAAAAAAoAAAAAAAAAAQAAAAAAAAAbmFtZQAAAAABAAAAAAAAAGYAAAAAAAAABAAAAAAAAABub2RlAAAAAAEAAAAAAAAAKAAAAAAAAAAEAAAAAAAAAHR5cGUAAAAABwAAAAAAAAByZWd1bGFyAAgAAAAAAAAAY29udGVudHNyAAAAAAAAAC9uaXgvc3RvcmUvZDlqYmc4eDNqbTB4bXZzd3A4Nm01YmhmbGI2MjBoMDctc2VsZnJlZiBhbmQgYWdhaW4gL25peC9zdG9yZS9kOWpiZzh4M2ptMHhtdnN3cDg2bTViaGZsYjYyMGgwNy1zZWxmcmVmCgAAAAAAAAEAAAAAAAAAKQAAAAAAAAABAAAAAAAAACkAAAAAAAAABQAAAAAAAABlbnRyeQAAAAEAAAAAAAAAKAAAAAAAAAAEAAAAAAAAAG5hbWUAAAAAAQAAAAAAAABnAAAAAAAAAAQAAAAAAAAAbm9kZQAAAAABAAAAAAAAACgAAAAAAAAABAAAAAAAAAB0eXBlAAAAAAcAAAAAAAAAcmVndWxhcgAIAAAAAAAAAGNvbnRlbnRzNAAAAAAAAAAvbml4L3N0b3JlL2Q5amJnOHgzam0weG12c3dwODZtNWJoZmxiNjIwaDA3LXNlbGZyZWYKAAAAAAEAAAAAAAAAKQAAAAAAAAABAAAAAAAAACkAAAAAAAAAAQAAAAAAAAApAAAAAAAAAA=="
	selfRefHashPart = "d9jbg8x3jm0xmvswp86m5bhflb620h07"
	selfRefNarHash  = "sha256-kl0BqJOEwPcsEsNnoCBdKNky0etdI4s8hCr6tA5l9rA="
	selfRefCA       = "fixed:r:sha256:1k69a50cxxzj56l8yy3fk4n71l7m5irjmsjq39k7ba2mqhi3yn8x"
)

func TestVerifyNarSelfReferenceFromNix(t *testing.T) {
	t.Parallel()

	nar := b64(t, selfRefNarB64)
	want := server.NarExpectation{
		Compression: "none",
		NarHash:     selfRefNarHash,
		NarSize:     uint64(len(nar)),
		CA:          selfRefCA,
		HashPart:    selfRefHashPart,
	}
	checkVerdict(t, server.VerifyNar(bytes.NewReader(nar), want), accept)
}

func TestVerifyNarContentAddress(t *testing.T) {
	t.Parallel()

	const hashPart = "26xbg1ndr7hbcncrlf9nhx5is2b25d13"

	plain := "some contents\n"
	file := narFile(plain)
	dir := narOf("nix-archive-1", "(", "type", "directory", ")")

	// The hash part straddles the 32 KiB reads the contents are copied in,
	// so the modulo has to carry across writes.
	selfRef := strings.Repeat("a", 32760) + hashPart + " and again " + hashPart + "\n"
	selfRefNar := narFile(selfRef)
	zeroedNar := narFile(strings.ReplaceAll(selfRef, hashPart, strings.Repeat("\x00", len(hashPart))))

	sha1Of := func(data []byte) []byte {
		d := sha1.Sum(data) //nolint:gosec // testing sha1 content addresses

		return d[:]
	}

	for _, tc := range []struct {
		name string
		nar  []byte
		ca   string
		want verdict
	}{
		{"nar", file, "fixed:r:sha256:" + nix32(sha256Of(file)), accept},
		{"nar wrong", file, "fixed:r:sha256:" + nix32(sha256Of(dir)), mismatch},
		{"nar of a directory", dir, "fixed:r:sha256:" + nix32(sha256Of(dir)), accept},
		{"nar sha1 hex", file, "fixed:r:sha1:" + hex.EncodeToString(sha1Of(file)), accept},
		{"flat", file, "fixed:sha256:" + nix32(sha256Of([]byte(plain))), accept},
		{"flat wrong", file, "fixed:sha256:" + nix32(sha256Of(file)), mismatch},
		{"flat of a directory", dir, "fixed:sha256:" + nix32(sha256Of(nil)), mismatch},
		{"text", file, "text:sha256:" + nix32(sha256Of([]byte(plain))), accept},
		{"nar modulo self-reference", selfRefNar, "fixed:r:sha256:" + nix32(sha256Of(moduloOf(selfRefNar, hashPart))), accept},
		{"nar without the modulo", selfRefNar, "fixed:r:sha256:" + nix32(sha256Of(selfRefNar)), mismatch},
		{"nar modulo without the offsets", selfRefNar, "fixed:r:sha256:" + nix32(sha256Of(zeroedNar)), mismatch},
		{"flat modulo self-reference", selfRefNar, "fixed:sha256:" + nix32(sha256Of(moduloOf([]byte(selfRef), hashPart))), accept},
		{"git", file, "fixed:git:sha1:" + hex.EncodeToString(sha1Of(file)), unverifiable},
		{"unknown prefix", file, "floating:sha256:" + nix32(sha256Of(file)), mismatch},
		{"unknown algorithm", file, "fixed:r:sha3:" + nix32(sha256Of(file)), mismatch},
		{"malformed hash", file, "fixed:r:sha256:abc", mismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			want := expectFor(tc.nar)
			want.CA = tc.ca
			want.HashPart = hashPart
			checkVerdict(t, server.VerifyNar(bytes.NewReader(tc.nar), want), tc.want)
		})
	}
}

// The fill feeds the verifier as the body arrives; a check that fails
// early must keep taking writes, and the verdict must not depend on how
// the file was cut up.
func TestVerifyNarStreaming(t *testing.T) {
	t.Parallel()

	contents := strings.Repeat("0123456789abcdef", 1<<16)
	nar := narFile(contents)
	file := zstdOf(t, nar)
	want := withCompression(expectFor(nar), "zstd")

	for _, chunk := range []int{1, 7, 4096, len(file)} {
		checkVerdict(t, server.VerifyNarStreaming(file, chunk, want), accept)
	}

	garbage := bytes.Repeat([]byte{0xff}, 1<<20)
	checkVerdict(t, server.VerifyNarStreaming(garbage, 4096, want), mismatch)

	wrong := want
	wrong.NarSize--
	checkVerdict(t, server.VerifyNarStreaming(file, 4096, wrong), mismatch)
}
