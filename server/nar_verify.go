package server

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"crypto/md5"  //nolint:gosec // content addresses may name md5
	"crypto/sha1" //nolint:gosec // content addresses may name sha1
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/mikelolasagasti/xz"
)

// A pulled NAR file is verified the way Nix verifies one it substitutes
// from a binary cache (Nix 2.35: BinaryCacheStore::narFromPath, then
// LocalStore::addToStore):
//
//   - the file is decompressed with exactly the method its narinfo's
//     Compression names, bzip2 when it names none, and must decompress
//     cleanly to its end; a name Nix does not know refuses the narinfo;
//   - the result must parse as a NAR, by parseDump's rules;
//   - the bytes that parse consumed must hash to NarHash and number
//     NarSize; anything decompressed after them is not looked at;
//   - with a CA, the content address must match: the NAR (fixed:r:) or
//     the contents of the single regular file it holds (fixed: and
//     text:), hashed with the CA's algorithm after every occurrence of
//     the store path's hash part is replaced with NUL bytes, followed by
//     the offset of each occurrence.
//
// FileHash and FileSize play no part, as in Nix, which only reports
// download progress with them. They are not covered by the signature
// either, and upstream may replace the file they describe: cache.nixos.org
// names NARs by NarHash and has re-uploaded some recompressed.
//
// The signature, the remaining check Nix makes, was verified when the
// narinfo was pulled.

var (
	// errNarMismatch is a NAR file Nix would refuse to substitute.
	errNarMismatch = errors.New("pulled NAR fails verification")
	// errNarUnverifiable is a NAR file this server cannot check the way
	// Nix would: a compression or content address method it does not
	// implement.
	errNarUnverifiable = errors.New("pulled NAR cannot be verified")
)

const (
	narVersionMagic = "nix-archive-1"
	narMaxDepth     = 64
	narMaxTag       = 32
	narMaxName      = 255
	narMaxTarget    = 4095

	// narVerifyBuf is the read-ahead between the decompressor and the
	// NAR parser.
	narVerifyBuf = 64 << 10

	// narZstdMaxWindow is the largest zstd window Nix decompresses with:
	// libarchive streams through libzstd at its default limit,
	// ZSTD_MAXWINDOWSIZE_DEFAULT. A single-segment frame's window is its
	// content size, so this bounds those too.
	narZstdMaxWindow = 1<<27 + 1
)

// narExpectation is what a narinfo says its NAR file must satisfy.
type narExpectation struct {
	compression string // as Nix reads it: never empty
	narHash     string
	narSize     uint64
	ca          string // empty when the path is not content-addressed
	hashPart    string // the store path's, for the content address
}

// narCompression is the method Nix decompresses a narinfo's NAR with:
// its NarInfo parser reads a missing Compression as bzip2.
func narCompression(compression string) string {
	if compression == "" {
		return "bzip2"
	}

	return compression
}

// caMethod is how a content address hashes a path's contents.
type caMethod int

const (
	caFlat caMethod = iota // the single regular file's contents
	caNar                  // the NAR
	caGit                  // a git tree hash
)

type contentAddress struct {
	method  caMethod
	newHash func() hash.Hash
	hash    string // encoded, as in the CA field
}

// parseContentAddress parses a narinfo's CA field as Nix's
// ContentAddress::parse does: text:<algo>:<hash>, which hashes like
// fixed:<algo>:<hash>, or fixed:r:<algo>:<hash> or fixed:git:<algo>:<hash>.
func parseContentAddress(ca string) (contentAddress, error) {
	prefix, rest, ok := strings.Cut(ca, ":")
	if !ok {
		return contentAddress{}, fmt.Errorf("content address %q has no prefix", ca)
	}

	method := caFlat

	switch prefix {
	case "text":
	case "fixed":
		if r, ok := strings.CutPrefix(rest, "r:"); ok {
			method, rest = caNar, r
		} else if r, ok := strings.CutPrefix(rest, "git:"); ok {
			method, rest = caGit, r
		}
	default:
		return contentAddress{}, fmt.Errorf("content address %q has an unknown prefix", ca)
	}

	algo, encoded, ok := strings.Cut(rest, ":")
	if !ok {
		return contentAddress{}, fmt.Errorf("content address %q has no hash algorithm", ca)
	}

	newHash, size, err := hashAlgorithm(algo)
	if err != nil {
		return contentAddress{}, fmt.Errorf("content address %q: %w", ca, err)
	}

	if !validEncodedDigest(encoded, size) {
		return contentAddress{}, fmt.Errorf("content address %q has a malformed hash", ca)
	}

	return contentAddress{method: method, newHash: newHash, hash: encoded}, nil
}

func hashAlgorithm(algo string) (func() hash.Hash, int, error) {
	switch algo {
	case "md5":
		return md5.New, md5.Size, nil
	case "sha1":
		return sha1.New, sha1.Size, nil
	case "sha256":
		return sha256.New, sha256.Size, nil
	case "sha512":
		return sha512.New, sha512.Size, nil
	}

	return nil, 0, fmt.Errorf("unknown hash algorithm %q", algo)
}

// unimplementedCompressions are the Compression names Nix's narinfo
// parser accepts (NIX_FOR_EACH_COMPRESSION_ALGO) beyond those in
// narDecompressors. It refuses a narinfo naming any other.
var unimplementedCompressions = []string{ //nolint:gochecknoglobals // a constant table
	"br", "compress", "grzip", "lrzip", "lz4", "lzip", "lzma", "lzop",
}

// narDecompressors are the Compression methods Nix reads NARs with that
// are implemented here, by name. Nix reads all of libarchive's filters
// and brotli; cache.nixos.org uses xz, zstd and, for its oldest paths,
// bzip2.
var narDecompressors = map[string]func(io.Reader) (io.Reader, error){ //nolint:gochecknoglobals // a constant table
	"none":  func(r io.Reader) (io.Reader, error) { return r, nil },
	"bzip2": func(r io.Reader) (io.Reader, error) { return bzip2.NewReader(r), nil },
	"gzip":  func(r io.Reader) (io.Reader, error) { return gzip.NewReader(r) },
	"xz":    func(r io.Reader) (io.Reader, error) { return xz.NewReader(r, 0) },
	"zstd": func(r io.Reader) (io.Reader, error) {
		dec, err := zstd.NewReader(r, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxWindow(narZstdMaxWindow))
		if err != nil {
			return nil, err //nolint:wrapcheck // wrapped by the caller
		}

		return dec.IOReadCloser(), nil
	},
}

// verifiable reports, before anything is fetched, whether the NAR can be
// checked the way Nix would check it, and returns its parsed content
// address (the zero value without one). An error wraps errNarUnverifiable
// when this server lacks something Nix has, and errNarMismatch when Nix
// itself would refuse the narinfo.
func (e narExpectation) verifiable() (contentAddress, error) {
	if _, ok := narDecompressors[e.compression]; !ok {
		if !slices.Contains(unimplementedCompressions, e.compression) {
			return contentAddress{}, fmt.Errorf("%w: unknown compression %q", errNarMismatch, e.compression)
		}

		return contentAddress{}, fmt.Errorf("%w: compression %q is not implemented", errNarUnverifiable, e.compression)
	}

	if e.ca == "" {
		return contentAddress{}, nil
	}

	ca, err := parseContentAddress(e.ca)
	if err != nil {
		return contentAddress{}, fmt.Errorf("%w: %w", errNarMismatch, err)
	}

	if ca.method == caGit {
		return contentAddress{}, fmt.Errorf("%w: git content addresses are not implemented", errNarUnverifiable)
	}

	return ca, nil
}

// verifyNar reads a NAR file to its end and checks it against want. The
// error wraps errNarMismatch or errNarUnverifiable.
func verifyNar(file io.Reader, want narExpectation) error {
	ca, err := want.verifiable()
	if err != nil {
		return err
	}

	dec, err := narDecompressors[want.compression](file)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", decodeVerdict(err), want.compression, err)
	}

	if c, ok := dec.(io.Closer); ok {
		defer func() { _ = c.Close() }()
	}

	buffered := bufio.NewReaderSize(dec, narVerifyBuf)
	narHash := sha256.New()
	narSize := &countingWriter{}
	sinks := []io.Writer{narHash, narSize}

	var caSum *moduloHasher
	if ca.newHash != nil {
		caSum = newModuloHasher(ca.newHash(), want.hashPart)
		if ca.method == caNar {
			sinks = append(sinks, caSum)
		}
	}

	parser := &narParser{r: io.TeeReader(buffered, io.MultiWriter(sinks...))}
	if ca.method == caFlat && caSum != nil {
		parser.rootContents = caSum
	}

	if err := parser.parse(); err != nil {
		return fmt.Errorf("%w: %w", decodeVerdict(err), err)
	}

	// Nix reads the file to its end, so a corrupt or truncated tail fails
	// it, but does not look at what decompresses after the NAR.
	if _, err := io.Copy(io.Discard, buffered); err != nil {
		return fmt.Errorf("%w: %s: %w", decodeVerdict(err), want.compression, err)
	}

	if !hashMatches(want.narHash, narHash.Sum(nil)) {
		return fmt.Errorf("%w: NAR does not match NarHash %s", errNarMismatch, want.narHash)
	}

	if narSize.n != want.narSize {
		return fmt.Errorf("%w: NAR is %d bytes, NarSize %d", errNarMismatch, narSize.n, want.narSize)
	}

	if caSum == nil {
		return nil
	}

	if ca.method == caFlat && !parser.rootRegular {
		return fmt.Errorf("%w: flat content address on a NAR that is not a single regular file", errNarMismatch)
	}

	if !encodedDigestMatches(ca.hash, caSum.sum()) {
		return fmt.Errorf("%w: contents do not match content address %s", errNarMismatch, want.ca)
	}

	return nil
}

// decodeVerdict is what a failure to read the decompressed NAR means. An
// xz dictionary over xz.DefaultDictMax (64 MiB) is one this server will not
// allocate, though Nix would (libarchive allows liblzma 1 GiB);
// cache.nixos.org uses 8 MiB. Anything else is a file Nix would refuse.
func decodeVerdict(err error) error {
	if errors.Is(err, xz.ErrMemlimit) {
		return errNarUnverifiable
	}

	return errNarMismatch
}

type countingWriter struct{ n uint64 }

func (c *countingWriter) Write(p []byte) (int, error) {
	c.n += uint64(len(p))

	return len(p), nil
}

// moduloHasher hashes what is written to it with every occurrence of
// modulus replaced by as many NUL bytes, then "|<offset>" for each
// occurrence in order, as Nix's HashModuloSink does with a store path's
// hash part. Occurrences are found left to right without overlapping,
// across writes.
type moduloHasher struct {
	h       hash.Hash
	modulus []byte
	pending []byte // the tail that may begin an occurrence
	offset  int    // of pending[0] in what was written
	matches []int  // offsets of the occurrences
}

func newModuloHasher(h hash.Hash, modulus string) *moduloHasher {
	return &moduloHasher{h: h, modulus: []byte(modulus)}
}

func (m *moduloHasher) Write(p []byte) (int, error) {
	if len(m.modulus) == 0 {
		_, _ = m.h.Write(p)

		return len(p), nil
	}

	m.pending = append(m.pending, p...)

	for i := 0; ; {
		j := bytes.Index(m.pending[i:], m.modulus)
		if j < 0 {
			break
		}

		m.matches = append(m.matches, m.offset+i+j)
		clear(m.pending[i+j : i+j+len(m.modulus)])
		i += j + len(m.modulus)
	}

	if keep := len(m.modulus) - 1; len(m.pending) > keep {
		cut := len(m.pending) - keep
		_, _ = m.h.Write(m.pending[:cut])
		m.pending = append(m.pending[:0], m.pending[cut:]...)
		m.offset += cut
	}

	return len(p), nil
}

func (m *moduloHasher) sum() []byte {
	_, _ = m.h.Write(m.pending)
	m.pending = nil

	for _, pos := range m.matches {
		_, _ = m.h.Write(strconv.AppendInt([]byte{'|'}, int64(pos), 10))
	}

	return m.h.Sum(nil)
}

// narParser checks that a stream is a NAR, with the rules of Nix's
// parseDump. It reads exactly the NAR and nothing after it.
type narParser struct {
	r   io.Reader
	num [8]byte
	// rootContents, when set, receives the contents of the root if it is
	// a regular file, and rootRegular records that it was one.
	rootContents io.Writer
	rootRegular  bool
}

func (p *narParser) parse() error {
	// Nix reads the magic as a string of at most its own length and
	// reports anything else, too long included, as not a NAR.
	version, err := p.str(uint64(len(narVersionMagic)))
	if err != nil || version != narVersionMagic {
		return errors.New("input doesn't look like a Nix archive")
	}

	return p.node(0)
}

func (p *narParser) uint64() (uint64, error) {
	if _, err := io.ReadFull(p.r, p.num[:]); err != nil {
		return 0, unexpectedEOF(err)
	}

	return binary.LittleEndian.Uint64(p.num[:]), nil
}

func (p *narParser) padding(n uint64) error {
	if n%8 == 0 {
		return nil
	}

	pad := p.num[:8-n%8]
	if _, err := io.ReadFull(p.r, pad); err != nil {
		return unexpectedEOF(err)
	}

	for _, b := range pad {
		if b != 0 {
			return errors.New("non-zero padding")
		}
	}

	return nil
}

func (p *narParser) str(maxLen uint64) (string, error) {
	n, err := p.uint64()
	if err != nil {
		return "", err
	}

	if n > maxLen {
		return "", errors.New("string is too long")
	}

	buf := make([]byte, n)
	if _, err := io.ReadFull(p.r, buf); err != nil {
		return "", unexpectedEOF(err)
	}

	return string(buf), p.padding(n)
}

func (p *narParser) expect(tag string) error {
	got, err := p.str(narMaxTag)
	if err != nil {
		return err
	}

	if got != tag {
		return fmt.Errorf("expected tag '%s', got '%s'", tag, got)
	}

	return nil
}

func (p *narParser) node(depth int) error {
	if depth >= narMaxDepth {
		return fmt.Errorf("NAR directory nesting exceeds maximum depth of %d", narMaxDepth)
	}

	if err := p.expect("("); err != nil {
		return err
	}

	if err := p.expect("type"); err != nil {
		return err
	}

	typ, err := p.str(narMaxTag)
	if err != nil {
		return err
	}

	switch typ {
	case "regular":
		return p.regular(depth)
	case "directory":
		return p.directory(depth)
	case "symlink":
		return p.symlink()
	}

	return fmt.Errorf("unknown file type '%s'", typ)
}

func (p *narParser) regular(depth int) error {
	tag, err := p.str(narMaxTag)
	if err != nil {
		return err
	}

	if tag == "executable" {
		marker, err := p.str(0)
		if err != nil {
			return err
		}

		if marker != "" {
			return errors.New("executable marker has non-empty value")
		}

		if tag, err = p.str(narMaxTag); err != nil {
			return err
		}
	}

	if tag != "contents" {
		return fmt.Errorf("expected tag 'contents', got '%s'", tag)
	}

	size, err := p.uint64()
	if err != nil {
		return err
	}

	sink := io.Discard
	if depth == 0 && p.rootContents != nil {
		sink = p.rootContents
		p.rootRegular = true
	}

	if size > math.MaxInt64 {
		// More than any stream can hold: Nix would run out of input.
		return io.ErrUnexpectedEOF
	}

	if _, err := io.CopyN(sink, p.r, int64(size)); err != nil {
		return unexpectedEOF(err)
	}

	if err := p.padding(size); err != nil {
		return err
	}

	return p.expect(")")
}

func (p *narParser) directory(depth int) error {
	prev := ""

	for {
		tag, err := p.str(narMaxTag)
		if err != nil {
			return err
		}

		if tag == ")" {
			return nil
		}

		if tag != "entry" {
			return fmt.Errorf("expected tag 'entry' or ')', got '%s'", tag)
		}

		if err := p.expect("("); err != nil {
			return err
		}

		if err := p.expect("name"); err != nil {
			return err
		}

		name, err := p.str(narMaxName)
		if err != nil {
			return err
		}

		if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
			return fmt.Errorf("NAR contains invalid file name '%s'", name)
		}

		if name <= prev {
			return errors.New("NAR directory is not sorted")
		}

		prev = name

		if err := p.expect("node"); err != nil {
			return err
		}

		if err := p.node(depth + 1); err != nil {
			return err
		}

		if err := p.expect(")"); err != nil {
			return err
		}
	}
}

func (p *narParser) symlink() error {
	if err := p.expect("target"); err != nil {
		return err
	}

	target, err := p.str(narMaxTarget)
	if err != nil {
		return err
	}

	if target == "" || strings.Contains(target, "\x00") {
		return errors.New("NAR contains invalid symlink target")
	}

	return p.expect(")")
}

func unexpectedEOF(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}

	return err
}

// narVerifier checks a NAR file as it is written, so a fill can verify
// what it streams without holding it. Writes block until the check has
// taken them; the check keeps reading to the end whatever it finds, so
// they never block for good.
type narVerifier struct {
	pw   *io.PipeWriter
	done chan error
}

func newNarVerifier(want narExpectation) *narVerifier {
	pr, pw := io.Pipe()
	v := &narVerifier{pw: pw, done: make(chan error, 1)}

	go func() {
		err := verifyNar(pr, want)
		// A check that failed early has stopped reading; drain the rest so
		// the writer is not stuck.
		_, _ = io.Copy(io.Discard, pr)
		v.done <- err
	}()

	return v
}

func (v *narVerifier) Write(p []byte) (int, error) {
	n, err := v.pw.Write(p)
	if err != nil {
		return n, fmt.Errorf("NAR verifier: %w", err)
	}

	return n, nil
}

// finish ends the file and returns the verdict.
func (v *narVerifier) finish() error {
	_ = v.pw.Close()

	return <-v.done
}
