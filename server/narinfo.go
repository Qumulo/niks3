package server

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/Mic92/niks3/server/signing"
)

// narinfo is a parsed Nix narinfo. Only the fields the pull-through path
// needs are interpreted; the file itself is stored byte for byte so upstream
// signatures stay valid.
type narinfo struct {
	StorePath   string
	URL         string
	Compression string
	FileHash    string
	FileSize    uint64
	NarHash     string
	NarSize     uint64
	References  []string // store path basenames, without the store dir
	Sigs        []string
}

// storePathHashLen is the length of the hash part of a store path basename.
const storePathHashLen = 32

func parseNarinfo(data []byte) (*narinfo, error) {
	info := &narinfo{}

	for lineNo, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}

		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("line %d: missing ':'", lineNo+1)
		}

		value = strings.TrimSpace(value)

		var err error

		switch key {
		case "StorePath":
			info.StorePath = value
		case "URL":
			info.URL = value
		case "Compression":
			info.Compression = value
		case "FileHash":
			info.FileHash = value
		case "FileSize":
			info.FileSize, err = strconv.ParseUint(value, 10, 64)
		case "NarHash":
			info.NarHash = value
		case "NarSize":
			info.NarSize, err = strconv.ParseUint(value, 10, 64)
		case "References":
			info.References = strings.Fields(value)
		case "Sig":
			info.Sigs = append(info.Sigs, value)
		}

		if err != nil {
			return nil, fmt.Errorf("line %d: %s: %w", lineNo+1, key, err)
		}
	}

	switch {
	case info.StorePath == "":
		return nil, errors.New("missing StorePath")
	case info.URL == "":
		return nil, errors.New("missing URL")
	case info.NarHash == "":
		return nil, errors.New("missing NarHash")
	case len(path.Base(info.StorePath)) < storePathHashLen:
		return nil, fmt.Errorf("StorePath too short: %q", info.StorePath)
	}

	return info, nil
}

// hashPart returns the 32-character hash prefix of the store path.
func (n *narinfo) hashPart() string {
	return path.Base(n.StorePath)[:storePathHashLen]
}

// refKeys returns the object keys this narinfo keeps alive: its NAR and the
// narinfos of its references, excluding itself.
func (n *narinfo) refKeys() []string {
	self := n.hashPart()
	keys := []string{n.URL}

	for _, ref := range n.References {
		if len(ref) < storePathHashLen {
			continue
		}

		if hash := ref[:storePathHashLen]; hash != self {
			keys = append(keys, hash+".narinfo")
		}
	}

	return keys
}

// signingInfo converts to the form the fingerprint is computed over, with
// references as full store paths.
func (n *narinfo) signingInfo() *signing.NarInfo {
	storeDir := path.Dir(n.StorePath)

	refs := make([]string, len(n.References))
	for i, ref := range n.References {
		refs[i] = storeDir + "/" + ref
	}

	return &signing.NarInfo{
		StorePath:  n.StorePath,
		NarHash:    n.NarHash,
		NarSize:    n.NarSize,
		References: refs,
	}
}

// hashMatches reports whether a raw sha256 digest matches a Nix hash string
// such as "sha256:<nix-base32>", "sha256:<hex>" or "sha256:<base64>".
// Anything else never matches.
func hashMatches(nixHash string, digest []byte) bool {
	algo, encoded, ok := strings.Cut(nixHash, ":")
	if !ok || algo != "sha256" {
		return false
	}

	switch len(encoded) {
	case 52:
		return encoded == encodeNixBase32(digest)
	case 64:
		return strings.EqualFold(encoded, hex.EncodeToString(digest))
	case 44:
		return encoded == base64.StdEncoding.EncodeToString(digest)
	}

	return false
}

// encodeNixBase32 encodes bytes in Nix's base32 (src/libutil/base-nix-32.cc).
// Mirrors client.EncodeNixBase32; the server does not import the client.
func encodeNixBase32(input []byte) string {
	if len(input) == 0 {
		return ""
	}

	length := (len(input)*8-1)/5 + 1
	result := make([]byte, 0, length)

	for n := length - 1; n >= 0; n-- {
		b := n * 5
		i := b / 8
		j := b % 8

		var c byte
		if i < len(input) {
			c = input[i] >> j
		}

		if i+1 < len(input) {
			c |= input[i+1] << (8 - j)
		}

		result = append(result, nixBase32Alphabet[c&0x1f])
	}

	return string(result)
}
