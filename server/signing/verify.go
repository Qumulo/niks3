package signing

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// PublicKey is a Nix binary cache public key in the "name:base64" form used
// by nix.conf's trusted-public-keys.
type PublicKey struct {
	Name string
	key  ed25519.PublicKey
}

// ParsePublicKey parses "name:base64-public-key".
func ParsePublicKey(s string) (*PublicKey, error) {
	name, keyBase64, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok || name == "" || keyBase64 == "" {
		return nil, errors.New("public key must have the form name:base64-key")
	}

	keyBytes, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return nil, fmt.Errorf("decoding public key %q: %w", name, err)
	}

	if len(keyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key %q: expected %d bytes, got %d", name, ed25519.PublicKeySize, len(keyBytes))
	}

	return &PublicKey{Name: name, key: ed25519.PublicKey(keyBytes)}, nil
}

// String returns the key in "name:base64-key" form.
func (k *PublicKey) String() string {
	return k.Name + ":" + base64.StdEncoding.EncodeToString(k.key)
}

// VerifyNarinfo returns the first of signatures ("name:base64") that was
// made over info's fingerprint by one of keys, or "" when none was.
// Signatures that name an unknown key or fail to decode are ignored,
// matching Nix's behaviour of accepting a narinfo as soon as any trusted
// signature checks out.
func VerifyNarinfo(keys []*PublicKey, info *NarInfo, signatures []string) (string, error) {
	fingerprint, err := GenerateFingerprint(info)
	if err != nil {
		return "", err
	}

	for _, sig := range signatures {
		name, sigBase64, ok := strings.Cut(sig, ":")
		if !ok {
			continue
		}

		sigBytes, err := base64.StdEncoding.DecodeString(sigBase64)
		if err != nil || len(sigBytes) != ed25519.SignatureSize {
			continue
		}

		for _, key := range keys {
			if key.Name == name && ed25519.Verify(key.key, fingerprint, sigBytes) {
				return sig, nil
			}
		}
	}

	return "", nil
}
