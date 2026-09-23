package accounts

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strings"
)

// Key is one authorized public key, mirroring profile-keys.py key_info().
type Key struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
	Comment     string `json:"comment"`
}

// keyPrefixes marks the token that starts a public key, matching the
// profile-keys.py key_info() "ssh-/ecdsa-/sk-" detection.
var keyPrefixes = []string{"ssh-", "ecdsa-", "sk-"}

// addKeyPattern is the exact accepted form for an added key: one of the allowed
// algorithms followed by a space, mirroring profile-keys.py manage()'s regex.
// It deliberately rejects keys carrying options (which would not start with the
// algorithm token).
var addKeyPattern = regexp.MustCompile(`^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) `)

// KeyInfo parses one authorized_keys line into a Key, or returns ok=false when
// the line carries no recognizable key. It reproduces profile-keys.py key_info:
// the id is the SHA-256 hex of the whole line; the fingerprint is
// "SHA256:" + base64(sha256(blob)) with padding stripped.
func KeyInfo(line string) (Key, bool) {
	tokens := strings.Fields(line)
	pos := -1
	for i, t := range tokens {
		if hasKeyPrefix(t) {
			pos = i
			break
		}
	}
	if pos < 0 || pos+1 >= len(tokens) {
		return Key{}, false
	}
	blob, err := base64.StdEncoding.DecodeString(tokens[pos+1])
	if err != nil {
		return Key{}, false
	}
	sum := sha256.Sum256(blob)
	fp := "SHA256:" + strings.TrimRight(base64.StdEncoding.EncodeToString(sum[:]), "=")
	id := sha256.Sum256([]byte(line))
	return Key{
		ID:          hex.EncodeToString(id[:]),
		Type:        tokens[pos],
		Fingerprint: fp,
		Comment:     strings.Join(tokens[pos+2:], " "),
	}, true
}

func hasKeyPrefix(t string) bool {
	for _, p := range keyPrefixes {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	return false
}

// keyID is the stable identifier profile-keys.py uses for delete matching:
// the SHA-256 hex of the full line.
func keyID(line string) string {
	sum := sha256.Sum256([]byte(line))
	return hex.EncodeToString(sum[:])
}

// parseKeys extracts every recognizable key from authorized_keys text,
// preserving order, matching manage()'s list action.
func parseKeys(lines []string) []Key {
	out := []Key{}
	for _, line := range lines {
		if k, ok := KeyInfo(line); ok {
			out = append(out, k)
		}
	}
	return out
}
