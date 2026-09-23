package systemops

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
)

// secretKeys are the parameter names excluded from a fingerprint, matching the
// Python common.fingerprint exclusion set. Their values never enter the hash so
// a plan can be confirmed without the secret being pinned into the job record.
var secretKeys = map[string]bool{
	"password":        true,
	"passphrase":      true,
	"currentPassword": true,
}

// Fingerprint reproduces backend/management/common.fingerprint byte-for-byte:
// sha256 over the canonical JSON of [action, publicParams, state], where
// publicParams drops the secret keys, keys are sorted, separators are "," and
// ":", non-ASCII is escaped as \uXXXX and integers keep full precision.
//
// params and state must decode from JSON using json.Number (see Decode) so that
// large integers and the integer/boolean distinction survive; passing float64
// values risks a mismatching hash for big sizes, UIDs or timestamps.
func Fingerprint(action string, params map[string]any, state any) (string, error) {
	public := make(map[string]any, len(params))
	for k, v := range params {
		if !secretKeys[k] {
			public[k] = v
		}
	}
	var buf bytes.Buffer
	if err := canonical(&buf, []any{action, public, state}); err != nil {
		return "", err
	}
	sum := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(sum[:]), nil
}

// canonical writes v in Python's json.dumps(sort_keys=True,
// separators=(",",":")) form. It accepts the value shapes produced by
// json.Unmarshal into `any` when the decoder uses UseNumber.
func canonical(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		writeCanonicalString(buf, t)
	case json.Number:
		// A json.Number is either an integer (kept verbatim, so precision is
		// never lost) or a float we re-encode the way Python would.
		if isCanonicalInteger(t.String()) {
			// Integer wider than int64; keep the literal digits verbatim.
			n, ok := new(big.Int).SetString(t.String(), 10)
			if !ok {
				return fmt.Errorf("invalid integer")
			}
			buf.WriteString(n.String())
		} else {
			f, err := t.Float64()
			if err != nil {
				return fmt.Errorf("systemops: uncanonicalizable number %q", t.String())
			}
			if math.IsNaN(f) || math.IsInf(f, 0) {
				return fmt.Errorf("non-finite number")
			}
			scientific := strconv.FormatFloat(f, 'e', -1, 64)
			parts := strings.Split(scientific, "e")
			exponent, _ := strconv.Atoi(parts[1])
			if exponent >= -4 && exponent < 16 {
				value := strconv.FormatFloat(f, 'f', -1, 64)
				if !strings.Contains(value, ".") {
					value += ".0"
				}
				buf.WriteString(value)
			} else {
				buf.WriteString(scientific)
			}
		}
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := canonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeCanonicalString(buf, k)
			buf.WriteByte(':')
			if err := canonical(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("systemops: unsupported fingerprint value %T", v)
	}
	return nil
}

// isCanonicalInteger reports whether s is a plain (possibly signed) integer
// literal with no fraction or exponent, i.e. one Python would emit verbatim.
func isCanonicalInteger(s string) bool {
	if s == "" {
		return false
	}
	i := 0
	if s[0] == '-' {
		i = 1
		if len(s) == 1 {
			return false
		}
	}
	for ; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// writeCanonicalString emits s the way Python's json.dumps does with its
// default ensure_ascii=True: standard short escapes for the control set,
// \uXXXX (lowercase hex) for every non-ASCII rune, and no escaping of the
// HTML characters <, > and & that Go's encoding/json escapes by default.
func writeCanonicalString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		default:
			switch {
			case r < 0x20:
				fmt.Fprintf(buf, `\u%04x`, r)
			case r < 0x7f:
				buf.WriteRune(r)
			case r <= 0xffff:
				fmt.Fprintf(buf, `\u%04x`, r)
			default:
				// Python escapes astral characters as a UTF-16 surrogate pair.
				r -= 0x10000
				fmt.Fprintf(buf, `\u%04x\u%04x`, 0xd800+(r>>10), 0xdc00+(r&0x3ff))
			}
		}
	}
	buf.WriteByte('"')
}

// Decode unmarshals JSON into `any` using json.Number so integers keep full
// precision for Fingerprint. Use it wherever request params or stored state
// feed a fingerprint.
func Decode(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err != nil {
			return err
		}
		return fmt.Errorf("multiple JSON values")
	}
	return nil
}
