package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ContentDigestSHA256 builds an RFC 9530 Content-Digest for sha-256.
func ContentDigestSHA256(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

// SignRequest adds Content-Digest (when body present) and RFC 9421–style
// Signature-Input / Signature headers using HMAC-SHA256.
func SignRequest(req *http.Request, keyID string, secret []byte, body []byte, now time.Time) error {
	if keyID == "" || len(secret) == 0 {
		return fmt.Errorf("keyid and secret are required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	created := now.Unix()
	components := []string{`"@method"`, `"@path"`}
	lines := []string{
		`"@method": ` + req.Method,
		`"@path": ` + req.URL.EscapedPath(),
	}
	if len(body) > 0 {
		digest := ContentDigestSHA256(body)
		req.Header.Set("Content-Digest", digest)
		components = append(components, `"content-digest"`)
		lines = append(lines, `"content-digest": `+digest)
	}
	if ct := req.Header.Get("Content-Type"); ct != "" {
		components = append(components, `"content-type"`)
		lines = append(lines, `"content-type": `+ct)
	}
	params := fmt.Sprintf("(%s);created=%d;keyid=%q;alg=\"hmac-sha256\"",
		strings.Join(components, " "), created, keyID)
	lines = append(lines, `"@signature-params": `+params)
	base := strings.Join(lines, "\n")
	mac := hmac.New(sha256.New, secret)
	_, _ = io.WriteString(mac, base)
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	req.Header.Set("Signature-Input", "sig1="+params)
	req.Header.Set("Signature", "sig1=:"+sig+":")
	return nil
}

type signatureParams struct {
	Components []string
	Created    int64
	Expires    int64
	KeyID      string
	Alg        string
	// Raw is the full Inner List + parameters as sent (for @signature-params).
	Raw string
}

func parseSignatureInput(header string) (signatureParams, error) {
	// Expect: sig1=("@method" "@path" ...);created=...;keyid="...";alg="hmac-sha256"
	header = strings.TrimSpace(header)
	_, rest, ok := strings.Cut(header, "=")
	if !ok {
		return signatureParams{}, fmt.Errorf("missing signature label")
	}
	rest = strings.TrimSpace(rest)
	if !strings.HasPrefix(rest, "(") {
		return signatureParams{}, fmt.Errorf("missing component list")
	}
	end := strings.Index(rest, ")")
	if end < 0 {
		return signatureParams{}, fmt.Errorf("unterminated component list")
	}
	list := rest[1:end]
	var sp signatureParams
	sp.Raw = rest // keep exact bytes for signature base
	sp.Alg = "hmac-sha256"
	for _, part := range strings.Fields(list) {
		part = strings.Trim(part, `"`)
		if part != "" {
			sp.Components = append(sp.Components, part)
		}
	}
	paramsTail := strings.TrimPrefix(rest[end+1:], ";")
	for _, part := range strings.Split(paramsTail, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"`)
		switch k {
		case "created":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return sp, fmt.Errorf("created: %w", err)
			}
			sp.Created = n
		case "expires":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return sp, fmt.Errorf("expires: %w", err)
			}
			sp.Expires = n
		case "keyid":
			sp.KeyID = v
		case "alg":
			sp.Alg = v
		}
	}
	if sp.KeyID == "" || sp.Created == 0 || len(sp.Components) == 0 {
		return sp, fmt.Errorf("incomplete signature params")
	}
	return sp, nil
}

func parseSignatureValue(header string) (string, error) {
	// Expect: sig1=:BASE64:
	header = strings.TrimSpace(header)
	_, rest, ok := strings.Cut(header, "=")
	if !ok {
		return "", fmt.Errorf("missing signature label")
	}
	rest = strings.TrimSpace(rest)
	if !strings.HasPrefix(rest, ":") || !strings.HasSuffix(rest, ":") {
		return "", fmt.Errorf("signature must be :base64:")
	}
	return rest[1 : len(rest)-1], nil
}

func buildSignatureBase(req *http.Request, sp signatureParams, body []byte) (string, error) {
	var lines []string
	for _, c := range sp.Components {
		switch c {
		case "@method":
			lines = append(lines, `"@method": `+req.Method)
		case "@path":
			lines = append(lines, `"@path": `+req.URL.EscapedPath())
		case "content-digest":
			digest := req.Header.Get("Content-Digest")
			if digest == "" {
				return "", fmt.Errorf("content-digest covered but missing")
			}
			if len(body) > 0 && digest != ContentDigestSHA256(body) {
				return "", fmt.Errorf("content-digest mismatch")
			}
			lines = append(lines, `"content-digest": `+digest)
		case "content-type":
			ct := req.Header.Get("Content-Type")
			if ct == "" {
				return "", fmt.Errorf("content-type covered but missing")
			}
			lines = append(lines, `"content-type": `+ct)
		default:
			return "", fmt.Errorf("unsupported covered component %q", c)
		}
	}
	// RFC 9421: @signature-params is the exact Inner List + parameters from Signature-Input.
	lines = append(lines, `"@signature-params": `+sp.Raw)
	return strings.Join(lines, "\n"), nil
}

func verifyHMAC(cfg Config, req *http.Request, body []byte) error {
	input := req.Header.Get("Signature-Input")
	sigHdr := req.Header.Get("Signature")
	if input == "" || sigHdr == "" {
		return fmt.Errorf("missing Signature-Input or Signature")
	}
	sp, err := parseSignatureInput(input)
	if err != nil {
		return err
	}
	if !strings.EqualFold(sp.Alg, "hmac-sha256") {
		return fmt.Errorf("unsupported alg %q", sp.Alg)
	}
	secret, ok := cfg.HMACKeys[sp.KeyID]
	if !ok {
		return fmt.Errorf("unknown keyid")
	}
	now := time.Now().UTC()
	created := time.Unix(sp.Created, 0).UTC()
	if skew := now.Sub(created); skew > cfg.MaxSkew || skew < -cfg.MaxSkew {
		return fmt.Errorf("created timestamp skew too large")
	}
	if sp.Expires > 0 && now.After(time.Unix(sp.Expires, 0).UTC()) {
		return fmt.Errorf("signature expired")
	}
	base, err := buildSignatureBase(req, sp, body)
	if err != nil {
		return err
	}
	wantB64, err := parseSignatureValue(sigHdr)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = io.WriteString(mac, base)
	want, err := base64.StdEncoding.DecodeString(wantB64)
	if err != nil {
		return fmt.Errorf("signature base64: %w", err)
	}
	if !hmac.Equal(want, mac.Sum(nil)) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

func verifyBearer(cfg Config, req *http.Request) error {
	h := req.Header.Get("Authorization")
	if h == "" {
		return fmt.Errorf("missing Authorization")
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return fmt.Errorf("Authorization must be Bearer")
	}
	tok := strings.TrimSpace(strings.TrimPrefix(h, prefix))
	if _, ok := cfg.BearerTokens[tok]; !ok {
		return fmt.Errorf("invalid bearer token")
	}
	return nil
}
