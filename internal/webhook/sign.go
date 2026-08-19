package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// contentDigestSHA256 builds an RFC 9530 Content-Digest for sha-256.
func contentDigestSHA256(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

// signBody computes hex(HMAC-SHA256(secret, "<ts>.<body>")).
func signBody(secret []byte, ts int64, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = fmt.Fprintf(mac, "%d.", ts)
	_, _ = mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature checks X-Scintx-Signature against the raw body (for tests / receivers).
func VerifySignature(secret []byte, sigHeader string, body []byte, maxSkew time.Duration) error {
	var ts int64
	var v1 string
	for _, part := range strings.Split(sigHeader, ",") {
		part = strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(part, "t="):
			if _, err := fmt.Sscanf(part, "t=%d", &ts); err != nil {
				return fmt.Errorf("bad t=: %w", err)
			}
		case strings.HasPrefix(part, "v1="):
			v1 = strings.TrimPrefix(part, "v1=")
		}
	}
	if ts == 0 || v1 == "" {
		return fmt.Errorf("missing t= or v1=")
	}
	if maxSkew > 0 {
		skew := time.Since(time.Unix(ts, 0).UTC())
		if skew < 0 {
			skew = -skew
		}
		if skew > maxSkew {
			return fmt.Errorf("timestamp skew too large")
		}
	}
	want := signBody(secret, ts, body)
	if !hmac.Equal([]byte(want), []byte(v1)) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}
