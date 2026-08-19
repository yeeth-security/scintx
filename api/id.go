package api

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// RandHex returns a random hex id fragment with a short time suffix.
// Used for submission, result, decision, and event ids in the reference impl.
func RandHex() string {
	b := make([]byte, 8)
	// Best-effort entropy; fall back to zeros if the CSPRNG fails (rare).
	if _, err := rand.Read(b); err != nil {
		// Still produce a unique-enough id via wall clock so callers never panic.
		return fmt.Sprintf("0000000000000000-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b) + fmt.Sprintf("-%d", time.Now().UnixNano()%100000)
}
