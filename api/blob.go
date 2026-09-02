package api

import "strings"

// BlobURNPrefix is the URI scheme for content stored via POST /v1/artifacts.
const BlobURNPrefix = "urn:scintx:blob:"

// BlobURN builds the content_ref URI for a stored digest (sha256:<hex>).
func BlobURN(digest string) string {
	return BlobURNPrefix + digest
}

// LocalBlobDigest extracts the store key from a local blob URI.
// External URLs return ok=false (the gateway does not fetch them).
func LocalBlobDigest(uri string) (digest string, ok bool) {
	uri = strings.TrimSpace(uri)
	if !strings.HasPrefix(uri, BlobURNPrefix) {
		return "", false
	}
	digest = strings.TrimPrefix(uri, BlobURNPrefix)
	if digest == "" {
		return "", false
	}
	return digest, true
}
