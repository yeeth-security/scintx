package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestAttachRawReport(t *testing.T) {
	res := &ProviderResult{}
	body := []byte(`{"version":"2.1.0","runs":[]}`)
	AttachRawReport(res, FormatSARIF, FormatVersionSARIF, MediaTypeSARIF, RoleInterchange, body)

	if len(res.RawResults) != 1 {
		t.Fatalf("raw_results len=%d", len(res.RawResults))
	}
	ref := res.RawResults[0]
	if ref.Format != FormatSARIF || ref.FormatVersion != FormatVersionSARIF {
		t.Fatalf("format=%q version=%q", ref.Format, ref.FormatVersion)
	}
	if ref.MediaType != MediaTypeSARIF {
		t.Fatalf("media_type=%q", ref.MediaType)
	}
	sum := sha256.Sum256(body)
	wantDigest := hex.EncodeToString(sum[:])
	if ref.Digests["sha256"] != wantDigest {
		t.Fatalf("digest=%q want=%q", ref.Digests["sha256"], wantDigest)
	}
	key := "sha256:" + wantDigest
	if ref.URI != BlobURN(key) {
		t.Fatalf("uri=%q", ref.URI)
	}
	if string(res.PendingArtifacts[key]) != string(body) {
		t.Fatalf("pending artifact mismatch")
	}
	if ref.Extensions["org.eclipse.scintx.role"] != RoleInterchange {
		t.Fatalf("role=%v", ref.Extensions["org.eclipse.scintx.role"])
	}
}

func TestProviderResultOmitsPendingArtifacts(t *testing.T) {
	res := &ProviderResult{
		ID:            "res_test",
		SchemaVersion: "1.0.0",
		PendingArtifacts: map[string][]byte{
			"sha256:abc": []byte("x"),
		},
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["PendingArtifacts"]; ok {
		t.Fatal("PendingArtifacts must not appear in JSON")
	}
	if _, ok := m["pending_artifacts"]; ok {
		t.Fatal("pending_artifacts must not appear in JSON")
	}
}

func TestAttachRawReportEmptySkipped(t *testing.T) {
	res := &ProviderResult{}
	AttachRawReport(res, "osv", "", "application/json", RoleNative, nil)
	if len(res.RawResults) != 0 {
		t.Fatalf("expected no entries, got %d", len(res.RawResults))
	}
}
