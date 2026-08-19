package api

import "testing"

func TestLocalBlobDigest(t *testing.T) {
	d, ok := LocalBlobDigest(BlobURN("sha256:abcd"))
	if !ok || d != "sha256:abcd" {
		t.Fatalf("got %q ok=%v", d, ok)
	}
	if _, ok := LocalBlobDigest("https://example/file.bin"); ok {
		t.Fatal("external URL must not parse as a local blob")
	}
	if _, ok := LocalBlobDigest(BlobURNPrefix); ok {
		t.Fatal("empty digest must fail")
	}
}

func TestArtifactContentOmittedFromJSON(t *testing.T) {
	a := Artifact{Content: []byte("secret-bytes")}
	cp := CloneJSON(a)
	if len(cp.Content) != 0 {
		t.Fatalf("Content leaked through JSON: %q", cp.Content)
	}
}
