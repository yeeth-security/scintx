package api_test

import (
	"testing"

	"github.com/yeeth-security/scintx/api"
)

func TestCanonicalPurl_LowercasesPyPI(t *testing.T) {
	got, err := api.CanonicalPurl("pkg:PYPI/Requests@2.32.3")
	if err != nil {
		t.Fatal(err)
	}
	want := "pkg:pypi/requests@2.32.3"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestCanonicalPurl_SortsQualifiers(t *testing.T) {
	got, err := api.CanonicalPurl("pkg:npm/foo@1.0.0?b=2&a=1")
	if err != nil {
		t.Fatal(err)
	}
	want := "pkg:npm/foo@1.0.0?a=1&b=2"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestCanonicalPurl_Invalid(t *testing.T) {
	if _, err := api.CanonicalPurl("not-a-purl"); err == nil {
		t.Fatal("expected error")
	}
}

func TestPurlTypeAndVersion(t *testing.T) {
	typ, err := api.PurlType("pkg:npm/left-pad@1.3.0")
	if err != nil || typ != "npm" {
		t.Fatalf("type=%q err=%v", typ, err)
	}
	ver, ok, err := api.PurlVersion("pkg:npm/left-pad@1.3.0")
	if err != nil || !ok || ver != "1.3.0" {
		t.Fatalf("ver=%q ok=%v err=%v", ver, ok, err)
	}
}
