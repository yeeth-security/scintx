package credentials

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"
)

const testProvider = "test-provider"

func withTestSpec(t *testing.T) {
	t.Helper()
	resetSpecsForTest()
	Register(Spec{
		ID:       testProvider,
		TokenEnv: "SCINTX_TEST_PROVIDER_TOKEN",
		UserEnv:  "SCINTX_TEST_PROVIDER_USER",
		HelpURL:  "https://example.test",
		Summary:  "test provider",
	})
	t.Cleanup(resetSpecsForTest)
}

func TestGetPrefersEnv(t *testing.T) {
	keyring.MockInit()
	withTestSpec(t)
	t.Setenv("SCINTX_CONFIG_DIR", t.TempDir())
	t.Setenv("SCINTX_TEST_PROVIDER_TOKEN", "env-token")
	t.Setenv("SCINTX_TEST_PROVIDER_USER", "env-user")

	if _, err := Set(testProvider, ProviderCreds{Token: "file-or-keyring"}); err != nil {
		t.Fatal(err)
	}

	r, err := Get(testProvider)
	if err != nil {
		t.Fatal(err)
	}
	if r.Source != SourceEnv || r.Creds.Token != "env-token" || r.Creds.User != "env-user" {
		t.Fatalf("got %+v", r)
	}
}

func TestSetKeyringThenGet(t *testing.T) {
	keyring.MockInit()
	withTestSpec(t)
	t.Setenv("SCINTX_CONFIG_DIR", t.TempDir())
	t.Setenv("SCINTX_TEST_PROVIDER_TOKEN", "")
	t.Setenv("SCINTX_TEST_PROVIDER_USER", "")

	src, err := Set(testProvider, ProviderCreds{Token: "secret-pat", User: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if src != SourceKeyring {
		t.Fatalf("source=%s", src)
	}

	r, err := Get(testProvider)
	if err != nil {
		t.Fatal(err)
	}
	if r.Source != SourceKeyring || r.Creds.Token != "secret-pat" || r.Creds.User != "alice" {
		t.Fatalf("got %+v", r)
	}

	path, err := CredentialsPath()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "secret-pat") {
		t.Fatalf("token leaked to file: %s", data)
	}
}

func TestFileFallbackWhenNoKeyringToken(t *testing.T) {
	keyring.MockInit()
	withTestSpec(t)
	dir := t.TempDir()
	t.Setenv("SCINTX_CONFIG_DIR", dir)
	t.Setenv("SCINTX_TEST_PROVIDER_TOKEN", "")

	path := filepath.Join(dir, credentialsFileName)
	content := []byte("providers:\n  test-provider:\n    token: file-token\n    user: bob\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}

	r, err := Get(testProvider)
	if err != nil {
		t.Fatal(err)
	}
	if r.Source != SourceFile || r.Creds.Token != "file-token" || r.Creds.User != "bob" {
		t.Fatalf("got %+v", r)
	}
}

func TestClear(t *testing.T) {
	keyring.MockInit()
	withTestSpec(t)
	t.Setenv("SCINTX_CONFIG_DIR", t.TempDir())
	t.Setenv("SCINTX_TEST_PROVIDER_TOKEN", "")

	if _, err := Set(testProvider, ProviderCreds{Token: "x"}); err != nil {
		t.Fatal(err)
	}
	if err := Clear(testProvider); err != nil {
		t.Fatal(err)
	}
	r, err := Get(testProvider)
	if err != nil {
		t.Fatal(err)
	}
	if r.Source != SourceNone || r.Creds.Token != "" {
		t.Fatalf("got %+v", r)
	}
}

func TestRegisterAndSpecs(t *testing.T) {
	resetSpecsForTest()
	t.Cleanup(resetSpecsForTest)
	Register(Spec{ID: "b", TokenEnv: "B", Summary: "second"})
	Register(Spec{ID: "a", TokenEnv: "A", Summary: "first"})
	got := Specs()
	if len(got) != 2 || got[0].ID != "a" || got[1].ID != "b" {
		t.Fatalf("Specs=%+v", got)
	}
	if !Known("a") || Known("missing") {
		t.Fatal("Known mismatch")
	}
}
