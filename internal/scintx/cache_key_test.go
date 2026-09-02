package scintx_test

import (
	"testing"

	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/internal/scintx"
)

func TestResultCacheKey_Stable(t *testing.T) {
	purl := "pkg:PYPI/Clean-Package@1.0.0"
	a := api.Artifact{PURL: &purl}
	k1 := scintx.ResultCacheKey("stub-osv", "vulnerability", a)
	k2 := scintx.ResultCacheKey("stub-osv", "vulnerability", a)
	if k1 != k2 {
		t.Fatalf("unstable key")
	}
	other := "pkg:pypi/other@1.0.0"
	k3 := scintx.ResultCacheKey("stub-osv", "vulnerability", api.Artifact{PURL: &other})
	if k1 == k3 {
		t.Fatalf("expected different keys")
	}
}
