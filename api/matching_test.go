package api_test

import (
	"testing"

	"github.com/yeeth-security/scintx/api"
)

func TestCapabilityEligible_PurlMatch(t *testing.T) {
	purl := "pkg:npm/left-pad@1.3.0"
	art := &api.Artifact{PURL: &purl}
	cap := &api.Capability{
		ID:      "vulnerability",
		Version: "v1",
		InputProfiles: []api.InputProfile{{
			ID: "purl",
			Requires: []api.Requirement{
				{Kind: api.ReqPurl, Types: []string{"npm", "pypi"}},
			},
		}},
	}
	res := api.CapabilityEligible(art, cap)
	if !res.Eligible {
		t.Fatalf("expected eligible, got %+v", res)
	}
}

func TestCapabilityEligible_WrongPurlType(t *testing.T) {
	purl := "pkg:docker/redis@7.0"
	art := &api.Artifact{PURL: &purl}
	cap := &api.Capability{
		ID:      "vulnerability",
		Version: "v1",
		InputProfiles: []api.InputProfile{{
			ID: "purl",
			Requires: []api.Requirement{
				{Kind: api.ReqPurl, Types: []string{"npm"}},
			},
		}},
	}
	res := api.CapabilityEligible(art, cap)
	if res.Eligible {
		t.Fatal("expected ineligible")
	}
}

func TestMatchingCapability(t *testing.T) {
	purl := "pkg:pypi/x@1"
	art := &api.Artifact{PURL: &purl}
	caps := []api.Capability{{
		ID: "vulnerability", Version: "v1",
		InputProfiles: []api.InputProfile{{
			ID: "purl", Requires: []api.Requirement{{Kind: api.ReqPurl, Types: []string{"pypi"}}},
		}},
	}}
	c, incompat := api.MatchingCapability(art, caps, "vulnerability")
	if c == nil || incompat != nil {
		t.Fatalf("expected match, c=%v incompat=%v", c, incompat)
	}
	c, incompat = api.MatchingCapability(art, caps, "secrets")
	if c != nil || incompat == nil || incompat.Eligible {
		t.Fatalf("expected miss for secrets")
	}
}
