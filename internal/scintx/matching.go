package scintx

func requirementSatisfied(artifact *Artifact, req *Requirement) (bool, string) {
	switch req.Kind {
	case ReqPurl:
		if artifact.PURL == nil || *artifact.PURL == "" {
			return false, "missing purl"
		}
		cp, err := CanonicalPurl(*artifact.PURL)
		if err != nil {
			return false, "invalid purl"
		}
		typ, _ := PurlType(cp)
		if len(req.Types) > 0 {
			found := false
			for _, t := range req.Types {
				if t == typ {
					found = true
					break
				}
			}
			if !found {
				return false, "unsupported purl type: " + typ
			}
		}
		return true, ""

	case ReqDigest:
		if len(artifact.Digests) == 0 {
			return false, "missing digests"
		}
		if len(req.Algorithms) > 0 {
			found := false
			for _, a := range req.Algorithms {
				if _, ok := artifact.Digests[a]; ok {
					found = true
					break
				}
			}
			if !found {
				return false, "no supported digest algorithm"
			}
		}
		return true, ""

	case ReqContent:
		if artifact.ContentRef == nil {
			return false, "missing content"
		}
		return true, ""

	case ReqSBOM:
		if len(artifact.SBOMRefs) == 0 {
			return false, "missing sbom"
		}
		for _, ref := range artifact.SBOMRefs {
			if len(req.Formats) == 0 {
				return true, ""
			}
			versions, ok := req.Formats[ref.Format]
			if !ok {
				continue
			}
			for _, v := range versions {
				if v == ref.FormatVersion {
					return true, ""
				}
			}
		}
		return false, "no matching sbom format/version"

	case ReqProvenance:
		if len(artifact.ProvenanceRefs) == 0 {
			return false, "missing provenance"
		}
		for _, ref := range artifact.ProvenanceRefs {
			if len(req.Formats) == 0 {
				return true, ""
			}
			versions, ok := req.Formats[ref.Format]
			if !ok {
				continue
			}
			for _, v := range versions {
				if v == ref.FormatVersion {
					return true, ""
				}
			}
		}
		return false, "no matching provenance format/version"
	}
	return false, "unknown requirement kind"
}

func profileSatisfied(artifact *Artifact, profile *InputProfile) (bool, string) {
	for _, req := range profile.Requires {
		ok, detail := requirementSatisfied(artifact, &req)
		if !ok {
			return false, detail
		}
	}
	return true, ""
}

func CapabilityEligible(artifact *Artifact, capability *Capability) CompatibilityResult {
	for _, profile := range capability.InputProfiles {
		ok, _ := profileSatisfied(artifact, &profile)
		if ok {
			return CompatibilityResult{
				Capability: capability.ID + ":" + capability.Version,
				Eligible:   true,
			}
		}
	}
	var reasons []CompatibilityReason
	for _, profile := range capability.InputProfiles {
		for _, req := range profile.Requires {
			ok, detail := requirementSatisfied(artifact, &req)
			if !ok {
				reasons = append(reasons, CompatibilityReason{
					Code:   ReasonMissingInput,
					Input:  string(req.Kind),
					Detail: detail,
				})
			}
		}
	}
	if len(reasons) == 0 {
		reasons = []CompatibilityReason{{Code: ReasonNoMatchingProfile}}
	}
	return CompatibilityResult{
		Capability: capability.ID + ":" + capability.Version,
		Eligible:   false,
		Reasons:    reasons,
	}
}

func MatchingCapability(artifact *Artifact, capabilities []Capability, requestedCapability string) (*Capability, *CompatibilityResult) {
	for i := range capabilities {
		c := &capabilities[i]
		if c.ID != requestedCapability {
			continue
		}
		res := CapabilityEligible(artifact, c)
		if res.Eligible {
			return c, nil
		}
		return nil, &res
	}
	return nil, &CompatibilityResult{
		Capability: requestedCapability,
		Eligible:   false,
		Reasons:    []CompatibilityReason{{Code: ReasonNoMatchingProfile, Detail: "capability not advertised"}},
	}
}