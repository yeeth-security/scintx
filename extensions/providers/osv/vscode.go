package osv

import (
	"net/url"
	"strings"

	"github.com/yeeth-security/scintx/api"
)

// OSV indexes Open VSX / Marketplace malware under ecosystem forms like
// "VSCode:https://open-vsx.org" with package name "publisher.name" — not under
// pkg:vscode-extension/… PURLs yet. See e.g. MAL-2026-2231.
func vscodeExtensionOsvQueries(canonicalPURL string) []queryPackage {
	typ, err := api.PurlType(canonicalPURL)
	if err != nil || typ != "vscode-extension" {
		return nil
	}
	parsed, err := parseVsCodeExtensionPurl(canonicalPURL)
	if err != nil || parsed.publisher == "" || parsed.name == "" || parsed.version == "" {
		return nil
	}
	pkgName := parsed.publisher + "." + parsed.name
	var out []queryPackage
	switch parsed.repo {
	case "https://open-vsx.org", "https://openvsx.org":
		out = append(out, queryPackage{
			Ecosystem: "VSCode:https://open-vsx.org",
			Name:      pkgName,
			Version:   parsed.version,
		})
	default:
		// Marketplace default (no repository_url) and unknown repos.
		out = append(out,
			queryPackage{Ecosystem: "VSCode", Name: pkgName, Version: parsed.version},
			queryPackage{
				Ecosystem: "VSCode:https://marketplace.visualstudio.com",
				Name:      pkgName,
				Version:   parsed.version,
			},
		)
	}
	return out
}

type vsCodePurlParts struct {
	publisher string
	name      string
	version   string
	repo      string
}

func parseVsCodeExtensionPurl(purl string) (vsCodePurlParts, error) {
	var out vsCodePurlParts
	// Strip pkg:vscode-extension/
	rest := strings.TrimPrefix(purl, "pkg:vscode-extension/")
	if rest == purl {
		rest = strings.TrimPrefix(strings.ToLower(purl), "pkg:vscode-extension/")
	}
	qIdx := strings.IndexAny(rest, "?#")
	qualifiers := ""
	if qIdx >= 0 {
		qualifiers = rest[qIdx:]
		rest = rest[:qIdx]
	}
	at := strings.LastIndex(rest, "@")
	if at > 0 {
		out.version = rest[at+1:]
		rest = rest[:at]
	}
	slash := strings.Index(rest, "/")
	if slash < 0 {
		return out, errInvalidVsCodePurl
	}
	out.publisher = strings.ToLower(rest[:slash])
	out.name = strings.ToLower(rest[slash+1:])
	if strings.HasPrefix(qualifiers, "?") {
		vals, _ := url.ParseQuery(strings.TrimPrefix(strings.SplitN(qualifiers, "#", 2)[0], "?"))
		out.repo = strings.TrimSuffix(vals.Get("repository_url"), "/")
	}
	return out, nil
}

var errInvalidVsCodePurl = errString("invalid vscode-extension purl")

type errString string

func (e errString) Error() string { return string(e) }

func mergeVulnsByID(base []Vulnerability, extra []Vulnerability) []Vulnerability {
	seen := make(map[string]struct{}, len(base))
	for _, v := range base {
		seen[v.ID] = struct{}{}
	}
	for _, v := range extra {
		if _, ok := seen[v.ID]; ok {
			continue
		}
		seen[v.ID] = struct{}{}
		base = append(base, v)
	}
	return base
}
