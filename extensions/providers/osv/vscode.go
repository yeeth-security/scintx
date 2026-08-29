package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// Default OSV VS Code registry ecosystems when the PURL has no repository_url.
// OSV indexes extensions as ecosystem "VSCode:<registry-base>" + dotted
// extension id ("publisher.name"), not as pkg:vscode-extension/… PURLs.
var defaultVSCodeEcosystems = []string{
	"VSCode:https://open-vsx.org",
	"VSCode:https://marketplace.visualstudio.com",
}

// vscodeEcosystemQuery is one OSV ecosystem+name(+version) lookup derived
// from a vscode-extension PURL.
type vscodeEcosystemQuery struct {
	Ecosystem string
	Name      string
	Version   string
}

// vscodeExtensionQueries maps a canonical vscode-extension PURL to OSV
// ecosystem queries.
//
// Example:
//
//	pkg:vscode-extension/checkmarx/ast-results@2.56.0?repository_url=https://open-vsx.org
//	→ ecosystem=VSCode:https://open-vsx.org name=checkmarx.ast-results version=2.56.0
//
// Without repository_url, both Open VSX and the Microsoft Marketplace are
// queried so a clean miss on one registry does not hide hits on the other.
func vscodeExtensionQueries(canonicalPURL string) ([]vscodeEcosystemQuery, error) {
	typ, ns, name, version, quals, err := splitVSCodePURL(canonicalPURL)
	if err != nil {
		return nil, err
	}
	if typ != "vscode-extension" {
		return nil, fmt.Errorf("not a vscode-extension purl: %s", typ)
	}
	if ns == "" || name == "" {
		return nil, fmt.Errorf("vscode-extension purl needs publisher/name: %s", canonicalPURL)
	}
	// OSV package name is the dotted VS Code extension id.
	extID := ns + "." + name

	repoURL := strings.TrimSpace(quals["repository_url"])
	if repoURL != "" {
		eco, err := vscodeEcosystemFromRepoURL(repoURL)
		if err != nil {
			return nil, err
		}
		return []vscodeEcosystemQuery{{Ecosystem: eco, Name: extID, Version: version}}, nil
	}

	out := make([]vscodeEcosystemQuery, 0, len(defaultVSCodeEcosystems))
	for _, eco := range defaultVSCodeEcosystems {
		out = append(out, vscodeEcosystemQuery{Ecosystem: eco, Name: extID, Version: version})
	}
	return out, nil
}

// vscodeEcosystemFromRepoURL builds "VSCode:<origin>" from a repository_url
// qualifier. Trailing slashes are stripped so open-vsx.org/ matches OSV.
func vscodeEcosystemFromRepoURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid repository_url %q", raw)
	}
	base := strings.TrimRight(u.Scheme+"://"+u.Host+u.Path, "/")
	return "VSCode:" + base, nil
}

// QueryVSCodeExtension runs ecosystem fallback queries and merges by vuln ID.
func (c *Client) QueryVSCodeExtension(ctx context.Context, canonicalPURL string) ([]Vulnerability, []byte, error) {
	queries, err := vscodeExtensionQueries(canonicalPURL)
	if err != nil {
		return nil, nil, err
	}

	seen := map[string]struct{}{}
	var merged []Vulnerability
	var rawPages []json.RawMessage

	for _, q := range queries {
		vulns, raw, err := c.QueryByEcosystem(ctx, q.Ecosystem, q.Name, q.Version)
		if err != nil {
			return nil, nil, err
		}
		rawPages = append(rawPages, raw)
		for _, v := range vulns {
			if v.ID == "" {
				merged = append(merged, v)
				continue
			}
			if _, ok := seen[v.ID]; ok {
				continue
			}
			seen[v.ID] = struct{}{}
			merged = append(merged, v)
		}
	}

	combined, _ := json.Marshal(map[string]any{
		"fallback": "vscode-extension-ecosystem",
		"queries":  queries,
		"pages":    rawPages,
		"count":    len(merged),
	})
	return merged, combined, nil
}

// splitVSCodePURL is a small PURL splitter for the fields we need.
// Kept local so the OSV adapter does not depend on unexported api.parsePurl.
func splitVSCodePURL(purl string) (typ, namespace, name, version string, quals map[string]string, err error) {
	quals = map[string]string{}
	if !strings.HasPrefix(purl, "pkg:") {
		return "", "", "", "", nil, fmt.Errorf("invalid purl: %s", purl)
	}
	rest := purl[4:]

	// Separate qualifiers / subpath.
	var tail string
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		tail = rest[i:]
		rest = rest[:i]
	}

	// type/namespace/name@version  OR  type/name@version
	slash := strings.Index(rest, "/")
	if slash < 0 {
		return "", "", "", "", nil, fmt.Errorf("invalid purl: %s", purl)
	}
	typ = strings.ToLower(rest[:slash])
	path := rest[slash+1:]

	if at := strings.Index(path, "@"); at >= 0 {
		version = path[at+1:]
		path = path[:at]
	}

	if i := strings.Index(path, "/"); i >= 0 {
		namespace = path[:i]
		name = path[i+1:]
	} else {
		name = path
	}

	if len(tail) > 0 && tail[0] == '?' {
		body := tail[1:]
		if i := strings.Index(body, "#"); i >= 0 {
			body = body[:i]
		}
		for _, kv := range strings.Split(body, "&") {
			if kv == "" {
				continue
			}
			eq := strings.Index(kv, "=")
			if eq < 0 {
				continue
			}
			// Qualifier keys are case-insensitive per PURL spec.
			k := strings.ToLower(kv[:eq])
			v, decErr := url.QueryUnescape(kv[eq+1:])
			if decErr != nil {
				v = kv[eq+1:]
			}
			quals[k] = v
		}
	}
	return typ, namespace, name, version, quals, nil
}
