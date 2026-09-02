package api

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var namespaceLowerTypes = map[string]bool{
	"pypi": true, "npm": true, "gem": true, "composer": true, "golang": true,
}

var purlRe = regexp.MustCompile(`^pkg:([^/#?]+)((?:/[^?#]*)?)(([?#].*)?)$`)

type parsedPurl struct {
	Type       string
	Namespace  string
	Name       string
	Version    string
	Qualifiers map[string]string
	Subpath    string
	Hash       string
}

func parsePurl(purl string) (*parsedPurl, error) {
	m := purlRe.FindStringSubmatch(purl)
	if m == nil {
		return nil, fmt.Errorf("invalid purl: %s", purl)
	}
	typ := strings.ToLower(m[1])
	rest := m[2]
	tail := m[3]

	p := &parsedPurl{Type: typ, Qualifiers: map[string]string{}}

	if len(rest) > 0 {
		body := rest[1:]
		slashIdx := strings.Index(body, "/")
		if slashIdx >= 0 {
			p.Namespace = body[:slashIdx]
			p.Name = body[slashIdx+1:]
		} else {
			p.Name = body
		}
	}

	if v, ok := extractVersion(p.Name); ok {
		p.Version = v
	}
	p.Name = stripVersion(p.Name)

	if len(tail) > 0 {
		if tail[0] == '?' {
			body := tail[1:]
			var hashSub string
			if idx := strings.Index(body, "#"); idx >= 0 {
				hashSub = body[idx+1:]
				body = body[:idx]
			}
			for _, kv := range strings.Split(body, "&") {
				if kv == "" {
					continue
				}
				eq := strings.Index(kv, "=")
				if eq < 0 {
					continue
				}
				p.Qualifiers[strings.ToLower(kv[:eq])] = kv[eq+1:]
			}
			if hashSub != "" {
				slashIdx := strings.Index(hashSub, "/")
				if slashIdx >= 0 {
					p.Hash = hashSub[:slashIdx]
					p.Subpath = hashSub[slashIdx:]
				} else {
					p.Hash = hashSub
				}
			}
		} else if tail[0] == '#' {
			body := tail[1:]
			slashIdx := strings.Index(body, "/")
			if slashIdx >= 0 {
				p.Hash = body[:slashIdx]
				p.Subpath = body[slashIdx:]
			} else {
				p.Hash = body
			}
		}
	}

	if namespaceLowerTypes[typ] {
		p.Namespace = strings.ToLower(p.Namespace)
		p.Name = strings.ToLower(p.Name)
	}
	p.Subpath = strings.TrimRight(p.Subpath, "/")
	return p, nil
}

func extractVersion(s string) (string, bool) {
	idx := strings.Index(s, "@")
	if idx < 0 {
		return "", false
	}
	return s[idx+1:], true
}

func stripVersion(s string) string {
	idx := strings.Index(s, "@")
	if idx < 0 {
		return s
	}
	return s[:idx]
}

func CanonicalPurl(purl string) (string, error) {
	p, err := parsePurl(purl)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "pkg:%s", p.Type)
	if p.Namespace != "" {
		fmt.Fprintf(&b, "/%s", p.Namespace)
	}
	fmt.Fprintf(&b, "/%s", p.Name)
	if p.Version != "" {
		fmt.Fprintf(&b, "@%s", p.Version)
	}
	if len(p.Qualifiers) > 0 {
		keys := make([]string, 0, len(p.Qualifiers))
		for k := range p.Qualifiers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var qs []string
		for _, k := range keys {
			qs = append(qs, fmt.Sprintf("%s=%s", k, p.Qualifiers[k]))
		}
		fmt.Fprintf(&b, "?%s", strings.Join(qs, "&"))
	}
	if p.Hash != "" {
		fmt.Fprintf(&b, "#%s", p.Hash)
	}
	if p.Subpath != "" {
		fmt.Fprintf(&b, "%s", p.Subpath)
	}
	return b.String(), nil
}

func PurlType(purl string) (string, error) {
	p, err := parsePurl(purl)
	if err != nil {
		return "", err
	}
	return p.Type, nil
}

func PurlName(purl string) (string, error) {
	p, err := parsePurl(purl)
	if err != nil {
		return "", err
	}
	return p.Name, nil
}

func PurlVersion(purl string) (string, bool, error) {
	p, err := parsePurl(purl)
	if err != nil {
		return "", false, err
	}
	if p.Version == "" {
		return "", false, nil
	}
	return p.Version, true, nil
}
