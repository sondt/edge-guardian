//go:build ignore

// build-i18n generates the localized landing pages from a single source template.
//
//	cd landing && go run build-i18n.go
//
// It reads index.src.html (the English source), applies each language's string map from
// i18n/<lang>.json, and writes static per-language files: index.html (English, default)
// and <lang>/index.html for the rest — each with the right <html lang>, a hreflang block
// and a language switcher. Stdlib only; no module dependency (//go:build ignore keeps it
// out of the daemon build). Re-run after editing index.src.html or any i18n/*.json.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type lang struct {
	code  string // ISO code → <html lang> + i18n/<code>.json
	label string // shown in the switcher
	path  string // site path of this language's page (root-relative)
}

// langs: English is the default at the root; the rest live under /<code>/. To add a
// language, append here and drop an i18n/<code>.json — no other change needed.
var langs = []lang{
	{"en", "EN", "/"},
	{"fr", "FR", "/fr/"},
	{"de", "DE", "/de/"},
	{"es", "ES", "/es/"},
	{"zh", "中文", "/zh/"},
	{"vi", "Tiếng Việt", "/vi/"},
}

// baseURL is the site origin for absolute hreflang URLs. Empty → root-relative (works on
// any host; set to e.g. "https://edge-guardian.example" for spec-perfect hreflang).
const baseURL = ""

func main() {
	src, err := os.ReadFile("index.src.html")
	if err != nil {
		fmt.Fprintln(os.Stderr, "read source:", err)
		os.Exit(1)
	}
	// Only emit (and link to) languages that actually have content: English always, plus
	// every language with an i18n/<code>.json. This keeps the switcher and hreflang from
	// pointing at pages that don't exist yet.
	var active []lang
	dicts := map[string]map[string]string{}
	for _, l := range langs {
		if l.code == "en" {
			active = append(active, l)
			continue
		}
		dict, err := loadDict("i18n/" + l.code + ".json")
		if os.IsNotExist(err) {
			fmt.Printf("skip %-4s (no i18n/%s.json yet)\n", l.code, l.code)
			continue
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "load dict", l.code, ":", err)
			os.Exit(1)
		}
		dicts[l.code] = dict
		active = append(active, l)
	}

	hreflang := hreflangBlock(active)
	for _, l := range active {
		html := string(src)
		if dict := dicts[l.code]; dict != nil {
			// Longest keys first so a phrase is never partially clobbered by a shorter
			// substring key.
			for _, k := range keysByLenDesc(dict) {
				html = strings.ReplaceAll(html, k, dict[k])
			}
		}
		html = strings.Replace(html, `<html lang="en"`, `<html lang="`+l.code+`"`, 1)
		html = strings.ReplaceAll(html, "<!--EG_HREFLANG-->", hreflang)
		html = strings.ReplaceAll(html, "<!--EG_LANGSWITCH-->", switcher(active, l.code))

		out := "index.html"
		if l.code != "en" {
			out = filepath.Join(l.code, "index.html")
			if err := os.MkdirAll(l.code, 0o755); err != nil {
				fmt.Fprintln(os.Stderr, "mkdir", l.code, ":", err)
				os.Exit(1)
			}
		}
		if err := os.WriteFile(out, []byte(html), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "write", out, ":", err)
			os.Exit(1)
		}
		fmt.Printf("wrote %-18s (%s)\n", out, l.code)
	}
}

func loadDict(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return m, nil
}

func keysByLenDesc(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Slice(ks, func(i, j int) bool { return len(ks[i]) > len(ks[j]) })
	return ks
}

func hreflangBlock(active []lang) string {
	var b strings.Builder
	for _, l := range active {
		fmt.Fprintf(&b, "<link rel=\"alternate\" hreflang=\"%s\" href=\"%s%s\">\n", l.code, baseURL, l.path)
	}
	fmt.Fprintf(&b, "<link rel=\"alternate\" hreflang=\"x-default\" href=\"%s/\">", baseURL)
	return b.String()
}

func switcher(active []lang, cur string) string {
	var b strings.Builder
	b.WriteString(`<div class="lang-switch" aria-label="Language" style="display:flex;gap:10px;align-items:center;font-size:13px;font-weight:500;margin-right:4px">`)
	for _, l := range active {
		if l.code == cur {
			fmt.Fprintf(&b, `<span aria-current="true" style="color:var(--ink)">%s</span>`, l.label)
		} else {
			fmt.Fprintf(&b, `<a href="%s%s" hreflang="%s" style="color:var(--muted)">%s</a>`, baseURL, l.path, l.code, l.label)
		}
	}
	b.WriteString(`</div>`)
	return b.String()
}
