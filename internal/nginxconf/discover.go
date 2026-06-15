// Package nginxconf discovers the domains nginx is actually serving, so the dashboard
// can list and count every website even before any traffic arrives — independent of
// whether the access log carries $host.
//
// The authoritative source is `nginx -T`, which dumps the FULL effective configuration
// (every conf.d file, sites-enabled symlink and include merged together). That reflects
// exactly what nginx loaded, regardless of where the site files live (conf.d vs
// sites-available/enabled). If nginx isn't available, it falls back to scanning a set of
// config-file globs. Always best-effort: it returns whatever it can and never errors.
package nginxconf

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// defaultGlobs are the common nginx config locations, used only when `nginx -T` fails.
var defaultGlobs = []string{
	"/etc/nginx/nginx.conf",
	"/etc/nginx/conf.d/*.conf",
	"/etc/nginx/sites-enabled/*",
}

// serverNameRe captures the operands of every `server_name …;` directive.
var serverNameRe = regexp.MustCompile(`(?m)^[ \t]*server_name[ \t]+([^;]+);`)

// Discover returns the sorted, de-duplicated list of server_name domains nginx serves.
// extraGlobs, if non-empty, REPLACE the default fallback globs (the `nginx -T` path is
// always tried first regardless).
func Discover(extraGlobs []string) []string {
	if out, err := exec.Command("nginx", "-T").Output(); err == nil {
		if names := parseServerNames(string(out)); len(names) > 0 {
			return names
		}
	}
	globs := extraGlobs
	if len(globs) == 0 {
		globs = defaultGlobs
	}
	return parseServerNames(readGlobs(globs))
}

// readGlobs concatenates the contents of every file matching the globs. Unreadable
// files are skipped silently (best-effort).
func readGlobs(globs []string) string {
	var b strings.Builder
	for _, g := range globs {
		matches, err := filepath.Glob(g)
		if err != nil {
			continue
		}
		for _, path := range matches {
			if data, err := os.ReadFile(path); err == nil {
				b.Write(data)
				b.WriteByte('\n')
			}
		}
	}
	return b.String()
}

// parseServerNames extracts the distinct, real hostnames from nginx config text. The
// catch-all "_", regex names ("~…") and empty tokens are dropped; the rest (including
// wildcards like *.example.com) are kept, lower-cased, and sorted.
func parseServerNames(text string) []string {
	set := make(map[string]struct{})
	for _, m := range serverNameRe.FindAllStringSubmatch(text, -1) {
		for name := range strings.FieldsSeq(m[1]) {
			name = strings.ToLower(strings.TrimSpace(name))
			if name == "" || name == "_" || strings.HasPrefix(name, "~") {
				continue
			}
			set[name] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
