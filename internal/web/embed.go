package web

import "embed"

// staticFS holds every browser-served asset — htmx, the stylesheet, and self-hosted
// fonts — embedded directly in the binary. A security product must not fetch assets
// from a CDN, and embedding keeps the strict `'self'` CSP honest.
//
//go:embed static
var staticFS embed.FS
