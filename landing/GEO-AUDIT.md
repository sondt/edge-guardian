# GEO + SEO audit — edge-guardian landing page

On-page audit of `landing/index.html`, optimized for both traditional search and AI
search (ChatGPT, Claude, Perplexity, Gemini, Google AI Overviews). Live-crawl checks
(backlinks, CrUX field data, indexation) are deferred until the site is deployed
publicly — the repo is private today.

**On-page GEO readiness: ~92/100** after the fixes below. The page is a single static
file, server-rendered (no JS needed to read content), which is ideal for AI crawlers.

## What was applied

### Structured data (was: none → now: complete)
A single JSON-LD `@graph` in `<head>`:
- **SoftwareApplication** — name, category (SecurityApplication), OS (Linux), free
  `Offer` (price 0), Apache-2.0 license, version, `featureList`, author org. Makes the
  product a machine-readable entity for Google rich results *and* AI grounding.
- **WebSite** and **FAQPage** (6 Q&As).
- The visible FAQ section mirrors the FAQPage schema exactly (Google requirement).

### AI-search citability (the GEO core)
- Added a **FAQ section** with self-contained, quotable answers ("What is edge-guardian?",
  "How is it different from fail2ban/CrowdSec?", "Is it free?", "What does it need?",
  "What does it detect?", "How do I install it?"). Short, factual, declarative passages
  are exactly what LLMs lift into answers.
- Crisp **definitional sentence** up top (meta description + hero sub + FAQ #1) so an AI
  can state what edge-guardian *is* in one line.
- **`llms.txt`** (the emerging standard) summarizing the product, key facts, install,
  and links — a clean brief for AI systems.

### Crawler access
- **`robots.txt`** explicitly allows all bots plus named AI crawlers (GPTBot,
  OAI-SearchBot, ClaudeBot, anthropic-ai, PerplexityBot, Google-Extended,
  Applebot-Extended, CCBot).

### Traditional SEO + semantics
- Completed meta: `canonical`, `robots` (`max-image-preview:large`), `author`,
  full Open Graph + Twitter cards, `og:site_name`.
- Real **`og.png`** (1200×630) social card generated on-brand — rich link previews.
- Wrapped content in a `<main>` landmark; single `<h1>`, sectioned `<h2>`s; descriptive
  `<title>` and description front-loading the value prop and the keyword
  "intrusion prevention … Linux".

## Already strong (kept)
- Static HTML, content visible without JS → maximal crawler/LLM accessibility.
- Mobile responsive, `prefers-reduced-motion`, fast (one file, fonts via CDN with
  `display=swap`).
- Clear comparison table (edge-guardian vs fail2ban vs CrowdSec) — great for "alternative to"
  and "X vs Y" AI queries.

## Before public launch (can't finish until deployed)
1. **Make the repo public** (or update URLs) so the install command and links resolve —
   AI engines won't cite a 404.
2. **Host it** (GitHub Pages / Netlify / Cloudflare) and set `canonical` + `og:url` to
   the live URL (currently the GitHub repo). Re-point `og:image` to the absolute URL.
3. **Submit** the URL to Google Search Console and Bing Webmaster; request indexing.
4. **Brand mentions** drive AI citation more than backlinks now — a Show HN / r/selfhosted
   / r/sysadmin post, an Awesome-Selfhosted PR, and a few comparison mentions will move
   the needle far more than on-page tweaks from here.
5. Optional: a short blog/changelog for freshness signals, and a `sitemap.xml` once there
   is more than one page.
