# edge-guardian landing page

A self-contained marketing page (`index.html` — inline CSS + a little JS, Google Fonts
via CDN). No build step. Drop it on any static host.

## What's in here

| File | Purpose |
|---|---|
| `index.html` | The page. JSON-LD (SoftwareApplication/WebSite/FAQPage), full OG/Twitter meta, FAQ section, `<main>` landmark. |
| `og.png` | 1200×630 social preview card (on-brand). |
| `llms.txt` | LLM-friendly site summary ([llmstxt.org](https://llmstxt.org) standard) for AI search. |
| `robots.txt` | Allows all crawlers, including named AI bots (GPTBot, ClaudeBot, PerplexityBot, Google-Extended…). |
| `GEO-AUDIT.md` | The SEO + GEO (AI-search) audit and what was applied. |

### Launch copy (ready to paste)

| File | For |
|---|---|
| `SHOW-HN.md` | Show HN: title options, the post, and prepared replies to likely questions. |
| `SHOW-HN.vi.md` | Vietnamese version of the Show HN kit. |
| `REDDIT.md` | r/selfhosted (screenshot-first, friendly) + r/sysadmin (pragmatic) posts. |
| `BLOG-why.md` | Long-form "why I built edge-guardian" launch blog post / README "why". |

Before posting: make the repo public so links/install resolve, attach a real dashboard
screenshot (run `make demo`), and read each platform's self-promotion rules.

## Preview locally

```bash
cd landing && python3 -m http.server 4321
# open http://127.0.0.1:4321/
```

## Deploy

**GitHub Pages** (automated): `.github/workflows/pages.yml` deploys this folder on every
push to `main`. Enable it once in the repo: **Settings → Pages → Source: GitHub Actions**.
(Pages on a *private* repo needs a paid plan — flip the repo public, or use a host below.)

**Anything static** — it's one folder:

- **Netlify / Cloudflare Pages**: drag-drop `landing/`, or point the project at it.
- **Vercel**: `vercel deploy landing`.
- **Any web server**: copy `landing/index.html` to the docroot.

## Design

Follows the product's [`DESIGN.md`](../DESIGN.md) — the "static instrument" identity:
cool neutral canvas, a single `#D7402B` alert color spent sparingly, Space Grotesk +
IBM Plex. The animated **Sentinel line** in the hero is the product's signature.

## To finish before launch

- The install command and GitHub links point to `sondt/edge-guardian` — make the repo public
  (or update the URLs) so `curl … | sudo bash` and the links resolve.
- Once hosted, set `canonical`, `og:url`, and the `og:image`/`twitter:image` to the live
  **absolute** URL (today `og:image` is the relative `og.png`, which works on the same
  origin; social crawlers prefer an absolute URL).
- Submit the live URL to Google Search Console + Bing Webmaster. See `GEO-AUDIT.md` for
  the full pre-launch checklist (brand mentions move AI citation more than backlinks now).

### Regenerating `og.png`

The social card is rendered from an HTML template via headless Chrome (brand fonts).
To tweak it, edit the template in `dev/`-style flow or re-run the one-off command in the
project history; any 1200×630 image works.
