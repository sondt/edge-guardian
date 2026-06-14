---
name: edge-guardian dashboard
description: Design system for the edge-guardian local security dashboard — a calm "static instrument" that stays quiet until something is wrong.
colors:
  paper: "#F6F7F9"
  panel: "#FFFFFF"
  line: "#E2E5EA"
  ink: "#16181D"
  muted: "#5C636E"
  alert: "#D7402B"
  dark:
    paper: "#16181D"
    panel: "#1D2026"
    line: "#2A2E37"
    ink: "#E7E9EC"
    muted: "#9AA1AC"
typography:
  display:
    family: "Space Grotesk"
    weights: [600, 700]
  body:
    family: "IBM Plex Sans"
    weights: [400, 500]
  data:
    family: "IBM Plex Mono"
    weights: [400, 500]
layout:
  radius: "8px"
  gap: "16px"
  max_width: "1120px"
shapes:
  radius_default: "8px"
---

# edge-guardian Dashboard — Design System

Source of truth for the dashboard's visual identity. Distilled from
[`docs/09-giao-dien.md`](docs/09-giao-dien.md); read that for full rationale,
wireframes, and the technical architecture. Tokens here are canonical — reference
them, never hardcode.

## Overview

The dashboard is the product **wedge**: the reason a self-hoster picks edge-guardian over
wiring Grafana onto CrowdSec. The single job of the home screen is: *at a glance, is
my server under attack, who is hitting it, and is it blocked yet?*

Guiding idea — **"static instrument"**: a light, cool, precise gauge face. The whole
UI is neutral; **one signal color** (`alert`) is spent very sparingly, only for
genuine danger. Because it is rare, when it turns red it *means* something. This is
the product's spirit made visual: **calm until something happens.**

Hard rule: **color is signal, not decoration.** Attack intensity is shown by the
*opacity* of the single `alert` color (0.08 faint wash → 1.0 hot mark), never by a
rainbow palette.

Deliberately avoided: the "black + neon-green hacker" security-dashboard cliché; the
cream + serif + terracotta default; and the hairline-newspaper look.

## Colors

| Token | Hex | Use |
|---|---|---|
| `paper` | `#F6F7F9` | Page background (cool neutral — not cream, not black) |
| `panel` | `#FFFFFF` | Card / panel surfaces |
| `line` | `#E2E5EA` | Hairlines, dividers, table rules |
| `ink` | `#16181D` | Primary text |
| `muted` | `#5C636E` | Secondary text, labels |
| `alert` | `#D7402B` | The only signal color — danger / just-banned / under scan |

Express severity as `alert` at varying opacity, e.g. `rgb(215 64 43 / 0.08)` for a
faint row wash up to full `#D7402B` for the hottest mark on the Sentinel line. Dark
theme inverts the canvas (see front matter `colors.dark`) but **keeps `alert`
unchanged** — the signal must read identically in both themes.

Contrast: `ink` on `paper`/`panel` and `muted` on `panel` must meet WCAG AA
(≥ 4.5:1 body, ≥ 3:1 large/UI). `alert` text on `panel` is for emphasis only; pair
with weight/size, never rely on red alone (colorblind-safe).

## Typography

Three roles, **self-hosted** in `embed.FS` — no external CDN (a security product must
not phone home for fonts).

| Role | Family | Used for |
|---|---|---|
| Display | **Space Grotesk** 600/700 | Wordmark, headings, large readout numbers |
| Body / UI | **IBM Plex Sans** 400/500 | Labels, descriptions, buttons |
| Data | **IBM Plex Mono** 400/500 | IP, port, ASN, timestamps, counts |

Data (IP / port / time) **must** be monospace so columns align and read precisely —
this is the defining typographic trait of a security tool. Tabular figures for all
counts.

## Layout

- Content max width `1120px`, centered, generous breathing room — an instrument panel,
  not a dense console.
- Base `gap` = `16px`; readout cards in a responsive 4-up grid that folds to 2-up then
  1-up. The ledger table folds to stacked cards below a narrow breakpoint.
- Top bar (wordmark · state chip · host · theme toggle) → **Sentinel line** directly
  beneath it → content. The Sentinel line is full-bleed within the content column.

## Elevation & Depth

Mostly flat. Separate surfaces with `line` hairlines and the `panel`/`paper` value
step, **not** heavy shadows. At most one very soft shadow on cards
(`0 1px 2px rgb(22 24 29 / 0.04)`). Depth is quiet; the only thing allowed to draw the
eye is the Sentinel line and a live `alert` mark.

## Shapes

- Corner radius `8px` (`radius_default`) on cards, inputs, buttons. Consistent — no
  mixed radii.
- Focus ring visible on every control (2px, `alert` or `ink` at high contrast) — the
  product must be fully keyboard-operable.

## Components

### Signature — "Sentinel line"

The one memorable element: a thin horizontal timeline strip just under the top bar,
drawing each detection event like a seismograph/ECG of the server's exposure.

- Each event = a vertical tick. **Height = severity**, **opacity = intensity** (of
  `alert`).
- **Banned** = solid tick; **dry-run "would-ban"** = hollow/outline tick.
- Quiet server = near-flat, still line. Under scan = sharp visible spikes.

All the boldness is concentrated here; everything around it stays silent and
disciplined. Respect `prefers-reduced-motion`: keep updating, drop easing/animation,
never flash.

### Readout cards

Large monospace number + a tiny sparkline + a 24h label (e.g. `BANNED · 142 · ▁▂▃▂▁`).
Neutral by default; tint with `alert` wash only when the metric itself is alarming.

### State chip

Plain-language status, sentence case: **Quiet** / **Under scan** — never internal
codes. Quiet = neutral; Under scan = `alert`.

### Ledger table (Banned IPs)

Dense but readable. Mono, left-aligned columns: IP · detector · first seen · expires
(live countdown) · origin (country·ASN). `Unban` is a write action with a confirm.
Folds to stacked cards on mobile.

### Buttons & forms

Button label states exactly what it does: **Unban**, not "Submit". Sentence case,
active voice. Inputs use `panel` fill, `line` border, `radius_default`, visible focus.

### States

- **Empty** (inviting, not blank): *"No bans yet. edge-guardian is watching."*
- **Error** (directive, not apologetic): *"Can't reach the daemon. Check the service:
  systemctl status edge-guardian."*

## Do's and Don'ts

**Do**
- Spend `alert` sparingly; let it earn attention.
- Use monospace for every piece of machine data (IP/port/ASN/time).
- Keep surfaces flat; separate with hairlines and value, not shadow.
- Self-host all assets (fonts, htmx, css) in the binary. CSP: `script-src 'self'`
  (strict, no inline scripts); `style-src 'self' 'unsafe-inline'` (HTMX and the
  data-driven Sentinel/bar styles need inline styles; values are server-computed, not
  attacker input).
- Honor reduced-motion, dark theme (keep `alert` constant), and full keyboard access.

**Don't**
- Don't use neon-green-on-black, rainbow palettes, or red as decoration.
- Don't introduce a second accent color or extra radii.
- Don't load anything from a CDN.
- Don't sell features in UI copy — describe plainly what each control does.
