# Landing page i18n

The landing page is **generated** from one English source, so there's a single place to
edit copy and the localized pages stay in sync.

```
landing/
  index.src.html     ← EDIT THIS (English source, with <!--EG_HREFLANG--> / <!--EG_LANGSWITCH--> markers)
  i18n/<lang>.json    ← per-language string map: "exact English HTML" → "translation"
  build-i18n.go        ← generator (stdlib, //go:build ignore)
  index.html           ← GENERATED (English, default, served at /)
  <lang>/index.html    ← GENERATED (fr, de, es, zh, vi, …)
```

## Rebuild after any change

```bash
cd landing && go run build-i18n.go
```

It applies each language's map, sets `<html lang>`, and injects the hreflang block + the
language switcher (only for languages that actually have a dict — no dead links).

## Add a language

1. Add it to the `langs` slice in `build-i18n.go` (code, switcher label, path).
2. Create `i18n/<code>.json` mapping the English strings to translations.
3. `go run build-i18n.go`.

## Editing copy

Edit `index.src.html`, then update the matching English **key** in each `i18n/*.json`
(the key is the exact English HTML substring — keep entities like `&#8209;`, `&amp;`,
`&middot;` intact). Re-run the generator. Keys with no entry fall back to English.

The dashboard mock and shell commands are intentionally left in English.
