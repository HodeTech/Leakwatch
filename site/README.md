# Leakwatch website

The marketing site and documentation portal for Leakwatch, published to GitHub
Pages. It is a **dependency-free static site** — plain HTML, CSS, and vanilla
JavaScript, no runtime framework and no client-side build step. The visual
concept is **"Redacted"**: a classified-dossier aesthetic with redaction bars,
scan-line reveals, and evidence stamps. Dark-only by design.

## Structure

```
site/
├── index.html          Landing page (Redacted hero with a scan-reveal document)
├── docs.html           Documentation portal (sidebar + hash-routed content)
├── contact.html        Contact page (Formspree-backed form + GitHub channels)
├── css/style.css       Design system (the Redacted dossier theme)
├── js/
│   ├── translations.js UI strings for EN / TR (marketing chrome + docs shell)
│   ├── i18n.js         Language detection, switching, persistence
│   ├── main.js         Mobile nav, copy buttons, hero scan animation, contact form
│   ├── docs.js         Docs portal controller (nav, routing, search, Mermaid)
│   └── manuals/        GENERATED — compiled manual content (do not edit by hand)
│       ├── _index.js   Navigation tree (from docs/user-manuals/_meta.yaml)
│       ├── en.js       English manual pages, rendered to HTML
│       └── tr.js       Turkish manual pages, rendered to HTML
├── assets/             favicon.svg, og.svg
└── .nojekyll           Disable Jekyll (so files like _index.js are served)
```

## Internationalization

The site is bilingual (English + Turkish) with **client-side switching**: a
single set of URLs, with the language toggled in the navbar and remembered in
`localStorage`. UI strings live in `js/translations.js`; manual content is
compiled per language into `js/manuals/<lang>.js`.

## Contact form (Formspree)

`contact.html` posts to [Formspree](https://formspree.io). Before it works you
must create a free form and paste its endpoint ID:

1. Create a form at https://formspree.io and copy your form ID.
2. In `contact.html`, replace `YOUR_FORM_ID` in the form's `action`:
   `https://formspree.io/f/YOUR_FORM_ID` → `https://formspree.io/f/abcdwxyz`.

The form submits via `fetch` (inline success/error) and degrades to a normal
POST without JavaScript. It includes a honeypot field and never asks for secrets.

## Editing the documentation

Manual pages are authored as Markdown under
[`../docs/user-manuals/`](../docs/user-manuals/):

```
docs/user-manuals/
├── _meta.yaml                       navigation: sections, page order, titles
├── en/<section>/<page>.md           English source
└── tr/<section>/<page>.md           Turkish source
```

Each page has YAML front matter (`title`, `description`), GFM Markdown, fenced
code blocks, optional `:::tip` / `:::note` / `:::warn` / `:::danger` callouts,
and ` ```mermaid ` diagrams. Cross-links use the hash-router form
`[Label](#/<section>/<page>)`.

After editing Markdown (or `_meta.yaml`), regenerate the compiled bags:

```bash
cd tools/site-build
go run .            # add -strict to fail on any missing translation
```

## Local preview

Serve the folder over HTTP (the docs portal loads JS files, so `file://` will
not work):

```bash
cd site
python3 -m http.server 8080
# then open http://localhost:8080/
```

## Deployment

Pushes to `main` that touch `site/`, `docs/user-manuals/`, or
`tools/site-build/` trigger
[`.github/workflows/site-deploy.yml`](../.github/workflows/site-deploy.yml),
which recompiles the manuals and deploys `site/` to GitHub Pages. Enable it once
under **Settings → Pages → Build and deployment → Source: GitHub Actions**.
