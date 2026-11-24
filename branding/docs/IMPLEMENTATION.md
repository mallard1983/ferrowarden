# Implementing Ferrowarden branding

Assume the full kit has been copied to `branding/` at the root of the Ferrowarden repo. If assets are placed elsewhere, update these relative paths.

## README header

Use the PNG banner for compatibility with GitHub and other Markdown renderers:

```md
<p align="center">
  <img src="branding/assets/png/banners/ferrowarden-readme-dark.png"
       width="100%" alt="Ferrowarden — The credential boundary for AI agents">
</p>

A credential proxy for AI agents. Agents use named vault placeholders;
Ferrowarden forwards authenticated API calls without returning credential
values to the agent by design.
```

To avoid duplicate text on screen readers, a README with a visible `# Ferrowarden` heading can use `alt=""` for the banner image instead.

## Header without the embedded tagline

Use an SVG lockup with no tagline when placing it beside readable live text:

```html
<img src="/branding/assets/svg/lockups/ferrowarden-lockup-light-plain.svg"
     alt="Ferrowarden" width="360" height="84">
<p>The credential boundary for AI agents</p>
```

## Favicon and PWA metadata

Copy everything under `assets/favicons/` to your site web root (or change paths accordingly):

```html
<link rel="icon" href="/favicon.ico" sizes="any">
<link rel="icon" href="/favicon-32.png" type="image/png" sizes="32x32">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="mask-icon" href="/safari-pinned-tab.svg" color="#17212B">
<link rel="manifest" href="/site.webmanifest">
<meta name="theme-color" content="#101820">
```

## Open Graph and social sharing

For a website, upload `ferrowarden-social-og.png` (1200 × 630) and set an absolute production URL:

```html
<meta property="og:type" content="website">
<meta property="og:title" content="Ferrowarden">
<meta property="og:description" content="The credential boundary for AI agents">
<meta property="og:image" content="https://YOUR-DOMAIN.example/ferrowarden-social-og.png">
<meta name="twitter:card" content="summary_large_image">
```

The placeholder URL above must be replaced; the brand kit does not assume a production domain exists.

## React/HTML header

```jsx
export function BrandHeader() {
  return (
    <header className="brand-header">
      <img
        src="/branding/assets/svg/marks/ferrowarden-mark-light.svg"
        alt=""
        width="48"
        height="43"
      />
      <div>
        <strong>Ferrowarden</strong>
        <small>The credential boundary for AI agents</small>
      </div>
    </header>
  );
}
```

Select `ferrowarden-mark-dark.svg` with theme state for dark UI. The icon is decorative here because the visible text supplies the accessible name.

## CSS tokens

Include `tokens/ferrowarden.css` in your UI build or copy its custom properties into the app's theme definitions.

```css
.brand-header {
  display: flex;
  align-items: center;
  gap: 1rem;
  color: var(--fw-text);
  font-family: var(--fw-font);
}
.brand-header > div {
  display: flex;
  flex-direction: column;
  line-height: 1.25;
}
.brand-header strong { font-size: 1.125rem; font-weight: 700; }
.brand-header small { color: var(--fw-muted); font-size: .8rem; }
```

## Documentation header

For static site generators, use `assets/png/banners/ferrowarden-docs-header.png` as a hero image, or render the SVG version if the framework accepts SVG assets. For nav bars, use the plain logo or symbol alone.

## GitHub repository avatar

Use `assets/favicons/github-avatar-512.png` for services that let the project or organization set an avatar. GitHub's repository social preview image is distinct: use `assets/png/banners/ferrowarden-social-og.png` there instead, where available.

## Dark mode

The F remains copper on both themes. Switch the outer portal to the lighter approved steel token (`--fw-dark-steel`) and the gateway to Paper. Do **not** invert the entire icon with CSS `filter: invert()`; that would also recolor the F incorrectly.

## Package integration checklist

1. Copy `branding/` into the repository.
2. Add the README banner and verify it on GitHub (including mobile widths).
3. Add favicons/webmanifest to the actual web root and update their URLs.
4. Use the SVG mark and CSS tokens in the admin UI or docs site, as applicable.
5. Review image alt text and contrast under both light and dark themes.
6. Confirm a project-owned logo/trademark policy before external redistribution.
