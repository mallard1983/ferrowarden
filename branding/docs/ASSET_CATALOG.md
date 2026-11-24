# Asset catalog and file map

All paths below are relative to the root of this downloaded **brand kit**. Copy the kit to your repository under `branding/` if you want to use these paths in GitHub Markdown.

## SVG masters

### Icon variants

| File | Canvas | Background | Use |
| --- | --- | --- | --- |
| `assets/svg/marks/ferrowarden-mark-light.svg` | 300 × 270 | Transparent | Default mark on light |
| `assets/svg/marks/ferrowarden-mark-dark.svg` | 300 × 270 | Transparent | Mark on dark |
| `assets/svg/marks/ferrowarden-mark-mono-iron.svg` | 300 × 270 | Transparent | Single-color on light |
| `assets/svg/marks/ferrowarden-mark-mono-paper.svg` | 300 × 270 | Transparent | Single-color on dark |
| `assets/svg/marks/ferrowarden-tile-light.svg` | 512 × 512 | Paper | App tile; white UI |
| `assets/svg/marks/ferrowarden-tile-dark.svg` | 512 × 512 | Deep Iron | App tile; dark UI |
| `assets/svg/marks/ferrowarden-tile-light-square.svg` | 512 × 512 | Paper | Square background variant |
| `assets/svg/marks/ferrowarden-tile-dark-square.svg` | 512 × 512 | Deep Iron | Square background variant |
| `assets/svg/marks/ferrowarden-tile-maskable-dark.svg` | 512 × 512 | Deep Iron | PWA-safe-zone icon for masks |

### Wordmarks and lockups

- `assets/svg/lockups/ferrowarden-lockup-light-tagline.svg`
- `assets/svg/lockups/ferrowarden-lockup-dark-tagline.svg`
- `assets/svg/lockups/ferrowarden-lockup-light-plain.svg`
- `assets/svg/lockups/ferrowarden-lockup-dark-plain.svg`
- `assets/svg/lockups/ferrowarden-stacked-light.svg`
- `assets/svg/lockups/ferrowarden-stacked-dark.svg`

Matching font-independent, outlined versions live in `assets/svg/lockups-outlined/`; the originals retain editable text.

The horizontal SVG canvas is **1260 × 295**. The stacked canvas is **940 × 445**. Logo text is editable text; install Inter for faithful rendering.

## PNG icon raster export set

All four categories (`mark-light`, `mark-dark`, `tile-light`, `tile-dark`) have 12 square exports each at:

**16, 24, 32, 48, 64, 96, 128, 180, 192, 256, 512 and 1024 px.**

Filename pattern: `assets/png/icons/ferrowarden-{variant}-{size}.png`. Thus `assets/png/icons/ferrowarden-tile-dark-512.png` is a valid application icon and `...mark-light-64.png` is a transparent standalone logo.

The transparent SVG mark's natural viewBox is not square (300 × 270). In the square PNG icon exports, its width and height are set to the selected pixel dimension and the graphic scales uniformly, preserving the SVG viewBox aspect ratio with a small internal padding. The tile versions are square backgrounds with intentionally larger padding.

## Favicons and avatars

| File | Use |
| --- | --- |
| `assets/favicons/favicon.ico` | Multi-size browser favicon (16/32/48/64) |
| `assets/favicons/favicon-16.png` | Browser PNG fallback |
| `assets/favicons/favicon-32.png` | Browser PNG fallback |
| `assets/favicons/favicon-48.png` | Browser PNG fallback |
| `assets/favicons/apple-touch-icon.png` | 180 × 180 Apple home-screen icon |
| `assets/favicons/android-chrome-192x192.png` | Android/PWA icon |
| `assets/favicons/android-chrome-512x512.png` | Android/PWA icon |
| `assets/favicons/android-maskable-512x512.png` | Android/PWA icon with safe-zone padding |
| `assets/favicons/github-avatar-512.png` | Square GitHub repository/organization identity |
| `assets/favicons/safari-pinned-tab.svg` | One-color Safari pinned tab |
| `assets/favicons/site.webmanifest` | PWA display metadata |

## Banners — SVG and PNG

Every banner has an identically named editable-text SVG at `assets/svg/banners/`, a font-independent outlined SVG at `assets/svg/banners-outlined/`, and PNG at `assets/png/banners/`.

| Basename | Exact resolution | Intended surface |
| --- | --- | --- |
| `ferrowarden-readme-dark` | 1280 × 320 | GitHub README banner, primary |
| `ferrowarden-readme-light` | 1280 × 320 | Light-themed alternatives |
| `ferrowarden-social-og` | 1200 × 630 | GitHub/Open Graph/social image |
| `ferrowarden-docs-header` | 1600 × 400 | Documentation site hero/header |
| `ferrowarden-release-header` | 1440 × 320 | Release notes or changelogs |
| `ferrowarden-site-hero` | 1920 × 480 | Wide landing page hero |
| `ferrowarden-dashboard-header` | 1920 × 480 | Administration UI/header |

Raster lockups also ship at widths **630**, **1260** and **2520** px, plus 940 px stacked variants.

## Design tokens and build files

- `tokens/ferrowarden.css`: CSS custom properties.
- `tokens/design-tokens.json`: source values for colors, typography and naming.
- `scripts/build_assets.py`: source path definitions and file generator.
- `source/approved-reference.png`: approved image, included to check the identity's history and intended geometry.
- `previews/brand-kit-overview.png`: overview contact sheet.

## Selection priority

Prefer **SVG** for websites, documentation headings and apps that support it; prefer **PNG** for GitHub README banners, OG cards, avatars, and image consumers without SVG support; use **ICO** only for browser favicons. Do not enlarge 16 px raster icons for headers. Use the corresponding larger PNG or SVG.
