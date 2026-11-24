# Brand kit publishing checklist

## Visual identity

- [ ] Mark matches the maintainer-approved hybrid in `source/approved-reference.png`.
- [ ] Outer portal has diagonal upper-left shoulder and rounded top-right; no battlements.
- [ ] Copper F and right-hand wedge preserve their geometry and spacing.
- [ ] Light gateway is Iron; dark gateway is Paper; copper F stays Copper.
- [ ] Wordmark is spelled `Ferrowarden`, with correct capitalization.
- [ ] Tagline reads exactly `The credential boundary for AI agents`.

## Files

- [ ] SVG mark and wordmark files open without missing image resources.
- [ ] PNG icons have alpha where intended, and tiles have square backgrounds.
- [ ] ICO contains 16/32/48/64 px images and renders in browsers.
- [ ] Apple touch icon, Android icons, pinned tab and webmanifest are present.
- [ ] The README banner is 1280 × 320 and social image is 1200 × 630.
- [ ] SVG and PNG banners use matching geometry and wording.
- [ ] No external font files are included in the package.

## Accessibility

- [ ] Light/dark themes are legible.
- [ ] Copper is not the only channel for status/error/success semantics.
- [ ] Small tagline is hidden or replaced in narrow UI.
- [ ] Decorative icons have empty alt text; informative graphics have meaningful alt text.
- [ ] Favicon tested at actual 16 px and in both light/dark browser chrome.

## Documentation and ownership

- [ ] README paths work after copying the kit into the actual repository.
- [ ] Site Open Graph URLs are changed from example values to real production URLs.
- [ ] The security messaging matches the current product threat model and implementation.
- [ ] The project maintainer has decided how artwork and trademark permissions are granted.
- [ ] No upstream endorsement or affiliation is falsely implied.
