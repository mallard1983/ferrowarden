# Drop-in README logo header

Copy the branding directory to `branding/` at the Ferrowarden repository root, then place this HTML at the top of `README.md`:

```html
<p align="center">
  <img src="branding/assets/png/banners/ferrowarden-readme-dark.png"
       alt="Ferrowarden — The credential boundary for AI agents"
       width="100%">
</p>
```

If the logo text duplicates a visible H1, set `alt=""` to avoid duplicate spoken branding. Keep the README's existing CI, license and other badges immediately below the header and retain all installation/security documentation as-is.
