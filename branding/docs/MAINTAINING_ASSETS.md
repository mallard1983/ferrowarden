# Maintaining and regenerating the brand assets

## Source-of-truth hierarchy

1. **Approved visual reference:** `source/approved-reference.png` (the user-selected hybrid image).
2. **Vector master geometry:** the three `PORTAL`, `F_PATH`, and `GATE` paths in `scripts/build_assets.py`.
3. **Design tokens:** `tokens/design-tokens.json` and the constants in the build script.
4. **Derived exports:** all SVG variants, PNGs, ICO, manifest and contact sheet.

The supplied icon paths are a hand-tuned vector interpretation of the approved raster. Because that raster did not include original Bézier source files, the package should not be represented as restoring the source artist's exact hidden control points. Geometry, silhouette, placement, identity and colors are designed to match the approved final concept.

## Regeneration

Python 3.10+ is recommended. Install the dependencies listed in `requirements.txt`, ensure **Inter** is available locally if you require exact raster text appearance, and run:

```sh
python scripts/build_assets.py
```

The generator is local/offline. For portable SVG text outlines, install Inter and `fonttools`, then run `python scripts/outline_svg_text.py` after the main generator. This writes copies under `assets/svg/*-outlined/` while leaving editable text intact. It writes all derived files in place and can be committed to git. Make changes through the central script, not the PNG exports, so variants stay consistent.

## Safe editing workflow

1. Duplicate the approved asset set in a branch.
2. Adjust the three vector paths or a token only after an intentional design decision.
3. Generate assets; review light and dark lockups and compare against the approved reference.
4. Inspect at 16, 24, 32, 64, 256 and 512 px. Small sizes can fail even when the large vector looks fine.
5. Inspect the README, social card, docs header and admin-header crops across different viewport widths.
6. Re-run the acceptance checks in `RELEASE_CHECKLIST.md` before publishing.

## Typography and font licensing

No font binaries are bundled. SVG lockups reference Inter by family name; a system fallback is available but may shift kerning. For strict corporate consistency across machines, install an appropriate freely licensed copy of Inter in the design environment. If distribution requires complete font independence, convert a duplicate of the SVG's text to vector outlines in your graphics editor while retaining the editable-text source files here.

## Migration into the repository

A suggested repository arrangement is:

```text
ferrowarden/
├── README.md
├── branding/
│   ├── README.md
│   ├── docs/
│   ├── assets/
│   ├── tokens/
│   ├── source/
│   ├── scripts/
│   └── previews/
└── ...
```

Keep upstream Vaultwarden/Bitwarden logos out of the Ferrowarden primary mark. If a README says “Built as a sidecar to Vaultwarden,” express the relationship as prose or a separate attribution/link, not a fused emblem.
