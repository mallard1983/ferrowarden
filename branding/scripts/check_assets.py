#!/usr/bin/env python3
"""Validate Ferrowarden asset bundle without network calls."""
from pathlib import Path
from PIL import Image
import xml.etree.ElementTree as ET
import json, re
ROOT=Path(__file__).resolve().parent.parent
issues=[]
svgs=list((ROOT/'assets'/'svg').rglob('*.svg'))
for p in svgs:
    try:
        root=ET.parse(p).getroot()
        if 'viewBox' not in root.attrib: issues.append(f'Missing viewBox: {p}')
        contents=p.read_text(encoding='utf8')
        if re.search(r'<image\b|href="(?:https?://|file:)',contents):
            issues.append(f'Unexpected external image/resource: {p}')
    except Exception as e:issues.append(f'Invalid SVG {p}: {e}')
expected={
    'ferrowarden-readme-dark':(1280,320), 'ferrowarden-readme-light':(1280,320),
    'ferrowarden-social-og':(1200,630), 'ferrowarden-docs-header':(1600,400),
    'ferrowarden-release-header':(1440,320), 'ferrowarden-site-hero':(1920,480),
    'ferrowarden-dashboard-header':(1920,480)}
for name,dim in expected.items():
    for ext in ['svg','png']:
        p=ROOT/'assets'/ext/'banners'/f'{name}.{ext}'
        if not p.exists(): issues.append(f'Missing {p}')
        if ext=='png' and p.exists() and Image.open(p).size!=dim:
            issues.append(f'Wrong size {p}: {Image.open(p).size}')
for variant in ['mark-light','mark-dark','tile-light','tile-dark']:
    for size in [16,24,32,48,64,96,128,180,192,256,512,1024]:
        p=ROOT/'assets/png/icons'/f'ferrowarden-{variant}-{size}.png'
        if not p.exists(): issues.append(f'Missing {p}')
        elif Image.open(p).size!=(size,size): issues.append(f'Wrong icon size {p}')
for name in ['BRAND_GUIDE.md','ASSET_CATALOG.md','LOGO_USAGE.md','VOICE_AND_MESSAGING.md','IMPLEMENTATION.md','MAINTAINING_ASSETS.md','RELEASE_CHECKLIST.md']:
    if not (ROOT/'docs'/name).exists(): issues.append(f'Missing docs/{name}')
manifest=json.loads((ROOT/'assets/favicons/site.webmanifest').read_text())
if len(manifest.get('icons',[]))<3:issues.append('PWA manifest incomplete')
ico=Image.open(ROOT/'assets/favicons/favicon.ico')
if set(ico.ico.sizes())!={(16,16),(32,32),(48,48),(64,64)}:
    issues.append(f'Unexpected favicon resolutions {ico.ico.sizes()}')
for sub in ['lockups','banners']:
    edits={x.name for x in (ROOT/'assets/svg'/sub).glob('*.svg')}
    outlines={x.name for x in (ROOT/'assets/svg'/f'{sub}-outlined').glob('*.svg')}
    if edits!=outlines:issues.append(f'Missing outlined SVGs for {sub}: {edits-outlines}')
if not (ROOT/'source/approved-reference.png').exists():issues.append('Approved source image missing')
if issues:
    print('\n'.join('FAIL: '+x for x in issues));raise SystemExit(1)
print(f'PASS: {len(svgs)} valid SVGs, {len(expected)} correctly sized banners, 48 icon PNGs, 4 ICO sizes, docs and manifest')
