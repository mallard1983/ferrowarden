#!/usr/bin/env python3
"""Optional: convert editable Inter text in SVG lockups/banners into paths.

This exports source-independent SVG artwork without embedding or shipping fonts.
Install Inter locally, set FERROWARDEN_FONT_DIR if needed, and run this script
*after* build_assets.py. The original editable SVGs are preserved.
"""
from __future__ import annotations
import os,re
from pathlib import Path
from functools import lru_cache
from xml.sax.saxutils import escape
from fontTools.ttLib import TTFont
from fontTools.pens.svgPathPen import SVGPathPen
from PIL import ImageFont

ROOT=Path(__file__).resolve().parent.parent
FONTPATHS={}
fontdir=os.environ.get('FERROWARDEN_FONT_DIR','/usr/share/fonts/opentype/inter')
for name in ['Bold','Medium','Regular']:
    p=Path(fontdir)/f'Inter-{name}.otf'
    if not p.exists():
        raise SystemExit(f'Font missing: {p}. Install Inter or set FERROWARDEN_FONT_DIR.')
    FONTPATHS[name]=p

@lru_cache(None)
def fnt(style):
    ft=TTFont(FONTPATHS[style]);return (ft,ft.getBestCmap(),ft.getGlyphSet(),ft['head'].unitsPerEm)

@lru_cache(None)
def glyph_path(style,char):
    ft,cmap,glyphs,upem=fnt(style)
    name=cmap.get(ord(char))
    if not name:return ''
    pen=SVGPathPen(glyphs)
    glyphs[name].draw(pen)
    return pen.getCommands()

@lru_cache(None)
def pil_font(style,size):
    return ImageFont.truetype(str(FONTPATHS[style]),size)

def to_paths(attrs,source):
    aa=dict(re.findall(r'(\S+)="([^"]*)"',attrs))
    txt=source.replace('&amp;','&').replace('&lt;','<').replace('&gt;','>')
    style='Bold' if int(aa.get('font-weight','400'))>=650 else 'Medium' if int(aa.get('font-weight','400'))>=500 else 'Regular'
    size=float(aa['font-size']); sizeint=round(size)
    x=float(aa.get('x',0)); y=float(aa.get('y',0)); space=float(aa.get('letter-spacing',0))
    font=pil_font(style,sizeint)
    width=font.getlength(txt)+(len(txt)-1)*space
    anchor=aa.get('text-anchor','start')
    if anchor=='middle': x-=width/2
    if anchor=='end': x-=width
    *_,upem=fnt(style)
    s=size/upem
    chunks=[f'<g fill="{aa.get("fill","#17212B")}" aria-label="{escape(txt)}">']
    for i,c in enumerate(txt):
        d=glyph_path(style,c)
        if d:
            pos=x+font.getlength(txt[:i])+i*space
            chunks.append(f'<path d="{d}" transform="translate({pos:.3f} {y:.3f}) scale({s:.7f} {-s:.7f})"/>')
    chunks.append('</g>')
    return ''.join(chunks)

for sub in ['lockups','banners']:
    source=ROOT/'assets'/'svg'/sub
    dest=ROOT/'assets'/'svg'/f'{sub}-outlined'
    dest.mkdir(parents=True,exist_ok=True)
    for src in source.glob('*.svg'):
        xml=src.read_text(encoding='utf8')
        converted=re.sub(r'<text([^>]*)>([^<]*)</text>',lambda m:to_paths(m.group(1),m.group(2)),xml)
        (dest/src.name).write_text(converted,encoding='utf-8')
        print(dest/src.name)
