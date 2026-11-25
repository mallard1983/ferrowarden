#!/usr/bin/env python3
"""Rebuild Ferrowarden vector/raster assets from the approved hybrid symbol.

Requires Python 3.10+, Pillow and CairoSVG; Inter should be installed for ideal
PNG text rendering. SVG masters contain editable text with system fallbacks.
Source of truth: the user-approved hybrid raster in source/approved-reference.png.
No external network or bundled fonts are required.
"""
from __future__ import annotations
import io
import json
import math
import os
from pathlib import Path
from xml.sax.saxutils import escape
from PIL import Image
import cairosvg

ROOT=Path(__file__).resolve().parent.parent
SV=ROOT/'assets'/'svg'
PN=ROOT/'assets'/'png'
FV=ROOT/'assets'/'favicons'
for p in [SV/'marks', SV/'lockups', SV/'banners', PN/'icons', PN/'lockups', PN/'banners', FV, ROOT/'previews', ROOT/'tokens']:
    p.mkdir(parents=True,exist_ok=True)

C={'iron':'#17212B','steel':'#3D5967','copper':'#CB7545','paper':'#F6F8F9','mist':'#A6B7C4','deep_iron':'#101820','dark_steel':'#7797A8'}
TAGLINE='The credential boundary for AI agents'
# Path coordinates form a 300x270 engineering master, traced and simplified
# from the user's APPROVED hybrid logo (no battlements, not earlier variants).
# The outer portal has the distinctive diagonal left shoulder and rounded top.
PORTAL='M 7 92 Q 7 80 19 70 L 80 11 Q 90 0 104 0 H 272 Q 295 0 295 23 V 268 H 243 V 62 Q 243 58 239 58 H 111 Q 105 58 100 63 L 69 91 Q 62 98 62 107 V 268 H 7 Z'
F_PATH='M 106 94 H 223 Q 226 94 226 97 V 128 Q 226 130 223 130 H 135 V 154 H 194 Q 196 154 196 157 V 176 Q 196 178 194 179 L 161 196 H 135 V 264 Q 135 268 131 268 H 94 Q 90 268 90 264 V 110 Q 90 94 106 94 Z'
GATE='M 160 221 Q 160 218 164 216 L 222 189 Q 226 187 226 192 V 263 Q 226 268 221 268 H 164 Q 160 268 160 264 Z'

FONT="'Inter','Arial',sans-serif"

def svg_root(w,h,inside,description):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" '
            f'role="img" aria-label="{escape(description)}">\n<title>{escape(description)}</title>\n{inside}\n</svg>\n')

def write_svg(rel,w,h,inside,description):
    p=SV/rel
    p.parent.mkdir(parents=True,exist_ok=True)
    p.write_text(svg_root(w,h,inside,description),encoding='utf-8')
    return p

def png_from_svg(svg_path,outpath,w=None,h=None):
    args={'url':str(svg_path),'write_to':str(outpath)}
    if w is not None: args['output_width']=int(w)
    if h is not None: args['output_height']=int(h)
    cairosvg.svg2png(**args)

def txt(x,y,s,size,weight,fill,letter_spacing=None,anchor=None):
    attrs=(f' x="{x}" y="{y}" fill="{fill}" font-family="{FONT}" '
           f'font-size="{size}" font-weight="{weight}"')
    if anchor: attrs+=f' text-anchor="{anchor}"'
    if letter_spacing is not None: attrs+=f' letter-spacing="{letter_spacing}"'
    return f'<text{attrs}>{escape(s)}</text>'

def mark_inner(outer,gate,offset_x=0,offset_y=0,scale=1):
    return (f'<g transform="translate({offset_x} {offset_y}) scale({scale})">'
            f'<path d="{PORTAL}" fill="{outer}"/>'
            f'<path d="{F_PATH}" fill="{C["copper"]}"/>'
            f'<path d="{GATE}" fill="{gate}"/>'
            '</g>')

def mono_inner(color,ox=0,oy=0,scale=1):
    return (f'<g transform="translate({ox} {oy}) scale({scale})">'
            f'<path d="{PORTAL}" fill="{color}"/><path d="{F_PATH}" fill="{color}"/><path d="{GATE}" fill="{color}"/></g>')

def square_tile(dark=True,rounded=True):
    fill=C['deep_iron'] if dark else C['paper']
    outer=C['dark_steel'] if dark else C['steel']
    gate=C['paper'] if dark else C['iron']
    radius=64 if rounded else 0
    return f'<rect x="0" y="0" width="512" height="512" rx="{radius}" fill="{fill}"/>' + mark_inner(outer,gate,36,50,1.46)

def lockup(dark=False,tagline=True):
    outer=C['dark_steel'] if dark else C['steel']
    gate=C['paper'] if dark else C['iron']
    fg=C['paper'] if dark else C['iron']
    sub=C['mist'] if dark else C['steel']
    components=mark_inner(outer,gate,22,25,.93)
    components+=txt(340,157,'Ferrowarden',100,750,fg,letter_spacing='-3')
    if tagline: components+=txt(343,213,TAGLINE,33,500,sub,letter_spacing='-.25')
    return components

def diagonal_decor(w,h,dark):
    # Subtle continuation of the icon's upper-left chamfer, not a second logo.
    if dark:
        return (f'<path d="M {w-430} {h} L {w-178} {h-250} H {w-75} L {w-324} {h} Z" fill="{C["steel"]}" opacity=".22"/>'
                f'<path d="M {w-255} {h} L {w-62} {h-193} H {w} V {h-149} L {w-149} {h} Z" fill="{C["dark_steel"]}" opacity=".13"/>')
    return (f'<path d="M {w-300} {h} L {w-90} {h-210} H {w+20} L {w-182} {h} Z" fill="{C["mist"]}" opacity=".26"/>')

def banner_inner(w,h,style='dark',tagline=True,label=None,hero=False):
    dark=style=='dark'
    bg=C['deep_iron'] if dark else C['paper']
    outer=C['dark_steel'] if dark else C['steel']
    gate=C['paper'] if dark else C['iron']
    title=C['paper'] if dark else C['iron']
    subt=C['mist'] if dark else C['steel']
    t=min(h*.57,270)/270
    # Relative mark and type scale adapt to banner height.
    logo_h=min(h*.64,260)
    scale=logo_h/270
    ox=int(w*.052)
    oy=(h-270*scale)/2
    textx=ox+305*scale+32
    # title dimensions limited by available width; use size suited to the banner's height.
    title_sz=min(max(46,h*.27),106)
    tag_sz=min(max(22,h*.105),39)
    title_y= h*.53 if tagline else h*.62
    tagline_y=title_y+tag_sz*1.45
    bg_rect=f'<rect width="{w}" height="{h}" rx="0" fill="{bg}"/>'
    ins=bg_rect+diagonal_decor(w,h,dark)
    ins+=mark_inner(outer,gate,ox,oy,scale)
    ins+=txt(textx,title_y,'Ferrowarden',round(title_sz,2),740,title,letter_spacing='-1.1')
    if tagline: ins+=txt(textx,tagline_y,TAGLINE,round(tag_sz,2),500,subt)
    if label:
        ins+=txt(w-55,h-37,label.upper(),23,650,C['copper'] if dark else C['steel'],letter_spacing='1.8',anchor='end')
    if hero:
        ins+=txt(textx,h-35,'SOURCE AVAILABLE  /  CREDENTIAL PROXY  /  AGENT ACCESS',22,620,subt,letter_spacing='1.5')
    return ins

# 1. Vector icon masters
write_svg('marks/ferrowarden-mark-light.svg',300,270,mark_inner(C['steel'],C['iron']),'Ferrowarden mark, light background')
write_svg('marks/ferrowarden-mark-dark.svg',300,270,mark_inner(C['dark_steel'],C['paper']),'Ferrowarden mark, dark background')
write_svg('marks/ferrowarden-mark-mono-iron.svg',300,270,mono_inner(C['iron']),'Ferrowarden one-color iron mark')
write_svg('marks/ferrowarden-mark-mono-paper.svg',300,270,mono_inner(C['paper']),'Ferrowarden one-color paper mark')
write_svg('marks/ferrowarden-tile-dark.svg',512,512,square_tile(True),'Ferrowarden dark app icon')
write_svg('marks/ferrowarden-tile-light.svg',512,512,square_tile(False),'Ferrowarden light app icon')
write_svg('marks/ferrowarden-tile-dark-square.svg',512,512,square_tile(True,False),'Ferrowarden square dark app icon')
write_svg('marks/ferrowarden-tile-light-square.svg',512,512,square_tile(False,False),'Ferrowarden square light app icon')
# PWA maskable-safe-zone: scale mark down so circular/system masks do not clip it.
write_svg('marks/ferrowarden-tile-maskable-dark.svg',512,512,
    f'<rect width="512" height="512" fill="{C["deep_iron"]}"/>'+mark_inner(C['dark_steel'],C['paper'],100,111,1.05),
    'Ferrowarden maskable app icon')
# 2. SVG wordmark combinations
for dark in [False,True]:
    scheme='dark' if dark else 'light'
    for tagline in [True,False]:
        suffix='tagline' if tagline else 'plain'
        write_svg(f'lockups/ferrowarden-lockup-{scheme}-{suffix}.svg',1260,295,
            lockup(dark,tagline),f'Ferrowarden {scheme} horizontal lockup {suffix}')
# compact stacked: icon above name, optional tagline
for dark in [False,True]:
    scheme='dark' if dark else 'light'
    outer=C['dark_steel'] if dark else C['steel']
    gate=C['paper'] if dark else C['iron']
    fg=C['paper'] if dark else C['iron']
    sub=C['mist'] if dark else C['steel']
    ins=mark_inner(outer,gate,314,12,1.04)
    ins+=txt(470,370,'Ferrowarden',76,750,fg,'-2','middle')
    ins+=txt(470,417,TAGLINE,27,500,sub,'-.4','middle')
    write_svg(f'lockups/ferrowarden-stacked-{scheme}.svg',940,445,ins,f'Ferrowarden stacked {scheme} logo')

# 3. Scalable banners (SVG and PNG generated from same geometry)
BANNERS=[
('ferrowarden-readme-dark',1280,320,'dark',None,False),
('ferrowarden-readme-light',1280,320,'light',None,False),
('ferrowarden-social-og',1200,630,'dark',None,False),
('ferrowarden-docs-header',1600,400,'light',None,False),
('ferrowarden-release-header',1440,320,'dark','RELEASE NOTES',False),
('ferrowarden-site-hero',1920,480,'dark',None,True),
('ferrowarden-dashboard-header',1920,480,'dark','ADMIN INTERFACE',False),
]
for name,w,h,style,label,hero in BANNERS:
    sp=write_svg(f'banners/{name}.svg',w,h,banner_inner(w,h,style,label=label,hero=hero),f'Ferrowarden {name} banner')
    png_from_svg(sp,PN/'banners'/f'{name}.png',w,h)

# 4. Raster icons: transparent mark, tile light & dark; multiple pixel sizes
for size in [16,24,32,48,64,96,128,180,192,256,512,1024]:
    for typ in ['mark-light','mark-dark','tile-light','tile-dark']:
        src=SV/'marks'/f'ferrowarden-{typ}.svg'
        png_from_svg(src,PN/'icons'/f'ferrowarden-{typ}-{size}.png',size,size)
# Generate a multi-resolution .ico from the highest-resolution tile.
# PIL only stores sizes <= the *base* image, so start from 512px.
base_icon=Image.open(PN/'icons'/'ferrowarden-tile-light-512.png').convert('RGBA')
base_icon.save(FV/'favicon.ico',format='ICO',sizes=[(16,16),(32,32),(48,48),(64,64)])
# Retain distinct PNG favicons for browsers that prefer PNG.
for s in [16,32,48]:
    src=PN/'icons'/f'ferrowarden-tile-light-{s}.png'
    (FV/f'favicon-{s}.png').write_bytes(src.read_bytes())
(FV/'apple-touch-icon.png').write_bytes((PN/'icons'/'ferrowarden-tile-light-180.png').read_bytes())
(FV/'android-chrome-192x192.png').write_bytes((PN/'icons'/'ferrowarden-tile-dark-192.png').read_bytes())
(FV/'android-chrome-512x512.png').write_bytes((PN/'icons'/'ferrowarden-tile-dark-512.png').read_bytes())
png_from_svg(SV/'marks'/'ferrowarden-tile-maskable-dark.svg',FV/'android-maskable-512x512.png',512,512)
(FV/'github-avatar-512.png').write_bytes((PN/'icons'/'ferrowarden-tile-light-512.png').read_bytes())
(FV/'safari-pinned-tab.svg').write_text(svg_root(300,270,mono_inner(C['iron']),'Ferrowarden pinned tab'),encoding='utf-8')
(FV/'site.webmanifest').write_text(json.dumps({
    'name':'Ferrowarden','short_name':'Ferrowarden','description':TAGLINE,
    'icons':[{'src':'android-chrome-192x192.png','sizes':'192x192','type':'image/png'},
             {'src':'android-chrome-512x512.png','sizes':'512x512','type':'image/png'},
             {'src':'android-maskable-512x512.png','sizes':'512x512','type':'image/png','purpose':'maskable'}],
    'theme_color':C['deep_iron'],'background_color':C['paper'],'display':'standalone'
},indent=2)+'\n',encoding='utf-8')

# 5. Raster wordmarks; two standard sizes each with/without tagline.
for style in ['light','dark']:
    for suffix in ['tagline','plain']:
        source=SV/'lockups'/f'ferrowarden-lockup-{style}-{suffix}.svg'
        for width in [630,1260,2520]:
            png_from_svg(source,PN/'lockups'/f'ferrowarden-lockup-{style}-{suffix}-{width}.png',width,round(width*295/1260))
    source=SV/'lockups'/f'ferrowarden-stacked-{style}.svg'
    png_from_svg(source,PN/'lockups'/f'ferrowarden-stacked-{style}-940.png',940,445)

# 6. Tokens for app/docs/CSS tooling.
colors={k:v for k,v in C.items()}
token_json={
    '$schema':'https://design-tokens.github.io/community-group/format/',
    'color':{k:{'$type':'color','$value':v} for k,v in colors.items()},
    'typography':{'family':{'$type':'fontFamily','$value':'Inter, system-ui, sans-serif'},
                  'weights':{'body':{'$value':400},'medium':{'$value':500},'heading':{'$value':700}}},
    'brand':{'name':'Ferrowarden','tagline':TAGLINE}
}
(ROOT/'tokens'/'design-tokens.json').write_text(json.dumps(token_json,indent=2)+'\n',encoding='utf-8')
css=':root {\n'+''.join(f'  --fw-{k.replace("_","-")}: {v};\n' for k,v in colors.items())+'''  --fw-font: "Inter", system-ui, -apple-system, "Segoe UI", sans-serif;
  --fw-radius-md: 12px;
  --fw-radius-lg: 20px;
}
:root[data-theme="dark"] {
  --fw-surface: var(--fw-deep-iron);
  --fw-text: var(--fw-paper);
  --fw-muted: var(--fw-mist);
}
:root:not([data-theme="dark"]) {
  --fw-surface: var(--fw-paper);
  --fw-text: var(--fw-iron);
  --fw-muted: var(--fw-steel);
}
'''
(ROOT/'tokens'/'ferrowarden.css').write_text(css,encoding='utf-8')

# 7. Contact-sheet / visual QA preview generated from exported assets.
from PIL import ImageDraw, ImageFont
W,H=1600,1230
canvas=Image.new('RGB',(W,H),'#E9EDF0')
d=ImageDraw.Draw(canvas)
font_dir='/usr/share/fonts/opentype/inter/'
try:
    hfont=ImageFont.truetype(font_dir+'Inter-Bold.otf',48)
    label_font=ImageFont.truetype(font_dir+'Inter-Medium.otf',24)
    smaller=ImageFont.truetype(font_dir+'Inter-Regular.otf',18)
except Exception:
    hfont=ImageFont.load_default();label_font=hfont;smaller=hfont
# Cards for light/dark lockup, exported banners and tiles.
d.text((60,38),'Ferrowarden  /  Approved identity',font=hfont,fill=C['iron'])

def card(x,y,w,h,fill='#FFFFFF'):
    d.rounded_rectangle((x,y,x+w,y+h),radius=20,fill=fill)

def load_rgba(p,sz):
    im=Image.open(p).convert('RGBA')
    im.thumbnail(sz,Image.Resampling.LANCZOS)
    return im
card(50,118,1500,260)
light=load_rgba(PN/'lockups'/'ferrowarden-lockup-light-tagline-1260.png',(1350,235))
canvas.paste(light,(80,125),light)
card(50,402,1500,260,C['deep_iron'])
dark=load_rgba(PN/'lockups'/'ferrowarden-lockup-dark-tagline-1260.png',(1350,235))
canvas.paste(dark,(80,411),dark)

d.text((65,710),'Common applications',font=ImageFont.truetype(font_dir+'Inter-Bold.otf',33),fill=C['iron'])
card(50,755,285,345)
card(365,755,285,345,C['deep_iron'])
for x,typ in [(75,'tile-light'),(390,'tile-dark')]:
    icon=load_rgba(PN/'icons'/f'ferrowarden-{typ}-256.png',(235,235))
    canvas.paste(icon,(x,777),icon)
# banners 1280x320 previews
for x,y,p,nm in [(690,755,PN/'banners'/'ferrowarden-readme-dark.png','README header'),(690,934,PN/'banners'/'ferrowarden-readme-light.png','Light header')]:
    card(x,y,860,153)
    im=load_rgba(p,(822,125))
    canvas.paste(im,(x+18,y+11),im)
    d.text((x+18,y+130),nm,font=smaller,fill=C['iron'])
d.text((65,1120),'All icons, lockups and banners export from the same vector mark. No image-generated redraws.',font=label_font,fill=C['steel'])
canvas.save(ROOT/'previews'/'brand-kit-overview.png',optimize=True)
print(f'Built Ferrowarden brand kit at {ROOT}')
