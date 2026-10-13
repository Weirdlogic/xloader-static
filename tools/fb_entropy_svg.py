"""Draw a stage-5 entropy-per-1KB SVG (before vs after static decryption) with decrypted ranges shaded.
Pure Python, no plotting dependencies. Reads only local files; writes one SVG.
Usage: fb_entropy_svg.py <original.bin> <decrypted.bin> <stage5-funcs.json> <stage5-funcs-bruteforce.jsonl> <out.svg>"""
import sys, math, json, collections

def ent(b):
    c = collections.Counter(b); n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())

orig, cur = open(sys.argv[1], 'rb').read(), open(sys.argv[2], 'rb').read()
B = 1024; n = len(orig) // B
eo = [ent(orig[i * B:(i + 1) * B]) for i in range(n)]; ec = [ent(cur[i * B:(i + 1) * B]) for i in range(n)]
rng = [(int(r['start_egg_at'], 16), int(r['end_egg_at'], 16), '#2e7d32') for r in json.load(open(sys.argv[3])) if 'key' in r]
rng += [(int(r['start_egg_at'], 16), int(r['end_egg_at'], 16), '#1565c0')
        for r in map(json.loads, open(sys.argv[4])) if r.get('applied')]
rng.append((0xad83, 0xb636, '#ef6c00'))
W, H, L, T, R, Bm = 960, 420, 60, 40, 20, 60; pw, ph = W - L - R, H - T - Bm
x = lambda i: L + pw * i / n; y = lambda e: T + ph * (1 - e / 8)
o = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" font-family="sans-serif" font-size="12">',
     f'<rect width="{W}" height="{H}" fill="#fff"/>',
     f'<text x="{L}" y="22" font-size="15" font-weight="bold">Stage 5 (a0588c55…): Shannon entropy per 1 KB block, before vs after static decryption</text>']
for a, b, c in rng:
    o.append(f'<rect x="{x(a / B):.1f}" y="{T}" width="{max(1, x(b / B) - x(a / B)):.1f}" height="{ph}" fill="{c}" opacity="0.18"/>')
for e in range(0, 9, 2):
    o.append(f'<line x1="{L}" x2="{L + pw}" y1="{y(e):.1f}" y2="{y(e):.1f}" stroke="#ddd"/><text x="{L - 8}" y="{y(e) + 4:.1f}" text-anchor="end">{e}</text>')
for k in range(0, n + 1, 32):
    o.append(f'<text x="{x(k):.1f}" y="{T + ph + 16}" text-anchor="middle">0x{k * B:x}</text>')
for ser, col in ((eo, '#c62828'), (ec, '#212121')):
    o.append('<polyline fill="none" stroke="%s" stroke-width="1.2" points="%s"/>' % (col, ' '.join(f'{x(i + 0.5):.1f},{y(v):.1f}' for i, v in enumerate(ser))))
ly = H - 18
o += [f'<line x1="{L}" x2="{L + 20}" y1="{ly}" y2="{ly}" stroke="#c62828" stroke-width="2"/><text x="{L + 25}" y="{ly + 4}">as recovered from stage 4</text>',
      f'<line x1="{L + 190}" x2="{L + 210}" y1="{ly}" y2="{ly}" stroke="#212121" stroke-width="2"/><text x="{L + 215}" y="{ly + 4}">after string/function/region decryption</text>',
      f'<rect x="{L + 470}" y="{ly - 8}" width="14" height="12" fill="#2e7d32" opacity="0.4"/><text x="{L + 488}" y="{ly + 4}">egg functions (immediate search)</text>',
      f'<rect x="{L + 680}" y="{ly - 8}" width="14" height="12" fill="#1565c0" opacity="0.4"/><text x="{L + 698}" y="{ly + 4}">egg functions (2³² sweep)</text>',
      f'<rect x="{L + 840}" y="{ly - 8}" width="14" height="12" fill="#ef6c00" opacity="0.4"/><text x="{L + 858}" y="{ly + 4}">marker region</text>',
      f'<text x="{L - 40}" y="{T + ph / 2}" transform="rotate(-90 {L - 40} {T + ph / 2})" text-anchor="middle">bits / byte</text>', '</svg>']
open(sys.argv[5], 'w').write('\n'.join(o))
print('blocks', n, 'mean before', round(sum(eo) / n, 2), 'after', round(sum(ec) / n, 2), 'shaded ranges', len(rng))
