"""Statically decrypt stage-5 egg-wrapped functions (port of FUN_00001670 logic; nothing is executed).
For every wrapper calling FUN_000018f0/FUN_00001910, recover its planted constants, then search the
+0x60 half of the mask among all 32-bit immediates in the image; accept a key only if both decrypted
eggs occur exactly once in the image and the start egg lies inside/after the wrapped target."""
import re, struct, sys, json
sys.path.insert(0, __file__.rsplit('/', 1)[0])
from fb_cipher import decrypt

BASE = struct.pack('<5I', 0x35b98505, 0xf21dfceb, 0xae10be3a, 0xdd719b86, 0xd5d4d340)

def key_for(mask):
    return b''.join(struct.pack('<I', struct.unpack_from('<I', BASE, i)[0] ^ mask) for i in range(0, 20, 4))

def wrappers(decomp):
    F = {f.split(' @ ')[0]: f for f in re.split(r'^// ==== ', decomp, flags=re.M)[1:]}
    out = []
    for name, body in F.items():
        if not re.search(r'FUN_000018f0\(|FUN_00001910\(', body) or name in ('FUN_000018f0', 'FUN_00001910'):
            continue
        g = lambda v: (lambda m: int(m.group(1), 0) & 0xffffffff if m else None)(re.search(rf'\b{v} = (-?0x[0-9a-f]+|-?\d+);', body))
        c34, s0, s1, s5, e0, e4 = g('local_80'), g('local_14'), g('local_13'), g('local_f'), g('local_70'), g('local_6c')
        tgt = re.search(r'if \(iVar1 != 0\) \{\s*(?:\w+ = )?(FUN_[0-9a-f]{8})\(', body)
        if None in (c34, s0, s1, s5, e0, e4) or not tgt:
            out.append({'wrapper': name, 'error': 'pattern'}); continue
        out.append({'wrapper': name, 'c34': c34, 'start_ct': bytes([s0 & 255]) + struct.pack('<I', s1) + bytes([s5 & 255]),
                    'end_ct': struct.pack('<I', e0) + struct.pack('<H', e4 & 0xffff), 'target': int(tgt.group(1)[4:], 16)})
    return out

def solve(img, w, candidates):
    for c60 in candidates:
        key = key_for((w['c34'] ^ c60) ^ 0xdf20ff20)
        st = decrypt(w['start_ct'], key)
        i = img.find(st)
        if i == -1 or img.find(st, i + 1) != -1 or not (w['target'] <= i < w['target'] + 0x40):
            continue
        en = decrypt(w['end_ct'], key)
        j = img.find(en, i + 6)
        if j == -1 or img.find(en, j + 1) != -1:
            continue
        return c60, key, i, j
    return None

def _solve_one(args):
    img, w, cands = args
    r = solve(img, w, cands) if 'error' not in w else None
    print(w['wrapper'], '->', 'solved' if r else 'no key', flush=True)
    return w, r

if __name__ == '__main__':
    from multiprocessing import Pool
    img = bytearray(open(sys.argv[1], 'rb').read()); decomp = open(sys.argv[2]).read()
    # candidate +0x60 values: 32-bit immediates appearing as instruction operands (objdump, argv[5])
    imm = re.findall(r',(0x[0-9a-f]{5,8})\b', open(sys.argv[5]).read())
    cands = sorted({int(x, 16) for x in imm}); print('candidates:', len(cands), flush=True)
    ws = wrappers(decomp); report = []
    with Pool(4) as pool:
        solved = pool.map(_solve_one, [(bytes(img), w, cands) for w in ws], chunksize=1)
    for w, r in solved:
        if 'error' in w: report.append(w); continue
        if not r: report.append({'wrapper': w['wrapper'], 'target': hex(w['target']), 'result': 'no key'}); continue
        c60, key, i, j = r
        body = decrypt(bytes(img[i + 6:j]), key)
        img[i:i + 6] = b'\x90' * 6; img[i + 6:j] = body; img[j:j + 6] = b'\x90' * 6
        report.append({'wrapper': w['wrapper'], 'target': hex(w['target']), 'c60': hex(c60), 'key': key.hex(),
                       'start_egg_at': hex(i), 'end_egg_at': hex(j), 'body_len': j - i - 6})
        print(w['wrapper'], '->', hex(w['target']), 'decrypted', hex(i), '-', hex(j), 'c60', hex(c60), flush=True)
    open(sys.argv[3], 'wb').write(bytes(img))
    json.dump(report, open(sys.argv[4], 'w'), indent=1)
    print('decrypted', sum(1 for r in report if 'key' in r), 'of', len(report), 'wrappers')
