"""Clean, order-independent rebuild of the fully decrypted stage-5 image from the ORIGINAL stage-5 file.
Static only: nothing from the sample is executed.

Inputs (all re-validated, none trusted blindly):
  - original stage 5 (sha256 checked)
  - egg constants (c34, start/end egg ciphertext, target) parsed afresh from the decompilations
  - per-wrapper c60 values from evidence/stage5-funcs*.json* (only the 32-bit value is reused; the key is
    recomputed, eggs are searched in the CURRENT image, and every patch must pass the checks below)
  - region marker constants and second-pass keys (REGIONS below, transcribed from the cited instructions)

Fixed-point loop: repeatedly apply any region whose start marker is present and any egg function whose decrypted
start egg occurs exactly once, until nothing changes. An egg patch is accepted only if both eggs are unique and
every E8 call in the body is coherent (fb_eggverify.calls_ok), unless the body has no calls, in which case it must
disassemble with zero (bad) opcodes. A region patch is accepted only if the decrypted block starts with a
`sub esp, imm` prologue continuation (81 ec / 83 ec).
Usage: fb_rebuild.py <orig_stage5.bin> <evidence_dir> <out.bin>"""
import sys, os, re, json, glob, struct, hashlib, subprocess, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fb_cipher import decrypt
from fb_funcs import wrappers, key_for
from fb_eggverify import calls_ok

ORIG_SHA = 'a0588c553619f40b3563ba701f0bde5e3330beb3552f16dd2baa136dd6acabbb'
X = 0x16bd229c
K1 = bytes(b ^ 0xbc for b in struct.pack('<5I', 0xc1ce8020, 0xbd0ae03a, 0x280accfb, 0x591a29a7, 0xdec21541))  # FUN_00001480 ^ 0xbc (FUN_00001110), = ctx+0x190
P = lambda m, *v: struct.pack('<5I', *[x ^ m for x in v])

def key_f():  # region F key: one register byte (bl) at index 14, recovered as the only value giving a prologue
    k = bytearray(bytes.fromhex('91a71a833c3c21f6b136a7f31e18') + b'\x47' + bytes.fromhex('a5420d3407'))
    for o in range(0, 20, 4):
        struct.pack_into('<I', k, o, struct.unpack_from('<I', k, o)[0] ^ 0x74712e55)
    return bytes(k)

# name: (start const, end const, pass-2 key or 'startmarker', source of pass 2)
REGIONS = {
    'R1': (0x444af82c, 0xdaf8b17c, P(0xcd08ad66, 0x8beaa480, 0x930d7770, 0x3284ed4a, 0x1117b223, 0xd0cb7d68), 'FUN_00016370'),
    'R2': (0x9d300bd4, 0xfdceb2ea, 'startmarker', 'FUN_000131a0'),
    'R3': (0x9fb32974, 0x33c0d4dc, P(0xad1f5922, 0x0a9d4de1, 0xa8194425, 0x4ceb9d77, 0x2a57fbd6, 0x41ba2449), 'FUN_00012b90'),
    'A': (0x7d77da90, 0xe333b780, P(0, 0xb3cd1c3b, 0xe4288676, 0x16cca825, 0x77fe9e0b, 0xabb8b071), 'FUN_00013460'),
    'B': (0xfbbbed04, 0xbb50131c, P(0x833e96ca, 0x8cb5059d, 0x4bebce4f, 0x78f54d72, 0x65fac627, 0x77bfb4b0), 'FUN_00015e60'),
    'C': (0xac47b29c, 0x69a290ae, P(0xf2516c46, 0x7c5f7eea, 0xd99d2cdc, 0x87ee791c, 0x0d18cd43, 0x914f0768), 'FUN_00015e60'),
    'E': (0xc71e25bd, 0x6f567180, P(0x82b25a12, 0x88c4d89f, 0x70ef3fe5, 0x059aa4f4, 0x76e09247, 0xe07ed3c3), 'FUN_00015e60'),
    'F': (0x4dc37f6e, 0xc208538c, key_f(), 'FUN_00015e60'),
    'G': (0x8dd4415c, 0x202d3544, P(0xb97052e0, 0xf85b8f83, 0xc89ce6ac, 0xe4b279c2, 0xf4f304f9, 0xf0e3dfcd), 'FUN_00013460'),
    'H': (0x82d4f908, 0x2eb0e8c4, P(0xb926c5d2, 0x8908e92c, 0x848ee530, 0x08f043e6, 0x715ab021, 0x24d1466e), 'FUN_00018460'),
}

def bad_opcodes(body, base):
    with tempfile.NamedTemporaryFile(suffix='.bin') as f:
        f.write(body); f.flush()
        asm = subprocess.run(['objdump', '-D', '-b', 'binary', '-m', 'i386', f'--adjust-vma={base:#x}', f.name],
                             capture_output=True, text=True).stdout
    return asm.count('(bad)')

def try_region(img, name):
    a, b, k2, _ = REGIONS[name]
    sm = struct.pack('<I', a ^ X)
    if img.count(sm) != 1: return None
    s = img.find(sm); e = img.find(struct.pack('<I', b ^ X), s + 4)
    if e < 0: return None
    if k2 == 'startmarker': k2 = sm + bytes(16)
    pt = decrypt(decrypt(bytes(img[s + 4:e]), K1), k2)
    if pt[:2] not in (b'\x81\xec', b'\x83\xec'): return 'reject'
    img[s + 4:e] = pt; img[s + 1:s + 4] = b'\x55\x8b\xec'; img[e:e + 4] = b'\x90' * 4
    return (s + 1, s + 4, e)

def try_egg(img, w, c60):
    key = key_for((w['c34'] ^ c60) ^ 0xdf20ff20)
    st = decrypt(w['start_ct'], key)
    if img.count(st) != 1: return None
    i = img.find(st)
    en = decrypt(w['end_ct'], key); j = img.find(en, i + 6)
    if j < 0 or img.find(en, j + 1) != -1: return 'reject'
    body = decrypt(bytes(img[i + 6:j]), key)
    ok, tot = calls_ok(img, i + 6, body)
    if tot and ok != tot: return 'reject'
    if not tot and bad_opcodes(body, i + 6): return 'reject'
    img[i:i + 6] = b'\x90' * 6; img[i + 6:j] = body; img[j:j + 6] = b'\x90' * 6
    return (i, j, f'{ok}/{tot}')

if __name__ == '__main__':
    orig = open(sys.argv[1], 'rb').read(); ev = sys.argv[2]
    assert hashlib.sha256(orig).hexdigest() == ORIG_SHA, 'not the original stage 5'
    W = {}
    wj = os.path.join(ev, 'stage5-wrappers.json')
    if os.path.exists(wj):  # constants-only export (the public repo ships this instead of decompiled code)
        for w in json.load(open(wj))['wrappers']:
            W[w['wrapper']] = {'wrapper': w['wrapper'], 'c34': int(w['c34'], 16), 'target': int(w['target'], 16),
                               'start_ct': bytes.fromhex(w['start_ct']), 'end_ct': bytes.fromhex(w['end_ct'])}
    for f in sorted(glob.glob(os.path.join(ev, 'stage5*-decomp.c'))):
        for w in wrappers(open(f).read()):
            if 'error' not in w: W.setdefault(w['wrapper'], w)
    W.setdefault('FUN_00027e80', {'wrapper': 'FUN_00027e80', 'c34': 0x1f2fa9c4, 'target': 0xff20,  # parse-failed in Ghidra; from raw disassembly
                 'start_ct': bytes([0x11]) + struct.pack('<I', 0xcc1d2301) + bytes([0xe8]),
                 'end_ct': struct.pack('<I', 0xafd3925f) + struct.pack('<H', 0x29f2)})
    C60 = {}
    for r in json.load(open(os.path.join(ev, 'stage5-funcs.json'))):
        if 'c60' in r: C60[r['wrapper']] = int(r['c60'], 16)
    for f in glob.glob(os.path.join(ev, 'stage5-funcs-*.jsonl')):
        for l in open(f):
            r = json.loads(l)
            if r.get('applied'): C60[r['wrapper']] = int(r['c60'], 16)
    img = bytearray(orig); log = []; done_r = set(); done_e = set(); rounds = 0
    while True:
        rounds += 1; progress = False
        for n in REGIONS:
            if n in done_r: continue
            r = try_region(img, n)
            if r and r != 'reject': done_r.add(n); progress = True; log.append({'round': rounds, 'region': n, 'fn': hex(r[0])})
        for name, c60 in C60.items():
            if name in done_e or name not in W: continue
            r = try_egg(img, W[name], c60)
            if r and r != 'reject':
                done_e.add(name); progress = True
                log.append({'round': rounds, 'egg': name, 'target': hex(W[name]['target']), 'start': hex(r[0]), 'end': hex(r[1]), 'calls': r[2]})
        if not progress: break
    open(sys.argv[3], 'wb').write(bytes(img))
    missing_e = sorted(set(C60) - done_e); missing_r = sorted(set(REGIONS) - done_r)
    print(json.dumps({'rounds': rounds, 'regions': len(done_r), 'eggs': len(done_e), 'missing_regions': missing_r,
                      'missing_eggs': missing_e, 'sha256': hashlib.sha256(bytes(img)).hexdigest()}, indent=1))
    json.dump(log, open(sys.argv[3] + '.log.json', 'w'), indent=1)
