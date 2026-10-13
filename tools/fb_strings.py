"""Statically recover stage-5 inline strings: parse objdump around each `call 0x8680`."""
import re, struct, sys, json
sys.path.insert(0, __file__.rsplit('/', 1)[0])
from fb_cipher import decrypt

BASE = bytes(b ^ 0x90 for b in bytes.fromhex('f5cc60ef712839b739ce6e04f5f6e72602f6b090'))
ins_re = re.compile(r'^\s*([0-9a-f]+):\s+(?:[0-9a-f]{2} )+\s*(.*)$')

def load(path):
    out = []
    for l in open(path):
        m = ins_re.match(l)
        if m: out.append((int(m.group(1), 16), m.group(2).strip()))
    return out

def recover(ins, target=0x8680, window=120):
    res = []
    idx = [i for i, (a, t) in enumerate(ins) if t == f'call   0x{target:x}']
    for ci in idx:
        lo = max(0, ci - window)
        # start from the function prologue nearest above
        for k in range(ci, lo, -1):
            if ins[k][1].startswith('push   ebp') and ins[k + 1][1].startswith('mov    ebp,esp'):
                lo = k; break
        mem, bl, pushes, src, copylen = {}, None, [], None, None
        for a, t in ins[lo:ci]:
            m = re.match(r'mov\s+(DWORD|WORD|BYTE) PTR \[ebp-0x([0-9a-f]+)\],(0x[0-9a-f]+|\d+)$', t)
            if m:
                size = {'DWORD': 4, 'WORD': 2, 'BYTE': 1}[m.group(1)]
                off = -int(m.group(2), 16); v = int(m.group(3), 0) & ((1 << (8 * size)) - 1)
                for b in range(size): mem[off + b] = (v >> (8 * b)) & 255
                continue
            m = re.match(r'mov\s+bl,(0x[0-9a-f]+)$', t)
            if m: bl = int(m.group(1), 16); continue
            m = re.match(r'push\s+(0x[0-9a-f]+)$', t)
            if m: pushes.append(int(m.group(1), 16)); continue
            m = re.match(r'lea\s+eax,\[ebp-0x([0-9a-f]+)\]$', t)
            if m: src = -int(m.group(1), 16); continue
            if t == 'call   0x2c440' and pushes:
                copylen = pushes[-1]
        n = pushes[-1] if pushes else None
        if None in (bl, src, n):
            res.append({'call': hex(ins[ci][0]), 'error': f'bl={bl} src={src} len={n}'}); continue
        ct = bytes(mem.get(src + i, 0) for i in range(n))
        pt = decrypt(ct, bytes(b ^ bl for b in BASE))
        res.append({'call': hex(ins[ci][0]), 'bl': hex(bl), 'len': n, 'ct': ct.hex(), 'pt': pt.decode('latin1')})
    return res

if __name__ == '__main__':
    r = recover(load(sys.argv[1]))
    json.dump(r, open(sys.argv[2], 'w'), indent=1)
    for x in r:
        print(x['call'], x.get('error') or repr(x['pt']))
