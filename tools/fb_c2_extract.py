"""Independent static extraction of the stage-5 (XLoader-style) C2 configuration from a decrypted image.
Every constant is parsed from the given decompilation / disassembly of THAT image; nothing is hard-coded except
function addresses and the structure of the algorithm (documented in report §5.7). Nothing is executed and no
domain is resolved. Usage: fb_c2_extract.py <decrypted_stage5.bin> <decomp.c> <out.json>"""
import sys, os, re, json, struct, base64, subprocess
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fb_cipher import decrypt

SIZE = {'undefined4': 4, 'uint': 4, 'int': 4, 'undefined2': 2, 'ushort': 2, 'undefined1': 1, 'byte': 1, 'char': 1}

def funcs(decomp):
    return {f.split(' @ ')[0]: f for f in re.split(r'^// ==== ', decomp, flags=re.M)[1:]}

def stack(body, prefix=r'(?:local|uStack)_'):
    """Rebuild stack bytes from `local_XX = imm;` assignments (offset from the name, size from the declaration)."""
    decl = {m.group(2): SIZE.get(m.group(1), 4) for m in re.finditer(r'^\s+(\w+) \*?((?:local|uStack)_[0-9a-f]+)(?: \[\d+\])?;', body, re.M)}
    mem = {}
    for m in re.finditer(rf'^\s+({prefix}([0-9a-f]+)) = (0x[0-9a-f]+|\d+);', body, re.M):
        name, off, v = m.group(1), -int(m.group(2), 16), int(m.group(3), 0)
        n = decl.get(name, 4)
        for k in range(n): mem[off + k] = (v >> (8 * k)) & 255
    return mem

def dwords(body, count=5):
    vals = [int(x, 16) for x in re.findall(r'^\s+local_\w+ = (0x[0-9a-f]{5,8});', body, re.M)]
    assert len(vals) >= count, body[:200]
    return vals[:count]

def at_t(img_path, lo, hi):
    return subprocess.run(['objdump', '-D', '-b', 'binary', '-m', 'i386', f'--start-address={lo:#x}', f'--stop-address={hi:#x}',
                           img_path], capture_output=True, text=True).stdout

def producer_string(img_path, start, base):
    """Producer = stack-built ciphertext, `mov $imm,%bl`, call 0x8680 (string decryptor). Parse from raw disassembly."""
    asm = at_t(img_path, start, start + 0x100).split('call   0x8680')[0]  # stop at this producer's own call
    mem = {}
    for m in re.finditer(r'mov([lwb])\s+\$0x([0-9a-f]+),(-0x[0-9a-f]+)\(%ebp\)', asm):
        n = {'l': 4, 'w': 2, 'b': 1}[m.group(1)]; v = int(m.group(2), 16); off = int(m.group(3), 16)
        for k in range(n): mem[off + k] = (v >> (8 * k)) & 255
    bl = int(re.search(r'mov\s+\$0x([0-9a-f]+),%bl', asm).group(1), 16)
    ln = [int(x, 16) for x in re.findall(r'push\s+\$0x([0-9a-f]+)', asm.split('call   0x8680')[0])][-1]
    src = int(re.findall(r'lea\s+(-0x[0-9a-f]+)\(%ebp\),%eax', asm)[0], 16)
    ct = bytes(mem.get(src + i, 0) for i in range(ln))
    return decrypt(ct, bytes(b ^ bl for b in base))

if __name__ == '__main__':
    img_path, F = sys.argv[1], funcs(open(sys.argv[2]).read())
    ev = {}
    # string-decryptor base key: FUN_00001220 byte table, XOR byte from its loop
    b1220 = F['FUN_00001220']
    tbl = {int(i, 0): int(v, 0) & 255 for i, v in re.findall(r'local_20\[((?:0x)?[0-9a-f]+)\] = (0x[0-9a-f]+|\d+);', b1220)}
    sx = int(re.search(r'\^ (0x[0-9a-f]+);', b1220).group(1), 16)
    sbase = bytes(tbl.get(i, 0) ^ sx for i in range(20)); ev['string_base'] = sbase.hex()
    # producer order from the 64-way chain in FUN_00001b20
    d = F['FUN_00001b20']
    order = {int(n, 0): int(f, 16) for n, f in re.findall(r'param_3 == (0x[0-9a-f]+|\d+)\) \{\s*FUN_([0-9a-f]{8})\(param_2\)', d)}
    assert sorted(order) == list(range(1, 65)), sorted(order)
    # per-entry key: ctx+0x12a1 = FUN_000013b0 ^ byte (from the init site), then ^ n
    init = re.search(r'FUN_000013b0\((\w+) \+ 0x12a1\);\s*FUN_00001110\(\1 \+ 0x12a1,(0x[0-9a-f]+)\);', open(sys.argv[2]).read())
    k1 = bytes(b ^ int(init.group(2), 16) for b in struct.pack('<5I', *dwords(F['FUN_000013b0'])))
    assert 'param_1 + 0x12a1' in d
    # shared key: seed (constant written to +0x2620) ^ five constants in FUN_00006bd0
    seed = int(re.search(r'\+ 0x2620\) = (0x[0-9a-f]+);', open(sys.argv[2]).read()).group(1), 16)
    xs = [int(x, 16) for x in re.findall(r'= local_4c \^ (0x[0-9a-f]+);', F['FUN_00006bd0'])][:5]
    k2 = struct.pack('<5I', *[seed ^ x for x in xs]); assert len(xs) == 5
    # path table and path key in FUN_00001b20 (0xde branch)
    ptab = {int(i, 0): int(v, 0) for i, v in re.findall(r'local_154\[((?:0x)?[0-9a-f]+)\] = (0x[0-9a-f]+|0);', d)}
    pmem = stack(d)  # path key: five dwords local_24..local_14 assigned in the 0xde branch
    pkey = bytes(pmem.get(-0x24 + i, 0) for i in range(20))
    # real C2: FUN_00008710 string -> base64 -> key A (FUN_00001350 ^ b, dwords ^ m, bytes ^ c) -> key B (FUN_000012f0 ^ b2)
    a = F['FUN_00004730']
    ka = bytearray(b ^ int(re.search(r'FUN_00001110\(puVar1,(0x[0-9a-f]+)\)', a).group(1), 16)
                   for b in struct.pack('<5I', *dwords(F['FUN_00001350'])))
    dm = int(re.search(r'\*puVar1 = \*puVar1 \^ (0x[0-9a-f]+);', a).group(1), 16)
    for o in range(0, 20, 4): struct.pack_into('<I', ka, o, struct.unpack_from('<I', ka, o)[0] ^ dm)
    bm = int(re.search(r'local_5c\[uVar3\] \^ (0x[0-9a-f]+);', a).group(1), 16)
    ka = bytes(b ^ bm for b in ka)
    kb = bytes(b ^ int(re.search(r'FUN_000012f0\(iVar7\);\s*FUN_00001110\(iVar7,(0x[0-9a-f]+)\);', F['FUN_00006bd0']).group(1), 16)
               for b in struct.pack('<5I', *dwords(F['FUN_000012f0'])))
    real_b64 = producer_string(img_path, 0x8710, sbase).rstrip(b'\0')
    real = decrypt(decrypt(base64.b64decode(real_b64), ka), kb).decode('latin1')
    # slot order (16 bytes at -0x20 in FUN_00006bd0) and the substituted slot index
    b6 = F['FUN_00006bd0']; sm = stack(b6)
    slots = [sm.get(-0x20 + i) for i in range(16)]
    slot_idx = int(re.search(r'FUN_00001290 \+ \(int\)param_1\) = (0x[0-9a-f]+);', b6).group(1), 16)
    rows = []
    for n in range(1, 65):
        s = producer_string(img_path, order[n], sbase).rstrip(b'\0')
        try:
            dom = decrypt(decrypt(base64.b64decode(s, validate=True), bytes(b ^ n for b in k1)), k2).decode('latin1')
        except Exception:
            dom = None
        path = decrypt(struct.pack('<I', ptab[n]), bytes(b ^ n for b in pkey)).decode('latin1')
        rows.append({'index': n, 'producer': hex(order[n]), 'domain': dom, 'path': f'/{path}/'})
    out = {'real_c2': {'host': real, 'slot_index': slot_idx, 'entry': slots[slot_idx],
                       'path': rows[slots[slot_idx] - 1]['path']},
           'prefix': real[:4], 'slot_order': slots, 'decoys': rows,
           'parsed_inputs': {'string_base': sbase.hex(), 'entry_key_base': k1.hex(), 'seed': hex(seed), 'shared_key': k2.hex(),
                             'path_key_base': pkey.hex(), 'real_key_a': ka.hex(), 'real_key_b': kb.hex(), 'real_b64': real_b64.decode()}}
    json.dump(out, open(sys.argv[3], 'w'), indent=1)
    print(json.dumps(out['real_c2']), '| decoys with domain:', sum(1 for r in rows if r['domain']))
