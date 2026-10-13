"""Validate and apply brute-forced egg masks (output of tools/c/fb_eggbf.c). Static only.
A candidate is accepted only if the decrypted start egg sits right after the target prologue, the decrypted
end egg occurs exactly once after it, and every E8 call in the decrypted body lands on a 55 8b ec prologue
(or a 0x90 egg pad / known get-PC thunk) inside the image.
Usage: fb_eggverify.py <image_in> <image_out> <bf_input.txt> <hits...>"""
import sys, struct, re, json
sys.path.insert(0, __file__.rsplit('/', 1)[0])
from fb_cipher import decrypt
from fb_funcs import key_for

def calls_ok(img, base, body):
    """Count real E8 calls from a linear disassembly (objdump), not raw 0xE8 bytes, which also occur as
    ModRM displacements (e.g. c7 45 e8 = mov [ebp-0x18], imm)."""
    import subprocess, tempfile
    with tempfile.NamedTemporaryFile(suffix='.bin') as f:
        f.write(body); f.flush()
        asm = subprocess.run(['objdump', '-D', '-b', 'binary', '-m', 'i386', f'--adjust-vma={base:#x}', f.name],
                             capture_output=True, text=True).stdout
    tot = ok = 0
    for t in (int(x, 16) for x in re.findall(r'\te8 (?:[0-9a-f]{2} ){4}\s*call\s+0x([0-9a-f]+)', asm)):
        if not 0 <= t < len(img): continue
        tot += 1
        ok += (img[t:t + 3] == b"\x55\x8b\xec" or img[t] in (0x58, 0x90)      # prologue / egg pad
               or img[t:t + 6] == b"\xe8\0\0\0\0\x58"                      # get-PC thunk
               or img[t:t + 3] == b"\x33\xc0\xc3"                            # leaf: xor eax,eax; ret
               or (img[t] == 0xb8 and img[t + 5] == 0xc3)                     # leaf: mov eax,imm32; ret
               or img[t:t + 6] == b"\x8b\x0d\x18\x00\xfe\x7f")                # leaf: mov ecx,[0x7ffe0018] (KUSER_SHARED_DATA time)
    return ok, tot

if __name__ == '__main__':
    img = bytearray(open(sys.argv[1], 'rb').read())
    meta = {l.split()[0]: l.split() for l in open(sys.argv[3])}
    ends = {l.split()[0]: l.split()[3] for l in open(sys.argv[3].replace('bf_input', 'wrappers'))}
    out = []
    for h in sys.argv[4:]:
        name, mask, c60, off = re.match(r'(\S+) mask=(\w+) c60=(\w+) off=\+(\d+)', h).groups()
        key = key_for(int(mask, 16)); tgt = None
        st = decrypt(bytes.fromhex(meta[name][2]), key)
        i = img.find(st)
        en = decrypt(bytes.fromhex(ends[name]), key)
        j = img.find(en, i + 6)
        uniq = img.count(st) == 1 and j != -1 and img.find(en, j + 1) == -1
        body = decrypt(bytes(img[i + 6:j]), key) if uniq else b''
        ok, tot = calls_ok(img, i + 6, body) if uniq else (0, 0)
        rec = {'wrapper': name, 'c60': '0x' + c60, 'key': key.hex(), 'start_egg_at': hex(i), 'end_egg_at': hex(j),
               'unique_eggs': uniq, 'calls_coherent': f'{ok}/{tot}', 'body_len': j - i - 6}
        if uniq and tot and ok == tot:
            img[i:i + 6] = b'\x90' * 6; img[i + 6:j] = body; img[j:j + 6] = b'\x90' * 6; rec['applied'] = True
        out.append(rec); print(json.dumps(rec))
    open(sys.argv[2], 'wb').write(bytes(img))
