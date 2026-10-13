"""Reproduce stage 5 from the stage-4 native loader, statically (report: Stage 4, data flow steps 1-9).
Body = file 0x2c51..0x45451 (0x42800 bytes, ends at the 11-zero run); layer 1 = RC4 key A over the whole body;
layer 2 = RC4 restarted per 0x32aa block with key B. Keys are rebuilt from the constants the stage-4 entry plants.
Usage: fb_stage4_unpack.py <stage4.bin> <out_stage5.bin>"""
import sys, struct, hashlib

def rc4(key, data):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 255; S[i], S[j] = S[j], S[i]
    i = j = 0; out = bytearray(data)
    for x in range(len(out)):
        i = (i + 1) & 255; j = (j + S[i]) & 255; S[i], S[j] = S[j], S[i]; out[x] ^= S[(S[i] + S[j]) & 255]
    return bytes(out)

def xor_dw(b, m):
    return b''.join(struct.pack('<I', struct.unpack_from('<I', b, o)[0] ^ m) for o in range(0, 20, 4))

if __name__ == '__main__':
    s4 = open(sys.argv[1], 'rb').read()
    assert hashlib.sha256(s4).hexdigest() == 'd71939e6e91ad412304d04b1a2385afa105c9921086e0381b54054f8dfe33a6b'
    zero = s4.find(b'\0' * 11, 0x118f)               # handler 0xb5: first run of 11 zero bytes after the scan start
    base = zero - 0x44451                              # handler 0xb5: base = run - region length
    body = s4[base + 0x1c51: base + 0x1c51 + 0x42800]  # handler 0x1b: body = base + 0x1c51
    string_key = bytes.fromhex('9fc21254c2977ab20912a84df885331800a0ed9b')   # table 0x188 ^ 0x7f6e7818 (report step 3)
    key_a = xor_dw(string_key, 0x4c591180)                                    # step 6
    key_b = xor_dw(bytes.fromhex('ed4e0433e5be1a01d71737463ee8e5c9acd07632'), 0xc71f88f5)  # local_d4[0:20] ^ 0xc71f88f5
    l1 = rc4(key_a, body)
    nblk = 0x9cff13ad ^ 0x9cff13b8                    # handler 0x85: block count = 21 (bytes past 21*0x32aa keep layer 1 only)
    l2 = b''.join(rc4(key_b, l1[o:o + 0x32aa]) for o in range(0, nblk * 0x32aa, 0x32aa)) + l1[nblk * 0x32aa:]
    open(sys.argv[2], 'wb').write(l2)
    print('zero run', hex(zero), 'base', hex(base), 'key A', key_a.hex(), 'key B', key_b.hex(), 'sha256', hashlib.sha256(l2).hexdigest())
