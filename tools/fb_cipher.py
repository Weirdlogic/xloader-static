"""Stage-5 buffer cipher reimplemented from FUN_00004440 and helpers (static port; no sample code executed).
Order: passA, passB, RC4, passA, passB. mode 0x80 = add, else subtract."""
def _rc4(k, d):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + k[i % len(k)]) & 255; S[i], S[j] = S[j], S[i]
    i = j = 0
    for x in range(len(d)):
        i = (i + 1) & 255; j = (j + S[i]) & 255; S[i], S[j] = S[j], S[i]
        d[x] ^= S[(S[i] + S[j]) & 255]

def _pass_a(d, add):  # FUN_000041a0: backwards
    n = len(d)
    for i in range(1, n):
        a, b = n - 1 - i, n - i
        d[a] = (d[a] + d[b]) & 255 if add else (d[a] - d[b]) & 255

def _pass_b(d, add):  # FUN_00004210: forwards
    n = len(d)
    for i in range(1, n):
        d[i - 1] = (d[i - 1] + d[i]) & 255 if add else (d[i - 1] - d[i]) & 255

def decrypt(data, key, mode=0x8d):
    d = bytearray(data); add = (mode == 0x80)
    _pass_a(d, add); _pass_b(d, add); _rc4(key, d); _pass_a(d, add); _pass_b(d, add)
    return bytes(d)
