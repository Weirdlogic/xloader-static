"""Minimal, read-only parser for .NET embedded .resources (ResourceReader v2) inside a PE file."""
import struct

def _secs(b):
    pe = struct.unpack_from('<I', b, 0x3c)[0]
    n = struct.unpack_from('<H', b, pe + 6)[0]
    opt = struct.unpack_from('<H', b, pe + 20)[0]
    return [struct.unpack_from('<IIII', b, pe + 24 + opt + 40 * i + 8) for i in range(n)]

def rva2off(b, rva):
    for vs, va, rs, ro in _secs(b):
        if va <= rva < va + max(vs, rs):
            return rva - va + ro
    raise ValueError(hex(rva))

def embedded(b, resources_rva, declared_offset):
    off = rva2off(b, resources_rva) + declared_offset
    ln = struct.unpack_from('<I', b, off)[0]
    return b[off + 4: off + 4 + ln]

def entries(r):
    """Yield (name, type_name, data_offset) for each resource in a .resources blob."""
    def u7(p):
        v = s = 0
        while True:
            c = r[p]; p += 1; v |= (c & 0x7f) << s; s += 7
            if c < 0x80:
                return v, p
    assert struct.unpack_from('<I', r, 0)[0] == 0xBEEFCACE
    p = 12 + struct.unpack_from('<i', r, 8)[0]
    _ver, n, nt = struct.unpack_from('<iii', r, p); p += 12
    types = []
    for _ in range(nt):
        l, p = u7(p); types.append(r[p:p + l].decode()); p += l
    p += (-p) % 8; p += 8 * n
    dso = struct.unpack_from('<i', r, p)[0]; p += 4
    for _ in range(n):
        l, q = u7(p); name = r[q:q + l].decode('utf-16le'); q += l
        doff = struct.unpack_from('<i', r, q)[0]; p = q + 4
        tc, dp = u7(dso + doff)
        yield name, (types[tc - 0x40] if tc >= 0x40 else f'primitive:{tc}'), dp
