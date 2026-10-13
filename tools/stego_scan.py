#!/usr/bin/env python3
"""Static pixel-steganography extractor for .NET samples (never executes anything).

    python3 tools/stego_scan.py <sha256> [<sha256> ...]  -> JSON lines on stdout

For every Bitmap resource inside every embedded .resources blob of
samples/<sha256>/sample.bin, decode the pixels with each candidate layout
(channel order x traversal) and report any layout that yields a structurally
valid PE. Recovered PEs are written as samples/<sha256>/px_<sha16>.bin (0400).
"""
import hashlib
import json
import os
import struct
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dotnet_resources import embedded, entries, rva2off  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


# ---------- .NET metadata: CLI header -> resources RVA, ManifestResource offsets ----------
def cli_resources(b):
    pe = struct.unpack_from('<I', b, 0x3c)[0]
    magic = struct.unpack_from('<H', b, pe + 24)[0]
    dd = pe + 24 + (96 if magic == 0x10b else 112)
    cli_rva = struct.unpack_from('<I', b, dd + 14 * 8)[0]
    if not cli_rva:
        return None, []
    c = rva2off(b, cli_rva)
    md_rva, _ = struct.unpack_from('<II', b, c + 8)
    res_rva, res_sz = struct.unpack_from('<II', b, c + 24)
    if not res_rva:
        return None, []
    # Walk the resources directory blob: entries are [u32 len][data] back to back.
    base = rva2off(b, res_rva)
    offs, p = [], 0
    while p + 4 <= res_sz:
        ln = struct.unpack_from('<I', b, base + p)[0]
        if ln == 0 or p + 4 + ln > res_sz:
            break
        offs.append(p)
        p += 4 + ln
        p += (-p) % 8  # entries are 8-byte aligned
    return res_rva, offs


# ---------- image decoders (stdlib only) ----------
def decode_bmp(d):
    pix_off = struct.unpack_from('<I', d, 10)[0]
    w, h = struct.unpack_from('<ii', d, 18)
    bpp, comp = struct.unpack_from('<HI', d, 28)
    if comp not in (0, 3) or bpp not in (24, 32):
        raise ValueError(f'bmp bpp={bpp} comp={comp}')
    bottom_up, h = h > 0, abs(h)
    step = bpp // 8
    stride = (w * step + 3) & ~3
    rows = []
    for y in range(h):
        r = (h - 1 - y) if bottom_up else y
        line = d[pix_off + r * stride: pix_off + r * stride + w * step]
        rows.append([(line[x * step + 2], line[x * step + 1], line[x * step],
                      line[x * step + 3] if step == 4 else 255) for x in range(w)])
    return w, h, rows


def decode_png(d):
    p, idat, plte = 8, b'', None
    while p < len(d):
        ln, typ = struct.unpack_from('>I4s', d, p)
        body = d[p + 8: p + 8 + ln]
        p += 12 + ln
        if typ == b'IHDR':
            w, h, bd, ct, _, _, il = struct.unpack('>IIBBBBB', body)
        elif typ == b'PLTE':
            plte = body
        elif typ == b'IDAT':
            idat += body
        elif typ == b'IEND':
            break
    if bd != 8 or il != 0 or ct not in (2, 3, 6):
        raise ValueError(f'png bd={bd} ct={ct} il={il}')
    bpp = {2: 3, 3: 1, 6: 4}[ct]
    raw = zlib.decompress(idat)
    stride, prev, q, rows = w * bpp, bytearray(w * bpp), 0, []
    for _ in range(h):
        f, line = raw[q], bytearray(raw[q + 1: q + 1 + stride])
        q += 1 + stride
        for x in range(stride):
            a = line[x - bpp] if x >= bpp else 0
            up, c = prev[x], (prev[x - bpp] if x >= bpp else 0)
            if f == 1:
                line[x] = (line[x] + a) & 255
            elif f == 2:
                line[x] = (line[x] + up) & 255
            elif f == 3:
                line[x] = (line[x] + ((a + up) >> 1)) & 255
            elif f == 4:
                pp = a + up - c
                pa, pb, pc = abs(pp - a), abs(pp - up), abs(pp - c)
                line[x] = (line[x] + (a if pa <= pb and pa <= pc else up if pb <= pc else c)) & 255
        prev = line
        if ct == 3:
            rows.append([(plte[i * 3], plte[i * 3 + 1], plte[i * 3 + 2], 255) for i in line])
        else:
            rows.append([(line[x * bpp], line[x * bpp + 1], line[x * bpp + 2],
                          line[x * bpp + 3] if bpp == 4 else 255) for x in range(w)])
    return w, h, rows


def image_from_blob(blob):
    for sig, dec in ((b'\x89PNG\r\n\x1a\n', decode_png), (b'BM', decode_bmp)):
        i = blob.find(sig)
        if i >= 4:
            ln = struct.unpack_from('<I', blob, i - 4)[0]
            return sig[:2].decode('latin1'), dec(blob[i:i + ln])
    return None, None


# ---------- layouts ----------
CHANNELS = {'RGB': (0, 1, 2), 'BGR': (2, 1, 0), 'BGRA': (2, 1, 0, 3), 'ARGB': (3, 0, 1, 2), 'RGBA': (0, 1, 2, 3)}


def stream(w, h, rows, order, chans):
    idx = CHANNELS[chans]
    coords = ((x, y) for x in range(w) for y in range(h)) if order == 'col' else \
             ((x, y) for y in range(h) for x in range(w))
    out = bytearray()
    for x, y in coords:
        px = rows[y][x]
        out += bytes(px[i] for i in idx)
    return bytes(out)


def pe_extent(d):
    """Return the on-disk length of a PE starting at d[0], or None if not a valid PE."""
    if d[:2] != b'MZ' or len(d) < 0x40:
        return None
    pe = struct.unpack_from('<I', d, 0x3c)[0]
    if pe + 24 > len(d) or d[pe:pe + 4] != b'PE\0\0':
        return None
    nsec = struct.unpack_from('<H', d, pe + 6)[0]
    opt = struct.unpack_from('<H', d, pe + 20)[0]
    end = 0
    for i in range(nsec):
        o = pe + 24 + opt + 40 * i
        if o + 40 > len(d):
            return None
        rsz, rptr = struct.unpack_from('<II', d, o + 16)
        end = max(end, rptr + rsz)
    return end if 0 < end <= len(d) else None


def scan(sha):
    d = ROOT / 'samples' / sha
    b = (d / 'sample.bin').read_bytes()
    res_rva, offs = cli_resources(b)
    result = {'sha256': sha, 'dotnet': res_rva is not None, 'bitmaps': [], 'payloads': []}
    if res_rva is None:
        return result
    for off in offs:
        try:
            blob = embedded(b, res_rva, off)
            ents = list(entries(blob))
        except Exception:
            continue  # not a .resources blob (raw manifest resource)
        for name, typ, dp in ents:
            if not typ.startswith('System.Drawing.Bitmap'):
                continue
            fmt, img = image_from_blob(blob[dp:dp + 64 + 16_000_000])
            if not img:
                continue
            w, h, rows = img
            result['bitmaps'].append({'name': name, 'format': fmt, 'w': w, 'h': h})
            for order in ('col', 'row'):
                for chans in CHANNELS:
                    s = stream(w, h, rows, order, chans)
                    for hdr in (0, 4):  # raw, or int32 length prefix
                        body = s[hdr:]
                        ext = pe_extent(body)
                        if ext:
                            pl = body[:ext]
                            h256 = hashlib.sha256(pl).hexdigest()
                            dst = d / f'px_{h256[:16]}.bin'
                            if not dst.exists():
                                fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
                                os.write(fd, pl)
                                os.close(fd)
                            result['payloads'].append({'resource': name, 'order': order, 'channels': chans,
                                                       'length_prefix': bool(hdr), 'size': ext, 'sha256': h256})
    return result


if __name__ == '__main__':
    for sha in sys.argv[1:]:
        try:
            print(json.dumps(scan(sha.lower())), flush=True)
        except Exception as e:
            print(json.dumps({'sha256': sha, 'error': f'{type(e).__name__}: {e}'}), flush=True)
