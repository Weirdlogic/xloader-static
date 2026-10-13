# Stage 4 static reversing notes (2026-10-14)

Binary: samples/<sha>/stage4_d71939e6e91ad412.bin (PE32 i386, no imports, .text raw @0x1000, file 0x45600)
Ghidra via rea: entry ev_6a4402e9…, dispatcher FUN_004010a0 ev_10f13139…, FUN_00401000 ev_30f4adf6…

## Dispatcher model (FUN_004010a0)
- Finds caller context by scanning the stack for marker 0x109ddd80 (planted by entry); ctx = marker_addr - 0x346.
- Command byte = ctx[0x185]; XORs 4 bytes at *(ctx+0x155) with it; ctx[0x356] = ctx[0x362].
- Every handler is selected by `(ctx[0x356] ^ CONST) == ctx[field]` - opcode→handler mapping depends on
  values the entry function plants in ctx. NOT yet mapped.

## Payload path (handler 0x5e86d210)
- body = ctx[0x161] (set outside dispatcher - probably an allocation + copy), size 0x42800, blocks of 0x32aa,
  block count = ctx[0x30e] ^ ctx[0x171].
- cmd 0xa3 → FUN_00401000 writes a 68-byte stub (XOR 7). Decoded stub = junk loop (sum to 0x5207, ret 0);
  it is copied over each block start, called, and the original bytes restored → no effect on data (anti-emulation).
- cmd 0xe6 with ctx[0x175]=0xc71f88f5, ctx[0x444]=ctx+0x2e2 (31 bytes from local_d4: ed4e0433e5be1a01d7173746
  3ee8e5c9acd07632 + zeros). Candidate handler 0x394e7648 XORs 5 dwords with ctx[0x175].
- per block: cmd 0xe2 (handler 0x1731fbbc: struct init, 0x78/0xe/0xdb split constants), cmd 0xe5 (0xc23a3d4:
  +0x88→256, +6→keylen 20, -0xda→1; KSA init) → 0x3b9316f6 (KSA mix) → 0xff4083c0 (PRGA, data ^= ks) = **RC4**,
  re-keyed per block with the same 20-byte key.
- finally jump to body + 0x2d9a0 (handler 0xf1a02fd0) = stage-5 entry.

## Tested and failed
- RC4 with key = local_d4[0:20] ^ 0xc71f88f5 (dword-wise) and with raw local_d4[0:20], keystream slid over every
  file offset: no plaintext (zero-count at noise level). ⇒ key derivation and/or body source still wrong.
- Handlers selected by ctx[0x306] = 0x188 / 0x4a35 / 0x4a4e copy constant tables (0x4a35 = the XOR constants of the
  case-insensitive compare at 0x44245700) → API-name matching tables, not the payload key.

## Open
1. Map opcode → handler: reconstruct the ctx values planted by entry (marker-relative offsets) and solve each
   `(sel ^ C) == ctx[field]`.
2. Find where ctx[0x161] comes from (zero-run search at 0x40118f / offsets 0x44451, 0x1c51 suggest the body is
   located by a run of N zero bytes inside the image, then copied).
3. Confirm which handler cmd 0xe6 hits (key derivation).
