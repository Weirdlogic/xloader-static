#!/usr/bin/env bash
# Clean, end-to-end static reproduction of the stage-5 C2 configuration for
# 0404070ceb269b1590a7d600bf02f47ed8559d02ef247d54f491ccd529828f26.
# stage 4 -> stage 5 -> order-independent rebuild -> fresh Ghidra decompile -> independent C2 extraction -> diff.
# Nothing from the sample is executed; no domain is resolved. Usage: tools/reproduce_c2.sh <empty_out_dir>
set -euo pipefail
R="$(cd "$(dirname "$0")/.." && pwd)"
S="$R/samples/0404070ceb269b1590a7d600bf02f47ed8559d02ef247d54f491ccd529828f26"
E="$R/reports/formbook/2026-10-13-0404070ceb26/evidence"
O="${1:?out dir}"; mkdir -p "$O"; [ -z "$(ls -A "$O")" ] || { echo "out dir must be empty"; exit 1; }
source "$R/tools/env.sh"
python3 -I "$R/tools/fb_stage4_unpack.py" "$S/stage4_d71939e6e91ad412.bin" "$O/stage5.bin"
python3 -I "$R/tools/fb_rebuild.py" "$O/stage5.bin" "$E" "$O/stage5_decrypted.bin"
mkdir -p "$O/ghidra"; cp "$O/stage5_decrypted.bin" "$O/ghidra/s.bin"
analyzeHeadless "$O/ghidra" proj -import "$O/ghidra/s.bin" -loader BinaryLoader -processor x86:LE:32:default \
  -scriptPath "$R/tools/ghidra_scripts" -postScript ExportDecomp.java "$O/decomp.c" \
  0x2d9a0,0xad80,0x2c110,0x1b20,0x6bd0,0x5b30,0x4730,0x8710,0x13b0,0x1350,0x12f0,0x1220 -deleteProject > "$O/ghidra.log" 2>&1
python3 -I "$R/tools/fb_c2_extract.py" "$O/stage5_decrypted.bin" "$O/decomp.c" "$O/c2.json"
sha256sum "$O/stage5.bin" "$O/stage5_decrypted.bin"
python3 -I - "$O/c2.json" "$E/stage5-c2.json" <<'EOF'
import json, sys
a, b = json.load(open(sys.argv[1])), json.load(open(sys.argv[2]))
d = [x['index'] for x, y in zip(a['decoys'], b['decoys']) if (x['domain'], x['path']) != (y['domain'], y['path'])]
same_real = (a['real_c2']['host'], a['real_c2']['path']) == (b['real_c2']['host'], b['real_c2']['path'])
print('real C2 match:', same_real, '| decoy differences:', d, '| slot order match:', a['slot_order'] == b['fixed_slot_order_FUN_00006bd0'])
sys.exit(0 if same_real and not d else 1)
EOF
