# xloader-static

Static analysis of a five-stage loader chain that delivers an XLoader 8.x-style payload
(sample SHA-256 `0404070ceb269b1590a7d600bf02f47ed8559d02ef247d54f491ccd529828f26`, first seen 2026-10-12).
Every stage was unpacked and decrypted without running the sample, down to the C2 configuration.

**Read the write-up:** [ARTICLE.md](ARTICLE.md)

**Full technical report:** [reports/formbook/2026-10-13-0404070ceb26/report.md](reports/formbook/2026-10-13-0404070ceb26/report.md)

## Results

- Real C2: `hxxp://www[.]minha[.]cc/36vc/` (defanged; not resolved or contacted), plus 63 decoy domains.
  Full list: [evidence/stage5-c2.json](reports/formbook/2026-10-13-0404070ceb26/evidence/stage5-c2.json).
- Payload fully decrypted: 175 strings, 88 egg-wrapped functions, 10 encrypted code regions.
- Reproduced from scratch with separate tools: byte-identical payload, identical C2 list.

## Repository layout

| Path | Contents |
|---|---|
| `tools/` | Decryptors, rebuild, C2 extractor, brute-forcer, helpers. None of them runs sample code. |
| `detections/` | YARA rules, KQL (Microsoft Defender XDR) and Elastic (EQL / ES\|QL) hunts |
| `reports/formbook/2026-10-13-0404070ceb26/` | Report, figure, evidence (JSON records, keys, validation logs) |

## Reproduce the C2 extraction

You need the stage-4 binary (`d71939e6…3a6b`). Get the sample from MalwareBazaar and extract stages 1–4 as the
report describes, then place the stage-4 binary at `samples/<sha256>/stage4_d71939e6e91ad412.bin`.
Requires Python 3, objdump and Ghidra 12.1.4 (`tools/install.sh` installs pinned versions).

```bash
tools/reproduce_c2.sh /path/to/empty_dir
```

## What is not here

No samples, no binaries, no decompiled malware code and no disassembly. Publish hashes, not samples.

## Prior work

The crypter family was documented by Threatray (2022–2025) and Unit 42; XLoader internals by Zscaler and
Check Point. See the report's *Prior art* section for what is new here.
