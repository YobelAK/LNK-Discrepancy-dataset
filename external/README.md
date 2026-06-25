# External Dataset — Hash List Only

This directory does **not** contain any `.lnk` files. The external set consists of
**real malicious Windows shortcuts** collected from public malware repositories
(VirusTotal and MalwareBazaar). To avoid redistributing malware, only their
**SHA-256 hashes** are published here.

## What is here

- [`EXTERNAL_HASHES.csv`](EXTERNAL_HASHES.csv) — 189 SHA-256 hashes.

| Column | Description |
|---|---|
| `sha256` | SHA-256 of the original external `.lnk` sample. |
| `group` | `blind` (186 randomly drawn samples) or `constructed` (3 samples with a manually verified real target discrepancy). |
| `sample_id` | Internal id (for `blind` rows this equals the hash; for `constructed` rows it is `EXT_T1` / `EXT_T4` / `EXT_T5`). |
| `system_output_status` | Status produced by the reference analyzer (`CONSISTENT` / `CONFLICTING` / `UNKNOWN` / `PARSE_ERROR`). Provided for transparency. |
| `source` | Origin repositories: VirusTotal / MalwareBazaar. |

## Composition (189)

- **186 blind** — drawn without structural selection; treated distributionally.
- **3 constructed-discrepancy** (`EXT_T1`, `EXT_T4`, `EXT_T5`) — manually verified to
  carry a genuine target discrepancy and used as the small labeled subset.

## How ground truth was established

For the external set, ground truth was determined by executing the shortcut inside an
**isolated Windows sandbox** with the dangerous command disabled, observing the actual
execution target. The reference analyzer itself processes every sample **statically**
(`analyze_lnk()`), without launching any file.

## How to obtain the samples

These are malicious files; download and handle them **only** in an isolated lab.

1. Look up a hash on MalwareBazaar: `https://bazaar.abuse.ch/sample/<sha256>/`
2. Or on VirusTotal: `https://www.virustotal.com/gui/file/<sha256>`
3. After downloading, verify integrity:
   ```bash
   sha256sum suspicious.lnk   # must equal the value in EXTERNAL_HASHES.csv
   ```

## Safety

Do **not** double-click or execute these samples. Analyze them statically, or only
detonate inside a disposable VM with no network and no access to your host.
