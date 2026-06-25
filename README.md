# LNK Target-Discrepancy Dataset

[![License: CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-blue.svg)](LICENSE)
[![Data: Windows .lnk](https://img.shields.io/badge/data-Windows%20.lnk-lightgrey.svg)](#)

A labeled dataset of **Windows Shortcut (`.lnk`) files** for studying **target
discrepancy** — the condition where the target shown to a user (*target UI*) differs
from the target most plausibly resolved for execution (*predicted execution target*).
It is the dataset companion to the final-project research on **rule-based detection of
`.lnk` target discrepancy**.

The dataset has three parts:

| Split | Contents | Count | Role | Included here |
|---|---|---|---|---|
| **Controlled** | `.lnk` + full ground truth | 647 files | Functional validation (labeled) | ✅ files + manifest |
| **Adversarial** | synthetic `.lnk` stress tests | 336 files (340 cases) | Robustness / failure-mode discovery | ✅ files + manifest |
| **External** | real malicious `.lnk` | 189 hashes | Robustness case study | 🔑 **hashes only** (not redistributed) |

---

## ⚠️ Safety / Disclaimer

- The **adversarial** `.lnk` files are **synthetic** and crafted to probe a static
  analyzer. Some embed command-like strings (e.g. `cmd.exe /c …`). **Do not
  double-click or execute any `.lnk` in this repository.** Inspect them statically.
- The **external** split contains real malware and is therefore **not** shipped here —
  only SHA-256 hashes are provided (see [`external/`](external/)). Handle those samples
  only inside an isolated lab/VM.
- A `CONFLICTING` status is **not** a malware verdict. It only flags that a shortcut's
  displayed target and its predicted execution target diverge and should be reviewed.

---

## What is "target discrepancy"?

A single `.lnk` can store a target in several active fields — `LinkTargetIDList`,
`LinkInfo`, `EnvironmentVariableDataBlock`, `RelativePath`, and `TrackerDataBlock`
(per the Microsoft **[MS-SHLLINK]** specification). When these disagree, are empty, or
no longer exist on disk, the **target UI** (what the user sees) can differ from the
**predicted execution target** (what would most plausibly run). Each sample carries one
of three labels:

| Label | Meaning |
|---|---|
| `CONSISTENT` | Target UI and predicted execution target resolve to the same path after normalization. |
| `CONFLICTING` | They resolve to different paths after normalization. |
| `UNKNOWN` | At least one side cannot be resolved, so no comparison is possible (evidence is insufficient — not a system failure). |

---

## Repository structure

```
.
├── README.md                     ← you are here
├── LICENSE                       ← CC BY 4.0
├── CITATION.cff                  ← "Cite this repository"
├── lnk/
│   ├── consistent/               (265 .lnk)  env 101 · idlist 132 · special 32
│   ├── conflict/                 (214 .lnk)  linkinfo 42 · relative 54 · special 64 · tracker 54
│   ├── unknown/                  (168 .lnk, flat)
│   └── adversarial/              (336 .lnk across 9 categories)
│       ├── ENV_POISON/ PATH_IDENTITY/ EXT_CONFLICT/ TRACKER_FORGERY/
│       ├── UNICODE_NFC/ PRIORITY_COLLISION/ TOCTOU_MISSING/
│       └── HEADER_POISON/ MIXED_CONSISTENCY/
├── manifests/
│   ├── controlled_manifest.csv   ← 647 rows, full ground truth (authoritative labels)
│   ├── adversarial_manifest.csv  ← 340 rows
│   └── SCHEMA.md                 ← column dictionary
└── external/
    ├── EXTERNAL_HASHES.csv        ← 189 SHA-256 (malware not redistributed)
    └── README.md                 ← hash-only policy + how to obtain samples
```

> **Labels live in the manifests, not in the folder names.** Folders are a quick visual
> grouping only. For any analysis, join on `sample_id` and read `expected_status`.

---

## 1. Controlled dataset (647 files)

Built specifically to have explicit ground truth. Targets and field states were
constructed deliberately, and the expected behavior was established through **controlled
Windows behavioral observation** — running shortcuts manually in a controlled Windows
environment, recording which target opens, and observing how the resolution falls back
when a priority candidate is made invalid. Labels therefore come from documented
expected behavior, **not** from the system being evaluated.

**Authoritative label distribution (`expected_status`):**

| Label | Count |
|---|---|
| CONSISTENT | 263 |
| CONFLICTING | 318 |
| UNKNOWN | 66 |
| **Total** | **647** |

**Conflict family (`scenario_group`, used in the thesis tables):**

| Group | Count | Expected |
|---|---|---|
| BASELINE | 329 | CONSISTENT / UNKNOWN |
| IDLIST | 114 | CONFLICTING |
| KHUSUS (combination/special) | 96 | CONFLICTING |
| ENV | 60 | CONFLICTING |
| LINKINFO | 30 | CONFLICTING |
| TRACKER | 17 | CONFLICTING |
| RELATIVE | 1 | CONFLICTING |

### Folder grouping vs. label — important
The repo folders use a **coarse grouping** (`main_category`: `consistent/` 265,
`conflict/` 214, `unknown/` 168). The **evaluation label** is `expected_status`
(263 / 318 / 66). They do not match one-to-one because `main_category` is a content
grouping while `expected_status` is the per-sample decision label. **Use
`expected_status` from `controlled_manifest.csv` as the ground truth.** See
[`manifests/SCHEMA.md`](manifests/SCHEMA.md) for every column.

> Note: filenames mirror the real artifacts used to construct the targets (documents,
> media, executables of varied types). Target *type* indicates variety only, never a
> malware/benign label.

---

## 2. Adversarial dataset (336 files / 340 cases)

Synthetic shortcuts crafted to stress each assumption of the analysis pipeline. They are
scored as **PASS / FAIL / INFO** (`system_correct` in the manifest), not as a binary
confusion matrix.

| Category | Tests / failure surface |
|---|---|
| `ENV_POISON` | Detection of command-like, quoted, or misleading ENV paths. |
| `PATH_IDENTITY` | Path canonicalization: path-equivalent strings must normalize equal. |
| `EXT_CONFLICT` | Explicit external-style conflict patterns. |
| `TRACKER_FORGERY` | TrackerDataBlock validation that is too permissive (volume match ≠ file identity). |
| `UNICODE_NFC` | Unicode normalization and parser behavior on filenames. |
| `PRIORITY_COLLISION` | Candidate-priority collisions. |
| `TOCTOU_MISSING` | Existing-check dependence on filesystem state at analysis time. |
| `HEADER_POISON` | Robustness to irrelevant header noise. |
| `MIXED_CONSISTENCY` | Partly-consistent / partly-conflicting field combinations. |

**Counts (files in repo):** ENV_POISON 104 · PATH_IDENTITY 82 · EXT_CONFLICT 54 ·
PRIORITY_COLLISION 21 · TRACKER_FORGERY 21 · HEADER_POISON 14 · MIXED_CONSISTENCY 14 ·
TOCTOU_MISSING 13 · UNICODE_NFC 13 = **336**.

The manifest lists **340** cases. The 4 extra are `UNICODE_NFC` NFD-encoded names that
cannot be materialized as valid Windows filenames; they are kept in the manifest as
documented cases but have no `.lnk` file.

---

## 3. External dataset (189 hashes, files not included)

Real malicious `.lnk` files from **VirusTotal / MalwareBazaar**. To avoid redistributing
malware, only SHA-256 hashes are published. The set is **189** = 186 *blind* (drawn
without structural selection, read distributionally) + 3 *constructed-discrepancy*
(`EXT_T1`, `EXT_T4`, `EXT_T5`, manually verified). Ground truth was set by detonating each
sample in an isolated Windows sandbox with the dangerous command disabled.

See [`external/README.md`](external/README.md) and
[`external/EXTERNAL_HASHES.csv`](external/EXTERNAL_HASHES.csv) for the list and for how to
obtain samples by hash.

---

## Reproducibility

- **OS:** Windows 11 (64-bit). **Implementation language:** Python 3.11.
- **Supporting tools:** LECmd (parsing/cross-check), ExifTool (metadata cross-check),
  MFTECmd (droid-UUID lookup in `$MFT` for tracker validation).
- Every controlled and adversarial sample carries a **SHA-256** in its manifest for
  integrity checking. Cross-check columns (`lecmd_crosscheck`, `exiftool_crosscheck`)
  record field readability against existing tools — they verify readability, **not** the
  discrepancy label.
- `TrackerDataBlock` validation requires `$MFT`; without it, tracker status is `UNKNOWN`.
  Existing-check results depend on the analysis machine's filesystem, so reproducing them
  requires the same documented environment.

---


## Mapping to the thesis

| Repo split | Thesis role |
|---|---|
| Controlled (647, `expected_status`) | Main detection-effectiveness evaluation (confusion matrix on the 581 binary-labeled samples; 66 UNKNOWN analyzed separately). |
| Adversarial (340 cases) | Adversarial robustness study (PASS/FAIL/INFO, 9 categories, failure modes). |
| External (189 hashes) | External blind robustness case study (1 TP / 2 FN / 154 TN on the 3 constructed-discrepancy + distributional read of the rest). |

---

## Limitations

- Labels reflect a **controlled** construction; they validate the rules against documented
  scenarios, not universal real-world performance.
- Predicted execution target is derived by **static analysis**; it does not claim the exact
  runtime target Windows would choose.
- Detection is at the **path level** and does not cover argument-level abuse
  (`CommandLineArguments`).
- Filenames intentionally preserve the real artifacts used to build the targets.

---

## Citation

If you use this dataset, please cite it (GitHub shows a "Cite this repository" button from
[`CITATION.cff`](CITATION.cff)):

```bibtex
@misc{kastanja_lnk_discrepancy_dataset_2026,
  author       = {Kastanja, Yobel Alvino},
  title        = {LNK Target-Discrepancy Dataset (controlled, adversarial, external-hashes)},
  year         = {2026},
  howpublished = {\url{https://github.com/YobelAK/LNK-Discrepancy-dataset}},
  note         = {Companion dataset to research on rule-based detection of Windows .lnk target discrepancy}
}
```

## License

Released under [Creative Commons Attribution 4.0 International (CC BY 4.0)](LICENSE).
You may share and adapt the material for any purpose, provided you give appropriate
credit. The external-split samples themselves are **not** distributed here (hashes only);
their use is subject to the terms of their source repositories.
