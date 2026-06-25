# Manifest Schema

This folder holds the per-sample ground truth for the dataset. The manifests are
the **authoritative source of labels** — the folder a `.lnk` file lives in is only
a coarse grouping (see note on `main_category` vs `expected_status` below).

- `controlled_manifest.csv` — 647 rows, one per controlled `.lnk` file.
- `adversarial_manifest.csv` — 340 rows, one per adversarial case.

Join key: the file basename without the `.lnk` extension equals `sample_id`
(verified: 647/647 controlled files match their `sample_id`).

---

## controlled_manifest.csv

| Column | Type | Description |
|---|---|---|
| `sample_id` | string | Unique id; equals the `.lnk` filename without extension. |
| `main_category` | enum | Coarse grouping used for the repo folders: `CONSISTENT` / `CONFLICTING` / `UNKNOWN`. **Not** the evaluation label (see `expected_status`). |
| `target_type` | string | Extension/type of the intended target (e.g. `.exe`, `.pdf`, `.vbs`); empty for some UNKNOWN cases. Indicates target variety, not malware/benign. |
| `scenario_group` | enum | Conflict family: `BASELINE`, `IDLIST`, `LINKINFO`, `ENV`, `RELATIVE`, `TRACKER`, `KHUSUS` (combination/special). |
| `subscenario_desc` | string | Short description of the specific scenario. |
| `state_idlist` | enum | State of LinkTargetIDList in this sample (e.g. present/absent/exists/not-found variants). Used by simple baselines. |
| `state_linkinfo` | enum | State of LinkInfo. |
| `state_env` | enum | State of EnvironmentVariableDataBlock (e.g. empty, quoted, command-like, exists, not-found). |
| `state_relativepath` | enum | State of RelativePath. |
| `state_tracker` | enum | State of TrackerDataBlock. |
| `expected_status` | enum | **Ground-truth label** used by the thesis confusion matrix: `CONSISTENT`, `CONFLICTING`, or empty = `UNKNOWN`. |
| `expected_ui_target_field` | enum | Field that should be read as the **target UI** (e.g. `LinkTargetIDList`, `EnvironmentVariableDataBlock`). |
| `expected_ui_target_path` | string | Expected absolute path of the target UI. |
| `expected_execution_target_field` | enum | Field that should resolve as the **predicted execution target**. |
| `expected_execution_target_path` | string | Expected absolute path of the predicted execution target. |
| `expected_tracker_status` | enum | Expected tracker validation outcome: `VALID` / `INVALID` / `NO_TRACKER`. |
| `target_file_relpath` | string | Relative path of the constructed target file used during ground-truth setup. |
| `target_file_exists_at_creation` | bool | Whether the target file existed on disk when the sample was created. |
| `sha256` | hex64 | SHA-256 of the `.lnk` file, for integrity verification. |
| `lecmd_crosscheck` | enum | Field-readability cross-check vs LECmd: `MATCH` / `SKIP` / `MISMATCH`. (Readability only, not a discrepancy label.) |
| `exiftool_crosscheck` | enum | Field-readability cross-check vs ExifTool: `MATCH` / `SKIP` / `MISMATCH`. |
| `system_output_status` | enum | Status produced by the reference rule-based analyzer (`analyze_lnk`) for this sample. Provided for transparency; **not** the ground truth. |

### `main_category` vs `expected_status` (read this)
The repo folders are organized by `main_category` (`consistent/` = 265, `conflict/`
= 214, `unknown/` = 168 = 647). The **evaluation ground truth** is `expected_status`
(`CONSISTENT` = 263, `CONFLICTING` = 318, `UNKNOWN` = 66 = 647). They differ because
`main_category` is a coarse content grouping while `expected_status` is the per-sample
label after resolution/normalization/existing-check reasoning. **Always use
`expected_status` for labels**; treat folder names as navigation only.

---

## adversarial_manifest.csv

Synthetic stress-test cases. These are reported in the thesis as PASS/FAIL/INFO,
**not** as a binary confusion matrix.

| Column | Type | Description |
|---|---|---|
| `sample_id` | string | Unique id. |
| `category` | enum | One of nine attack categories (see root README). |
| `variant` | string | Specific construction variant within the category. |
| `construction` | string | How the adversarial case was built. |
| `ground_truth` | string | Intended/expected outcome from the construction. |
| `system_status` | enum | Status produced by the analyzer (CONSISTENT/CONFLICTING/UNKNOWN, etc.). |
| `system_detail` | string | Detail/reason of the analyzer output. |
| `system_correct` | enum | Scoring of the case: `TRUE` = PASS, `FALSE` = FAIL, `INFO` = non-decisive. |
| `failure_mode` | string | Identified failure mode for FAIL cases. |
| `sha256` | hex64 | SHA-256 of the `.lnk`. |

Note: the repo ships **336** adversarial `.lnk` files while the manifest lists
**340** cases. The 4 missing files are `UNICODE_NFC` NFD-encoded names that cannot
be materialized as valid Windows filenames; they remain in the manifest as
documented cases.
