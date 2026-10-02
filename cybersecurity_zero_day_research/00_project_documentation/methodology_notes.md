# Methodology notes

All decisions below are implemented in code; the code is the authority (file references given).

## 1. Raw-data preservation (`08_scripts/download/download_datasets.py`)
- Downloads go to `<file>.part`, are size-checked against the publisher's listing, then renamed and set read-only.
- Interrupted/truncated transfers are retried (max 4) and never kept as raw data.
- SHA-256 for every raw file → `02_raw_metadata/raw_checksums.csv`.

## 2. Validation (`08_scripts/validation/validate_raw.py`)
Per file: size, format, strict UTF-8 check, physical line count, parsed rows/columns, malformed lines,
repeated in-file header rows, blank cells, ±Infinity, literal `NaN`, non-numeric tokens in numeric columns,
exact duplicate rows (64-bit row hash), label values, timestamp parse rate and range.
→ `02_raw_metadata/data_validation_report.csv`, `10_research_outputs/tables/raw_column_profile.csv`,
`raw_label_counts.csv`.

## 3. Cleaning (`08_scripts/cleaning/clean_dataset.py`) — cleaned *copies* only
| Step | Treatment | Justification |
|---|---|---|
| Repeated header rows inside CSVs | dropped, counted | publisher artefact from concatenating capture files; they are not observations |
| Completely empty rows/columns | dropped, counted | carry no information |
| Column names | snake_case; mapping in `03_data_dictionary/column_name_mapping.csv` | consistent access |
| Timestamp | parsed with the publisher format (`%d/%m/%Y %H:%M:%S` for CSE-CIC-IDS2018); failures → NaT, counted | no guessing of formats |
| Numeric conversion | `to_numeric(errors='coerce')`; coerced tokens counted per column | explicit |
| ±Infinity | → NaN **and** row flag `had_infinite_value=True` | CICFlowMeter divides by a zero flow duration in `Flow Byts/s`/`Flow Pkts/s`; the flag preserves the information without fake numbers |
| Missing values | **reported, not imputed** (original count, method, final count in `09_logs/cleaning_log.csv`) | imputation must be fit on training data only |
| Negative values (e.g. `Init Fwd Win Byts = -1`) | kept, counted | `-1` is CICFlowMeter's "not available" sentinel; changing it would alter semantics |
| Duplicates | **kept** in cleaned data; counted | removal is decided per split (see §6) |
| Labels | `original_label` verbatim; `standardized_label`, `mapping_confidence`, `is_attack` added | never alter publisher labels |

## 4. Label standardisation (`08_scripts/common.py → LABEL_MAP`)
Families: BENIGN, DOS, DDOS, BRUTE_FORCE, PORT_SCAN, WEB_ATTACK, BOT, INFILTRATION, BOTNET, OTHER.
- `exact`: name unambiguously identifies the family (e.g. `DoS attacks-Hulk` → DOS).
- `publisher_category`: the publisher groups it in that family (e.g. CSE-CIC-IDS2018 `Brute Force -Web` and
  `Brute Force -XSS` belong to the publisher's *Web attacks* scenario → WEB_ATTACK, not BRUTE_FORCE).
- `ambiguous`: **not forced**; labelled `UNMAPPED_AMBIGUOUS` (UNSW-NB15 Reconnaissance, Analysis, Fuzzers, Generic).
- Unknown labels become `UNMAPPED_UNKNOWN` and are reported.
Full table: `05_harmonized_data/labels/label_mapping_table.csv`; applied counts:
`05_harmonized_data/cross_dataset/label_mapping_applied.csv`.

## 5. Harmonisation (`08_scripts/harmonization/harmonize.py`)
- Unified schema of 33 flow features (`03_data_dictionary/unified_dictionary.csv`).
- A feature is filled only from the documented source column; otherwise NaN
  (`05_harmonized_data/cross_dataset/feature_availability.csv`). No feature is derived.
- Only transformation: unit conversion (CICFlowMeter microseconds → seconds; UNSW-NB15 milliseconds → seconds).
- Note on byte counts: CIC `TotLen Fwd Pkts` is payload length; UNSW-NB15 `sbytes` is transaction bytes. They are
  mapped to the same unified name for convenience but are **not** strictly identical; cross-dataset results must
  mention this.
- Temporal tables are time-sorted with a stable sort and never shuffled.

### 5a. Timestamp correction (CSE-CIC-IDS2018) — an obvious formatting problem
Validation showed that in **every** file the published hour lies in 01–12 and never in 00 or 13–23, i.e. a 12-hour
clock whose AM/PM marker was lost. Cross-tabulating hour × label confirmed it: SSH-Bruteforce (scheduled by the
publisher for 14:01–15:31 on 14-02-2018) appears at hours 02–03. Correction (`common.correct_timestamp`):

| Published hour | Interpretation | Flag (`timestamp_correction`) |
|---|---|---|
| 01–05 | afternoon → +12 h (13–17 h) | `pm_shift_+12h` |
| 06–07 | cannot be resolved (early morning or evening) → kept | `ambiguous_hour_kept` |
| 08–12 | morning / noon → kept | `none` |
| date ≠ capture day (e.g. 1970-01-xx) | invalid → NaT, excluded from splits | `invalid_date_set_NaT` |

`timestamp_as_published` is kept next to the corrected `timestamp`. After correction every attack window matches
the publisher's schedule (see FINAL_DATA_AUDIT.md §4). Counts per file are in `09_logs/cleaning_log.csv`
(step `timestamp_12h_correction`). `capture_day` is taken from the file name.

## 6. Splits (`08_scripts/dataset_split/make_splits.py`)
**Standard (closed-world) split:** inside every (capture_day, original_label) group, flows are ordered by
(timestamp, row_in_file) and cut 70/15/15 → train/validation/test. Every class appears in every split and no
later flow of an attack episode trains a model evaluated on an earlier one. It is *not* globally chronological;
use the continual-learning stages for strictly forward-in-time evaluation.

**Leakage control:** validation/test rows whose model-facing feature vector also occurs in training are removed
(counts in the leakage report and in `class_distribution.csv` *_before_dedup columns). Training data are never
reduced. Within-split duplicates are kept.

**Unseen-attack simulation (zero-day-like):** one family withheld from train+validation; all its flows are in
test (`is_unseen_family=1`):

| Scenario | Withheld | Rationale |
|---|---|---|
| 01 | WEB_ATTACK | application-layer, low-volume; very different from volumetric DoS/DDoS seen in training |
| 02 | INFILTRATION | insider-like traffic that resembles benign flows; hardest case |
| 03 | BOT | periodic C2 beaconing; behavioural rather than volumetric |

**Continual-learning stages** (capture days, strictly chronological):

| Stage | Days | Role |
|---|---|---|
| 1 | 14–15 Feb 2018 | initial distribution: BENIGN, BRUTE_FORCE, DOS |
| 2 | 16 & 20 Feb | new attack distribution: new DoS variants, DDOS appears |
| 3 | 21–23 Feb | evolving traffic (new DDoS variant HOIC) + new family WEB_ATTACK |
| 4 | 28 Feb – 1 Mar | new family INFILTRATION |
| 5 | 2 Mar | final unseen-attack evaluation: BOT never seen before |

Each stage has its own train/validation/test (same rule as the standard split). Stage validation/test rows that
duplicate any training vector from stages ≤ current are removed.

## 7. Preprocessing that is intentionally deferred to the modelling phase
Imputation, scaling, class re-weighting/resampling and feature selection must be fit **on the relevant training
split only**. Train-only descriptive statistics are provided (`feature_stats_train_only.csv`).

## 8. Known limitations
- Only CSE-CIC-IDS2018 is present; cross-dataset code paths for the other datasets are implemented but untested
  on real files.
- CSE-CIC-IDS2018 timestamps required the 12-hour-clock correction above; the time zone is not stated by the
  publisher; 14 flows dated 1970 were set to NaT and excluded from splits; flows at published hours 06–07 are ambiguous.
- **Truncation:** seven CSE-CIC-IDS2018 day files contain exactly 1,048,575 data rows (the Microsoft Excel row
  limit), so the publisher's CSVs appear truncated (e.g. DoS-Hulk on 16-02-2018 stops at 13:48 although the attack
  is scheduled until ~14:19). Class counts for those days are lower bounds; the missing flows exist only in the
  ~479 GB PCAPs.
- In CSE-CIC-IDS2018 only the 20-02-2018 file publishes Flow ID/IPs/source port; `source_port` is therefore mostly
  NaN and excluded from model features.
- The *Infilteration* label is known in the literature to contain many flows indistinguishable from benign traffic
  (label noise); conflicting-label vectors are counted in the leakage report.
- `destination_port` is a strong, dataset-specific shortcut; report results with and without it.
- CIC-IDS2017 timestamps (when used) are 12-hour without AM/PM on some days; flagged in `common.py`.
- Nepal records are at `search_extract_only` verification level (see `data_sources.md`).
