# Cybersecurity zero-day research data repository

## 1. Research title
**Explainable Continual Learning for Zero-Day Cyberattack Detection Under Evolving Threat Landscapes**

## 2. Research objective (this repository)
This repository provides a reproducible, audited data foundation for the study. It covers finding, verifying,
downloading, preserving, validating, cleaning, harmonising, organising and documenting the data.
**No model has been trained.** Experiments may start only after `FINAL_DATA_AUDIT.md` has been reviewed.

## Current status at a glance (collected 2026-10-02)

| Item | Status |
|---|---|
| CSE-CIC-IDS2018 | ✅ 10 official CSVs (6.9 GB, 16,232,943 flows) downloaded from the publisher's AWS Open Data bucket, SHA-256 recorded, validated, cleaned, harmonised and split |
| CIC-IDS2017, CIC-DDoS2019, UNSW-NB15, TON_IoT (optional) | ⏳ **pending manual download.** The official hosts were blocked by the collection environment's network policy, and the CIC downloads sit behind a registration form, which was not bypassed. The adapters are ready; drop the files in and re-run. |
| Nepal public data | ✅ 14 incidents, 11 reports/policies, 17 indicators, 38 sources. ⚠️ Every record is at verification level `search_extract_only` and must be confirmed against the full source before citation. |
| Leakage report / class distribution / audit | ✅ `06_analysis_ready/data_leakage_report.md`, `10_research_outputs/tables/class_distribution.csv`, `FINAL_DATA_AUDIT.md` |

## 3–6. Dataset sources, versions, download dates, licences
Full detail: `00_project_documentation/data_sources.md`, `02_raw_metadata/data_catalog.csv`,
`02_raw_metadata/source_registry.csv`.

| Dataset | Version used | Downloaded | Licence / terms | Cite |
|---|---|---|---|---|
| CSE-CIC-IDS2018 | *Processed Traffic Data for ML Algorithms* (CICFlowMeter-V3), `s3://cse-cic-ids2018` | 2026-10-02 | CIC/UNB terms: redistribution with citation (re-confirm on official page) | Sharafaldin, Lashkari & Ghorbani, ICISSP 2018 |
| CIC-IDS2017 | MachineLearningCSV / GeneratedLabelledFlows | pending | CIC/UNB terms | Sharafaldin et al., ICISSP 2018 |
| CIC-DDoS2019 | CSV-01-12, CSV-03-11 | pending | CIC/UNB terms | Sharafaldin et al., ICCST 2019 |
| UNSW-NB15 | training/testing sets + full CSVs | pending | academic use with citation | Moustafa & Slay, MilCIS 2015 |
| TON_IoT (optional) | Train_Test_Network | pending | academic use with citation | Moustafa, SCS 2021 |

## 7. Raw-data structure
```
01_raw_data/
├── CSE_CIC_IDS2018/                 10 × *_TrafficForML_CICFlowMeter.csv (read-only, 0444)
│   └── _publisher_documentation/    AWS registry YAML, CICFlowMeter ReadMe (feature definitions)
├── CIC_IDS2017/ CIC_DDoS2019/ UNSW_NB15/ TON_IoT/   PLACE_FILES_HERE.md (instructions)
└── Nepal_public_data/               README.md (why no raw pages were captured)
```
Raw files are never modified. `02_raw_metadata/raw_checksums.csv` holds the SHA-256 of every raw file.
Raw and derived data files are not committed to Git (see `.gitignore`); `08_scripts/run_pipeline.sh` re-creates them.

## 8. Cleaning procedures
Details: `00_project_documentation/methodology_notes.md` §3, with per-step counts in `09_logs/cleaning_log.csv`.
- 59 repeated in-file header rows dropped. These are publisher artefacts, not observations.
- Columns renamed to snake_case, and timestamps parsed with the publisher format.
- 131,799 `±Infinity` cells set to NaN, with the row flag `had_infinite_value` kept.
- Values that are already missing are reported but not imputed; no blank cells exist in the feature columns.
- Duplicates are reported but kept in the cleaned data; see §12 for the split-level policy.
- Negative sentinels such as `Init Fwd Win Byts = -1` are kept and reported.

## 9. Harmonisation procedure
- 33 unified flow features (`03_data_dictionary/unified_dictionary.csv`). A feature that a dataset does not
  publish is NaN (`05_harmonized_data/cross_dataset/feature_availability.csv`).
- The only transform is unit conversion: CICFlowMeter µs → s, and UNSW ms → s.
- **Timestamp correction:** the published CSE-CIC-IDS2018 times use a 12-hour clock with AM/PM dropped. The hours
  that are unambiguously afternoon are shifted +12 h, the ambiguous hours are flagged, and invalid 1970 dates are
  set to NaT. `timestamp_as_published` is kept. After correction, every attack window matches the publisher's schedule.

## 10. Feature engineering
None. No feature is derived. The unified schema renames and converts units only; this keeps explanations faithful
to published, documented measurements. `03_data_dictionary/explainability_feature_registry.csv` describes the 32
model-facing features: description, unit, interpretation and possible security meaning. This supports SHAP,
LIME, permutation importance and global/local explanations.

## 11. Label mapping
`original_label` is kept verbatim. `standardized_label` comes from the auditable table in `08_scripts/common.py`
(exported to `05_harmonized_data/labels/label_mapping_table.csv`), and `mapping_confidence` takes the values
exact, publisher_category or ambiguous. Ambiguous labels, such as UNSW Reconnaissance, become
`UNMAPPED_AMBIGUOUS`; they are not forced into a family.

| CSE-CIC-IDS2018 original | standardized |
|---|---|
| Benign | BENIGN |
| DoS attacks-GoldenEye / -Slowloris / -SlowHTTPTest / -Hulk | DOS |
| DDoS attacks-LOIC-HTTP, DDOS attack-LOIC-UDP, DDOS attack-HOIC | DDOS |
| FTP-BruteForce, SSH-Bruteforce | BRUTE_FORCE |
| Brute Force -Web, Brute Force -XSS, SQL Injection | WEB_ATTACK (publisher's "Web attacks" scenario) |
| Infilteration (publisher spelling) | INFILTRATION |
| Bot | BOT |

## 12. Temporal splitting (`06_analysis_ready/{train,validation,test}/`)
- Within each (capture day, original label) group, flows are cut chronologically: 70% train, 15% validation,
  15% test. There is no shuffling, and every class appears in every split.
- Validation/test flows whose model-facing feature vector already occurs in training are **removed from
  validation/test**; training is never reduced. This removes almost all FTP-BruteForce, DoS-SlowHTTPTest and
  HOIC DDoS test flows, which are verbatim repeats. See the warning in the leakage report.
- No scaler or imputer has been fitted. Train-only statistics are in `train/feature_stats_train_only.csv`.

## 13. Zero-day simulation (`06_analysis_ready/zero_day/`)
This is an **unseen-attack simulation** (zero-day-like evaluation scenario), **not real zero-day attacks**.
One family is removed from train and validation, and all of its flows go to test (`is_unseen_family = 1`).

| Scenario | Withheld family | Training/validation classes |
|---|---|---|
| zero_day_scenario_01 | WEB_ATTACK | BENIGN, BOT, BRUTE_FORCE, DDOS, DOS, INFILTRATION |
| zero_day_scenario_02 | INFILTRATION | BENIGN, BOT, BRUTE_FORCE, DDOS, DOS, WEB_ATTACK |
| zero_day_scenario_03 | BOT | BENIGN, BRUTE_FORCE, DDOS, DOS, INFILTRATION, WEB_ATTACK |

Each scenario folder holds `train/validation/test.parquet` and `scenario.json`. `zero_day_test.parquet` is
scenario 01's test set.

## 14. Continual-learning stages (`06_analysis_ready/continual_learning/`)
The stages follow strictly chronological, disjoint capture days, so no future data reaches an earlier stage.
Each stage has its own train/validation/test, and full periods and counts are in `stages.json`.

| Stage | Days (2018) | New classes | Previously observed |
|---|---|---|---|
| 1 | 14–15 Feb | BENIGN, BRUTE_FORCE, DOS | – |
| 2 | 16, 20 Feb | DDOS (+ new DoS variants) | BENIGN, DOS |
| 3 | 21–23 Feb | WEB_ATTACK (+ new DDoS variant HOIC) | BENIGN, DDOS |
| 4 | 28 Feb – 1 Mar | INFILTRATION | BENIGN |
| 5 | 2 Mar | BOT (final unseen-attack evaluation) | BENIGN |

## 15. Nepal data collection (`07_nepal_analysis/`)
- `cyber_incidents.csv` (= `nepal_cyber_incidents.csv`): 14 publicly reported incidents from 2016 to 2026 in the
  government, banking/finance, telecom and e-commerce sectors.
- `cybersecurity_reports.csv`: 11 items, including the National Cyber Security Policy 2023, the NTA Cyber Security
  Byelaw 2077, NTA MIS reports, NRB payment oversight reports and the APNIC IPv6 study.
- `digital_infrastructure.csv` (summarised in `nepal_cybersecurity_statistics.csv`): 17 indicators covering
  broadband subscriptions, 4G users, international bandwidth, IPv6, wallet/mobile-banking users and cybercrime
  complaints.
- `source_register.csv` lists the 38 sources, and `source_evidence/source_NNN/source.md` holds the URL, title,
  publisher, date and the records that use each source. No article text is copied.
- Fields not stated in a source are recorded as `Unknown`, and nothing is inferred. Claims that appeared without a
  specific source page were excluded.

## 16. Ethical considerations
See `00_project_documentation/ethical_and_data_usage.md`. In short: public data only, no access-control bypass,
no mirrors, immutable raw data, no fabrication, no personal names, and simulated attacks are named honestly.

## 17. Reproducibility
```bash
pip install -r requirements.txt          # Python 3.11; pandas 3.0.6, numpy 2.4.6, pyarrow 25.0.1
bash 08_scripts/run_pipeline.sh          # download → Nepal register → validate → clean → harmonise → split → dictionaries → audit
```
To add the pending datasets, place the official files in `01_raw_data/<DATASET>/` as described in each
`PLACE_FILES_HERE.md`, then re-run the pipeline. The run needs about 16 GB of RAM for the 7.9M-row 20-02-2018 file
and about 20 GB of free disk. Splitting is deterministic; there is no random seed in any data split.

Script map: `08_scripts/common.py` (all methodological decisions), `download/`, `validation/`, `cleaning/`,
`harmonization/`, `dataset_split/`, `feature_engineering/`. Logs: `09_logs/download_log.csv`,
`cleaning_log.csv`, `processing_log.csv`.

## 18. Known limitations
1. Only one of the four required datasets is present, so cross-dataset generalisation cannot yet be evaluated.
2. Seven CSE-CIC-IDS2018 CSVs stop at exactly 1,048,575 rows, Excel's row limit. The publisher's files appear
   truncated: for example, DoS-Hulk on 16 Feb ends at 13:48. Class counts for those days are lower bounds.
3. The timestamps needed the 12-hour-clock correction. Flows at published hours 06–07 (9,378 rows) stay ambiguous,
   and the publisher does not state the time zone.
4. Heavy exact duplication: after de-duplication, FTP-BruteForce, DoS-SlowHTTPTest and HOIC DDoS are almost absent
   from validation/test. 22,370 feature vectors carry more than one label, which is label noise and concentrated in
   *Infilteration*.
5. `destination_port` is a strong, dataset-specific shortcut. Report results with and without it.
6. The standard split is chronological within each day and label, not across days. Use the continual-learning
   stages for strictly forward-in-time claims.
7. Nepal records are at `search_extract_only` verification. The sample is small and biased towards events that
   English-language media reported, so it is not a complete incident census.
8. Testbed data (CIC/UNSW) do not represent Nepali network traffic. Nepal data are contextual, not training data.

## Repository map
```
00_project_documentation/  README.md (copy), research_scope, data_sources, data_dictionary, methodology_notes, ethical_and_data_usage
01_raw_data/               immutable raw files (git-ignored)
02_raw_metadata/           data_catalog.csv, source_registry.csv, raw_checksums.csv, data_validation_report.csv
03_data_dictionary/        per-dataset + unified dictionaries, column mapping, explainability registry
04_cleaned_data/           cleaned parquet copies (git-ignored)
05_harmonized_data/        network_features/, labels/, temporal_data/, cross_dataset/
06_analysis_ready/         network_harmonized(.parquet|_train|_validation|_test), zero_day/, continual_learning/, leakage report
07_nepal_analysis/         incidents, reports, indicators, source register, source_evidence/
08_scripts/                pipeline code (+ run_pipeline.sh)
09_logs/                   download / cleaning / processing logs
10_research_outputs/       tables/ (validation profile, class distribution, purity screen), summaries/ (audit, leakage)
FINAL_DATA_AUDIT.md        final quality-control report
```
Large outputs are Parquet (zstd). CSV previews (`*_sample.csv`, up to 2,000 rows per class, deterministic) sit
next to each analysis-ready Parquet file.
