# Data dictionary (guide)

The dictionaries are CSV files in `03_data_dictionary/`:

| File | Content | Verified against raw files? |
|---|---|---|
| `CSE_CIC_IDS2018_dictionary.csv` | every raw column actually present, its clean name, CICFlowMeter description, unit, raw missing/infinite/non-numeric counts, unified-feature mapping, and how many files contain it | **yes** |
| `CIC_IDS2017_dictionary.csv` | publisher schema (CICFlowMeter long names) | no, pending download |
| `CIC_DDoS2019_dictionary.csv` | publisher schema | no, pending download |
| `UNSW_NB15_dictionary.csv` | publisher feature list for the partitioned train/test sets | no, pending download |
| `unified_dictionary.csv` | harmonised schema: unit, description, source column and scale factor per dataset, and the metadata columns | n/a |
| `column_name_mapping.csv` | raw column name → snake_case clean name, per file | yes |
| `explainability_feature_registry.csv` | model-facing features with interpretation and possible security meaning (for SHAP/LIME/permutation importance) | n/a |

## Column groups in harmonised / analysis-ready files

| Group | Columns | Use in models |
|---|---|---|
| Provenance | `dataset_source`, `source_file`, `row_in_file` | never (identifiers); used to join back to cleaned native features |
| Time | `timestamp`, `capture_day` (+ `date`, `year`, `month`, `day`, `hour` in temporal tables) | never as features; used for ordering and splitting |
| Labels | `original_label` (verbatim), `standardized_label`, `mapping_confidence`, `is_attack`, `is_unseen_family` (zero-day files) | targets only |
| Split metadata | `split`, `stage`, `removed_reason` | bookkeeping |
| Quality flags | `had_infinite_value`, `model_feature_hash` | flag may be used as a feature if justified; hash never |
| Features | the 32 names in `06_analysis_ready/model_feature_list.csv` | yes |

## Units
CICFlowMeter time features are **microseconds** in the raw/cleaned data and **seconds** in the harmonised data.
Rates are per second as published. Byte counts are bytes. Protocol is the IANA protocol number.
`Init Fwd/Bwd Win Byts = -1` means "not available" (CICFlowMeter sentinel), not a negative size.

## Joining the full native feature set
The harmonised schema keeps 33 cross-dataset features. To use all 78 CSE-CIC-IDS2018 features, join an
analysis-ready file to `04_cleaned_data/CSE_CIC_IDS2018/<source_file>.parquet` on (`source_file`, `row_in_file`).
The split assignment and de-duplication then carry over unchanged.
