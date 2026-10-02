#!/usr/bin/env bash
# Full, re-runnable pipeline. Raw files are never modified (read-only, SHA-256 recorded).
# Usage: bash 08_scripts/run_pipeline.sh   (from the repository root cybersecurity_zero_day_research/)
set -euo pipefail
cd "$(dirname "$0")/.."
python3 08_scripts/download/download_datasets.py        # official sources only; idempotent
python3 08_scripts/download/build_nepal_register.py      # Nepal public-source register
python3 08_scripts/validation/validate_raw.py            # validation report + checksums
python3 08_scripts/cleaning/clean_dataset.py             # cleaned copies (parquet)
python3 08_scripts/harmonization/harmonize.py            # unified schema, labels, temporal tables
python3 08_scripts/dataset_split/make_splits.py          # standard / zero-day-like / continual splits + leakage report
python3 08_scripts/feature_engineering/build_dictionaries.py
python3 08_scripts/validation/build_catalog_and_audit.py # data_catalog, source_registry, FINAL_DATA_AUDIT.md
