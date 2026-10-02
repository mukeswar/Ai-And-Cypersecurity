# Research scope

**Title:** Explainable Continual Learning for Zero-Day Cyberattack Detection Under Evolving Threat Landscapes

## Objective of this repository (data phase only)

Build a reproducible, research-ready data foundation:
Find → Verify → Download → Preserve raw data → Validate → Clean → Harmonise → Organise → Document.

**Model training is out of scope** and must not start until `FINAL_DATA_AUDIT.md` has been reviewed.

## Research questions the data must support

1. **Continual learning:** can a detector learn new attack families as they appear over time without
   forgetting earlier ones? → chronological stages in `06_analysis_ready/continual_learning/`.
2. **Unseen-attack detection:** how does a detector behave on attack families that were never in its
   training data? → withheld-family scenarios in `06_analysis_ready/zero_day/`
   (an *unseen-attack simulation*, never described as real zero-day attacks).
3. **Explainability:** which flow features drive decisions, globally and per alert? → interpretable,
   unit-documented unified features (`03_data_dictionary/explainability_feature_registry.csv`),
   ready for SHAP, LIME and permutation importance.
4. **Generalisation:** do models transfer across datasets/environments? → unified schema across
   CIC-IDS2017, CSE-CIC-IDS2018, CIC-DDoS2019, UNSW-NB15 (and optionally TON_IoT). The adapters are in place;
   only CSE-CIC-IDS2018 is downloaded at present (see FINAL_DATA_AUDIT.md §9).
5. **Contextual relevance for Nepal:** what public evidence describes Nepal's cyber-threat landscape and
   digital exposure? → `07_nepal_analysis/` (secondary, public sources only).

## In scope
- Publicly released benchmark intrusion-detection datasets from their official publishers.
- Publicly reported Nepal cyber incidents, public reports/policies and public statistics.

## Out of scope
- Any private, confidential or restricted data (ISP logs, bank records, government internal logs,
  personal data, credentials); any access-control bypass; model training.
