# Ethical considerations and data-usage conditions

## Principles applied
| Rule | How it is enforced |
|---|---|
| Public secondary data only | Datasets come only from their official publishers (CSE-CIC-IDS2018 from the AWS Open Data bucket that the publisher links). Nepal records come from public news, regulator and central-bank publications. |
| No access-control bypass | CIC-IDS2017 and CIC-DDoS2019 are distributed after a registration form; UNSW-NB15/TON_IoT through SharePoint links. These were **not** scraped or bypassed; they are marked `pending_manual_download`. Hosts the network policy denied were reported, not tunnelled around. |
| No unofficial mirrors | Kaggle/Hugging Face/GitHub copies were not used. |
| Raw data immutable | Raw files are set read-only (0444) on download and checksummed (SHA-256). All processing writes new files. |
| No fabrication | Unavailable features are NaN; unknown Nepal fields are `Unknown`; no incident is inferred. Every Nepal record cites a URL and carries a verification status. |
| No silent changes | Every cleaning/processing step is logged with counts (`09_logs/`). `original_label` is never altered. |
| Honest terminology | Withheld-family experiments are called *unseen-attack simulation* / *zero-day-like evaluation scenario*. |
| Copyright | Nepal evidence notes are short factual summaries; no article text is reproduced. |

## Personal data
- The CIC datasets contain IP addresses of **testbed** machines (CSE-CIC-IDS2018: Tuesday 20-02-2018 file only).
  They are not personal data of real users, but they are still excluded from all model features.
- Nepal incident records describe organisations, not individuals. Names of arrested or accused
  persons appearing in news reports are deliberately **not** recorded.

## Licences and citation obligations
See `02_raw_metadata/data_catalog.csv` (`license`, `citation` columns). Summary:
- CIC datasets (CIC-IDS2017, CSE-CIC-IDS2018, CIC-DDoS2019): redistribution permitted only with citation of the dataset
  and the publisher's paper (CIC/UNB terms). The full licence text must be re-checked on the official page before
  publication, because that page could not be opened from the collection environment.
- UNSW-NB15 / TON_IoT: free for academic research use with citation of the publisher's papers.
- Raw and derived data files are **not** committed to Git (size and redistribution hygiene); they are re-created by
  `08_scripts/run_pipeline.sh`.

## Dual-use note
The data describe attack traffic for **defensive** detection research. No exploit code, malware or attack
tooling is included or produced.
