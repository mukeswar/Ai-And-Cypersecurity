# Data sources

Machine-readable versions: `02_raw_metadata/data_catalog.csv` (files) and `02_raw_metadata/source_registry.csv`
(sources, licences, citations, access status). Collection date for everything: **2026-10-02**.

## Network-intrusion datasets

| Dataset | Official source | Channel used | Status |
|---|---|---|---|
| CSE-CIC-IDS2018 | https://www.unb.ca/cic/datasets/ids-2018.html | Publisher-designated AWS Open Data bucket `s3://cse-cic-ids2018` (region ca-central-1), folder *Processed Traffic Data for ML Algorithms* (10 CSVs) | **Downloaded**, size-verified, SHA-256 recorded |
| CIC-IDS2017 | https://www.unb.ca/cic/datasets/ids-2017.html | registration form → download page | pending manual download |
| CIC-DDoS2019 | https://www.unb.ca/cic/datasets/ddos-2019.html | registration form → download page | pending manual download |
| UNSW-NB15 | https://research.unsw.edu.au/projects/unsw-nb15-dataset | SharePoint/OneDrive link on project page | pending manual download |
| TON_IoT (optional) | https://research.unsw.edu.au/projects/toniot-datasets | SharePoint/OneDrive link on project page | pending manual download |

Why only one dataset was downloaded: the collection environment's egress policy denied `www.unb.ca`,
`cicresearch.ca`, `research.unsw.edu.au`, Kaggle, Zenodo and Hugging Face. The AWS bucket for
CSE-CIC-IDS2018 is the publisher's official channel (listed in the AWS Open Data Registry with documentation and
licence fields pointing to the UNB page), so it was used. Mirrors were not used for the others.

The *Original Network Traffic and Log data* folder of the same bucket (PCAPs + logs, 31 objects, ~479 GB) was
not downloaded: the publisher's flow CSVs are the analysis unit for this study.

### Publisher documentation saved with the raw data
- `01_raw_data/CSE_CIC_IDS2018/_publisher_documentation/aws_open_data_registry_cse-cic-ids2018.yaml`
  (from github.com/awslabs/open-data-registry)
- `01_raw_data/CSE_CIC_IDS2018/_publisher_documentation/CICFlowMeter_ReadMe.txt`
  (feature definitions, from github.com/ahlashkari/CICFlowMeter)

### Citations
- Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). *Toward Generating a New Intrusion Detection Dataset
  and Intrusion Traffic Characterization.* ICISSP 2018. (CIC-IDS2017, CSE-CIC-IDS2018)
- Sharafaldin, I., Lashkari, A. H., Hakak, S., & Ghorbani, A. A. (2019). *Developing Realistic Distributed Denial of
  Service (DDoS) Attack Dataset and Taxonomy.* IEEE ICCST 2019. (CIC-DDoS2019)
- Moustafa, N., & Slay, J. (2015). *UNSW-NB15: a comprehensive data set for network intrusion detection systems.*
  MilCIS 2015. (UNSW-NB15)
- Moustafa, N. (2021). *A new distributed architecture for evaluating AI-based security systems at the edge: Network
  TON_IoT datasets.* Sustainable Cities and Society, 72. (TON_IoT)

## Nepal public secondary data

- Register of 38 sources: `07_nepal_analysis/source_register.csv`; one evidence folder per source in
  `07_nepal_analysis/source_evidence/source_NNN/source.md` (URL, title, publisher, date, records using it).
- Source types: national newspapers (The Kathmandu Post, myRepublica, Setopati, OnlineKhabar, Khabarhub),
  specialised tech press (NepaliTelecom, ICT Frame), international press (Reuters via Insurance Journal, The Star,
  BankInfoSecurity), regulator/government documents (NTA MIS reports, NTA Cyber Security Byelaw 2077, National Cyber
  Security Policy 2023), central bank (NRB Payment Systems Oversight Reports), RIR (APNIC blog), DataReportal,
  organisation statements (Vianet, Have I Been Pwned).

### Verification level — important
All Nepal hosts and the World Bank/ITU/APNIC/DataReportal sites were blocked in the collection environment. Each
record was therefore taken from a **web-search result**: the URL and title of the page plus the search engine's
extract of it. Every record carries `verification_status = search_extract_only`. Before a value is cited, open the
URL, confirm it, and change the status to `verified_full_text`. Fields not stated in the extract are `Unknown`;
nothing was inferred.

Not used: social-media posts, unattributed blog aggregations, and claims that appeared only in a search-engine
summary without a specific source page (e.g. unsourced claims about attacks on the Nepal Electricity Authority or a
central-bank data sale were **excluded**).
