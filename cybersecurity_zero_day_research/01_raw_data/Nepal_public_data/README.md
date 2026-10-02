# Nepal public data — raw capture

No raw web pages are stored here. In the collection environment (2026-10-02) all Nepali hosts
(kathmandupost.com, nta.gov.np, nrb.org.np, npcert.org.np, ...), the World Bank API, ITU, DataReportal
and APNIC were blocked by the egress policy. The only channel available was a web-search engine; the
URLs, titles and extracts it returned are recorded in `07_nepal_analysis/source_register.csv` and
`07_nepal_analysis/source_evidence/source_XXX/source.md`, each marked `search_extract_only`.

When the sources can be opened, save PDFs of official reports (NTA MIS, NRB oversight reports,
policies) here, unchanged, and re-run `08_scripts/validation/validate_raw.py` to checksum them.
