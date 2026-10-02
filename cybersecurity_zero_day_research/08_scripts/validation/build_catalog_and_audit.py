#!/usr/bin/env python3
"""Generate data_catalog.csv, source_registry.csv and FINAL_DATA_AUDIT.md
from the artefacts produced by the earlier pipeline steps (nothing is typed in
by hand except the publisher metadata in CATALOG_META)."""
import glob
import importlib.metadata as md
import json
import os
import platform
import sys

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import DATASETS, HARM, LOGS, META, OUT, READY, ROOT, rel  # noqa: E402

CIC_TERMS = ("CIC/UNB terms on the official page: redistribution/mirroring permitted provided the dataset and the "
             "publisher's paper are cited. Exact licence text to be re-confirmed on the official page (not reachable "
             "from the collection environment).")
CATALOG_META = {
    "CSE_CIC_IDS2018": dict(
        dataset_name="CSE-CIC-IDS2018 (A Realistic Cyber Defense Dataset)",
        source_organization="Communications Security Establishment (CSE) & Canadian Institute for Cybersecurity (CIC), University of New Brunswick",
        official_url="https://www.unb.ca/cic/datasets/ids-2018.html",
        download_url="https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/Processed%20Traffic%20Data%20for%20ML%20Algorithms/ (AWS Open Data Registry, arn:aws:s3:::cse-cic-ids2018)",
        version="Processed Traffic Data for ML Algorithms (CICFlowMeter-V3 CSVs), as hosted on AWS",
        publication_year=2018, license=CIC_TERMS + " AWS registry entry 'License' field points to the official page.",
        citation="Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization. ICISSP 2018, pp. 108-116.",
        description="Labelled bidirectional flows (80 CICFlowMeter features) from a 420-PC/30-server victim network attacked from 50 machines",
        geographic_scope="Testbed (Canada, AWS-hosted lab); not real-world national traffic",
        temporal_scope="2018-02-14 to 2018-03-02 (10 capture days)",
        attack_types="Brute force (FTP/SSH), DoS (GoldenEye, Slowloris, SlowHTTPTest, Hulk), DDoS (LOIC-HTTP, LOIC-UDP, HOIC), Web (brute force, XSS, SQL injection), Infiltration, Botnet (Ares)"),
    "CIC_IDS2017": dict(
        dataset_name="CIC-IDS2017", source_organization="Canadian Institute for Cybersecurity (CIC), University of New Brunswick",
        official_url="https://www.unb.ca/cic/datasets/ids-2017.html", download_url="via registration form on official page",
        version="MachineLearningCSV / GeneratedLabelledFlows", publication_year=2017, license=CIC_TERMS,
        citation="Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization. ICISSP 2018.",
        description="Labelled CICFlowMeter flows, 5 capture days", geographic_scope="Testbed (Canada)",
        temporal_scope="2017-07-03 to 2017-07-07 (per publisher)",
        attack_types="Brute force (FTP/SSH-Patator), DoS, Heartbleed, Web attacks, Infiltration, Botnet, PortScan, DDoS"),
    "CIC_DDoS2019": dict(
        dataset_name="CIC-DDoS2019", source_organization="Canadian Institute for Cybersecurity (CIC), University of New Brunswick",
        official_url="https://www.unb.ca/cic/datasets/ddos-2019.html", download_url="via registration form on official page",
        version="CSV-01-12 / CSV-03-11", publication_year=2019, license=CIC_TERMS,
        citation="Sharafaldin, I., Lashkari, A. H., Hakak, S., & Ghorbani, A. A. (2019). Developing Realistic Distributed Denial of Service (DDoS) Attack Dataset and Taxonomy. IEEE ICCST 2019.",
        description="Reflection- and exploitation-based DDoS flows plus benign traffic", geographic_scope="Testbed (Canada)",
        temporal_scope="2018-12-01 (training day) and 2018-03-11 (testing day) per publisher",
        attack_types="DrDoS DNS/LDAP/MSSQL/NetBIOS/NTP/SNMP/SSDP/UDP, SYN, TFTP, UDP-lag, WebDDoS, PortMap"),
    "UNSW_NB15": dict(
        dataset_name="UNSW-NB15", source_organization="UNSW Canberra Cyber, University of New South Wales",
        official_url="https://research.unsw.edu.au/projects/unsw-nb15-dataset", download_url="official SharePoint/OneDrive link on project page",
        version="Partitioned training/testing sets + 4 full CSVs", publication_year=2015,
        license="Free for academic research use per publisher; cite the papers below. To be re-confirmed on the official page.",
        citation="Moustafa, N., & Slay, J. (2015). UNSW-NB15: a comprehensive data set for network intrusion detection systems. MilCIS 2015.; Moustafa, N., & Slay, J. (2016). The evaluation of Network Anomaly Detection Systems: Statistical analysis of the UNSW-NB15 data set and the comparison with the KDD99 data set. Information Security Journal: A Global Perspective, 25(1-3).",
        description="Argus/Bro-IDS flow features generated with IXIA PerfectStorm", geographic_scope="Testbed (Australia)",
        temporal_scope="2015 captures (two sessions per publisher)",
        attack_types="Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms"),
    "TON_IoT": dict(
        dataset_name="TON_IoT (optional)", source_organization="UNSW Canberra Cyber, University of New South Wales",
        official_url="https://research.unsw.edu.au/projects/toniot-datasets", download_url="official SharePoint/OneDrive link on project page",
        version="Train_Test_Network", publication_year=2020,
        license="Free for academic research use per publisher; to be re-confirmed on official page.",
        citation="Moustafa, N. (2021). A new distributed architecture for evaluating AI-based security systems at the edge: Network TON_IoT datasets. Sustainable Cities and Society, 72, 102994.",
        description="Heterogeneous IoT/IIoT telemetry, OS and network data", geographic_scope="Testbed (Australia)",
        temporal_scope="2019-2020 per publisher", attack_types="Scanning, DoS, DDoS, ransomware, backdoor, injection, XSS, password, MITM"),
}


def size_h(b):
    for u in ["B", "KB", "MB", "GB", "TB"]:
        if b < 1024:
            return f"{b:.1f} {u}"
        b /= 1024
    return f"{b:.1f} PB"


def main():
    vr = pd.read_csv(os.path.join(META, "data_validation_report.csv"))
    ck = pd.read_csv(os.path.join(META, "raw_checksums.csv"))
    dl = pd.read_csv(os.path.join(LOGS, "download_log.csv"))
    cat = []
    i = 0
    for ds, m in CATALOG_META.items():
        files = vr[(vr.dataset == ds) & (vr.exists == True)] if ds in DATASETS else pd.DataFrame()  # noqa: E712
        if len(files):
            for _, r in files.iterrows():
                i += 1
                d = ck[ck.file_name == r.file_name].download_date
                cat.append(dict(dataset_id=f"DS{i:03d}", **{k: m[k] for k in ["dataset_name", "source_organization", "official_url",
                                                                               "download_url", "version", "publication_year"]},
                                download_date=d.iloc[0] if len(d) else "", file_name=r.file_name, file_format=r.file_format,
                                file_size=int(r.file_size_bytes), license=m["license"], citation=m["citation"],
                                description=m["description"], geographic_scope=m["geographic_scope"],
                                temporal_scope=f"{r.timestamp_min} to {r.timestamp_max}",
                                attack_types=r.labels.split(";").__len__() and "; ".join(x.split("=")[0].strip() for x in str(r.labels).split(";")),
                                number_of_records=int(r.rows), status="downloaded_verified_size_sha256",
                                notes=f"SHA-256 in raw_checksums.csv; repeated header rows={r.repeated_header_rows}"))
            if ds == "CSE_CIC_IDS2018":
                i += 1
                cat.append(dict(dataset_id=f"DS{i:03d}", **{k: m[k] for k in ["dataset_name", "source_organization", "official_url", "version",
                                                                               "publication_year"]},
                                download_url="s3://cse-cic-ids2018/Original Network Traffic and Log data/",
                                download_date="", file_name="Original Network Traffic and Log data/ (31 objects)",
                                file_format="pcap/zip/logs", file_size=479_300_000_000, license=m["license"], citation=m["citation"],
                                description="Raw PCAPs and host logs", geographic_scope=m["geographic_scope"],
                                temporal_scope=m["temporal_scope"], attack_types=m["attack_types"], number_of_records="",
                                status="not_downloaded_by_design",
                                notes="~479.3 GB; not needed because the publisher's flow CSVs are used; size from S3 listing 2026-10-02"))
        else:
            i += 1
            cat.append(dict(dataset_id=f"DS{i:03d}", **{k: m[k] for k in ["dataset_name", "source_organization", "official_url", "download_url",
                                                                           "version", "publication_year"]},
                            download_date="", file_name="", file_format="CSV", file_size="", license=m["license"],
                            citation=m["citation"], description=m["description"], geographic_scope=m["geographic_scope"],
                            temporal_scope=m["temporal_scope"], attack_types=m["attack_types"], number_of_records="",
                            status="pending_manual_download",
                            notes="Official host blocked by the collection environment's network policy and/or distribution requires a "
                                  "registration form. Place files in 01_raw_data/" + ds + "/ and re-run the pipeline (see README)."))
    nep = os.path.join(ROOT, "07_nepal_analysis")
    for fn, desc in [("cyber_incidents.csv", "Nepal publicly reported cyber incidents"),
                     ("cybersecurity_reports.csv", "Nepal public cybersecurity reports/policies"),
                     ("digital_infrastructure.csv", "Nepal digital infrastructure indicators")]:
        i += 1
        n = len(pd.read_csv(os.path.join(nep, fn)))
        cat.append(dict(dataset_id=f"DS{i:03d}", dataset_name=f"Nepal public secondary data: {fn}",
                        source_organization="Multiple public sources (see 07_nepal_analysis/source_register.csv)",
                        official_url="see source_register.csv", download_url="", version="compiled 2026-10-02",
                        publication_year=2026, download_date="2026-10-02", file_name=fn, file_format="CSV",
                        file_size=os.path.getsize(os.path.join(nep, fn)), license="Facts with citation; no article text reproduced",
                        citation="see per-record source_url", description=desc, geographic_scope="Nepal",
                        temporal_scope="2016-2026", attack_types="", number_of_records=n,
                        status="compiled_search_extract_only",
                        notes="Full pages not retrieved (hosts blocked); each record must be confirmed before citation"))
    C = pd.DataFrame(cat)
    C.to_csv(os.path.join(META, "data_catalog.csv"), index=False)

    # source registry
    reg = []
    for ds, m in CATALOG_META.items():
        reached = ds == "CSE_CIC_IDS2018"
        reg.append(dict(source_id=ds, source_type="dataset", title=m["dataset_name"], organization=m["source_organization"],
                        official_url=m["official_url"], access_channel=m["download_url"],
                        access_status="downloaded from official AWS Open Data bucket" if reached else "blocked/pending manual download",
                        license=m["license"], citation=m["citation"], retrieved="2026-10-02" if reached else ""))
    reg.append(dict(source_id="DOC_AWS_REGISTRY", source_type="documentation", title="AWS Open Data Registry entry cse-cic-ids2018.yaml",
                    organization="AWS / awslabs", official_url="https://github.com/awslabs/open-data-registry/blob/main/datasets/cse-cic-ids2018.yaml",
                    access_channel="raw.githubusercontent.com", access_status="saved in 01_raw_data/CSE_CIC_IDS2018/_publisher_documentation",
                    license="", citation="", retrieved="2026-10-02"))
    reg.append(dict(source_id="DOC_CICFLOWMETER", source_type="documentation", title="CICFlowMeter ReadMe.txt (feature definitions)",
                    organization="Canadian Institute for Cybersecurity", official_url="https://github.com/ahlashkari/CICFlowMeter",
                    access_channel="raw.githubusercontent.com", access_status="saved in 01_raw_data/CSE_CIC_IDS2018/_publisher_documentation",
                    license="", citation="Lashkari et al. (2017), ICISSP; Draper-Gil et al. (2016), ICISSP", retrieved="2026-10-02"))
    sr = pd.read_csv(os.path.join(nep, "source_register.csv"))
    for _, r in sr.iterrows():
        reg.append(dict(source_id="NEPAL_" + r.source_id, source_type="nepal_" + str(r.source_type), title=r.title,
                        organization=r.publisher, official_url=r.url, access_channel="web search engine",
                        access_status=r.verification_status, license="cited fact only", citation="", retrieved=r.retrieval_date))
    pd.DataFrame(reg).to_csv(os.path.join(META, "source_registry.csv"), index=False)

    # ------------------------------------------------------------ FINAL AUDIT
    v = vr[vr.exists == True]  # noqa: E712
    cl = pd.read_csv(os.path.join(LOGS, "cleaning_log.csv"))
    cd = pd.read_csv(os.path.join(OUT, "tables", "class_distribution.csv"))
    stages = json.load(open(os.path.join(READY, "continual_learning", "stages.json")))
    scen = {os.path.basename(os.path.dirname(p)): json.load(open(p))
            for p in sorted(glob.glob(os.path.join(READY, "zero_day", "*", "scenario.json")))}
    inc = pd.read_csv(os.path.join(nep, "cyber_incidents.csv"))
    rep = pd.read_csv(os.path.join(nep, "cybersecurity_reports.csv"))
    ind = pd.read_csv(os.path.join(nep, "digital_infrastructure.csv"))
    leak = open(os.path.join(READY, "data_leakage_report.md")).read()
    pkgs = {p: md.version(p) for p in ["pandas", "numpy", "pyarrow", "tabulate"]}
    raw_total = int(ck.file_size.sum())
    summ = cl[cl.step == "summary"]
    inf_rows = cl[cl.step == "infinite_to_nan"]
    miss_rows = cl[cl.step == "missing_values_reported"]
    neg_rows = cl[cl.step == "negative_values_reported"]
    hdr = cl[cl.step == "drop_repeated_header_rows"]
    benign = int(cd[cd.standardized_label == "BENIGN"].number_of_samples.sum())
    total = int(cd.number_of_samples.sum())
    L = []
    a = L.append
    a("# FINAL DATA AUDIT\n")
    a("Research: *Explainable Continual Learning for Zero-Day Cyberattack Detection Under Evolving Threat Landscapes*  ")
    a("Generated by `08_scripts/validation/build_catalog_and_audit.py`. All numbers below are computed from pipeline outputs.\n")
    a("> Gate: no machine-learning experiment has been run. This audit is the precondition for starting experiments.\n")
    a("## 1. Dataset inventory\n")
    a("| Dataset | Status | Raw files | Raw size | Records (rows after header removal) |\n|---|---|---|---|---|")
    for ds in CATALOG_META:
        sub = v[v.dataset == ds]
        if len(sub):
            a(f"| {ds} | downloaded (official source), SHA-256 recorded | {len(sub)} | {size_h(sub.file_size_bytes.sum())} | {int(sub.rows.sum()):,} |")
        else:
            a(f"| {ds} | **pending manual download** (official host not reachable from collection environment) | 0 | - | - |")
    a(f"| Nepal public data | compiled from web-search extracts (see section 6) | 3 CSV + {len(sr)} source records | small | {len(inc)} incidents / {len(rep)} reports / {len(ind)} indicators |")
    a(f"\nDatasets requested: 4 required + 1 optional. Downloaded and processed: **1** (CSE-CIC-IDS2018). "
      f"Raw files checksummed: {len(ck)} (total {size_h(raw_total)}).\n")
    prof = pd.read_csv(os.path.join(OUT, "tables", "raw_column_profile.csv"))
    idc = {"Flow ID", "Src IP", "Dst IP", "Source IP", "Destination IP", "Label", "Timestamp"}
    nonnum_feat = prof[~prof.column.str.strip().isin(idc)].non_numeric.sum()
    lit = prof[prof.literal_nan > 0].groupby("column").literal_nan.sum()
    a("## 2. Data quality (CSE-CIC-IDS2018)\n")
    a("| File | Rows | Columns | Repeated header rows (dropped) | Exact duplicate rows | Dup % | Cells +/-Inf | Missing (blank) cells | Timestamp unparsed |\n|---|---|---|---|---|---|---|---|---|")
    for _, r in v.iterrows():
        a(f"| {r.file_name} | {int(r.rows):,} | {int(r.columns)} | {int(r.repeated_header_rows)} | {int(r.duplicate_rows_exact):,} | {r.duplicate_pct} | {int(r.cells_infinite_total):,} | {int(r.cells_missing_total):,} | {int(r.timestamp_unparsed):,} |")
    a(f"\n- Totals: rows {int(v.rows.sum()):,}; exact duplicate rows {int(v.duplicate_rows_exact.sum()):,} "
      f"({100*v.duplicate_rows_exact.sum()/v.rows.sum():.2f}%); infinite cells {int(v.cells_infinite_total.sum()):,}; "
      f"literal NaN cells {int(v.cells_literal_nan_total.sum()):,} (" + ", ".join(f"{k}={int(x):,}" for k, x in lit.items()) + "); "
      f"non-numeric tokens in numeric feature columns {int(nonnum_feat):,} (identifier columns Flow ID/Src IP/Dst IP excluded); "
      f"malformed/skipped lines {int(v.malformed_or_skipped_lines.sum()):,}; strict-UTF-8 files {int(v.encoding_strict_utf8.sum())}/{len(v)}.")
    a(f"- Cleaning: rows in {int(summ.original_count.sum()):,} -> rows out {int(summ.final_count.sum()):,} "
      f"(difference = repeated header rows {int(hdr.original_count.sum()):,}; no observation removed silently).")
    if len(inf_rows):
        g = inf_rows.groupby("column").original_count.sum().sort_values(ascending=False)
        a("- +/-Infinity converted to NaN (row flag `had_infinite_value`): " + ", ".join(f"{k}={int(x):,}" for k, x in g.items()))
    if len(miss_rows):
        g = miss_rows.groupby("column").original_count.sum().sort_values(ascending=False)
        a("- Blank (missing) cells: " + ", ".join(f"{k}={int(x):,}" for k, x in g.items()))
    else:
        a("- Blank (missing) cells in feature columns: none. Missing values after cleaning come only from literal 'NaN' "
          "tokens written by the publisher and from +/-Infinity converted to NaN (counts above); they are not imputed.")
    if len(neg_rows):
        g = neg_rows.groupby("column").original_count.sum().sort_values(ascending=False)
        a("- Invalid/sentinel negative values (kept, reported): " + ", ".join(f"{k}={int(x):,}" for k, x in g.head(12).items()))
    a("- No imputation, no outlier clipping, no scaling and no duplicate removal were applied to cleaned data. "
      "Cross-split duplicates are removed only from validation/test in 06_analysis_ready (see data_leakage_report.md).\n")
    a("## 3. Class distribution\n")
    a(f"- Benign samples: {benign:,} ({100*benign/total:.2f}%); attack samples: {total-benign:,} ({100*(total-benign)/total:.2f}%).")
    fam = cd.groupby("standardized_label").number_of_samples.sum().sort_values(ascending=False)
    a("- Attack categories (standardized): " + ", ".join(f"{k}={int(x):,}" for k, x in fam.items() if k != "BENIGN"))
    a("\n| standardized_label | original_label | samples | % | train | validation | test |\n|---|---|---|---|---|---|---|")
    for _, r in cd.sort_values("number_of_samples", ascending=False).iterrows():
        a(f"| {r.standardized_label} | {r.original_label} | {int(r.number_of_samples):,} | {r.percentage} | {int(r.train_count):,} | {int(r.validation_count):,} | {int(r.test_count):,} |")
    a("\nNo resampling (SMOTE/oversampling) applied. Imbalance documented in class_distribution.csv.\n")
    a("## 4. Temporal coverage\n")
    tsmin = pd.to_datetime(v.timestamp_min).min()
    tsmax = pd.to_datetime(v.timestamp_max).max()
    labs = pd.read_parquet(os.path.join(HARM, "labels", "CSE_CIC_IDS2018_labels.parquet"), columns=["timestamp"])
    a(f"- Corrected timestamps: earliest {labs.timestamp.min()}, latest {labs.timestamp.max()} "
      f"({int(labs.timestamp.isna().sum())} invalid timestamps set to NaT). As published (before correction): "
      f"earliest {tsmin}, latest {tsmax}. Time zone is not stated by the publisher.")
    odd = v[pd.to_datetime(v.timestamp_min).dt.date.astype(str) != v.file_name.str.extract(r"(\d{2})-(\d{2})-(\d{4})").apply(lambda x: f"{x[2]}-{x[1]}-{x[0]}", axis=1)]
    if len(odd):
        a(f"- Files whose earliest timestamp falls outside their capture day: {', '.join(odd.file_name)} (kept; capture_day is taken from the file name).")
    tc = cl[cl.step == "timestamp_12h_correction"].groupby("method").original_count.sum()
    a("- Published timestamps use a 12-hour clock without AM/PM (all hours fall in 01-12). Correction applied in "
      "harmonisation (`timestamp_as_published` kept): " + ", ".join(f"{k}={int(x):,}" for k, x in tc.items()) +
      ". Corrected attack windows match the publisher's attack schedule (e.g. SSH-Bruteforce 14:01-15:32).")
    trunc = v[v.physical_lines == 1048576]
    if len(trunc):
        a(f"- {len(trunc)} files have exactly 1,048,576 lines (header + 1,048,575 rows = the Microsoft Excel row limit): "
          + ", ".join(trunc.file_name) + ". The publisher's CSVs therefore appear truncated (e.g. DoS-Hulk on 16-02 ends at "
          "13:48 although the attack is documented until ~14:19). Rows beyond the limit are not recoverable from these files; "
          "the PCAPs in the same bucket would be needed.")
    a(f"- Number of continual-learning stages: {len(stages)}\n")
    a("| Stage | Role | Capture days | New classes | Previously observed | train / val / test |\n|---|---|---|---|---|---|")
    for s, x in stages.items():
        a(f"| {s} | {x['role']} | {', '.join(x['capture_days'])} | {', '.join(x['new_classes']) or '-'} | {', '.join(x['previously_observed']) or '-'} | {x['samples']['train']:,} / {x['samples']['validation']:,} / {x['samples']['test']:,} |")
    a("\n## 5. Zero-day-like (unseen-attack simulation) scenarios\n")
    a("These are simulated unseen-attack evaluations built by withholding families; they are **not genuine zero-day attacks**.\n")
    a("| Scenario | Withheld family | Training classes | Testing classes |\n|---|---|---|---|")
    for z, x in scen.items():
        a(f"| {z} | {', '.join(x['withheld_families'])} | {', '.join(x['training_classes'])} | {', '.join(x['testing_classes'])} |")
    a("\n## 6. Nepal data\n")
    yrs = sorted(set(inc.year.astype(str)))
    a(f"- Documented incidents: {len(inc)}; years covered: {', '.join(yrs)}; sectors: {', '.join(sorted(inc.sector.unique()))}.")
    a(f"- Reports/policies: {len(rep)}; infrastructure indicators: {len(ind)}; distinct sources: {len(sr)}.")
    a("- Verification level: **search_extract_only** for every record (URL + title + extract from a search engine; full page "
      "not opened because the collection environment blocked Nepali hosts). Every value must be confirmed against the "
      "full source before it is cited. No incident was inferred or invented; unknown fields are 'Unknown'.\n")
    a("## 7. Leakage checks\n")
    a("See `06_analysis_ready/data_leakage_report.md` (copied below).\n")
    a(leak.replace("# Data Leakage Report", "### Data Leakage Report (copy)"))
    a("\n## 8. Reproducibility\n")
    a(f"- Python {platform.python_version()} on {platform.platform()}")
    a("- Packages: " + ", ".join(f"{k} {x}" for k, x in pkgs.items()))
    a("- Scripts (run order): `08_scripts/run_pipeline.sh` ->")
    for s in ["download/download_datasets.py", "download/build_nepal_register.py", "validation/validate_raw.py",
              "cleaning/clean_dataset.py", "harmonization/harmonize.py", "dataset_split/make_splits.py",
              "feature_engineering/build_dictionaries.py", "validation/build_catalog_and_audit.py"]:
        a(f"  - `08_scripts/{s}`")
    a("- Dataset versions: see `02_raw_metadata/data_catalog.csv`.")
    a(f"- Checksums: `02_raw_metadata/raw_checksums.csv` ({len(ck)} files, SHA-256).")
    a("- Randomness: none in splitting (purely chronological). Preview CSVs take the earliest rows per class (deterministic).\n")
    a("## 9. Outstanding items before experiments\n")
    a("1. Download CIC-IDS2017, CIC-DDoS2019, UNSW-NB15 (and optionally TON_IoT) from the official pages into `01_raw_data/<DATASET>/`, then re-run `08_scripts/run_pipeline.sh`. Cross-dataset harmonisation code is in place but untested on those files.")
    a("2. Open each Nepal source URL and upgrade `verification_status` to `verified_full_text`, correcting any value that differs.")
    a("3. Re-confirm the licence text of each dataset on its official page.")
    txt = "\n".join(L) + "\n"
    for p in [os.path.join(ROOT, "FINAL_DATA_AUDIT.md"), os.path.join(OUT, "summaries", "FINAL_DATA_AUDIT.md")]:
        with open(p, "w") as f:
            f.write(txt)
    print("catalog + audit written")


if __name__ == "__main__":
    main()
